import argparse, html, json, time
from collections import Counter, deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

from checks import (FindingStore, ParamInventory, SEV_RANK, analyze_forms,
                    check_body, check_cookies, check_headers, check_html_structure,
                    check_link_targets, check_tls, register_query_params)

UA = "Passive-Web-Audit/2.0"

def origin(u):
    p=urlparse(u); return (p.scheme.lower(), p.hostname.lower() if p.hostname else "", p.port or (443 if p.scheme=="https" else 80))

def normalize(u):
    u,_=urldefrag(u); p=urlparse(u)
    if p.scheme not in ("http","https"): return None
    path=p.path or "/"
    return p._replace(scheme=p.scheme.lower(), netloc=p.netloc.lower(), path=path, fragment="").geturl()

def cookie_headers(resp):
    raw=getattr(resp.raw, "headers", None)
    if raw and hasattr(raw,"getlist"): return raw.getlist("Set-Cookie")
    v=resp.headers.get("Set-Cookie"); return [v] if v else []

def crawl(start, max_pages, max_depth, delay, timeout, excludes):
    s=requests.Session(); s.headers.update({"User-Agent":UA})
    store, params = FindingStore(), ParamInventory(); forms=[]; pages=[]
    q=deque([(normalize(start),0)]); seen=set(); start_origin=origin(start); tls_done=set()
    while q and len(pages)<max_pages:
        url,depth=q.popleft()
        if not url or url in seen or any(x in url for x in excludes): continue
        seen.add(url); register_query_params(store, params, url, url)
        try:
            r=s.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as e:
            store.add("CRAWL-ERROR", url, url, detail=str(e)); continue
        final=normalize(r.url) or r.url
        if origin(final)!=start_origin:
            store.add("CRAWL-REDIRECT-EXTERNAL", url, url, evidence=final); continue
        ct=r.headers.get("Content-Type",""); is_html="text/html" in ct.lower()
        pages.append({"url":final,"status":r.status_code,"content_type":ct,"depth":depth,"bytes":len(r.content)})
        if r.status_code>=500: store.add("CRAWL-5XX", final, final, detail="HTTP %s"%r.status_code)
        check_headers(store, final, r.headers, is_html)
        check_cookies(store, final, cookie_headers(r))
        text=r.text if (is_html or "javascript" in ct.lower() or r.status_code>=400) else ""
        if text: check_body(store, final, text, is_html, r.status_code)
        p=urlparse(final)
        if p.scheme=="https" and p.hostname and p.hostname not in tls_done:
            check_tls(store,p.hostname,p.port or 443,final); tls_done.add(p.hostname)
        if is_html:
            soup=BeautifulSoup(r.text,"html.parser")
            base=final
            b=soup.find("base",href=True)
            if b: base=urljoin(final,b["href"])
            analyze_forms(store,params,forms,final,soup,base)
            check_html_structure(store,final,soup,base)
            discovered=[]
            for tag,attr in (("a","href"),("script","src"),("link","href"),("img","src")):
                for el in soup.find_all(tag):
                    v=(el.get(attr) or "").strip()
                    if v and not v.lower().startswith(("javascript:","mailto:","tel:","data:")):
                        u=normalize(urljoin(base,v))
                        if u: discovered.append(u); register_query_params(store,params,u,final)
            check_link_targets(store,final,discovered)
            can=soup.find("link",rel=lambda x:x and "canonical" in x)
            if can and can.get("href"):
                cu=normalize(urljoin(base,can["href"]))
                if cu and origin(cu)!=start_origin: store.add("CRAWL-CANONICAL-EXTERNAL",cu,final,evidence=cu)
            if depth<max_depth:
                for u in discovered:
                    if origin(u)==start_origin and u not in seen: q.append((u,depth+1))
        if delay: time.sleep(delay)
    return {"target":start,"generated_at":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "config":{"max_pages":max_pages,"max_depth":max_depth,"delay":delay,"timeout":timeout,"same_origin":True},
            "pages":pages,"forms":forms,"parameters":params.as_list(),"findings":store.as_list()}

def esc(v): return html.escape(str(v or ""))
def report(data):
    findings=data["findings"]; counts=Counter(f["severity"] for f in findings)
    cards="".join(f'<div class="card {s}"><b>{counts[s]}</b><span>{s.title()}</span></div>' for s in ("critical","high","medium","low","info"))
    rows=[]
    for f in findings:
        probs="".join(f"<li>{esc(x)}</li>" for x in f.get("problems",[]))
        urls="".join(f"<li><code>{esc(x)}</code></li>" for x in f.get("urls",[])[:8])
        rows.append(f'''<details class="finding {esc(f['severity'])}"><summary><span class="badge">{esc(f['severity']).upper()}</span><b>{esc(f['issue'])}</b><code>{esc(f['id'])}</code></summary>
        <div class="body"><p>{esc(f.get('detail',''))}</p><dl><dt>CWE / OWASP</dt><dd>{esc(f.get('cwe'))} · {esc(f.get('owasp'))}</dd><dt>Evidence</dt><dd><pre>{esc(f.get('evidence',''))}</pre></dd><dt>Affected URLs ({f.get('count',1)})</dt><dd><ul>{urls}</ul></dd>{'<dt>Problems</dt><dd><ul>'+probs+'</ul></dd>' if probs else ''}<dt>Recommendation</dt><dd>{esc(f.get('recommendation'))}</dd></dl></div></details>''')
    formrows="".join(f"<tr><td><code>{esc(x['page'])}</code></td><td>{esc(x['method'])}</td><td><code>{esc(x['action'])}</code></td><td>{len(x.get('inputs',[]))}</td><td>{'Yes' if x.get('csrf_token_present') else 'No'}</td></tr>" for x in data['forms']) or '<tr><td colspan="5">None discovered</td></tr>'
    prows="".join(f"<tr><td><code>{esc(x['name'])}</code></td><td>{x['count']}</td><td>{', '.join(sorted(set(y['kind'] for y in x['locations'])))}</td></tr>" for x in data['parameters']) or '<tr><td colspan="3">None discovered</td></tr>'
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Passive Security Audit</title><style>
:root{{--bg:#f6f7f9;--panel:#fff;--ink:#17202a;--muted:#667085;--line:#e4e7ec}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,sans-serif}}main{{max-width:1180px;margin:auto;padding:36px 22px}}h1{{margin-bottom:4px}}.muted{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0}}.card{{background:var(--panel);border:1px solid var(--line);border-top:4px solid #98a2b3;border-radius:9px;padding:16px}}.card b{{font-size:26px;display:block}}.critical,.high{{border-top-color:#b42318}}.medium{{border-top-color:#dc6803}}.low{{border-top-color:#1570ef}}section{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin:18px 0}}details{{border:1px solid var(--line);border-left:5px solid #98a2b3;border-radius:7px;margin:9px 0;background:#fff}}summary{{display:flex;gap:12px;align-items:center;padding:14px;cursor:pointer}}summary code{{margin-left:auto;color:var(--muted)}}.badge{{font-size:11px;font-weight:700;min-width:64px}}.body{{padding:0 16px 16px}}dl{{display:grid;grid-template-columns:150px 1fr;gap:10px}}dt{{font-weight:700}}dd{{margin:0}}pre{{white-space:pre-wrap;word-break:break-word;background:#f2f4f7;padding:10px;border-radius:6px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}code{{word-break:break-all}}@media(max-width:700px){{.cards{{grid-template-columns:1fr 1fr}}dl{{grid-template-columns:1fr}}}}
</style></head><body><main><h1>Passive Web Security Audit</h1><div class="muted">{esc(data['target'])} · generated {esc(data['generated_at'])}</div><div class="cards">{cards}</div>
<section><h2>Scan summary</h2><p><b>{len(data['pages'])}</b> pages · <b>{len(data['forms'])}</b> forms · <b>{len(data['parameters'])}</b> parameters · <b>{len(findings)}</b> unique findings</p><p class="muted">Passive checks only. Findings are heuristic and should be manually validated.</p></section>
<section><h2>Findings</h2>{''.join(rows) or '<p>No findings.</p>'}</section><section><h2>Forms</h2><table><tr><th>Page</th><th>Method</th><th>Action</th><th>Inputs</th><th>CSRF-looking token</th></tr>{formrows}</table></section><section><h2>Parameter inventory</h2><table><tr><th>Name</th><th>Seen</th><th>Locations</th></tr>{prows}</table></section></main></body></html>'''

def main():
    ap=argparse.ArgumentParser(description="Passive same-origin web security scanner")
    ap.add_argument("url"); ap.add_argument("--max-pages",type=int,default=100); ap.add_argument("--max-depth",type=int,default=4)
    ap.add_argument("--delay",type=float,default=.25); ap.add_argument("--timeout",type=float,default=10); ap.add_argument("--exclude",action="append",default=[])
    ap.add_argument("--json",default="security-report.json"); ap.add_argument("--html",default="security-report.html")
    a=ap.parse_args(); data=crawl(a.url,a.max_pages,a.max_depth,a.delay,a.timeout,a.exclude)
    with open(a.json,"w",encoding="utf-8") as f: json.dump(data,f,indent=2)
    with open(a.html,"w",encoding="utf-8") as f: f.write(report(data))
    print(f"Pages: {len(data['pages'])} | Findings: {len(data['findings'])} | Forms: {len(data['forms'])} | Parameters: {len(data['parameters'])}")
    print(f"JSON: {a.json}\nHTML: {a.html}")
if __name__=="__main__": main()

