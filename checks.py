"""Passive analysis helpers, rule metadata and finding storage.

Nothing in this module sends traffic except check_tls(), which performs a
single ordinary TLS handshake per host.
"""
import hashlib
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import Comment

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_URLS_PER_FINDING = 25

# rule_id: (default severity, title, CWE, OWASP Top 10 2021, remediation)
RULES = {
    # --- Security headers -------------------------------------------------
    "HDR-CSP-MISSING": ("medium", "Missing Content-Security-Policy", "CWE-693", "A05:2021",
        "Define a restrictive CSP that only allows trusted origins and avoids inline script via nonces or hashes."),
    "CSP-REPORT-ONLY": ("info", "Content-Security-Policy is report-only", "CWE-693", "A05:2021",
        "Once violations are triaged, enforce the policy with Content-Security-Policy."),
    "CSP-NO-SCRIPT-POLICY": ("medium", "CSP does not restrict scripts", "CWE-79", "A05:2021",
        "Add script-src (or default-src) so script sources are restricted."),
    "CSP-UNSAFE-INLINE": ("medium", "CSP allows 'unsafe-inline'", "CWE-79", "A05:2021",
        "Remove 'unsafe-inline'; use nonces or hashes (optionally with 'strict-dynamic')."),
    "CSP-UNSAFE-EVAL": ("medium", "CSP allows 'unsafe-eval'", "CWE-95", "A05:2021",
        "Remove 'unsafe-eval' and avoid eval()/new Function() in application code."),
    "CSP-WILDCARD": ("medium", "CSP uses overly broad sources", "CWE-693", "A05:2021",
        "Replace *, https:, http: and data: sources with an explicit allow-list of origins."),
    "CSP-INSECURE-SCHEME": ("low", "CSP allows plain-HTTP sources", "CWE-319", "A02:2021",
        "Use https:// sources only."),
    "CSP-NO-OBJECT-SRC": ("low", "CSP missing object-src", "CWE-693", "A05:2021",
        "Add object-src 'none' to block legacy plugin content."),
    "CSP-NO-BASE-URI": ("low", "CSP missing base-uri", "CWE-693", "A05:2021",
        "Add base-uri 'self' (or 'none') to prevent <base> tag injection."),
    "CSP-NO-FRAME-ANCESTORS": ("low", "CSP missing frame-ancestors", "CWE-1021", "A05:2021",
        "Add frame-ancestors 'none' or 'self' to prevent clickjacking."),
    "HDR-XFO-MISSING": ("medium", "Missing clickjacking protection (X-Frame-Options / frame-ancestors)", "CWE-1021", "A05:2021",
        "Send X-Frame-Options: DENY|SAMEORIGIN or a CSP frame-ancestors directive."),
    "HDR-XFO-WEAK": ("low", "X-Frame-Options uses obsolete ALLOW-FROM", "CWE-1021", "A05:2021",
        "Use CSP frame-ancestors instead; browsers ignore ALLOW-FROM."),
    "HDR-HSTS-MISSING": ("medium", "Missing Strict-Transport-Security", "CWE-319", "A02:2021",
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    "HDR-HSTS-WEAK": ("low", "Weak Strict-Transport-Security max-age", "CWE-319", "A02:2021",
        "Use max-age of at least 31536000 (one year)."),
    "HDR-HSTS-NO-SUBDOMAINS": ("info", "HSTS lacks includeSubDomains", "CWE-319", "A02:2021",
        "Add includeSubDomains once all subdomains support HTTPS."),
    "HDR-NOSNIFF-MISSING": ("low", "Missing X-Content-Type-Options: nosniff", "CWE-693", "A05:2021",
        "Send X-Content-Type-Options: nosniff."),
    "HDR-REFERRER-MISSING": ("low", "Missing Referrer-Policy", "CWE-200", "A05:2021",
        "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter)."),
    "HDR-REFERRER-WEAK": ("low", "Weak Referrer-Policy", "CWE-200", "A05:2021",
        "Avoid unsafe-url / no-referrer-when-downgrade / origin-when-cross-origin."),
    "HDR-PERMISSIONS-MISSING": ("info", "Missing Permissions-Policy", "CWE-693", "A05:2021",
        "Send a Permissions-Policy disabling unused browser features (camera, microphone, geolocation...)."),
    "HDR-OBSOLETE": ("info", "Obsolete or deprecated security header present", "CWE-1104", "A05:2021",
        "Remove the header; rely on CSP and modern defaults."),
    "HDR-CORS-WILDCARD": ("medium", "Permissive CORS policy", "CWE-942", "A05:2021",
        "Restrict Access-Control-Allow-Origin to trusted origins; never combine wildcard/null with credentials."),

    # --- Information exposure ---------------------------------------------
    "INFO-SERVER-BANNER": ("low", "Server header discloses version", "CWE-200", "A05:2021",
        "Suppress version details in the Server header."),
    "INFO-POWERED-BY": ("low", "Technology/version disclosure header", "CWE-200", "A05:2021",
        "Remove X-Powered-By / X-AspNet-Version / similar headers."),
    "INFO-STACKTRACE": ("medium", "Stack trace or verbose error message exposed", "CWE-209", "A05:2021",
        "Disable verbose errors in production and return generic error pages."),
    "INFO-DEBUG-PAGE": ("high", "Debug console or debug error page exposed", "CWE-489", "A05:2021",
        "Disable debug mode in production."),
    "INFO-DIRLIST": ("medium", "Directory listing enabled", "CWE-548", "A05:2021",
        "Disable automatic directory indexing."),
    "INFO-GIT-REF": ("medium", "Version-control metadata referenced", "CWE-527", "A05:2021",
        "Do not deploy .git/.svn/.hg directories; block access at the web server."),
    "INFO-BACKUP-LINK": ("medium", "Link to backup or sensitive file", "CWE-530", "A05:2021",
        "Remove backup/archive/config files from the web root."),
    "INFO-SOURCEMAP": ("low", "JavaScript source map exposed", "CWE-540", "A05:2021",
        "Do not publish source maps to production, or restrict them to authenticated developers."),
    "INFO-SECRET": ("high", "Possible secret embedded in page or script", "CWE-798", "A02:2021",
        "Remove the secret from client-delivered content and rotate it."),
    "INFO-INTERNAL-IP": ("low", "Internal IP address disclosed", "CWE-200", "A05:2021",
        "Remove internal addressing from client-visible content."),
    "INFO-COMMENT": ("low", "Sensitive-looking keyword in HTML comment", "CWE-615", "A05:2021",
        "Strip developer comments from production output."),
    "INFO-EMAIL": ("info", "Email addresses exposed in page", "CWE-200", "A05:2021",
        "Confirm exposure is intentional; consider contact forms."),

    # --- Cookies ----------------------------------------------------------
    "COOKIE-NO-SECURE": ("medium", "Cookie missing Secure attribute", "CWE-614", "A02:2021",
        "Set the Secure attribute on all cookies served over HTTPS."),
    "COOKIE-NO-HTTPONLY": ("medium", "Cookie missing HttpOnly attribute", "CWE-1004", "A05:2021",
        "Set HttpOnly on session and authentication cookies."),
    "COOKIE-SAMESITE-MISSING": ("low", "Cookie missing SameSite attribute", "CWE-1275", "A01:2021",
        "Set SameSite=Lax or Strict unless cross-site use is required."),
    "COOKIE-SAMESITE-NONE-INSECURE": ("medium", "SameSite=None without Secure", "CWE-1275", "A01:2021",
        "SameSite=None requires the Secure attribute."),
    "COOKIE-PREFIX-INVALID": ("low", "Cookie prefix requirements not met", "CWE-614", "A05:2021",
        "__Host- cookies need Secure, Path=/ and no Domain; __Secure- cookies need Secure."),

    # --- TLS / transport --------------------------------------------------
    "TLS-NO-REDIRECT": ("medium", "HTTP does not redirect to HTTPS", "CWE-319", "A02:2021",
        "Redirect all HTTP requests to HTTPS (301/308) and enable HSTS."),
    "TLS-CERT-EXPIRED": ("high", "TLS certificate expired", "CWE-298", "A02:2021",
        "Renew the certificate."),
    "TLS-CERT-EXPIRING": ("medium", "TLS certificate expires soon", "CWE-298", "A02:2021",
        "Renew the certificate and automate renewal."),
    "TLS-CERT-HOSTNAME": ("high", "TLS certificate does not match hostname", "CWE-297", "A02:2021",
        "Serve a certificate valid for this hostname."),
    "TLS-CERT-UNTRUSTED": ("high", "TLS certificate not trusted", "CWE-295", "A02:2021",
        "Use a certificate from a trusted CA with a complete chain."),
    "TLS-OLD-VERSION": ("medium", "Deprecated TLS version negotiated", "CWE-326", "A02:2021",
        "Disable TLS 1.0/1.1; require TLS 1.2+."),
    "TLS-ERROR": ("info", "TLS handshake failed", "CWE-295", "A02:2021",
        "Investigate the TLS configuration of this endpoint."),
    "MIXED-ACTIVE": ("high", "Mixed content: active resource loaded over HTTP", "CWE-319", "A02:2021",
        "Load scripts, styles, frames and objects over HTTPS only."),
    "MIXED-PASSIVE": ("low", "Mixed content: passive resource loaded over HTTP", "CWE-319", "A02:2021",
        "Load images and media over HTTPS."),

    # --- Forms / parameters -----------------------------------------------
    "FORM-PW-HTTP": ("high", "Password form submitted over HTTP", "CWE-319", "A02:2021",
        "Serve the page and submit the form over HTTPS only."),
    "FORM-PW-GET": ("high", "Password field in a GET form", "CWE-598", "A04:2021",
        "Submit credentials with POST; GET leaks them into URLs, logs and Referer."),
    "FORM-INSECURE-ACTION": ("medium", "HTTPS page submits form to HTTP", "CWE-319", "A02:2021",
        "Point the form action at an HTTPS URL."),
    "FORM-NO-CSRF": ("medium", "State-changing form without a CSRF-looking token", "CWE-352", "A01:2021",
        "Add anti-CSRF tokens (and SameSite cookies). Heuristic: verify manually."),
    "FORM-AUTOCOMPLETE": ("low", "Autocomplete setting on sensitive input", "CWE-525", "A05:2021",
        "Use autocomplete=current-password/new-password for passwords; disable for card/SSN data."),
    "FORM-CROSS-ORIGIN": ("low", "Form submits to a different origin", "CWE-346", "A05:2021",
        "Confirm the destination is trusted; never post credentials cross-origin."),
    "PARAM-SENSITIVE-QUERY": ("medium", "Sensitive-looking parameter in query string", "CWE-598", "A04:2021",
        "Send secrets in POST bodies or headers, not URLs."),

    # --- Crawl observations -----------------------------------------------
    "CRAWL-ERROR": ("info", "Request failed", "CWE-754", "A05:2021", "Check availability of the URL."),
    "CRAWL-5XX": ("info", "Server error response", "CWE-755", "A05:2021", "Investigate server-side errors."),
    "CRAWL-REDIRECT-EXTERNAL": ("info", "Redirect leaves scope", "CWE-601", "A01:2021",
        "Confirm the redirect target is intended."),
    "CRAWL-CANONICAL-EXTERNAL": ("info", "Canonical URL points outside scope", "CWE-345", "A05:2021",
        "Confirm the canonical target is intended."),
}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clip(value, n=600):
    value = str(value)
    return value if len(value) <= n else value[: n - 1] + "…"


class FindingStore:
    """Deduplicating store. IDs are stable across runs (rule + scope only)."""

    def __init__(self):
        self._items = {}

    def add(self, rule_id, scope, url, detail="", evidence=None, problems=None,
            severity=None):
        sev, title, cwe, owasp, fix = RULES[rule_id]
        fid = "%s-%s" % (rule_id, hashlib.sha1(("%s|%s" % (rule_id, scope)).encode()).hexdigest()[:8])
        item = self._items.get(fid)
        if item is None:
            item = {
                "id": fid,
                "rule_id": rule_id,
                "severity": severity or sev,
                "issue": title,
                "url": url,
                "urls": [url],
                "count": 1,
                "detail": detail,
                "cwe": cwe,
                "owasp": owasp,
                "reference": cwe,
                "recommendation": fix,
                "first_seen": now_iso(),
            }
            if evidence is not None:
                item["evidence"] = _clip(evidence)
            if problems:
                item["problems"] = list(dict.fromkeys(problems))
            self._items[fid] = item
            return item
        item["count"] += 1
        if url not in item["urls"] and len(item["urls"]) < MAX_URLS_PER_FINDING:
            item["urls"].append(url)
        if problems:
            merged = list(dict.fromkeys(item.get("problems", []) + list(problems)))
            item["problems"] = merged
        return item

    def as_list(self):
        return sorted(self._items.values(),
                      key=lambda f: (-SEV_RANK[f["severity"]], f["rule_id"], f["id"]))


class ParamInventory:
    """name -> where it was seen (query string or form field)."""

    def __init__(self):
        self._params = {}
        self._seen = set()

    def add(self, name, kind, url, **extra):
        entry = self._params.setdefault(name, {"name": name, "count": 0, "locations": []})
        entry["count"] += 1
        key = (name, kind, url, tuple(sorted(extra.items())))
        if key in self._seen or len(entry["locations"]) >= 25:
            return
        self._seen.add(key)
        loc = {"kind": kind, "url": url}
        loc.update(extra)
        entry["locations"].append(loc)

    def as_list(self):
        return sorted(self._params.values(), key=lambda p: p["name"].lower())


# headers
def parse_csp(value):
    directives = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, *tokens = part.split()
        directives.setdefault(name.lower(), tokens)
    return directives


def analyze_csp(store, url, origin, csp_value, has_xfo=False):
    for policy in csp_value.split(","):
        policy = policy.strip()
        if not policy:
            continue
        d = parse_csp(policy)
        evidence = "Content-Security-Policy: " + policy
        script = d.get("script-src", d.get("default-src"))
        lowered = [t.lower() for t in (script or [])]

        def flag(rule, *problems, severity=None, scope_suffix=""):
            store.add(rule, origin + scope_suffix, url, evidence=evidence,
                      problems=list(problems), severity=severity)

        if script is None:
            flag("CSP-NO-SCRIPT-POLICY", "Neither script-src nor default-src is set")
        else:
            protected = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            or t == "'strict-dynamic'" for t in lowered)
            if "'unsafe-inline'" in lowered and not protected:
                flag("CSP-UNSAFE-INLINE", "'unsafe-inline' in script sources")
            if "'unsafe-eval'" in lowered:
                flag("CSP-UNSAFE-EVAL", "'unsafe-eval' in script sources")
            broad = [t for t in lowered if t in ("*", "https:", "http:", "data:")]
            if broad:
                flag("CSP-WILDCARD", "Broad script source(s): " + ", ".join(broad))
        if "'unsafe-inline'" in [t.lower() for t in d.get("style-src", [])]:
            flag("CSP-UNSAFE-INLINE", "'unsafe-inline' in style-src",
                 severity="low", scope_suffix="|style")
        for name in ("default-src", "object-src", "frame-src", "img-src", "connect-src"):
            insecure = [t for t in d.get(name, []) if t.lower().startswith("http://")]
            if insecure:
                flag("CSP-INSECURE-SCHEME", "%s allows %s" % (name, ", ".join(insecure)))
        obj = d.get("object-src", d.get("default-src"))
        if obj is None or [t.lower() for t in obj] != ["'none'"]:
            if "object-src" not in d:
                flag("CSP-NO-OBJECT-SRC", "object-src not set to 'none'")
        if "base-uri" not in d:
            flag("CSP-NO-BASE-URI", "base-uri not set")
        if "frame-ancestors" not in d and not has_xfo:
            flag("CSP-NO-FRAME-ANCESTORS", "frame-ancestors not set")


def check_headers(store, url, headers, is_html):
    p = urlparse(url)
    origin = "%s://%s" % (p.scheme, p.netloc)
    h = headers
    csp = h.get("Content-Security-Policy")
    xfo = h.get("X-Frame-Options")

    if is_html:
        if csp:
            analyze_csp(store, url, origin, csp, has_xfo=bool(xfo))
        elif h.get("Content-Security-Policy-Report-Only"):
            store.add("CSP-REPORT-ONLY", origin, url,
                      evidence="Content-Security-Policy-Report-Only: " + h["Content-Security-Policy-Report-Only"])
        else:
            store.add("HDR-CSP-MISSING", origin, url, evidence="Content-Security-Policy: <not set>")

        has_fa = bool(csp and "frame-ancestors" in parse_csp(csp.split(",")[0]))
        if not xfo and not has_fa:
            store.add("HDR-XFO-MISSING", origin, url, evidence="X-Frame-Options: <not set>")
        elif xfo and xfo.strip().upper().startswith("ALLOW-FROM"):
            store.add("HDR-XFO-WEAK", origin, url, evidence="X-Frame-Options: " + xfo)

        if not h.get("Permissions-Policy") and not h.get("Feature-Policy"):
            store.add("HDR-PERMISSIONS-MISSING", origin, url, evidence="Permissions-Policy: <not set>")
        elif h.get("Feature-Policy") and not h.get("Permissions-Policy"):
            store.add("HDR-OBSOLETE", origin + "|feature-policy", url,
                      detail="Feature-Policy was replaced by Permissions-Policy.",
                      evidence="Feature-Policy: " + h["Feature-Policy"])

        ref = h.get("Referrer-Policy")
        if not ref:
            store.add("HDR-REFERRER-MISSING", origin, url, evidence="Referrer-Policy: <not set>")
        elif ref.split(",")[-1].strip().lower() in ("unsafe-url", "no-referrer-when-downgrade",
                                                    "origin-when-cross-origin"):
            store.add("HDR-REFERRER-WEAK", origin, url, evidence="Referrer-Policy: " + ref)

    if "nosniff" not in h.get("X-Content-Type-Options", "").lower():
        store.add("HDR-NOSNIFF-MISSING", origin, url,
                  evidence="X-Content-Type-Options: " + h.get("X-Content-Type-Options", "<not set>"))

    if p.scheme == "https":
        hsts = h.get("Strict-Transport-Security")
        if not hsts:
            store.add("HDR-HSTS-MISSING", origin, url, evidence="Strict-Transport-Security: <not set>")
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                store.add("HDR-HSTS-WEAK", origin, url, evidence="Strict-Transport-Security: " + hsts,
                          detail="max-age=%d (< 180 days)" % age)
            if "includesubdomains" not in hsts.lower():
                store.add("HDR-HSTS-NO-SUBDOMAINS", origin, url, evidence="Strict-Transport-Security: " + hsts)

    for name, why in (("X-XSS-Protection", "Legacy XSS auditor header; modern browsers ignore it and it can introduce leaks."),
                      ("Expect-CT", "Expect-CT is obsolete (Certificate Transparency is enforced by default)."),
                      ("Public-Key-Pins", "HPKP is removed from browsers and is dangerous to deploy.")):
        if name in h:
            store.add("HDR-OBSOLETE", "%s|%s" % (origin, name.lower()), url,
                      detail=why, evidence="%s: %s" % (name, h[name]))

    acao, acac = h.get("Access-Control-Allow-Origin"), h.get("Access-Control-Allow-Credentials", "")
    if acao in ("*", "null"):
        creds = acac.lower() == "true"
        store.add("HDR-CORS-WILDCARD", origin + "|" + acao, url,
                  severity="high" if creds else "low",
                  detail="Access-Control-Allow-Origin: %s%s" % (acao, " with credentials" if creds else ""),
                  evidence="Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: %s" % (acao, acac or "<not set>"))

    server = h.get("Server", "")
    if re.search(r"\d+\.\d+|/\d", server):
        store.add("INFO-SERVER-BANNER", origin, url, evidence="Server: " + server)
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        if name in h:
            store.add("INFO-POWERED-BY", "%s|%s" % (origin, name.lower()), url, evidence="%s: %s" % (name, h[name]))
    for name in ("SourceMap", "X-SourceMap"):
        if name in h:
            store.add("INFO-SOURCEMAP", url, url, evidence="%s: %s" % (name, h[name]))


# cookies
SESSION_NAME_RE = re.compile(r"sess|sid|auth|token|jwt|login|sso|remember|csrf|xsrf", re.I)


def check_cookies(store, url, set_cookie_headers):
    p = urlparse(url)
    host = p.hostname or ""
    https = p.scheme == "https"
    for raw in set_cookie_headers:
        parts = [x.strip() for x in raw.split(";")]
        name = parts[0].partition("=")[0].strip()
        attrs = {}
        for a in parts[1:]:
            k, _, v = a.partition("=")
            attrs[k.strip().lower()] = v.strip()
        shown = "Set-Cookie: %s=<redacted>%s" % (name, "".join("; " + a for a in parts[1:]))
        session_like = bool(SESSION_NAME_RE.search(name))
        scope = "%s|%s" % (host, name)
        samesite = attrs.get("samesite", "").lower()

        if https and "secure" not in attrs:
            store.add("COOKIE-NO-SECURE", scope, url, evidence=shown,
                      severity="medium" if session_like else "low")
        if "httponly" not in attrs and not name.lower().startswith(("csrf", "xsrf")):
            store.add("COOKIE-NO-HTTPONLY", scope, url, evidence=shown,
                      severity="medium" if session_like else "info")
        if not samesite:
            store.add("COOKIE-SAMESITE-MISSING", scope, url, evidence=shown,
                      severity="low" if session_like else "info")
        elif samesite == "none" and "secure" not in attrs:
            store.add("COOKIE-SAMESITE-NONE-INSECURE", scope, url, evidence=shown)
        lname = name.lower()
        if (lname.startswith("__host-") and ("secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs)) \
                or (lname.startswith("__secure-") and "secure" not in attrs):
            store.add("COOKIE-PREFIX-INVALID", scope, url, evidence=shown)


# TLS
def check_tls(store, host, port, url):
    scope = "%s:%s" % (host, port)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert, version = tls.getpeercert(), tls.version()
    except ssl.SSLCertVerificationError as exc:
        msg = exc.verify_message or str(exc)
        low = msg.lower()
        if "expired" in low:
            rule = "TLS-CERT-EXPIRED"
        elif "hostname" in low or "ip address mismatch" in low:
            rule = "TLS-CERT-HOSTNAME"
        else:
            rule = "TLS-CERT-UNTRUSTED"
        store.add(rule, scope, url, detail=msg, evidence="%s: %s" % (scope, msg))
        return
    except (ssl.SSLError, OSError) as exc:
        store.add("TLS-ERROR", scope, url, detail=str(exc))
        return
    days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    if days < 30:
        store.add("TLS-CERT-EXPIRING", scope, url, severity="high" if days < 7 else "medium",
                  detail="Certificate expires in %d day(s)." % days,
                  evidence="notAfter=%s" % cert["notAfter"])
    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        store.add("TLS-OLD-VERSION", scope, url, evidence="Negotiated " + version)


# bodies
STACK_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"\bat [\w$.]+\([\w$]+\.java:\d+\)", "Java stack trace"),
    (r"Exception in thread \"", "Java exception"),
    (r"\bat [\w.<>$]+ in [^\n<]+:line \d+", ".NET stack trace"),
    (r"Server Error in '[^']*' Application", "ASP.NET error page"),
    (r"(?:Warning|Fatal error|Parse error|Notice)</b>:\s.{0,200}? in <b>[^<]+</b> on line <b>\d+", "PHP error"),
    (r"(?:Warning|Fatal error|Parse error): .{0,200} in /[\w/.\-]+ on line \d+", "PHP error"),
    (r"#\d+ [\w/\\.\-]+\.php\(\d+\)", "PHP stack trace"),
    (r"ORA-\d{5}|SQLSTATE\[\w+\]|You have an error in your SQL syntax|PG::\w+Error|SQLite3::\w+Exception|Microsoft OLE DB Provider", "Database error"),
    (r"\bat \S+ \((?:/|file:|[A-Za-z]:\\)[^)\n]*:\d+:\d+\)", "Node.js stack trace"),
    (r"Action Controller: Exception caught|ActionView::Template::Error", "Rails error"),
]
DEBUG_PATTERNS = [
    (r"Werkzeug Debugger|werkzeug\.debug", "Werkzeug debugger"),
    (r"You're seeing this error because you have <code>DEBUG = True", "Django debug page"),
    (r"Whoops! There was an error|Illuminate\\\\", "Laravel debug page"),
]
DIRLIST_PATTERNS = [r"<title>Index of /", r"<h1>Index of /", r"Directory listing for /", r"\[To Parent Directory\]"]
SECRET_PATTERNS = [
    ("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", "critical"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "low"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}", "high"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high"),
    ("Stripe live key", r"\b[sr]k_live_[0-9A-Za-z]{16,}", "high"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "medium"),
    ("Hard-coded credential assignment",
     r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["'][^"'\s]{8,}["']""",
     "medium"),
]
INTERNAL_IP_RE = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def check_body(store, url, text, is_html, status):
    for pattern, label in DEBUG_PATTERNS:
        m = re.search(pattern, text)
        if m:
            store.add("INFO-DEBUG-PAGE", "%s|%s" % (url, label), url, detail=label,
                      evidence=_clip(m.group(0), 120))
    if is_html or status >= 400:
        for pattern, label in STACK_PATTERNS:
            m = re.search(pattern, text, re.S)
            if m:
                store.add("INFO-STACKTRACE", "%s|%s" % (url, label), url, detail=label,
                          evidence=_clip(m.group(0), 120))
    if is_html:
        for pattern in DIRLIST_PATTERNS:
            m = re.search(pattern, text, re.I)
            if m:
                store.add("INFO-DIRLIST", url, url, evidence=m.group(0))
                break
        ips = sorted(set(INTERNAL_IP_RE.findall(text)))
        if ips:
            store.add("INFO-INTERNAL-IP", url, url, evidence=", ".join(ips[:5]))
        emails = sorted(set(EMAIL_RE.findall(text)))
        if emails:
            store.add("INFO-EMAIL", url, url, evidence=", ".join(emails[:5]),
                      detail="%d distinct address(es)" % len(emails))
    for label, pattern, sev in SECRET_PATTERNS:
        m = re.search(pattern, text)
        if m:
            s = m.group(0)
            store.add("INFO-SECRET", "%s|%s" % (url, label), url, severity=sev, detail=label,
                      evidence="%s: %s… [%d chars, redacted]" % (label, s[:6], len(s)))
    m = SOURCEMAP_RE.search(text[-4096:]) if not is_html else None
    if m:
        store.add("INFO-SOURCEMAP", url, url, evidence="sourceMappingURL=" + _clip(m.group(1), 150))


BACKUP_EXT_SENSITIVE = {"bak", "old", "orig", "save", "swp", "swo", "sql", "dump", "backup", "env"}
BACKUP_EXT_ARCHIVE = {"zip", "tar", "tgz", "gz", "7z", "rar"}
VCS_RE = re.compile(r"/\.(git|svn|hg)(/|$)", re.I)


def check_link_targets(store, page_url, urls):
    """Look only at URLs the page itself links to; never guess filenames."""
    for u in urls:
        path = urlparse(u).path
        name = path.rsplit("/", 1)[-1].lower()
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        if VCS_RE.search(path):
            store.add("INFO-GIT-REF", u, page_url, evidence=u)
        elif name.endswith("~") or ext in BACKUP_EXT_SENSITIVE or name in (".env", ".htpasswd", ".ds_store"):
            store.add("INFO-BACKUP-LINK", u, page_url, evidence=u)
        elif ext in BACKUP_EXT_ARCHIVE:
            store.add("INFO-BACKUP-LINK", u, page_url, evidence=u, severity="low")


def check_html_structure(store, url, soup, base_url):
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        s = str(c)
        if s.lstrip().startswith("[if"):
            continue
        m = re.search(r"(?i)\b(password|passwd|todo|fixme|secret|api[_-]?key|token|credential|username)\b", s)
        if m:
            store.add("INFO-COMMENT", "%s|%s" % (url, m.group(1).lower()), url,
                      evidence="HTML comment (%d chars) containing '%s'" % (len(s), m.group(1)))

    if urlparse(url).scheme != "https":
        return
    active, passive = [], []
    for tag, attr, bucket in (("script", "src", active), ("iframe", "src", active), ("frame", "src", active),
                              ("embed", "src", active), ("object", "data", active),
                              ("img", "src", passive), ("audio", "src", passive),
                              ("video", "src", passive), ("source", "src", passive)):
        for el in soup.find_all(tag):
            val = (el.get(attr) or "").strip()
            if val.lower().startswith("http://"):
                bucket.append("<%s %s=%s>" % (tag, attr, val))
    for el in soup.find_all("link", href=True):
        rel = " ".join(el.get("rel", [])).lower()
        if el["href"].strip().lower().startswith("http://") and any(r in rel for r in ("stylesheet", "preload", "modulepreload")):
            active.append("<link rel=%s href=%s>" % (rel, el["href"]))
    if active:
        store.add("MIXED-ACTIVE", url, url, evidence="; ".join(active[:5]), detail="%d reference(s)" % len(active))
    if passive:
        store.add("MIXED-PASSIVE", url, url, evidence="; ".join(passive[:5]), detail="%d reference(s)" % len(passive))


# forms / params
CSRF_NAME_RE = re.compile(r"csrf|xsrf|authenticity|_token|requestverificationtoken|antiforgery|form_?key|nonce", re.I)
SENSITIVE_PARAM_RE = re.compile(
    r"(?<![a-z])(pass(word|wd)?|pwd|secret|token|api[_-]?key|session[_-]?id|sessid|sid|jwt|credential|"
    r"auth(orization|_token|key)?)(?![a-z])", re.I)
CARD_NAME_RE = re.compile(r"card|cc[-_]?num|cvv|cvc|ssn|social", re.I)


def register_query_params(store, params, url, page_url):
    q = parse_qsl(urlparse(url).query, keep_blank_values=True)
    base = url.split("?", 1)[0]
    for name, _ in q:
        params.add(name, "query", base, found_on=page_url)
        if SENSITIVE_PARAM_RE.search(name):
            store.add("PARAM-SENSITIVE-QUERY", "%s|%s" % (base, name), page_url, evidence="Parameter '%s' in %s" % (name, base))


def analyze_forms(store, params, forms_out, page_url, soup, base_url):
    page_p = urlparse(page_url)
    meta_csrf = bool(soup.find("meta", attrs={"name": re.compile(r"csrf|xsrf", re.I)}))
    for form in soup.find_all("form"):
        raw_action = (form.get("action") or "").strip()
        if raw_action.lower().startswith(("javascript:", "mailto:")):
            continue
        action = urljoin(base_url, raw_action) if raw_action else page_url
        ap = urlparse(action)
        method = (form.get("method") or "GET").upper()

        inputs, has_password, csrf, problems = [], False, meta_csrf, []
        for f in form.find_all(["input", "textarea", "select"]):
            ftype = (f.get("type") or f.name).lower()
            name = f.get("name")
            ac = (f.get("autocomplete") or "").lower()
            if ftype == "password":
                has_password = True
                if ac == "on":
                    problems.append("Password field explicitly sets autocomplete=on")
            if name and CARD_NAME_RE.search(name) and ftype in ("text", "tel", "number", "password") \
                    and ac not in ("off",) and not ac.startswith("cc-"):
                problems.append("Sensitive field '%s' without autocomplete=off" % name)
            if name:
                inputs.append({"name": name, "type": ftype})
                params.add(name, "form", action, method=method, found_on=page_url)
                if CSRF_NAME_RE.search(name):
                    csrf = True
        for name, _ in parse_qsl(ap.query, keep_blank_values=True):
            params.add(name, "query", action.split("?", 1)[0], found_on=page_url)

        forms_out.append({"page": page_url, "action": action, "method": method,
                          "enctype": form.get("enctype", ""), "inputs": inputs,
                          "has_password": has_password, "csrf_token_present": csrf})

        scope = "%s|%s|%s" % (page_url, action, method)
        if has_password and ap.scheme == "http":
            store.add("FORM-PW-HTTP", scope, page_url, evidence="%s %s" % (method, action))
        if has_password and method == "GET":
            store.add("FORM-PW-GET", scope, page_url, evidence="GET %s" % action)
        if page_p.scheme == "https" and ap.scheme == "http" and not has_password:
            store.add("FORM-INSECURE-ACTION", scope, page_url, evidence="%s %s" % (method, action))
        if method not in ("GET", "HEAD") and not csrf:
            store.add("FORM-NO-CSRF", scope, page_url, severity="medium" if has_password else "low",
                      evidence="%s %s (fields: %s)" % (method, action, ", ".join(i["name"] for i in inputs[:8])))
        if problems:
            store.add("FORM-AUTOCOMPLETE", scope, page_url, problems=problems,
                      evidence="%s %s" % (method, action))
        if ap.scheme in ("http", "https") and ap.netloc.lower() != page_p.netloc.lower():
            store.add("FORM-CROSS-ORIGIN", scope, page_url, severity="medium" if has_password else "low",
                      evidence="%s %s (page origin %s)" % (method, action, page_p.netloc))