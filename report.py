import html

def write_html_report(data, filename):
    findings = data["findings"]
    forms = data["forms"]

    rows = "\n".join(
        f"""
        <tr>
          <td>{html.escape(f['severity'].upper())}</td>
          <td>{html.escape(f['issue'])}</td>
          <td>{html.escape(f['url'])}</td>
          <td>
            <div class="finding-detail">
              {html.escape(f.get('detail', ''))}
              {f.get('evidence') and f'<br><strong>Evidence:</strong><br><code>{html.escape(f["evidence"])}</code>' or ''}
              {f.get('problems') and '<br><strong>Problems:</strong><ul>' + ''.join(f'<li>{html.escape(problem)}</li>' for problem in f['problems']) + '</ul>' or ''}
              {f.get('recommendation') and f'<br><strong>Recommendation:</strong><br>{html.escape(f["recommendation"]) }' or ''}
              {f.get('reference') and f'<br><strong>Reference:</strong> {html.escape(f["reference"]) }' or ''}
            </div>
          </td>
        </tr>
        """
        for f in findings
    ) or "<tr><td colspan='4'>No header findings.</td></tr>"

    form_rows = "\n".join(
        f"""
        <tr>
          <td>{html.escape(f['page'])}</td>
          <td>{html.escape(f['method'])}</td>
          <td>{html.escape(f['action'])}</td>
          <td>{html.escape(', '.join(i['name'] for i in f['inputs']))}</td>
        </tr>
        """
        for f in forms
    ) or "<tr><td colspan='4'>No forms discovered.</td></tr>"

    document = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Web Security Audit</title>
<style>
body {{
    font-family: system-ui, sans-serif;
    max-width: 1200px;
    margin: 40px auto;
    padding: 0 20px;
    color: #222;
}}
h1, h2 {{ color: #172554; }}
.summary {{
    background: #f1f5f9;
    padding: 18px;
    border-radius: 8px;
}}
.finding-detail {{
    line-height: 1.55;
}}
.finding-detail ul {{
    margin: 8px 0 0 18px;
    padding: 0;
}}
.finding-detail code {{
    background: #f8fafc;
    border-radius: 4px;
    padding: 2px 6px;
    display: inline-block;
    margin-top: 6px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 30px;
}}
th, td {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
    text-align: left;
    vertical-align: top;
}}
th {{ background: #e2e8f0; }}
code {{ word-break: break-all; }}
</style>
</head>
<body>

<h1>Web Security Audit</h1>

<div class="summary">
<strong>Target:</strong> {html.escape(data['target'])}<br>
<strong>Pages crawled:</strong> {data['pages_crawled']}<br>
<strong>Forms discovered:</strong> {len(forms)}<br>
<strong>Header findings:</strong> {len(findings)}
</div>

<h2>Security Header Findings</h2>
<table>
<tr>
<th>Severity</th>
<th>Issue</th>
<th>URL</th>
<th>Details</th>
</tr>
{rows}
</table>

<h2>Form Inventory</h2>
<table>
<tr>
<th>Page</th>
<th>Method</th>
<th>Action</th>
<th>Input names</th>
</tr>
{form_rows}
</table>

</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as fp:
        fp.write(document)
