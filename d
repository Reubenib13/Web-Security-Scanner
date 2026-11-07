# Passive Web Security Scanner

A small Python web-security auditing tool that crawls a target site and produces clean JSON and HTML reports.

The scanner is designed for **passive security assessment**. It inventories pages, forms, and parameters and analyzes security-relevant information already returned by the application. It does **not** inject XSS/SQLi payloads, brute-force endpoints, guess sensitive filenames, or otherwise attempt exploitation.

> Use this tool only on systems you own or are explicitly authorized to assess.

## Features

The scanner works with `checks.py` to provide:

- Same-origin web crawling
- Configurable page and crawl-depth limits
- Request throttling
- Redirect tracking
- Form and parameter inventory
- Security-header analysis
- Content Security Policy (CSP) analysis
- Cookie security checks
- TLS/certificate checks
- HTTP-to-HTTPS and transport observations
- Mixed-content detection
- Information-disclosure checks
- Stack trace and debug-page detection
- Directory-listing detection
- Source-map discovery
- References to backup, archive, and version-control files
- Potential secret-pattern detection with redacted evidence
- Internal IP and HTML-comment observations
- Password/form transport checks
- Heuristic CSRF observations
- Sensitive query-parameter detection
- Deduplicated findings with stable IDs
- CWE and OWASP Top 10 references
- JSON and HTML reporting

## Project Structure

```text
.
├── scanner.py
├── checks.py
├── security-report.html
└── security-report.json
```

`scanner.py` handles crawling, scope, requests, parsing, and report generation.

`checks.py` contains passive analysis helpers, finding storage, rule metadata, and the individual security checks.

The report files are generated after a scan.

## Requirements

- Python 3
- `requests`
- `beautifulsoup4`

Install the dependencies:

```bash
python -m pip install requests beautifulsoup4
```

## Usage

Run a basic scan:

```bash
python scanner.py https://example.com
```

For a larger crawl:

```bash
python scanner.py https://example.com \
  --max-pages 100 \
  --max-depth 4 \
  --delay 0.25
```

Use:

```bash
python scanner.py --help
```

to see the options supported by your current version of `scanner.py`.

## Scope and Crawling

The scanner is intended to stay within the target site's configured scope rather than following arbitrary external links.

Limits such as maximum pages, maximum depth, and request delay should be set appropriately for the application being assessed.

A conservative example is:

```bash
python scanner.py https://example.com \
  --max-pages 50 \
  --max-depth 3 \
  --delay 0.5
```

Using a delay reduces unnecessary load on the target server.

## Checks

### Security Headers

The scanner can identify missing or weak security controls including:

- `Content-Security-Policy`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

It also recognizes some obsolete security headers and potentially permissive CORS responses.

### Content Security Policy

CSP analysis includes checks for conditions such as:

- Missing script restrictions
- `'unsafe-inline'`
- `'unsafe-eval'`
- Broad source expressions
- Plain-HTTP sources
- Missing `object-src`
- Missing `base-uri`
- Missing `frame-ancestors`
- Report-only policies

These findings should be reviewed in the context of the application. A policy being flagged does not necessarily mean it is exploitable.

### Cookies

Cookie observations include:

- Missing `Secure`
- Missing `HttpOnly`
- Missing `SameSite`
- `SameSite=None` without `Secure`
- Invalid `__Host-` / `__Secure-` prefix usage

Cookie values are redacted from evidence.

### TLS and Transport

The scanner can report:

- Certificate verification problems
- Expired or soon-to-expire certificates
- Certificate hostname problems
- Deprecated negotiated TLS versions
- TLS handshake errors
- Missing HSTS
- HTTP/HTTPS transport issues
- Mixed active or passive content

TLS checking performs an ordinary TLS connection to the target host.

### Forms

Forms are inventoried without submitting attack payloads.

Checks include:

- Password forms submitted over HTTP
- Password fields in GET forms
- HTTPS pages submitting forms to HTTP
- Cross-origin form actions
- Sensitive autocomplete observations
- State-changing forms without a CSRF-looking token

The CSRF check is **heuristic**. Applications may implement CSRF protection in ways that cannot be determined from static HTML alone.

### Parameters

Query-string and form parameter names are collected to help map the application's input surface.

Sensitive-looking values in query-string parameter **names** can also be flagged, because credentials and secrets should generally not be transported in URLs.

### Information Exposure

Passive response analysis can identify indicators including:

- Server/version disclosure
- Technology disclosure headers
- Stack traces
- Debug pages
- Directory listings
- Internal IP addresses
- Sensitive-looking HTML comments
- Email addresses
- Source maps
- Links to backup/archive files
- Links to version-control metadata
- Patterns resembling exposed credentials or secrets

The scanner does not guess filenames such as `.env` or `.git/config`; linked resources are analyzed when the application itself references them.

Potential secrets are reported with redacted evidence rather than reproducing complete credentials.

## Reports

A scan produces two primary outputs.

### HTML

```text
security-report.html
```

The HTML report is intended for human review and includes scan metadata, severity summaries, findings, evidence, remediation guidance, CWE/OWASP references, forms, and parameter inventory.

Open it in a browser after the scan.

### JSON

```text
security-report.json
```

The JSON report contains structured results suitable for:

- CI/CD processing
- Archiving scan results
- Comparing assessments
- Importing results into other tooling
- Building custom dashboards

## Severity

Findings use the following levels:

| Severity | Meaning |
|---|---|
| Critical | Potentially severe exposure requiring immediate investigation |
| High | Significant security weakness or sensitive exposure |
| Medium | Important weakness that should be investigated |
| Low | Defense-in-depth or lower-impact issue |
| Info | Observation useful during security review |

Severity is a prioritization aid, not proof of exploitability.

## Understanding Findings

A finding can contain information such as:

```text
ID
Rule ID
Severity
Issue
Affected URL(s)
Evidence
Problems
CWE
OWASP category
Recommendation
```

Findings are deduplicated so that a site-wide issue does not necessarily produce an identical report entry for every page.

For example, a CSP finding might report:

```text
[MEDIUM] CSP allows 'unsafe-inline'

Evidence:
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

Problem:
'unsafe-inline' in script sources

Recommendation:
Remove 'unsafe-inline'; use nonces or hashes.

Reference:
CWE-79
```

Treat scanner results as leads for manual review rather than definitive vulnerability confirmations.

## What This Scanner Does Not Do

This project intentionally does not implement an automated exploitation engine.

In particular, it does not:

- Inject reflected-XSS payloads
- Inject SQL-injection payloads
- Attempt authentication bypasses
- Brute-force credentials
- Fuzz arbitrary endpoints
- Guess hidden sensitive files
- Exploit discovered weaknesses

For authorized active application-security testing, use a purpose-built tool such as OWASP ZAP or Burp Suite under an appropriate testing scope.

This scanner can complement those tools by providing a lightweight passive inventory and baseline report.

## False Positives and Limitations

Many checks are heuristic.

For example:

- CSRF defenses may be implemented outside visible form fields.
- CSP requirements vary between applications.
- An exposed email address may be completely intentional.
- A string matching a secret format may be test or example data.
- Missing headers may be intentional for a particular resource.
- Client-side applications may expose routes that a basic HTTP crawler cannot discover.
- JavaScript-generated content may not appear in the fetched HTML.

Always manually validate important findings before treating them as vulnerabilities.

## Responsible Use

Only scan targets for which you have permission.

Even passive crawling generates HTTP traffic and can create server load, logs, alerts, and third-party requests depending on how a target application behaves.

Use conservative crawl limits and delays, especially against production systems.

## Development

The design separates crawling from security rules:

```text
scanner.py  -> traversal, scope, HTTP, parsing, reporting
checks.py   -> rules, analysis, findings, metadata
```

When adding a passive check, prefer adding its rule metadata and analysis logic to `checks.py` and keeping network traversal in `scanner.py`.

A useful finding should generally provide:

1. A stable rule identifier
2. Appropriate severity
3. A concise title
4. Affected scope/URL
5. Minimal, non-sensitive evidence
6. CWE/OWASP mapping where applicable
7. A practical remediation

Avoid storing complete credentials, tokens, session cookies, or other secrets in reports.

## Disclaimer

This software is intended for defensive security assessment, development, and authorized testing.

Automated findings may be incomplete or incorrect. The scanner is not a substitute for manual security review, authenticated testing, source-code review, or a professional penetration test.
