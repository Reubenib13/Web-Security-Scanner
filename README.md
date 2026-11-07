# Web Security Crawler

A lightweight Python-based passive web security scanner that crawls websites, checks HTTP security headers, identifies weak Content Security Policies (CSP), and inventories HTML forms.

## Features

- Crawls same-origin links automatically.
- Detects missing security headers (CSP, X-Frame-Options, HSTS).
- Identifies weak CSP configurations.
- Collects HTML form details and input fields.
- Generates JSON and HTML security reports.
- Supports configurable crawling limits.

## Installation

**Requirements:** Python 3.8+

Install dependencies:

```bash
pip install requests beautifulsoup4
```

## Usage

Run the scanner:

```bash
python main.py https://example.com
```

Customize the scan:

```bash
python main.py https://example.com --max-pages 100 --json results.json --html results.html
```

## Output

The scanner generates two reports:

- `security-report.json` — Structured scan results.
- `security-report.html` — Readable HTML security report.

Reports include crawled URLs, discovered forms, security findings, severity levels, and recommendations.

## Disclaimer

This tool is intended for **educational purposes and authorized security assessments only**. It performs passive checks without submitting attack payloads. Only scan websites you own or have permission to test.

## Tech Stack

Python · Requests · BeautifulSoup · JSON
