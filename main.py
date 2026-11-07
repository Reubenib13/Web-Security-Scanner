import argparse
import json
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from report import write_html_report

HEADERS_TO_CHECK = {
    "Content-Security-Policy": "Helps mitigate XSS and content-injection attacks.",
    "X-Frame-Options": "Helps prevent clickjacking.",
    "Strict-Transport-Security": "Forces supported browsers to use HTTPS.",
}


def build_finding(
    severity,
    url,
    issue,
    detail="",
    evidence=None,
    problems=None,
    recommendation="",
    reference="",
):
    finding = {
        "severity": severity,
        "url": url,
        "issue": issue,
        "detail": detail,
    }

    if evidence is not None:
        finding["evidence"] = evidence
    if problems is not None:
        finding["problems"] = problems
    if recommendation:
        finding["recommendation"] = recommendation
    if reference:
        finding["reference"] = reference
    return finding


def analyze_csp(csp_value, url):
    if not csp_value:
        return build_finding(
            "high",
            url,
            "Missing Content-Security-Policy",
            "The response does not include a Content-Security-Policy header.",
            evidence="Content-Security-Policy: <not set>",
            problems=[
                "No Content Security Policy is present to restrict active content sources.",
            ],
            recommendation=(
                "Define a restrictive CSP that only allows trusted origins and "
                "avoids inline script execution through nonces or hashes."
            ),
            reference="CWE-693",
        )

    parsed = {}
    for directive in csp_value.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        name, _, value = directive.partition(" ")
        parsed[name.lower()] = value.strip()

    problems = []
    default_src = parsed.get("default-src", "")
    script_src = parsed.get("script-src", "")

    if "*" in default_src.split():
        problems.append("Wildcard default source")
    if "*" in script_src.split():
        problems.append("Wildcard script source")
    if "'unsafe-inline'" in csp_value or "unsafe-inline" in csp_value:
        problems.append("Inline JavaScript permitted")
    if "'unsafe-eval'" in csp_value or "unsafe-eval" in csp_value:
        problems.append("Dynamic code execution allowed")
    if "data:" in csp_value:
        problems.append("Data URLs are allowed for executable content")

    if not problems:
        return None

    return build_finding(
        "high",
        url,
        "Weak Content-Security-Policy",
        "The Content-Security-Policy permits risky active content sources or inline execution.",
        evidence=f"Content-Security-Policy: {csp_value}",
        problems=problems,
        recommendation=(
            "Restrict source origins and replace inline scripts with nonces or hashes."
        ),
        reference="CWE-693",
    )


def same_origin(a, b):
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def crawl(start_url, max_pages=50, timeout=10):
    session = requests.Session()
    session.headers["User-Agent"] = "Authorized-Security-Audit/1.0"

    queue = deque([start_url])
    visited = set()
    findings = []
    forms = []

    while queue and len(visited) < max_pages:
        url = queue.popleft()

        if url in visited:
            continue
        visited.add(url)

        try:
            response = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            findings.append({
                "severity": "info",
                "url": url,
                "issue": "Request failed",
                "detail": str(exc),
            })
            continue

        final_url = response.url

        # Security headers
        for header, explanation in HEADERS_TO_CHECK.items():
            if header not in response.headers:
                findings.append(
                    build_finding(
                        "medium",
                        final_url,
                        f"Missing {header}",
                        explanation,
                    )
                )
                continue

            if header == "Content-Security-Policy":
                csp_finding = analyze_csp(response.headers.get(header), final_url)
                if csp_finding is not None:
                    findings.append(csp_finding)

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type.lower():
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        # Inventory forms without submitting attack payloads.
        for form in soup.find_all("form"):
            action = urljoin(final_url, form.get("action") or final_url)
            method = (form.get("method") or "GET").upper()

            inputs = []
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": field.get("type", field.name),
                    })

            forms.append({
                "page": final_url,
                "action": action,
                "method": method,
                "inputs": inputs,
            })

        # Discover same-origin links.
        for tag in soup.find_all("a", href=True):
            target = urljoin(final_url, tag["href"])
            parsed = urlparse(target)

            target = parsed._replace(fragment="").geturl()

            if (
                parsed.scheme in ("http", "https")
                and same_origin(start_url, target)
                and target not in visited
            ):
                queue.append(target)

    return {
        "target": start_url,
        "pages_crawled": len(visited),
        "pages": sorted(visited),
        "forms": forms,
        "findings": findings,
    }




def main():
    parser = argparse.ArgumentParser(
        description="Passive web security crawler/report generator."
    )
    parser.add_argument("url")
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--json", default="security-report.json")
    parser.add_argument("--html", default="security-report.html")
    args = parser.parse_args()

    report = crawl(args.url, args.max_pages)

    with open(args.json, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2)

    write_html_report(report, args.html)

    print(f"Crawled:  {report['pages_crawled']} pages")
    print(f"Forms:    {len(report['forms'])}")
    print(f"Findings: {len(report['findings'])}")
    print(f"JSON:     {args.json}")
    print(f"HTML:     {args.html}")


if __name__ == "__main__":
    main()