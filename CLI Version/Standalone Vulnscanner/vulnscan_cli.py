#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from lxml import etree
from rich.console import Console
from rich.table import Table

console = Console()

# ---------------------------
# Utils: shell and validation
# ---------------------------

def run_cmd(cmd, timeout=600):
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Timeout running: {' '.join(cmd)}")
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{proc.stderr}")
    return proc.stdout, proc.stderr, proc.returncode

def is_url(target: str) -> bool:
    return target.startswith(("http://", "https://"))

def require_ack(args):
    if not getattr(args, "ack", False):
        console.print("[red]Refusing to run without authorization acknowledgement.[/red]")
        console.print("Add --ack to confirm you are authorized to scan the specified target(s).")
        raise SystemExit(2)

# --------------
# Nmap scanning
# --------------

def run_nmap(target, timeout=600, safe_only=False):
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        out_file = tmp.name
    scripts = "vuln" if not safe_only else "safe,vulners"
    cmd = ["nmap", "-sV", "--script", scripts, "-oX", out_file, target]
    run_cmd(cmd, timeout=timeout)
    xml = Path(out_file).read_text(encoding="utf-8")
    return xml

def parse_nmap_xml(xml_text):
    findings = []
    root = etree.fromstring(xml_text.encode("utf-8"))
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        for port in host.findall(".//port"):
            portid = port.get("portid")
            proto = port.get("protocol")
            service_el = port.find("service")
            service = service_el.get("name") if service_el is not None else "unknown"
            for script in port.findall("script"):
                sid = script.get("id") or "nse"
                output = script.get("output", "") or ""
                severity = classify_severity(output)
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", output, re.I)
                findings.append({
                    "source": "nmap",
                    "title": f"NSE {sid} on {service}",
                    "description": output.strip(),
                    "severity": severity,
                    "location": f"{addr}:{portid}/{proto}",
                    "tags": [service, sid],
                    "cve": [c.upper() for c in cves],
                    "remediation": suggest_remediation(service, sid, output),
                })
    return findings

def classify_severity(text):
    t = text.lower()
    if "critical" in t or "remote code execution" in t or "rce" in t:
        return "critical"
    if "high" in t or "authentication bypass" in t or "shellshock" in t or "heartbleed" in t:
        return "high"
    if "medium" in t or "misconfiguration" in t:
        return "medium"
    if "low" in t or "info" in t or "notice" in t:
        return "low"
    return "unknown"

def suggest_remediation(service, script_id, output):
    o = output.lower()
    if "ssl" in o or "tls" in o:
        return "Disable weak ciphers/protocols, enable TLS 1.2+, prefer modern cipher suites, renew certs."
    if service == "http":
        return "Patch web server/app, enable security headers, sanitize inputs, restrict admin endpoints."
    return "Apply vendor patches, harden configuration, and minimize exposed services."

# --------------
# Nikto scanning
# --------------

def run_nikto(target, timeout=600):
    # Nikto requires a host/URL; output JSON to stdout
    cmd = ["nikto", "-ask", "no", "-h", target, "-output", "-", "-Format", "json"]
    stdout, stderr, code = run_cmd(cmd, timeout=timeout)
    return stdout

def parse_nikto_json(json_text):
    findings = []
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return findings
    items = data.get("vulnerabilities") or data.get("data") or []
    host = data.get("host", "")
    for v in items:
        desc = (v.get("description") or v.get("msg") or "").strip()
        url = v.get("url") or host or ""
        severity = nikto_sev(v.get("severity"))
        cves = v.get("cve") or []
        if isinstance(cves, str):
            cves = [cves]
        findings.append({
            "source": "nikto",
            "title": v.get("id") or "Nikto finding",
            "description": desc,
            "severity": severity,
            "location": url,
            "tags": ["web", v.get("method","")],
            "cve": [c.strip().upper() for c in cves if isinstance(c, str)],
            "remediation": nikto_remediation(desc),
        })
    return findings

def nikto_sev(val):
    try:
        i = int(val)
    except Exception:
        i = 0
    return {0:"info",1:"low",2:"medium",3:"high",4:"critical"}.get(i, "unknown")

def nikto_remediation(desc):
    d = desc.lower()
    if "directory listing" in d:
        return "Disable directory listing and restrict access to sensitive paths."
    if "x-frame-options" in d or "content-security-policy" in d or "hsts" in d:
        return "Add/strengthen CSP, X-Frame-Options, X-Content-Type-Options, and HSTS."
    if "sql" in d:
        return "Use parameterized queries, validate inputs, and patch DB/ORM."
    return "Apply updates, harden web server configuration, and sanitize inputs."

# --------------
# CVE enrichment
# --------------

def enrich_with_cve(findings):
    import requests
    cache = {}
    def fetch(cve_id):
        if cve_id in cache:
            return cache[cve_id]
        try:
            r = requests.get(f"https://services.nvd.nist.gov/rest/json/cve/2.0?cveId={cve_id}", timeout=10)
            if r.ok:
                data = r.json()
                items = data.get("vulnerabilities", [])
                cache[cve_id] = items[0] if items else None
                return cache[cve_id]
        except Exception:
            return None
        return None

    for f in findings:
        found_ids = set([c.upper() for c in f.get("cve", [])])
        found_ids.update(re.findall(r"CVE-\d{4}-\d{4,7}", f.get("description",""), re.I))
        details = []
        for c in sorted(found_ids):
            info = fetch(c)
            if not info:
                continue
            metrics = info.get("cve", {}).get("metrics", {})
            cvss = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            details.append({
                "id": c,
                "cvss": cvss,
                "summary": (info.get("cve", {}).get("descriptions", [{}])[0].get("value","") or "")[:400],
                "references": [r.get("url") for r in info.get("cve", {}).get("references", [])][:5]
            })
            if cvss is not None:
                if cvss >= 9.0:
                    f["severity"] = "critical"
                elif cvss >= 7.0 and f.get("severity") not in ("critical","high"):
                    f["severity"] = "high"
        if details:
            f["cve_details"] = details
    return findings

# --------------
# Reporting
# --------------

def generate_report(findings, target, fmt="json"):
    meta = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "counts": {
            "critical": sum(1 for f in findings if f.get("severity")=="critical"),
            "high":     sum(1 for f in findings if f.get("severity")=="high"),
            "medium":   sum(1 for f in findings if f.get("severity")=="medium"),
            "low":      sum(1 for f in findings if f.get("severity")=="low"),
            "info":     sum(1 for f in findings if f.get("severity")=="info"),
            "unknown":  sum(1 for f in findings if f.get("severity")=="unknown"),
            "total":    len(findings),
        }
    }
    if fmt == "json":
        return json.dumps({"meta": meta, "findings": findings}, indent=2)
    if fmt == "md":
        lines = []
        lines.append(f"# Vulnerability report for {target}\n")
        lines.append(f"- Timestamp: {meta['timestamp']}")
        for k,v in meta["counts"].items():
            lines.append(f"- {k.capitalize()}: {v}")
        lines.append("\n---\n")
        for i, f in enumerate(findings, start=1):
            lines.append(f"## {i}. {f.get('title','Finding')}")
            lines.append(f"- Severity: {f.get('severity','unknown')}")
            lines.append(f"- Location: {f.get('location','')}")
            lines.append(f"- Source: {f.get('source','')}")
            tags = ", ".join(t for t in f.get("tags",[]) if t)
            if tags: lines.append(f"- Tags: {tags}")
            lines.append(f"\n**Description:**\n{f.get('description','').strip()}\n")
            if f.get("cve_details"):
                lines.append("**CVE:**")
                for c in f["cve_details"]:
                    lines.append(f"- {c['id']} (CVSS: {c.get('cvss','N/A')})")
                    if c.get("summary"):
                        lines.append(f"  - Summary: {c['summary']}")
                    if c.get("references"):
                        lines.append(f"  - References: {', '.join(c['references'])}")
            elif f.get("cve"):
                lines.append("**CVE:** " + ", ".join(f["cve"]))
            if f.get("remediation"):
                lines.append(f"\n**Remediation:**\n{f['remediation']}\n")
            lines.append("\n---\n")
        return "\n".join(lines)
    raise ValueError("Unsupported report format")

# --------------
# CLI
# --------------

def main():
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Automated Vulnerability Scanner CLI (Nmap + Nikto + CVE enrichment)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a scan against a target")
    scan.add_argument("--target", required=True, help="IP/CIDR or URL to scan")
    scan.add_argument("--nmap", action="store_true", help="Run Nmap scans")
    scan.add_argument("--nikto", action="store_true", help="Run Nikto web scans")
    scan.add_argument("--cve", action="store_true", help="Enrich findings with CVE data")
    scan.add_argument("--report-format", choices=["json","md"], default="json")
    scan.add_argument("--output", help="Path to write report file")
    scan.add_argument("--timeout", type=int, default=900, help="Max seconds per tool")
    scan.add_argument("--safe-only", action="store_true", help="Skip intrusive NSE scripts")
    scan.add_argument("--ack", action="store_true", help="Confirm authorized testing")

    args = parser.parse_args()

    if args.command == "scan":
        require_ack(args)
        tools = []
        if args.nmap: tools.append("nmap")
        if args.nikto: tools.append("nikto")
        if not tools:
            console.print("[yellow]No tools selected. Use --nmap and/or --nikto[/yellow]")
            raise SystemExit(2)

        console.rule(f"Scanning target: {args.target}")
        console.print(f"Tools: {', '.join(tools)}")

        all_findings = []

        if "nmap" in tools:
            console.print("[cyan]Running Nmap…[/cyan]")
            nmap_xml = run_nmap(args.target, timeout=args.timeout, safe_only=args.safe_only)
            nmap_findings = parse_nmap_xml(nmap_xml)
            all_findings.extend(nmap_findings)

        if "nikto" in tools:
            if not is_url(args.target):
                console.print("[yellow]Nikto expects a URL. Skipping Nikto because target is not http(s).[/yellow]")
            else:
                console.print("[cyan]Running Nikto…[/cyan]")
                nikto_json = run_nikto(args.target, timeout=args.timeout)
                nikto_findings = parse_nikto_json(nikto_json)
                all_findings.extend(nikto_findings)

        if args.cve and all_findings:
            console.print("[cyan]Enriching with CVE data…[/cyan]")
            all_findings = enrich_with_cve(all_findings)

        # Summary table
        table = Table(title="Findings Summary")
        table.add_column("ID", justify="right")
        table.add_column("Severity", justify="left")
        table.add_column("Title", justify="left")
        table.add_column("Location", justify="left")
        for i, f in enumerate(all_findings, start=1):
            table.add_row(str(i), f.get("severity","unknown"), f.get("title",""), f.get("location",""))
        console.print(table)

        report = generate_report(all_findings, target=args.target, fmt=args.report_format)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(report, encoding="utf-8")
            console.print(f"[green]Report written to {args.output}[/green]")
        else:
            console.print(report)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
