# scanner.py

import argparse
from modules.nmap_scan import run_nmap_scan
from modules.nikto_scan import run_nikto_scan
from modules.report import generate_report
from modules.openvas_scan import run_openvas_scan  # Optional
from modules.cve_lookup import match_with_cve

def main():
    parser = argparse.ArgumentParser(description="Automated Vulnerability Scanner")
    parser.add_argument('--target', required=True, help='Target IP address or domain')
    parser.add_argument('--web', action='store_true', help='Enable Nikto web scanning')
    parser.add_argument('--deep', action='store_true', help='Enable OpenVAS deep scanning')
    parser.add_argument('--report', choices=['txt', 'html', 'json'], default='txt', help='Report format')

    args = parser.parse_args()
    target = args.target

    print(f"[+] Starting scan for {target}")
    results = {}

    # Run Nmap Scan
    print("[*] Running Nmap scan...")
    nmap_results = run_nmap_scan(target)
    results['nmap'] = nmap_results

    # Run Nikto Scan
    if args.web:
        print("[*] Running Nikto scan...")
        nikto_results = run_nikto_scan(target)
        results['nikto'] = nikto_results

    # Run OpenVAS (optional)
    if args.deep:
        print("[*] Running OpenVAS scan (this may take a while)...")
        openvas_results = run_openvas_scan(target)
        results['openvas'] = openvas_results

    # Match with CVEs
    print("[*] Mapping to CVEs...")
    cve_results = match_with_cve(results)
    results['cves'] = cve_results

    # Generate Report
    print(f"[*] Generating {args.report.upper()} report...")
    generate_report(results, target, args.report)

    print("[+] Scan complete. Check the reports folder.")

if __name__ == "__main__":
    main()
