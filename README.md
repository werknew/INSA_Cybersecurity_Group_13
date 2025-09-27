# INSA_Cybersecurity_Group_13
this is the repository of Insa Cyber Talent Group 13


## Automated Vulnerability Scanner Security Tool, Modular CLI Vulnerability Scanner

**Vulnscanner** is a fast, modular, and extensible command-line vulnerability scanner built in Python. It orchestrates Nmap, Nikto, and optionally OpenVAS to detect services, extract versions, correlate known CVEs via the NVD API, and generate professional-grade reports.

---

## Features

- 🔍 **Nmap integration** – Service detection, port scanning, optional vulnerability scripts
- 🌐 **Nikto integration** – Web server misconfiguration and vulnerability detection
- 🛡️ **CVE enrichment** – Matches explicit CVEs and correlates service versions to known vulnerabilities
- ⚡ **Fast mode** – Quick scans using top ports and aggressive timing
- 📄 **Report generation** – Outputs in HTML, Markdown, or JSON
- 🧠 **Offline mode** – Uses cached CVE data when disconnected
- 🧰 **Modular design** – Easy to extend with new tools or parsers

---

## Installation

### 1. System dependencies
```bash
sudo apt update
sudo apt install -y nmap nikto
