import logging
import subprocess
import xmltodict
import requests
import json
import re
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self):
        self.cve_db = self._load_cve_database()
    
    def _load_cve_database(self) -> Dict:
        """Load CVE database from offline file or online source"""
        try:
            # This would typically load from a local CVE database
            # For now, we'll use a mock database
            return {
                "CVE-2021-44228": {
                    "description": "Log4Shell - Remote code execution in Log4j",
                    "severity": "critical",
                    "cvss": 10.0,
                    "solution": "Update Log4j to version 2.17.0 or later"
                },
                "CVE-2014-0160": {
                    "description": "Heartbleed - Information disclosure in OpenSSL",
                    "severity": "high", 
                    "cvss": 7.5,
                    "solution": "Update OpenSSL to version 1.0.1g or later"
                }
            }
        except Exception as e:
            logger.error(f"Failed to load CVE database: {e}")
            return {}
    
    def run_nmap_scan(self, target: str, scan_type: str = "quick") -> Dict:
        """Run Nmap scan based on scan type"""
        try:
            nmap_args = {
                "quick": ["-F", "-T4"],  # Fast scan
                "full": ["-sS", "-sV", "-sC", "-O", "-T4"],  # Full TCP SYN scan with version detection
                "stealth": ["-sS", "-T2", "--scan-delay", "1s"],  # Stealth scan
                "vulnerability": ["-sV", "--script", "vuln"],  # Vulnerability scan
                "web": ["-p", "80,443,8080,8443", "--script", "http-enum,http-vuln*"]  # Web-specific scan
            }
            
            args = nmap_args.get(scan_type, nmap_args["quick"])
            command = ["nmap"] + args + [target, "-oX", "-"]
            
            logger.info(f"Running Nmap scan: {' '.join(command)}")
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=1800)
            
            return self._parse_nmap_xml(result)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap scan failed: {e}")
            return {"status": "error", "output": str(e.output)}
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            return {"status": "error", "output": "Scan timed out after 30 minutes"}
        except Exception as e:
            logger.error(f"Unexpected error in Nmap scan: {e}")
            return {"status": "error", "output": str(e)}
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict:
        """Parse Nmap XML output into structured data"""
        try:
            data = xmltodict.parse(xml_output)
            result = {
                "target": data.get('nmaprun', {}).get('@host', ''),
                "timestamp": data.get('nmaprun', {}).get('@startstr', ''),
                "scanType": "nmap",
                "status": "completed",
                "ports": [],
                "vulnerabilities": [],
                "summary": {
                    "openPorts": 0,
                    "vulnerabilities": {"high": 0, "medium": 0, "low": 0, "info": 0},
                    "scanDuration": data.get('nmaprun', {}).get('@elapsed', '0') + "s"
                }
            }
            
            # Parse ports
            host = data.get('nmaprun', {}).get('host', {})
            ports = host.get('ports', {}).get('port', [])
            if not isinstance(ports, list):
                ports = [ports]
            
            for port in ports:
                if port.get('state', {}).get('@state') == 'open':
                    port_info = {
                        "number": port.get('@portid'),
                        "state": port.get('state', {}).get('@state'),
                        "service": port.get('service', {}).get('@name', 'unknown'),
                        "version": port.get('service', {}).get('@product', '') + ' ' + port.get('service', {}).get('@version', ''),
                    }
                    result["ports"].append(port_info)
                    result["summary"]["openPorts"] += 1
            
            # Parse script output for vulnerabilities
            for port in ports:
                scripts = port.get('script', [])
                if not isinstance(scripts, list):
                    scripts = [scripts]
                
                for script in scripts:
                    if 'vuln' in script.get('@id', '').lower() or 'http' in script.get('@id', '').lower():
                        output = script.get('@output', '')
                        self._parse_vulnerabilities(output, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return {"status": "error", "output": f"XML parsing failed: {str(e)}"}
    
    def _parse_vulnerabilities(self, script_output: str, result: Dict) -> None:
        """Parse vulnerability information from Nmap script output"""
        # Look for CVE references
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, script_output, re.IGNORECASE)
        
        for cve in cves:
            cve = cve.upper()
            vuln_info = self.cve_db.get(cve, {
                "description": f"Vulnerability detected: {cve}",
                "severity": "medium",
                "solution": "Investigate and apply appropriate patches"
            })
            
            vulnerability = {
                "severity": vuln_info["severity"],
                "description": vuln_info["description"],
                "solution": vuln_info["solution"],
                "cve": cve
            }
            
            result["vulnerabilities"].append(vulnerability)
            result["summary"]["vulnerabilities"][vuln_info["severity"]] += 1
    
    def run_nikto_scan(self, target: str) -> Dict:
        """Run Nikto web vulnerability scan"""
        try:
            # Ensure target has http:// or https:// prefix
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            command = ["nikto", "-h", target, "-Format", "xml", "-o", "-"]
            logger.info(f"Running Nikto scan: {' '.join(command)}")
            
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=1800)
            return self._parse_nikto_xml(result)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Nikto scan failed: {e}")
            return {"status": "error", "output": str(e.output)}
        except Exception as e:
            logger.error(f"Unexpected error in Nikto scan: {e}")
            return {"status": "error", "output": str(e)}
    
    def _parse_nikto_xml(self, xml_output: str) -> Dict:
        """Parse Nikto XML output"""
        try:
            data = xmltodict.parse(xml_output)
            result = {
                "target": data.get('niktoscan', {}).get('options', {}).get('host', ''),
                "timestamp": data.get('niktoscan', {}).get('scandetails', {}).get('starttime', ''),
                "scanType": "nikto",
                "status": "completed",
                "vulnerabilities": [],
                "summary": {
                    "openPorts": 0,
                    "vulnerabilities": {"high": 0, "medium": 0, "low": 0, "info": 0},
                    "scanDuration": "N/A"
                }
            }
            
            # Parse vulnerabilities
            items = data.get('niktoscan', {}).get('scan', {}).get('item', [])
            if not isinstance(items, list):
                items = [items]
            
            for item in items:
                description = item.get('description', '')
                severity = "medium"  # Nikto doesn't provide severity, so we default to medium
                
                vulnerability = {
                    "severity": severity,
                    "description": description,
                    "solution": "Review and fix the identified web vulnerability",
                    "reference": item.get('uri', '')
                }
                
                result["vulnerabilities"].append(vulnerability)
                result["summary"]["vulnerabilities"][severity] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse Nikto XML: {e}")
            return {"status": "error", "output": f"XML parsing failed: {str(e)}"}

def run_scan(target: str, scan_type: str = "quick") -> Dict:
    """Main function to run appropriate scan based on type"""
    scanner = VulnerabilityScanner()
    
    if scan_type in ["quick", "full", "stealth", "vulnerability"]:
        return scanner.run_nmap_scan(target, scan_type)
    elif scan_type == "web":
        return scanner.run_nikto_scan(target)
    else:
        return {"status": "error", "output": f"Unknown scan type: {scan_type}"}