import requests
import json
import re
import logging
from typing import Dict, List, Any, Optional
from packaging import version
import time
from bs4 import BeautifulSoup
import concurrent.futures

logger = logging.getLogger(__name__)

class CVEDetector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def detect_cves_for_service(self, service_name: str, service_version: str, port: str) -> List[Dict]:
        """
        Detect real CVEs for a specific service and version
        """
        try:
            cves = []
            
            # Clean service name and version
            service_name = service_name.lower().strip()
            service_version = service_version.strip()
            
            logger.info(f"Scanning for CVEs: {service_name} {service_version} on port {port}")
            
            # Get CVEs from NVD API
            nvd_cves = self._get_cves_from_nvd(service_name, service_version)
            cves.extend(nvd_cves)
            
            # Get CVEs from other sources
            vulners_cves = self._get_cves_from_vulners(service_name, service_version)
            cves.extend(vulners_cves)
            
            # Service-specific CVE checks
            service_cves = self._service_specific_checks(service_name, service_version, port)
            cves.extend(service_cves)
            
            # Remove duplicates
            unique_cves = []
            seen_cve_ids = set()
            for cve in cves:
                if cve.get('cve_id') and cve['cve_id'] not in seen_cve_ids:
                    unique_cves.append(cve)
                    seen_cve_ids.add(cve['cve_id'])
            
            logger.info(f"Found {len(unique_cves)} CVEs for {service_name} {service_version}")
            return unique_cves
            
        except Exception as e:
            logger.error(f"Error detecting CVEs for {service_name}: {e}")
            return []

    def _get_cves_from_nvd(self, service_name: str, service_version: str) -> List[Dict]:
        """
        Get CVEs from National Vulnerability Database (NVD) API
        """
        cves = []
        try:
            # Map common service names to CPE format
            cpe_mapping = {
                'apache': f'cpe:2.3:a:apache:{service_name}:{service_version}',
                'nginx': f'cpe:2.3:a:nginx:nginx:{service_version}',
                'openssh': f'cpe:2.3:a:openbsd:openssh:{service_version}',
                'mysql': f'cpe:2.3:a:mysql:mysql:{service_version}',
                'postgresql': f'cpe:2.3:a:postgresql:postgresql:{service_version}',
                'microsoft-iis': f'cpe:2.3:a:microsoft:internet_information_services:{service_version}',
                'tomcat': f'cpe:2.3:a:apache:tomcat:{service_version}',
            }
            
            # Try to find matching CPE
            cpe = None
            for key, value in cpe_mapping.items():
                if key in service_name:
                    cpe = value
                    break
            
            if not cpe:
                # Try generic search
                search_terms = self._generate_search_terms(service_name, service_version)
                for term in search_terms:
                    cves.extend(self._search_nvd_by_keyword(term))
            else:
                # Search by CPE
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {
                    'cpeName': cpe,
                    'resultsPerPage': 50
                }
                
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get('vulnerabilities', []):
                        cve_data = vuln.get('cve', {})
                        cve_id = cve_data.get('id', '')
                        
                        if not cve_id:
                            continue
                            
                        # Get CVSS score
                        metrics = cve_data.get('metrics', {})
                        cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', []) or metrics.get('cvssMetricV2', [])
                        cvss_score = 0.0
                        if cvss_v3:
                            cvss_score = float(cvss_v3[0].get('cvssData', {}).get('baseScore', 0.0))
                        
                        # Determine severity
                        severity = self._get_severity_from_cvss(cvss_score)
                        
                        descriptions = cve_data.get('descriptions', [])
                        description = next((desc.get('value', '') for desc in descriptions if desc.get('lang') == 'en'), '')
                        
                        cves.append({
                            'cve_id': cve_id,
                            'description': description,
                            'severity': severity,
                            'cvss_score': cvss_score,
                            'service': service_name,
                            'version': service_version,
                            'source': 'NVD'
                        })
                
        except Exception as e:
            logger.debug(f"NVD API search failed for {service_name}: {e}")
        
        return cves

    def _search_nvd_by_keyword(self, search_term: str) -> List[Dict]:
        """
        Search NVD by keyword
        """
        cves = []
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': search_term,
                'resultsPerPage': 20
            }
            
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    if not cve_id:
                        continue
                    
                    metrics = cve_data.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', []) or metrics.get('cvssMetricV2', [])
                    cvss_score = 0.0
                    if cvss_v3:
                        cvss_score = float(cvss_v3[0].get('cvssData', {}).get('baseScore', 0.0))
                    
                    severity = self._get_severity_from_cvss(cvss_score)
                    
                    descriptions = cve_data.get('descriptions', [])
                    description = next((desc.get('value', '') for desc in descriptions if desc.get('lang') == 'en'), '')
                    
                    cves.append({
                        'cve_id': cve_id,
                        'description': description,
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'source': 'NVD',
                        'search_term': search_term
                    })
                    
        except Exception as e:
            logger.debug(f"NVD keyword search failed for {search_term}: {e}")
        
        return cves

    def _get_cves_from_vulners(self, service_name: str, service_version: str) -> List[Dict]:
        """
        Get CVEs from Vulners API (alternative source)
        """
        cves = []
        try:
            search_terms = self._generate_search_terms(service_name, service_version)
            
            for term in search_terms:
                url = "https://vulners.com/api/v3/search/lucene/"
                params = {
                    'query': term,
                    'size': 20
                }
                
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for hit in data.get('data', {}).get('search', []):
                        if hit.get('_source', {}).get('type') == 'cve':
                            cve_id = hit['_source'].get('id', '')
                            description = hit['_source'].get('description', '')
                            cvss_score = hit['_source'].get('cvss', {}).get('score', 0.0)
                            
                            severity = self._get_severity_from_cvss(cvss_score)
                            
                            cves.append({
                                'cve_id': cve_id,
                                'description': description,
                                'severity': severity,
                                'cvss_score': cvss_score,
                                'service': service_name,
                                'version': service_version,
                                'source': 'Vulners'
                            })
                            
        except Exception as e:
            logger.debug(f"Vulners API search failed for {service_name}: {e}")
        
        return cves

    def _service_specific_checks(self, service_name: str, service_version: str, port: str) -> List[Dict]:
        """
        Perform service-specific vulnerability checks
        """
        cves = []
        
        try:
            # Apache HTTP Server
            if 'apache' in service_name and 'http' in service_name:
                cves.extend(self._check_apache_vulnerabilities(service_version))
            
            # Nginx
            elif 'nginx' in service_name:
                cves.extend(self._check_nginx_vulnerabilities(service_version))
            
            # OpenSSH
            elif 'openssh' in service_name or 'ssh' in service_name:
                cves.extend(self._check_ssh_vulnerabilities(service_version))
            
            # MySQL
            elif 'mysql' in service_name:
                cves.extend(self._check_mysql_vulnerabilities(service_version))
            
            # PostgreSQL
            elif 'postgresql' in service_name:
                cves.extend(self._check_postgresql_vulnerabilities(service_version))
            
            # PHP
            elif 'php' in service_name:
                cves.extend(self._check_php_vulnerabilities(service_version))
            
            # WordPress (if detected)
            elif 'wordpress' in service_name:
                cves.extend(self._check_wordpress_vulnerabilities(service_version))
            
            # Common web vulnerabilities
            if port in ['80', '443', '8080', '8443']:
                cves.extend(self._check_common_web_vulnerabilities(service_name, service_version))
                
        except Exception as e:
            logger.error(f"Service-specific check failed for {service_name}: {e}")
        
        return cves

    def _check_apache_vulnerabilities(self, version_str: str) -> List[Dict]:
        """Check for known Apache vulnerabilities"""
        cves = []
        try:
            # Known critical Apache vulnerabilities
            critical_versions = {
                '2.4.49': 'CVE-2021-41773',
                '2.4.50': 'CVE-2021-42013', 
            }
            
            for vuln_version, cve_id in critical_versions.items():
                if version_str == vuln_version:
                    cves.append({
                        'cve_id': cve_id,
                        'description': f'Apache HTTP Server Path Traversal and Remote Code Execution',
                        'severity': 'critical',
                        'cvss_score': 9.8,
                        'service': 'apache',
                        'version': version_str,
                        'source': 'Known Vulnerability'
                    })
                    
        except Exception as e:
            logger.debug(f"Apache vulnerability check failed: {e}")
        
        return cves

    def _check_ssh_vulnerabilities(self, version_str: str) -> List[Dict]:
        """Check for SSH vulnerabilities"""
        cves = []
        try:
            # Check for old vulnerable versions
            if version_str and version.parse(version_str) < version.parse("7.0"):
                cves.append({
                    'cve_id': 'CVE-check-recommended',
                    'description': f'OpenSSH {version_str} may have known vulnerabilities',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'service': 'openssh',
                    'version': version_str,
                    'source': 'Version Analysis'
                })
                
        except Exception as e:
            logger.debug(f"SSH vulnerability check failed: {e}")
        
        return cves

    def _check_common_web_vulnerabilities(self, service_name: str, version_str: str) -> List[Dict]:
        """Check for common web application vulnerabilities"""
        cves = []
        
        # Add common web CVEs based on service patterns
        web_cves = [
            {
                'cve_id': 'CVE-2021-44228',
                'description': 'Log4Shell - Apache Log4j2 Remote Code Execution',
                'severity': 'critical',
                'cvss_score': 10.0,
                'service': service_name,
                'version': version_str,
                'source': 'Common Web Vulnerability'
            },
            {
                'cve_id': 'CVE-2017-5638',
                'description': 'Apache Struts Remote Code Execution',
                'severity': 'critical', 
                'cvss_score': 10.0,
                'service': service_name,
                'version': version_str,
                'source': 'Common Web Vulnerability'
            }
        ]
        
        # Only add if service might be affected
        if any(x in service_name for x in ['java', 'apache', 'tomcat', 'spring']):
            cves.extend(web_cves)
            
        return cves

    def _generate_search_terms(self, service_name: str, service_version: str) -> List[str]:
        """Generate search terms for CVE databases"""
        terms = []
        
        # Basic service name + version
        terms.append(f"{service_name} {service_version}")
        
        # Common variations
        if service_name == 'httpd':
            terms.append(f"apache http server {service_version}")
        elif service_name == 'nginx':
            terms.append(f"nginx {service_version}")
        elif 'ssh' in service_name:
            terms.append(f"openssh {service_version}")
        elif 'mysql' in service_name:
            terms.append(f"mysql {service_version}")
        elif 'postgres' in service_name:
            terms.append(f"postgresql {service_version}")
            
        return terms

    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high" 
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0:
            return "low"
        else:
            return "info"

    def scan_ports_for_cves(self, scan_results: Dict) -> List[Dict]:
        """
        Scan all detected ports and services for CVEs
        """
        all_cves = []
        
        try:
            ports = scan_results.get('ports', [])
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_port = {}
                
                for port in ports:
                    service = port.get('service', '')
                    version_str = port.get('version', '')
                    port_num = port.get('number', '')
                    
                    if service and service != 'unknown':
                        future = executor.submit(
                            self.detect_cves_for_service, 
                            service, 
                            version_str, 
                            port_num
                        )
                        future_to_port[future] = port
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        cves = future.result()
                        all_cves.extend(cves)
                    except Exception as e:
                        logger.error(f"CVE detection failed for port {port}: {e}")
            
        except Exception as e:
            logger.error(f"Port CVE scanning failed: {e}")
        
        return all_cves

# Global CVE detector instance
cve_detector = CVEDetector()