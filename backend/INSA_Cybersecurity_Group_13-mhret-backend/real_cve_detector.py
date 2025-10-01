import requests
import json
import logging
import sqlite3
import re
from typing import Dict, List, Any, Optional
from packaging import version as packaging_version
from datetime import datetime, timedelta
import time
import os

logger = logging.getLogger(__name__)

class RealCVEDetector:
    def __init__(self, db_path: str = "real_cve_database.db"):
        self.db_path = db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Vulnerability-Scanner/1.0',
            'apiKey': 'DEMO_KEY'  # NVD provides free API keys
        })
        self._init_database()
    
    def _init_database(self):
        """Initialize real SQLite database for CVEs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main CVE table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                published_date TEXT,
                last_modified TEXT,
                references TEXT,
                vendor TEXT,
                product TEXT
            )
        ''')
        
        # CPE matching table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                cpe23Uri TEXT,
                versionStartExcluding TEXT,
                versionStartIncluding TEXT,
                versionEndExcluding TEXT,
                versionEndIncluding TEXT,
                vulnerable BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
            )
        ''')
        
        # Update tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS update_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                last_update TEXT,
                cves_added INTEGER,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Real CVE database initialized")

    def update_cve_database(self):
        """Update CVE database from REAL NVD API"""
        try:
            logger.info("Starting REAL CVE database update from NVD API...")
            
            total_cves_added = 0
            current_year = datetime.now().year
            
            # Get CVEs from current and previous year for comprehensive coverage
            for year in range(current_year - 1, current_year + 1):
                cves_added = self._fetch_cves_for_year(year)
                total_cves_added += cves_added
                time.sleep(6)  # Respect NVD rate limits (10 requests per minute)
            
            # Log the update
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO update_log (last_update, cves_added, status)
                VALUES (?, ?, ?)
            ''', (datetime.now().isoformat(), total_cves_added, 'success'))
            conn.commit()
            conn.close()
            
            logger.info(f"Real CVE database updated successfully with {total_cves_added} new CVEs")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update real CVE database: {e}")
            # Log failure
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO update_log (last_update, cves_added, status)
                VALUES (?, ?, ?)
            ''', (datetime.now().isoformat(), 0, f'failed: {str(e)}'))
            conn.commit()
            conn.close()
            return False

    def _fetch_cves_for_year(self, year: int) -> int:
        """Fetch CVEs for a specific year from REAL NVD API"""
        cves_added = 0
        start_index = 0
        results_per_page = 2000
        
        try:
            while True:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {
                    'pubStartDate': f'{year}-01-01T00:00:00.000',
                    'pubEndDate': f'{year}-12-31T23:59:59.999',
                    'startIndex': start_index,
                    'resultsPerPage': results_per_page
                }
                
                logger.info(f"Fetching CVEs for {year} (startIndex: {start_index})")
                
                response = self.session.get(url, params=params, timeout=60)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    if not vulnerabilities:
                        break  # No more results
                    
                    cves_added += self._process_real_cves(vulnerabilities)
                    
                    total_results = data.get('totalResults', 0)
                    if start_index + results_per_page >= total_results:
                        break  # Reached end of results
                    
                    start_index += results_per_page
                    time.sleep(6)  # Rate limiting
                    
                elif response.status_code == 403:
                    logger.warning("NVD API rate limit reached, waiting...")
                    time.sleep(60)  # Wait 1 minute
                    continue
                else:
                    logger.error(f"NVD API error for year {year}: {response.status_code}")
                    break
                    
        except Exception as e:
            logger.error(f"Error fetching CVEs for {year}: {e}")
        
        return cves_added

    def _process_real_cves(self, vulnerabilities: List[Dict]) -> int:
        """Process and store REAL CVEs in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cves_added = 0
        
        for vuln in vulnerabilities:
            try:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                if not cve_id:
                    continue
                
                # Get description
                descriptions = cve_data.get('descriptions', [])
                description = next((desc.get('value', '') for desc in descriptions if desc.get('lang') == 'en'), 'No description available')
                
                # Get CVSS metrics
                metrics = cve_data.get('metrics', {})
                cvss_score = 0.0
                cvss_vector = ""
                severity = "unknown"
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                cvss_data = None
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        cvss_metric = metrics[version][0]
                        cvss_data = cvss_metric.get('cvssData', {})
                        cvss_score = float(cvss_data.get('baseScore', 0.0))
                        cvss_vector = cvss_data.get('vectorString', '')
                        severity = self._get_severity_from_cvss(cvss_score)
                        break
                
                # Get dates
                published = cve_data.get('published', '')
                last_modified = cve_data.get('lastModified', '')
                
                # Get references
                references = cve_data.get('references', [])
                reference_links = [ref.get('url', '') for ref in references]
                
                # Extract vendor and product from first CPE if available
                vendor, product = self._extract_vendor_product(cve_data)
                
                # Insert CVE data
                cursor.execute('''
                    INSERT OR REPLACE INTO cves 
                    (cve_id, description, severity, cvss_score, cvss_vector, published_date, last_modified, references, vendor, product)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id, description, severity, cvss_score, cvss_vector, 
                    published, last_modified, json.dumps(reference_links), vendor, product
                ))
                
                # Process CPE matches
                configurations = cve_data.get('configurations', [])
                for config in configurations:
                    nodes = config.get('nodes', [])
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        for cpe_match in cpe_matches:
                            cursor.execute('''
                                INSERT OR REPLACE INTO cpe_matches 
                                (cve_id, cpe23Uri, versionStartExcluding, versionStartIncluding, 
                                 versionEndExcluding, versionEndIncluding, vulnerable)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                cve_id,
                                cpe_match.get('criteria', ''),
                                cpe_match.get('versionStartExcluding', ''),
                                cpe_match.get('versionStartIncluding', ''),
                                cpe_match.get('versionEndExcluding', ''),
                                cpe_match.get('versionEndIncluding', ''),
                                cpe_match.get('vulnerable', True)
                            ))
                
                cves_added += 1
                
            except Exception as e:
                logger.error(f"Error processing CVE {cve_data.get('id', 'unknown')}: {e}")
                continue
        
        conn.commit()
        conn.close()
        return cves_added

    def _extract_vendor_product(self, cve_data: Dict) -> tuple:
        """Extract vendor and product from CPE data"""
        try:
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe_match in cpe_matches:
                        cpe_string = cpe_match.get('criteria', '')
                        if cpe_string:
                            # Parse CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                            parts = cpe_string.split(':')
                            if len(parts) >= 5:
                                return parts[3], parts[4]  # vendor, product
        except Exception:
            pass
        return "unknown", "unknown"

    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Convert REAL CVSS score to severity level"""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0:
            return "low"
        else:
            return "unknown"

    def detect_vulnerabilities_for_service(self, service_name: str, service_version: str, port: str) -> List[Dict]:
        """REAL vulnerability detection for services"""
        vulnerabilities = []
        
        try:
            # Normalize service name for CPE matching
            service_name = service_name.lower().strip()
            service_version = service_version.strip()
            
            logger.info(f"Scanning REAL CVEs for {service_name} {service_version}")
            
            # Search for CVEs matching this service
            cves = self._search_cves_by_service(service_name, service_version)
            
            for cve in cves:
                vulnerabilities.append({
                    "cve_id": cve['cve_id'],
                    "severity": cve['severity'],
                    "description": cve['description'],
                    "cvss_score": cve['cvss_score'],
                    "solution": self._generate_solution(service_name, cve['severity']),
                    "port": port,
                    "service": service_name,
                    "version": service_version,
                    "source": "NVD CVE Database",
                    "published_date": cve['published_date'],
                    "references": cve['references']
                })
            
            logger.info(f"Found {len(vulnerabilities)} REAL CVEs for {service_name}")
            
        except Exception as e:
            logger.error(f"Real CVE detection failed for {service_name}: {e}")
        
        return vulnerabilities

    def _search_cves_by_service(self, service_name: str, service_version: str) -> List[Dict]:
        """Search for CVEs by service name and version using REAL CPE matching"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Map common service names to CPE patterns
            service_patterns = self._get_service_cpe_patterns(service_name)
            
            all_cves = []
            
            for pattern in service_patterns:
                query = '''
                    SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score, 
                           c.published_date, c.references, cm.cpe23Uri,
                           cm.versionStartIncluding, cm.versionEndIncluding,
                           cm.versionStartExcluding, cm.versionEndExcluding
                    FROM cves c
                    JOIN cpe_matches cm ON c.cve_id = cm.cve_id
                    WHERE cm.cpe23Uri LIKE ? AND cm.vulnerable = 1
                    ORDER BY c.cvss_score DESC
                    LIMIT 50
                '''
                cursor.execute(query, (f'%{pattern}%',))
                
                for row in cursor.fetchall():
                    cve_id, description, severity, cvss_score, published_date, references, cpe23Uri, vsi, vei, vse, vee = row
                    
                    # Check if version matches
                    if self._version_matches(service_version, vsi, vei, vse, vee):
                        all_cves.append({
                            'cve_id': cve_id,
                            'description': description,
                            'severity': severity,
                            'cvss_score': cvss_score,
                            'published_date': published_date,
                            'references': json.loads(references) if references else []
                        })
            
            # Remove duplicates
            unique_cves = []
            seen_cves = set()
            for cve in all_cves:
                if cve['cve_id'] not in seen_cves:
                    unique_cves.append(cve)
                    seen_cves.add(cve['cve_id'])
            
            return unique_cves
            
        except Exception as e:
            logger.error(f"Error searching CVEs for {service_name}: {e}")
            return []
        finally:
            conn.close()

    def _get_service_cpe_patterns(self, service_name: str) -> List[str]:
        """Get CPE patterns for common services"""
        patterns = {
            'apache': ['apache:http_server', 'apache:tomcat', 'apache:struts'],
            'nginx': ['nginx:nginx'],
            'openssh': ['openssh:openssh'],
            'ssh': ['openssh:openssh'],
            'mysql': ['mysql:mysql', 'oracle:mysql'],
            'postgresql': ['postgresql:postgresql'],
            'microsoft-iis': ['microsoft:iis'],
            'tomcat': ['apache:tomcat'],
            'wordpress': ['wordpress:wordpress'],
            'php': ['php:php'],
            'openssl': ['openssl:openssl'],
            'ftp': ['vsftpd:vsftpd', 'proftpd:proftpd'],
            'smtp': ['postfix:postfix', 'exim:exim'],
            'http': ['apache:http_server', 'nginx:nginx', 'microsoft:iis'],
            'https': ['apache:http_server', 'nginx:nginx', 'microsoft:iis'],
        }
        
        # Return matching patterns or use service name as fallback
        for key, pattern_list in patterns.items():
            if key in service_name.lower():
                return pattern_list
        
        # Fallback: try service name as product
        return [f':{service_name.lower()}:']

    def _version_matches(self, target_version: str, version_start_inc: str, version_end_inc: str, 
                        version_start_excl: str, version_end_excl: str) -> bool:
        """Check if target version matches CPE version constraints"""
        if not target_version or target_version == 'unknown':
            return True  # No version info, include all
        
        try:
            target_ver = packaging_version.parse(target_version.split()[0])  # Take first version part
            
            # Check version start inclusive
            if version_start_inc:
                start_ver = packaging_version.parse(version_start_inc)
                if target_ver < start_ver:
                    return False
            
            # Check version end inclusive  
            if version_end_inc:
                end_ver = packaging_version.parse(version_end_inc)
                if target_ver > end_ver:
                    return False
            
            # Check version start exclusive
            if version_start_excl:
                start_excl_ver = packaging_version.parse(version_start_excl)
                if target_ver <= start_excl_ver:
                    return False
            
            # Check version end exclusive
            if version_end_excl:
                end_excl_ver = packaging_version.parse(version_end_excl)
                if target_ver >= end_excl_ver:
                    return False
            
            return True
            
        except Exception:
            # If version parsing fails, be inclusive
            return True

    def _generate_solution(self, service_name: str, severity: str) -> str:
        """Generate solution recommendation based on service and severity"""
        base_solution = f"Update {service_name} to the latest version"
        
        if severity == "critical":
            return f"IMMEDIATE ACTION REQUIRED: {base_solution}. Apply patches immediately."
        elif severity == "high":
            return f"URGENT: {base_solution}. Schedule maintenance window for patching."
        elif severity == "medium":
            return f"RECOMMENDED: {base_solution}. Plan for next maintenance cycle."
        else:
            return base_solution + ". Consider during regular updates."

    def get_database_statistics(self) -> Dict:
        """Get REAL database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT COUNT(*) FROM cves')
            total_cves = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM cves WHERE severity = "critical"')
            critical_cves = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM cves WHERE severity = "high"')
            high_cves = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM cpe_matches')
            total_cpe_matches = cursor.fetchone()[0]
            
            cursor.execute('SELECT MAX(published_date) FROM cves')
            latest_cve = cursor.fetchone()[0]
            
            cursor.execute('SELECT last_update FROM update_log ORDER BY id DESC LIMIT 1')
            last_update = cursor.fetchone()
            last_update = last_update[0] if last_update else "Never"
            
            return {
                'total_cves': total_cves,
                'critical_cves': critical_cves,
                'high_cves': high_cves,
                'total_cpe_matches': total_cpe_matches,
                'latest_cve_date': latest_cve,
                'last_update': last_update,
                'database_size_mb': os.path.getsize(self.db_path) / (1024 * 1024) if os.path.exists(self.db_path) else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting database statistics: {e}")
            return {}
        finally:
            conn.close()

# Global real CVE detector instance
real_cve_detector = RealCVEDetector()