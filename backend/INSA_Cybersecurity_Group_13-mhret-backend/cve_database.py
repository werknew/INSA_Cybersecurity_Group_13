import json
import logging
import sqlite3
import requests
from typing import Dict, List, Any
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

class CVEDatabase:
    def __init__(self, db_path: str = "cve_database.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for CVEs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                last_modified TEXT,
                solutions TEXT,
                affected_products TEXT,
                "references" TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                cpe_string TEXT,
                version_start_excluding TEXT,
                version_start_including TEXT,
                version_end_excluding TEXT, 
                version_end_including TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("CVE database initialized")

    def update_cve_database(self):
        """Update CVE database from NVD API"""
        try:
            # Get current year and previous year for comprehensive coverage
            current_year = datetime.now().year
            years = [current_year, current_year - 1]
            
            for year in years:
                self._fetch_cves_for_year(year)
                
            logger.info("CVE database updated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update CVE database: {e}")
            return False

    def _fetch_cves_for_year(self, year: int):
        """Fetch CVEs for a specific year from NVD API"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'pubStartDate': f'{year}-01-01T00:00:00.000',
                'pubEndDate': f'{year}-12-31T23:59:59.999',
                'resultsPerPage': 2000
            }
            
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                self._process_cves(data.get('vulnerabilities', []))
            else:
                logger.warning(f"Failed to fetch CVEs for {year}: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error fetching CVEs for {year}: {e}")

    def _process_cves(self, vulnerabilities: List[Dict]):
        """Process and store CVEs in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for vuln in vulnerabilities:
            try:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                if not cve_id:
                    continue
                
                # Get description
                descriptions = cve_data.get('descriptions', [])
                description = next((desc.get('value', '') for desc in descriptions if desc.get('lang') == 'en'), '')
                
                # Get CVSS score and severity
                metrics = cve_data.get('metrics', {})
                cvss_score = 0.0
                severity = "unknown"
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        cvss_data = metrics[version][0].get('cvssData', {})
                        cvss_score = float(cvss_data.get('baseScore', 0.0))
                        severity = self._get_severity_from_cvss(cvss_score)
                        break
                
                # Get dates
                published = cve_data.get('published', '')
                last_modified = cve_data.get('lastModified', '')
                
                # Get references
                references = cve_data.get('references', [])
                reference_links = [ref.get('url', '') for ref in references]
                
                # Insert CVE data
                cursor.execute('''
                    INSERT OR REPLACE INTO cves 
                    (cve_id, description, severity, cvss_score, published_date, last_modified, "references")
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (cve_id, description, severity, cvss_score, published, last_modified, json.dumps(reference_links)))
                
                # Process CPE matches
                configurations = cve_data.get('configurations', [])
                for config in configurations:
                    nodes = config.get('nodes', [])
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        for cpe_match in cpe_matches:
                            cursor.execute('''
                                INSERT INTO cpe_matches 
                                (cve_id, cpe_string, version_start_excluding, version_start_including, 
                                 version_end_excluding, version_end_including)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (
                                cve_id,
                                cpe_match.get('criteria', ''),
                                cpe_match.get('versionStartExcluding', ''),
                                cpe_match.get('versionStartIncluding', ''),
                                cpe_match.get('versionEndExcluding', ''),
                                cpe_match.get('versionEndIncluding', '')
                            ))
                
            except Exception as e:
                logger.error(f"Error processing CVE {cve_data.get('id', 'unknown')}: {e}")
                continue
        
        conn.commit()
        conn.close()

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
            return "unknown"

    def search_cves_by_product(self, product_name: str, version: str = "") -> List[Dict]:
        """Search CVEs by product name and version"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if version:
                query = '''
                    SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score, 
                           c.published_date, c.references
                    FROM cves c
                    JOIN cpe_matches cm ON c.cve_id = cm.cve_id
                    WHERE cm.cpe_string LIKE ? 
                    AND (cm.version_start_including <= ? OR cm.version_start_including = '')
                    AND (cm.version_end_including >= ? OR cm.version_end_including = '')
                    ORDER BY c.cvss_score DESC
                '''
                cursor.execute(query, (f'%{product_name}%', version, version))
            else:
                query = '''
                    SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score, 
                           c.published_date, c.references
                    FROM cves c
                    JOIN cpe_matches cm ON c.cve_id = cm.cve_id
                    WHERE cm.cpe_string LIKE ?
                    ORDER BY c.cvss_score DESC
                    LIMIT 50
                '''
                cursor.execute(query, (f'%{product_name}%',))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'cve_id': row[0],
                    'description': row[1],
                    'severity': row[2],
                    'cvss_score': row[3],
                    'published_date': row[4],
                    'references': json.loads(row[5]) if row[5] else []
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return []
        finally:
            conn.close()

    def get_cve_by_id(self, cve_id: str) -> Dict:
        """Get specific CVE by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT cve_id, description, severity, cvss_score, published_date, last_modified, references
            FROM cves WHERE cve_id = ?
        ''', (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'cve_id': row[0],
                'description': row[1],
                'severity': row[2],
                'cvss_score': row[3],
                'published_date': row[4],
                'last_modified': row[5],
                'references': json.loads(row[6]) if row[6] else []
            }
        return {}

    def get_statistics(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM cves')
        total_cves = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cves WHERE severity = "critical"')
        critical_cves = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cves WHERE severity = "high"')
        high_cves = cursor.fetchone()[0]
        
        cursor.execute('SELECT MAX(published_date) FROM cves')
        latest_update = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_cves': total_cves,
            'critical_cves': critical_cves,
            'high_cves': high_cves,
            'latest_update': latest_update
        }

# Global CVE database instance
cve_db = CVEDatabase()