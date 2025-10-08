import os
import requests
import json
import whois
import dns.resolver
from dotenv import load_dotenv
import logging
from typing import Dict, List, Any, Optional
import time
import re
from datetime import datetime
import subprocess
import socket
import ssl
import random

load_dotenv()

logger = logging.getLogger(__name__)

class FixedSecurityTools:
    def __init__(self):
        # API Keys with fallbacks
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', '')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
        
        logger.info("Fixed Security Tools initialized")

    def get_api_status(self) -> Dict:
        """Get status of all APIs"""
        return {
            'shodan': bool(self.shodan_api_key),
            'virustotal': bool(self.virustotal_api_key),
            'abuseipdb': bool(self.abuseipdb_api_key),
            'demo_mode': not all([self.shodan_api_key, self.virustotal_api_key, self.abuseipdb_api_key])
        }

    # === UNIVERSAL INPUT CLEANING ===
    def _clean_input(self, input_str: str, input_type: str = 'auto') -> str:
        """Clean input for various security tools"""
        if not input_str:
            return ""
        
        input_str = input_str.strip()
        
        if input_type == 'auto':
            # Detect input type
            if self._is_valid_ip(input_str):
                input_type = 'ip'
            elif '.' in input_str and not input_str.startswith(('http://', 'https://')):
                input_type = 'domain'
            else:
                input_type = 'url'
        
        if input_type == 'ip':
            # Clean IP input
            if input_str.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                try:
                    parsed = urlparse(input_str)
                    input_str = parsed.hostname or input_str
                except:
                    pass
            
            # Remove port
            if ':' in input_str and not input_str.startswith('['):
                input_str = input_str.split(':')[0]
                
        elif input_type in ['domain', 'url']:
            # Clean domain/URL input
            if input_str.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                try:
                    parsed = urlparse(input_str)
                    input_str = parsed.hostname or input_str
                except:
                    pass
            
            # Remove port and path
            input_str = input_str.split(':')[0].split('/')[0]
            
            # Remove www. prefix for consistency
            if input_str.startswith('www.'):
                input_str = input_str[4:]
        
        return input_str

    # === IP VALIDATION ===
    def _is_valid_ip(self, ip: str) -> bool:
        """Very forgiving IP validation"""
        if not ip:
            return False
            
        ip = self._clean_input(ip, 'ip')
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    for part in parts:
                        if not 0 <= int(part) <= 255:
                            return False
                    return True
                except:
                    return False
        
        # IPv6 pattern (very basic)
        if ':' in ip and len(ip) > 2:
            return True
            
        return False

    # === DOMAIN VALIDATION ===
    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        if not domain:
            return False
            
        domain = self._clean_input(domain, 'domain')
        
        # Basic domain pattern
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    # === SHODAN WITH BETTER ERROR HANDLING ===
    def shodan_host_search(self, input_str: str) -> Dict:
        """Search Shodan with very forgiving input"""
        try:
            # Clean input
            cleaned_input = self._clean_input(input_str, 'ip')
            
            # If it doesn't look like an IP, try to resolve it
            if not self._is_valid_ip(cleaned_input):
                try:
                    # Try to resolve domain to IP
                    ip = socket.gethostbyname(cleaned_input)
                    cleaned_input = ip
                except:
                    return {
                        'success': False,
                        'error': f'Could not resolve "{input_str}" to an IP address. Please enter a valid IP or domain.',
                        'suggestions': [
                            'Try: 8.8.8.8 (Google DNS)',
                            'Try: 1.1.1.1 (Cloudflare DNS)', 
                            'Try: 192.168.1.1 (common router)',
                            'Or enter a domain like: google.com'
                        ]
                    }
            
            # Now we have a valid IP, proceed with Shodan
            if self.shodan_api_key:
                try:
                    url = f"https://api.shodan.io/shodan/host/{cleaned_input}"
                    params = {'key': self.shodan_api_key}
                    
                    response = requests.get(url, params=params, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        return {
                            'success': True,
                            'source': 'shodan',
                            'input_used': cleaned_input,
                            'original_input': input_str,
                            'data': {
                                'ip': data.get('ip_str'),
                                'ports': data.get('ports', []),
                                'hostnames': data.get('hostnames', []),
                                'org': data.get('org', 'Unknown'),
                                'os': data.get('os', 'Unknown'),
                                'services': [
                                    {
                                        'port': service.get('port'),
                                        'service': service.get('service'),
                                        'version': service.get('version'),
                                        'banner': (service.get('data', '')[:200] + '...') if len(service.get('data', '')) > 200 else service.get('data', '')
                                    }
                                    for service in data.get('data', [])
                                ]
                            }
                        }
                    else:
                        logger.warning(f"Shodan API failed with status {response.status_code}")
                except Exception as e:
                    logger.warning(f"Shodan API error: {e}")
            
            # Fallback to demo data
            return self._generate_shodan_demo(cleaned_input, input_str)
            
        except Exception as e:
            logger.error(f"Shodan search failed: {e}")
            return {
                'success': False,
                'error': f'Shodan search failed: {str(e)}',
                'input_used': input_str
            }

    def _generate_shodan_demo(self, ip: str, original_input: str) -> Dict:
        """Generate realistic Shodan demo data"""
        # Common services based on IP patterns
        if ip == '8.8.8.8' or ip == '1.1.1.1':
            services = [{'port': 53, 'service': 'domain', 'version': '', 'banner': 'DNS server'}]
            org = 'DNS Provider'
            os_system = 'Linux'
        elif ip.startswith('192.168.') or ip.startswith('10.'):
            services = [
                {'port': 80, 'service': 'http', 'version': '', 'banner': 'HTTP server'},
                {'port': 443, 'service': 'https', 'version': '', 'banner': 'HTTPS server'},
                {'port': 22, 'service': 'ssh', 'version': 'OpenSSH', 'banner': 'SSH server'}
            ]
            org = 'Private Network'
            os_system = 'Linux'
        else:
            # Random but realistic services
            common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
            services = []
            for port in random.sample(common_ports, min(3, len(common_ports))):
                service_info = {
                    'port': port,
                    'service': self._get_service_name(port),
                    'version': '',
                    'banner': f'Service on port {port}'
                }
                services.append(service_info)
            org = 'Unknown Organization'
            os_system = random.choice(['Linux', 'Windows', 'FreeBSD'])
        
        return {
            'success': True,
            'source': 'demo',
            'input_used': ip,
            'original_input': original_input,
            'data': {
                'ip': ip,
                'ports': [s['port'] for s in services],
                'hostnames': [f'host-{ip.replace(".", "-")}.example.com'],
                'org': org,
                'os': os_system,
                'services': services
            },
            'note': 'Using demo data. Add Shodan API key for real results.'
        }

    def _get_service_name(self, port: int) -> str:
        """Get service name from port number"""
        common_services = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 25: 'smtp',
            53: 'dns', 110: 'pop3', 143: 'imap', 993: 'imaps', 995: 'pop3s',
            3389: 'rdp', 5900: 'vnc', 27017: 'mongodb', 5432: 'postgresql',
            3306: 'mysql', 1433: 'mssql', 6379: 'redis', 9200: 'elasticsearch'
        }
        return common_services.get(port, 'unknown')

    # === VIRUSTOTAL WITH BETTER INPUT HANDLING ===
    def virustotal_ip_report(self, input_str: str) -> Dict:
        """VirusTotal IP reputation with better input handling"""
        try:
            cleaned_input = self._clean_input(input_str, 'ip')
            
            # Resolve domain to IP if needed
            if not self._is_valid_ip(cleaned_input):
                try:
                    ip = socket.gethostbyname(cleaned_input)
                    cleaned_input = ip
                except:
                    return {
                        'success': False,
                        'error': f'Could not resolve "{input_str}" to an IP address.',
                        'suggestions': ['Enter a valid IP address like 8.8.8.8 or domain like google.com']
                    }
            
            if self.virustotal_api_key:
                try:
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{cleaned_input}"
                    headers = {'x-apikey': self.virustotal_api_key}
                    
                    response = requests.get(url, headers=headers, timeout=15)
                    
                    if response.status_code == 200:
                        data = response.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        
                        return {
                            'success': True,
                            'source': 'virustotal',
                            'input_used': cleaned_input,
                            'original_input': input_str,
                            'data': {
                                'ip': cleaned_input,
                                'reputation': attributes.get('reputation', 0),
                                'harmless_votes': attributes.get('total_votes', {}).get('harmless', 0),
                                'malicious_votes': attributes.get('total_votes', {}).get('malicious', 0),
                                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                                'as_owner': attributes.get('as_owner', 'Unknown'),
                                'country': attributes.get('country', 'Unknown')
                            }
                        }
                    else:
                        logger.warning(f"VirusTotal API failed with status {response.status_code}")
                except Exception as e:
                    logger.warning(f"VirusTotal API error: {e}")
            
            # Fallback to demo data
            return self._generate_virustotal_demo(cleaned_input, input_str)
            
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")
            return {
                'success': False,
                'error': f'VirusTotal lookup failed: {str(e)}'
            }

    def _generate_virustotal_demo(self, ip: str, original_input: str) -> Dict:
        """Generate realistic VirusTotal demo data"""
        # Base stats based on IP type
        if ip.startswith('192.168.') or ip.startswith('10.'):
            stats = {'harmless': 10, 'malicious': 0, 'suspicious': 0, 'undetected': 2}
            reputation = 0
            as_owner = 'Private Network'
            country = 'Local'
        elif ip in ['8.8.8.8', '1.1.1.1']:
            stats = {'harmless': 75, 'malicious': 0, 'suspicious': 0, 'undetected': 5}
            reputation = 0
            as_owner = 'DNS Provider'
            country = 'US'
        else:
            # Random but realistic stats
            harmless = random.randint(20, 80)
            malicious = random.randint(0, 5)
            stats = {
                'harmless': harmless,
                'malicious': malicious,
                'suspicious': random.randint(0, 3),
                'undetected': random.randint(1, 10)
            }
            reputation = max(-100, min(100, (harmless - malicious * 20)))
            as_owner = random.choice(['Google LLC', 'Cloudflare', 'Amazon AWS', 'Microsoft Azure'])
            country = random.choice(['US', 'DE', 'GB', 'FR', 'JP'])
        
        return {
            'success': True,
            'source': 'demo',
            'input_used': ip,
            'original_input': original_input,
            'data': {
                'ip': ip,
                'reputation': reputation,
                'harmless_votes': stats['harmless'],
                'malicious_votes': stats['malicious'],
                'last_analysis_stats': stats,
                'as_owner': as_owner,
                'country': country
            },
            'note': 'Using demo data. Add VirusTotal API key for real results.'
        }

    # === ABUSEIPDB WITH BETTER INPUT HANDLING ===
    def abuseipdb_check(self, input_str: str) -> Dict:
        """AbuseIPDB check with better input handling"""
        try:
            cleaned_input = self._clean_input(input_str, 'ip')
            
            # Resolve domain to IP if needed
            if not self._is_valid_ip(cleaned_input):
                try:
                    ip = socket.gethostbyname(cleaned_input)
                    cleaned_input = ip
                except:
                    return {
                        'success': False,
                        'error': f'Could not resolve "{input_str}" to an IP address.'
                    }
            
            if self.abuseipdb_api_key:
                try:
                    url = "https://api.abuseipdb.com/api/v2/check"
                    headers = {
                        'Key': self.abuseipdb_api_key,
                        'Accept': 'application/json'
                    }
                    params = {
                        'ipAddress': cleaned_input,
                        'maxAgeInDays': 90
                    }
                    
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json().get('data', {})
                        
                        return {
                            'success': True,
                            'source': 'abuseipdb',
                            'input_used': cleaned_input,
                            'original_input': input_str,
                            'data': {
                                'ip': data.get('ipAddress'),
                                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                                'country_code': data.get('countryCode', 'Unknown'),
                                'isp': data.get('isp', 'Unknown'),
                                'domain': data.get('domain', 'Unknown'),
                                'total_reports': data.get('totalReports', 0),
                                'last_reported': data.get('lastReportedAt'),
                                'is_public': data.get('isPublic', False),
                                'is_whitelisted': data.get('isWhitelisted', False)
                            }
                        }
                    else:
                        logger.warning(f"AbuseIPDB API failed with status {response.status_code}")
                except Exception as e:
                    logger.warning(f"AbuseIPDB API error: {e}")
            
            # Fallback to demo data
            return self._generate_abuseipdb_demo(cleaned_input, input_str)
            
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            return {
                'success': False,
                'error': f'AbuseIPDB check failed: {str(e)}'
            }

    def _generate_abuseipdb_demo(self, ip: str, original_input: str) -> Dict:
        """Generate realistic AbuseIPDB demo data"""
        # Base score based on IP type
        if ip.startswith('192.168.') or ip.startswith('10.'):
            score = 0
            reports = 0
            is_whitelisted = True
            isp = 'Private Network'
            country = 'Local'
        elif ip in ['8.8.8.8', '1.1.1.1']:
            score = 0
            reports = 0
            is_whitelisted = True
            isp = 'DNS Provider'
            country = 'US'
        else:
            score = random.randint(0, 30)
            reports = random.randint(0, 50)
            is_whitelisted = score < 10
            isp = random.choice(['Comcast', 'AT&T', 'Verizon', 'Deutsche Telekom'])
            country = random.choice(['US', 'DE', 'GB', 'FR', 'JP'])
        
        return {
            'success': True,
            'source': 'demo',
            'input_used': ip,
            'original_input': original_input,
            'data': {
                'ipAddress': ip,
                'abuseConfidenceScore': score,
                'countryCode': country,
                'isp': isp,
                'domain': f'host-{ip.replace(".", "-")}.example.com',
                'totalReports': reports,
                'lastReportedAt': datetime.now().isoformat() if reports > 0 else None,
                'isPublic': True,
                'isWhitelisted': is_whitelisted
            },
            'note': 'Using demo data. Add AbuseIPDB API key for real results.'
        }

    # === DNS LOOKUP ===
    def dns_lookup(self, domain: str, record_type: str = 'A') -> Dict:
        """Perform DNS lookup with better error handling"""
        try:
            # Clean domain input
            domain = self._clean_input(domain, 'domain')
            
            # Validate domain format
            if not self._is_valid_domain(domain):
                return {
                    'success': False,
                    'error': f'Invalid domain format: {domain}',
                    'suggestions': ['Enter a valid domain like: google.com', 'Remove http:// or https:// prefixes']
                }
            
            # Supported record types
            supported_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
            if record_type not in supported_types:
                return {
                    'success': False,
                    'error': f'Unsupported record type: {record_type}',
                    'supported_types': supported_types
                }
            
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results = [str(rdata) for rdata in answers]
                
                return {
                    'success': True,
                    'data': {
                        'domain': domain,
                        'record_type': record_type,
                        'results': results
                    }
                }
            except dns.resolver.NoAnswer:
                return {
                    'success': True,
                    'data': {
                        'domain': domain,
                        'record_type': record_type,
                        'results': [],
                        'note': f'No {record_type} records found for this domain'
                    }
                }
            except dns.resolver.NXDOMAIN:
                return {
                    'success': False,
                    'error': f'Domain {domain} does not exist (NXDOMAIN)'
                }
            except dns.resolver.Timeout:
                return {
                    'success': False,
                    'error': 'DNS query timed out'
                }
                
        except Exception as e:
            logger.error(f"DNS lookup failed: {e}")
            return {
                'success': False,
                'error': f'DNS lookup failed: {str(e)}'
            }

    # === WHOIS LOOKUP ===
    def whois_lookup(self, domain: str) -> Dict:
        """Perform WHOIS lookup with multiple fallback methods"""
        try:
            # Clean domain input
            domain = self._clean_input(domain, 'domain')
            
            # Validate domain
            if not self._is_valid_domain(domain):
                return {
                    'success': False,
                    'error': f'Invalid domain format: {domain}'
                }
            
            # Method 1: Try python-whois first
            try:
                domain_info = whois.whois(domain)
                
                # Extract relevant information
                result = {
                    'domain': domain,
                    'registrar': domain_info.registrar or 'Unknown',
                    'creation_date': self._format_date(domain_info.creation_date),
                    'expiration_date': self._format_date(domain_info.expiration_date),
                    'updated_date': self._format_date(domain_info.updated_date),
                    'name_servers': list(domain_info.name_servers) if domain_info.name_servers else [],
                    'status': domain_info.status or 'Unknown',
                    'emails': list(domain_info.emails) if domain_info.emails else []
                }
                
                if result['registrar'] != 'Unknown':
                    return {
                        'success': True,
                        'source': 'python-whois',
                        'data': result
                    }
            except Exception as e:
                logger.warning(f"python-whois failed: {e}")
            
            # Method 2: Try command-line whois
            try:
                result = subprocess.run(
                    ['whois', domain], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                
                if result.returncode == 0:
                    whois_text = result.stdout
                    
                    # Parse common whois fields
                    parsed_data = self._parse_whois_text(whois_text, domain)
                    return {
                        'success': True,
                        'source': 'whois-command',
                        'data': parsed_data
                    }
            except Exception as e:
                logger.warning(f"Command-line whois failed: {e}")
            
            # Method 3: Fallback to mock data
            mock_data = self._generate_mock_whois(domain)
            return {
                'success': True,
                'source': 'demo',
                'data': mock_data,
                'note': 'Using demo WHOIS data. Real WHOIS may require proper installation.'
            }
            
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return {
                'success': False,
                'error': f'WHOIS lookup failed: {str(e)}'
            }

    def _parse_whois_text(self, whois_text: str, domain: str) -> Dict:
        """Parse whois command output"""
        lines = whois_text.split('\n')
        result = {
            'domain': domain,
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'updated_date': 'Unknown',
            'name_servers': [],
            'status': 'Unknown'
        }
        
        for line in lines:
            line_lower = line.lower()
            if 'registrar:' in line_lower and result['registrar'] == 'Unknown':
                result['registrar'] = line.split(':', 1)[1].strip()
            elif 'creation date:' in line_lower or 'created:' in line_lower:
                result['creation_date'] = line.split(':', 1)[1].strip()
            elif 'expiry date:' in line_lower or 'expiration date:' in line_lower:
                result['expiration_date'] = line.split(':', 1)[1].strip()
            elif 'updated date:' in line_lower or 'last updated:' in line_lower:
                result['updated_date'] = line.split(':', 1)[1].strip()
            elif 'name server:' in line_lower:
                ns = line.split(':', 1)[1].strip().lower()
                if ns and ns not in result['name_servers']:
                    result['name_servers'].append(ns)
            elif 'status:' in line_lower and result['status'] == 'Unknown':
                result['status'] = line.split(':', 1)[1].strip()
        
        return result

    def _generate_mock_whois(self, domain: str) -> Dict:
        """Generate realistic mock WHOIS data"""
        from datetime import datetime, timedelta
        
        # Common registrars
        registrars = ['GoDaddy', 'Namecheap', 'Google Domains', 'Cloudflare', 'NameSilo']
        
        # Generate random but realistic dates
        created = datetime.now() - timedelta(days=random.randint(100, 2000))
        expires = datetime.now() + timedelta(days=random.randint(30, 365))
        updated = datetime.now() - timedelta(days=random.randint(1, 90))
        
        # Common name servers
        name_servers = [
            f'ns1.{domain}', f'ns2.{domain}',
            'ns1.registrar.com', 'ns2.registrar.com',
            'dns1.p01.nsone.net', 'dns2.p01.nsone.net'
        ]
        
        return {
            'domain': domain,
            'registrar': random.choice(registrars),
            'creation_date': created.strftime('%Y-%m-%d'),
            'expiration_date': expires.strftime('%Y-%m-%d'),
            'updated_date': updated.strftime('%Y-%m-%d'),
            'name_servers': random.sample(name_servers, 2),
            'status': 'active',
            'emails': [f'admin@{domain}', f'hostmaster@{domain}']
        }

    # === SECURITY HEADERS CHECK ===
    def check_security_headers(self, url: str) -> Dict:
        """Check security headers of a website - always works"""
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Add timeout and better error handling
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            security_headers = {
                'Content-Security-Policy': headers.get('content-security-policy'),
                'Strict-Transport-Security': headers.get('strict-transport-security'),
                'X-Content-Type-Options': headers.get('x-content-type-options'),
                'X-Frame-Options': headers.get('x-frame-options'),
                'X-XSS-Protection': headers.get('x-xss-protection'),
                'Referrer-Policy': headers.get('referrer-policy'),
                'Permissions-Policy': headers.get('permissions-policy')
            }
            
            # Score the security headers
            score = 0
            max_score = 7
            
            if security_headers['Content-Security-Policy']:
                score += 1
            if security_headers['Strict-Transport-Security']:
                score += 1
            if security_headers['X-Content-Type-Options']:
                score += 1
            if security_headers['X-Frame-Options']:
                score += 1
            if security_headers['X-XSS-Protection']:
                score += 1
            if security_headers['Referrer-Policy']:
                score += 1
            if security_headers['Permissions-Policy']:
                score += 1
            
            return {
                'success': True,
                'data': {
                    'url': url,
                    'security_headers': security_headers,
                    'security_score': score,
                    'max_score': max_score,
                    'grade': 'A' if score >= 6 else 'B' if score >= 4 else 'C' if score >= 2 else 'F'
                }
            }
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            if url.startswith('https://'):
                return self.check_security_headers(url.replace('https://', 'http://'))
            else:
                return {
                    'success': False,
                    'error': 'SSL certificate error and HTTP fallback failed'
                }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Could not connect to the website'
            }
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Connection to website timed out'
            }
        except Exception as e:
            logger.error(f"Security headers check failed: {e}")
            return {
                'success': False,
                'error': f'Failed to check security headers: {str(e)}'
            }

    # === SSL/TLS CERTIFICATE CHECK ===
    def check_ssl_certificate(self, domain: str) -> Dict:
        """Check SSL/TLS certificate information"""
        try:
            # Clean domain
            domain = self._clean_input(domain, 'domain')
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate dates
                    not_before = self._parse_cert_date(cert['notBefore'])
                    not_after = self._parse_cert_date(cert['notAfter'])
                    days_until_expiry = (not_after - datetime.utcnow()).days
                    
                    # Get subject info
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    return {
                        'success': True,
                        'data': {
                            'domain': domain,
                            'issuer': issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                            'subject': subject.get('commonName', 'Unknown'),
                            'not_valid_before': not_before.isoformat(),
                            'not_valid_after': not_after.isoformat(),
                            'days_until_expiry': days_until_expiry,
                            'is_expired': days_until_expiry <= 0,
                            'san': cert.get('subjectAltName', [])
                        }
                    }
                    
        except socket.gaierror:
            return {
                'success': False,
                'error': f'Could not resolve domain: {domain}'
            }
        except ssl.SSLError:
            return {
                'success': False,
                'error': f'SSL error for domain: {domain}'
            }
        except socket.timeout:
            return {
                'success': False,
                'error': f'Connection timeout for domain: {domain}'
            }
        except Exception as e:
            logger.error(f"SSL certificate check failed: {e}")
            return {
                'success': False,
                'error': f'SSL certificate check failed: {str(e)}'
            }

    # === COMPREHENSIVE DOMAIN ANALYSIS ===
    def comprehensive_domain_analysis(self, domain: str) -> Dict:
        """Perform comprehensive domain analysis"""
        try:
            domain = self._clean_input(domain, 'domain')
            
            if not self._is_valid_domain(domain):
                return {
                    'success': False,
                    'error': f'Invalid domain format: {domain}'
                }
            
            results = {}
            
            # DNS Records
            dns_records = {}
            for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
                dns_result = self.dns_lookup(domain, record_type)
                if dns_result.get('success'):
                    dns_records[record_type] = dns_result['data']['results']
            
            results['dns_records'] = dns_records
            
            # WHOIS Information
            whois_result = self.whois_lookup(domain)
            if whois_result.get('success'):
                results['whois'] = whois_result['data']
            
            # Security Headers
            headers_result = self.check_security_headers(f'https://{domain}')
            if headers_result.get('success'):
                results['security_headers'] = headers_result['data']
            
            # SSL Certificate
            ssl_result = self.check_ssl_certificate(domain)
            if ssl_result.get('success'):
                results['ssl_certificate'] = ssl_result['data']
            
            return {
                'success': True,
                'data': results
            }
            
        except Exception as e:
            logger.error(f"Comprehensive domain analysis failed: {e}")
            return {
                'success': False,
                'error': f'Comprehensive domain analysis failed: {str(e)}'
            }

    # === HELPER METHODS ===
    def _format_date(self, date) -> str:
        """Format date for WHOIS results"""
        if not date:
            return 'Unknown'
        if isinstance(date, list):
            date = date[0]
        if hasattr(date, 'strftime'):
            return date.strftime('%Y-%m-%d')
        return str(date)

    def _parse_cert_date(self, date_str: str) -> datetime:
        """Parse SSL certificate date string"""
        from datetime import datetime
        # Handle different date formats in certificates
        for fmt in ['%b %d %H:%M:%S %Y %Z', '%Y%m%d%H%M%SZ']:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return datetime.utcnow()

# Global instance
security_tools = FixedSecurityTools()