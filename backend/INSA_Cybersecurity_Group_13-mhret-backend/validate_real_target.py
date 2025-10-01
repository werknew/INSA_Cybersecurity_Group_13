import socket
import requests
from urllib.parse import urlparse

def validate_real_target(target: str, scan_type: str) -> tuple:
    """Validate that target exists and is reachable"""
    try:
        # Clean target
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname or target.split('://')[1].split('/')[0]
        else:
            hostname = target.split('/')[0]
        
        # Remove port if present
        hostname = hostname.split(':')[0]
        
        # Try DNS resolution first
        try:
            ip = socket.gethostbyname(hostname)
            logger.info(f"Resolved {hostname} to {ip}")
        except socket.gaierror:
            return False, "Cannot resolve hostname"
        
        # For web scans, try HTTP connection
        if scan_type == 'web':
            schemes = ['https', 'http'] if not target.startswith(('http', 'https')) else [target.split('://')[0]]
            for scheme in schemes:
                try:
                    url = f"{scheme}://{hostname}"
                    response = requests.head(url, timeout=10, verify=False)
                    if response.status_code < 500:
                        return True, f"Target is reachable via {scheme}"
                except requests.RequestException:
                    continue
            return False, "Web target is not reachable via HTTP or HTTPS"
        
        # For network scans, try basic connectivity
        else:
            try:
                socket.create_connection((hostname, 80), timeout=10)
                return True, "Target is reachable"
            except socket.timeout:
                return False, "Connection timeout"
            except ConnectionRefusedError:
                return True, "Target exists but refused connection (may be firewalled)"
            except Exception as e:
                return False, f"Connection failed: {str(e)}"
                
    except Exception as e:
        return False, f"Validation error: {str(e)}"