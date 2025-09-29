import nmap

def run_nmap_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV --script vuln')

    results = {}
    for host in scanner.all_hosts():
        results[host] = []
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port]
                results[host].append({
                    'port': port,
                    'state': service['state'],
                    'name': service['name'],
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'script': service.get('script', {})
                })
    return results
