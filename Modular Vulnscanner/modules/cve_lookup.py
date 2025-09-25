def match_with_cve(results):
    # In real implementation, parse products/versions and query NVD API
    # For now, a placeholder
    return [
        {
            'id': 'CVE-2023-12345',
            'description': 'Sample vulnerability for demonstration',
            'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345'],
            'affected': 'Apache 2.4.49'
        }
    ]
