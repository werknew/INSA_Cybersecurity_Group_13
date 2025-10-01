from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from scanner import run_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scanType', 'quick')
        
        if not target:
            return jsonify({'error': 'No target provided'}), 400
        
        logger.info(f"Received scan request for {target} with type {scan_type}")
        
        # Validate target format
        if not is_valid_target(target, scan_type):
            return jsonify({'error': 'Invalid target format'}), 400
        
        results = run_scan(target, scan_type)
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Unexpected error in scan endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'service': 'vulnerability-scanner'})

def is_valid_target(target: str, scan_type: str) -> bool:
    """Validate target format based on scan type"""
    import re
    
    # IP validation regex
    ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Domain validation regex
    domain_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    # URL validation regex
    url_regex = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
    
    # For web scans, allow URLs and domains
    if scan_type == 'web':
        return (re.match(ip_regex, target) or 
                re.match(domain_regex, target) or 
                re.match(url_regex, target) or
                target.startswith(('http://', 'https://')))
    
    # For network scans, allow IPs and domains
    return re.match(ip_regex, target) or re.match(domain_regex, target)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)