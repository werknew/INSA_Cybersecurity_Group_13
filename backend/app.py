# backend/app.py
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import subprocess
import threading
import json
import re
import os
import time
from datetime import datetime
import logging
import signal
import psutil
import pdfkit
import csv
import zipfile
from io import StringIO, BytesIO
import base64
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from textwrap import wrap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"])
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# In-memory storage
scans_db = {}
vulnerabilities_db = {}
scan_processes = {}
scan_id_counter = 1
reports_db = {}

class AdvancedReporter:
    def __init__(self):
        self.reports_dir = 'reports'
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def generate_pdf_report(self, scan_data, vulnerabilities, report_id):
        """Generate professional PDF report"""
        try:
            filename = f"{self.reports_dir}/scan_report_{report_id}.pdf"
            doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=1*inch)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                textColor=colors.HexColor('#2E86AB'),
                alignment=1
            )
            title = Paragraph("SECURITY ASSESSMENT REPORT", title_style)
            story.append(title)
            
            # Scan Overview
            story.append(Paragraph("Scan Overview", styles['Heading2']))
            overview_data = [
                ['Target', scan_data['target']],
                ['Scan Type', scan_data['type'].upper()],
                ['Scan Date', scan_data['start_time']],
                ['Status', scan_data['status']],
                ['Vulnerabilities Found', len(vulnerabilities)]
            ]
            overview_table = Table(overview_data, colWidths=[2*inch, 4*inch])
            overview_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8F9FA')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(overview_table)
            story.append(Spacer(1, 20))
            
            # Vulnerability Summary
            if vulnerabilities:
                story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
                
                # Severity breakdown
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                for vuln in vulnerabilities:
                    severity_counts[vuln['severity']] += 1
                
                severity_data = [
                    ['Severity Level', 'Count', 'Percentage'],
                    ['Critical', severity_counts['critical'], f"{(severity_counts['critical']/len(vulnerabilities))*100:.1f}%"],
                    ['High', severity_counts['high'], f"{(severity_counts['high']/len(vulnerabilities))*100:.1f}%"],
                    ['Medium', severity_counts['medium'], f"{(severity_counts['medium']/len(vulnerabilities))*100:.1f}%"],
                    ['Low', severity_counts['low'], f"{(severity_counts['low']/len(vulnerabilities))*100:.1f}%"],
                    ['TOTAL', len(vulnerabilities), '100%']
                ]
                
                severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 1.5*inch])
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E74C3C')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#C0392B')),
                    ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#E74C3C')),
                    ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#F39C12')),
                    ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#3498DB')),
                    ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#2C3E50')),
                    ('TEXTCOLOR', (0, 5), (-1, 5), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(severity_table)
                story.append(Spacer(1, 20))
                
                # Detailed Findings
                story.append(Paragraph("Detailed Findings", styles['Heading2']))
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    # Vulnerability header
                    severity_color = {
                        'critical': '#C0392B',
                        'high': '#E74C3C', 
                        'medium': '#F39C12',
                        'low': '#3498DB'
                    }
                    
                    vuln_header = f"Finding #{i}: {vuln['title']} - {vuln['severity'].upper()}"
                    story.append(Paragraph(vuln_header, styles['Heading3']))
                    
                    # Vulnerability details
                    vuln_data = [
                        ['Description:', vuln['description']],
                        ['Port/Service:', f"{vuln.get('port', 'N/A')}/{vuln.get('service', 'N/A')}"],
                        ['CVE:', vuln.get('cve', 'Not specified')],
                        ['Evidence:', vuln['evidence'][:100] + '...' if len(vuln['evidence']) > 100 else vuln['evidence']],
                        ['Solution:', vuln['solution']]
                    ]
                    
                    vuln_table = Table(vuln_data, colWidths=[1.5*inch, 5*inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor(severity_color[vuln['severity']])),
                        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    story.append(vuln_table)
                    story.append(Spacer(1, 15))
            
            else:
                story.append(Paragraph("No vulnerabilities found during this scan.", styles['Normal']))
            
            # Recommendations
            story.append(Paragraph("Security Recommendations", styles['Heading2']))
            recommendations = [
                "Regularly update and patch all identified services",
                "Implement proper network segmentation",
                "Use firewall rules to restrict unnecessary port access",
                "Enable security headers for web applications",
                "Conduct regular security assessments",
                "Implement monitoring and alerting for critical services"
            ]
            
            for rec in recommendations:
                story.append(Paragraph(f"• {rec}", styles['Normal']))
            
            # Footer
            story.append(Spacer(1, 30))
            footer = Paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by Security Scanner", styles['Italic'])
            story.append(footer)
            
            doc.build(story)
            return filename
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None
    
    def generate_json_report(self, scan_data, vulnerabilities, report_id):
        """Generate comprehensive JSON report"""
        try:
            report = {
                "metadata": {
                    "report_id": report_id,
                    "generated_at": datetime.now().isoformat(),
                    "scanner_version": "2.0.0",
                    "report_format": "json_v2"
                },
                "scan_summary": {
                    "target": scan_data['target'],
                    "scan_type": scan_data['type'],
                    "start_time": scan_data['start_time'],
                    "end_time": scan_data.get('end_time'),
                    "status": scan_data['status'],
                    "total_vulnerabilities": len(vulnerabilities)
                },
                "vulnerability_statistics": {
                    "by_severity": {
                        "critical": len([v for v in vulnerabilities if v['severity'] == 'critical']),
                        "high": len([v for v in vulnerabilities if v['severity'] == 'high']),
                        "medium": len([v for v in vulnerabilities if v['severity'] == 'medium']),
                        "low": len([v for v in vulnerabilities if v['severity'] == 'low'])
                    },
                    "by_type": {},
                    "risk_score": self.calculate_risk_score(vulnerabilities)
                },
                "detailed_findings": vulnerabilities,
                "recommendations": self.generate_recommendations(vulnerabilities),
                "technical_details": {
                    "scan_parameters": {
                        "target": scan_data['target'],
                        "type": scan_data['type']
                    },
                    "tools_used": ["nmap", "curl", "custom_scanner"]
                }
            }
            
            # Save JSON file
            filename = f"{self.reports_dir}/scan_report_{report_id}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            return filename
            
        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")
            return None
    
    def generate_csv_report(self, scan_data, vulnerabilities, report_id):
        """Generate CSV report for data analysis"""
        try:
            filename = f"{self.reports_dir}/scan_report_{report_id}.csv"
            
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Header
                writer.writerow(['Scan Report - Security Assessment'])
                writer.writerow(['Target:', scan_data['target']])
                writer.writerow(['Scan Type:', scan_data['type']])
                writer.writerow(['Date:', scan_data['start_time']])
                writer.writerow(['Total Vulnerabilities:', len(vulnerabilities)])
                writer.writerow([])
                
                # Vulnerabilities
                writer.writerow(['ID', 'Title', 'Severity', 'Port', 'Service', 'CVE', 'Description', 'Solution'])
                for vuln in vulnerabilities:
                    writer.writerow([
                        vuln['id'],
                        vuln['title'],
                        vuln['severity'],
                        vuln.get('port', 'N/A'),
                        vuln.get('service', 'N/A'),
                        vuln.get('cve', 'N/A'),
                        vuln['description'],
                        vuln['solution']
                    ])
            
            return filename
            
        except Exception as e:
            logger.error(f"CSV report generation failed: {e}")
            return None
    
    def generate_executive_summary(self, scan_data, vulnerabilities, report_id):
        """Generate executive summary report"""
        try:
            filename = f"{self.reports_dir}/executive_summary_{report_id}.txt"
            
            with open(filename, 'w') as f:
                f.write("SECURITY SCAN EXECUTIVE SUMMARY\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Target: {scan_data['target']}\n")
                f.write(f"Scan Date: {scan_data['start_time']}\n")
                f.write(f"Scan Type: {scan_data['type'].upper()}\n\n")
                
                f.write("RISK OVERVIEW:\n")
                f.write("-" * 20 + "\n")
                
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                for vuln in vulnerabilities:
                    severity_counts[vuln['severity']] += 1
                
                f.write(f"Critical Findings: {severity_counts['critical']}\n")
                f.write(f"High Risk Findings: {severity_counts['high']}\n")
                f.write(f"Medium Risk Findings: {severity_counts['medium']}\n")
                f.write(f"Low Risk Findings: {severity_counts['low']}\n")
                f.write(f"TOTAL: {len(vulnerabilities)}\n\n")
                
                f.write("KEY FINDINGS:\n")
                f.write("-" * 15 + "\n")
                
                critical_vulns = [v for v in vulnerabilities if v['severity'] in ['critical', 'high']]
                for i, vuln in enumerate(critical_vulns[:5], 1):
                    f.write(f"{i}. {vuln['title']} ({vuln['severity'].upper()})\n")
                    f.write(f"   - {vuln['description'][:100]}...\n\n")
                
                f.write("RECOMMENDATIONS:\n")
                f.write("-" * 20 + "\n")
                f.write("1. Address critical and high-risk findings immediately\n")
                f.write("2. Implement regular security scanning\n")
                f.write("3. Review and harden network configurations\n")
                f.write("4. Update and patch identified services\n")
                f.write("5. Conduct penetration testing for critical systems\n")
            
            return filename
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return None
    
    def generate_zip_report(self, scan_data, vulnerabilities, report_id):
        """Generate complete report package (ZIP)"""
        try:
            zip_filename = f"{self.reports_dir}/complete_report_{report_id}.zip"
            
            with zipfile.ZipFile(zip_filename, 'w') as zipf:
                # Generate all report types
                pdf_file = self.generate_pdf_report(scan_data, vulnerabilities, report_id)
                json_file = self.generate_json_report(scan_data, vulnerabilities, report_id)
                csv_file = self.generate_csv_report(scan_data, vulnerabilities, report_id)
                exec_file = self.generate_executive_summary(scan_data, vulnerabilities, report_id)
                
                # Add files to zip
                if pdf_file and os.path.exists(pdf_file):
                    zipf.write(pdf_file, 'detailed_report.pdf')
                if json_file and os.path.exists(json_file):
                    zipf.write(json_file, 'technical_report.json')
                if csv_file and os.path.exists(csv_file):
                    zipf.write(csv_file, 'data_export.csv')
                if exec_file and os.path.exists(exec_file):
                    zipf.write(exec_file, 'executive_summary.txt')
                
                # Add scan log
                log_file = 'security_scanner.log'
                if os.path.exists(log_file):
                    zipf.write(log_file, 'scan_logs.log')
            
            return zip_filename
            
        except Exception as e:
            logger.error(f"ZIP report generation failed: {e}")
            return None
    
    def calculate_risk_score(self, vulnerabilities):
        """Calculate overall risk score (0-100)"""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total_weight = sum(weights[v['severity']] for v in vulnerabilities)
        max_possible = 10 * len(vulnerabilities)  # All critical
        return min(100, (total_weight / max_possible * 100)) if max_possible > 0 else 0
    
    def generate_recommendations(self, vulnerabilities):
        """Generate tailored recommendations based on findings"""
        recommendations = []
        
        critical_count = len([v for v in vulnerabilities if v['severity'] == 'critical'])
        if critical_count > 0:
            recommendations.append({
                "priority": "critical",
                "description": f"Immediately address {critical_count} critical vulnerabilities",
                "action": "Patch and remediate within 24 hours"
            })
        
        # Service-specific recommendations
        services = set(v.get('service') for v in vulnerabilities if v.get('service'))
        for service in services:
            if service and service != 'N/A':
                recommendations.append({
                    "priority": "high",
                    "description": f"Review and secure {service} service configuration",
                    "action": f"Harden {service} service settings and apply updates"
                })
        
        # General recommendations
        recommendations.extend([
            {
                "priority": "medium",
                "description": "Implement regular vulnerability scanning",
                "action": "Schedule weekly security assessments"
            },
            {
                "priority": "medium", 
                "description": "Review firewall and network access rules",
                "action": "Restrict unnecessary port access"
            }
        ])
        
        return recommendations

class RealTimeSecurityScanner:
    def __init__(self):
        self.tools = self.check_available_tools()
        self.reporter = AdvancedReporter()
        logger.info(f"Available tools: {self.tools}")
    
    def check_available_tools(self):
        tools = {}
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
            tools['nmap'] = True
        except:
            tools['nmap'] = False
        
        try:
            result = subprocess.run(['nikto', '-version'], capture_output=True, text=True, timeout=5)
            tools['nikto'] = True
        except:
            tools['nikto'] = False
            
        return tools
    
    def run_quick_scan(self, target, scan_id):
        cmd = ['nmap', '-T4', '-F', '--open', '--host-timeout', '90s', target]
        return self.execute_scan(cmd, target, scan_id, 'quick')
    
    def run_full_scan(self, target, scan_id):
        cmd = ['nmap', '-T4', '--top-ports', '500', '-sV', '--open', '--host-timeout', '120s', target]
        return self.execute_scan(cmd, target, scan_id, 'full')
    
    def run_stealth_scan(self, target, scan_id):
        cmd = ['nmap', '-T3', '-sS', '--top-ports', '300', '--open', '--host-timeout', '150s', target]
        return self.execute_scan(cmd, target, scan_id, 'stealth')
    
    def run_vulnerability_scan(self, target, scan_id):
        cmd = ['nmap', '-T4', '--top-ports', '100', '-sV', '--script', 'vulners', '--open', '--host-timeout', '180s', target]
        return self.execute_scan(cmd, target, scan_id, 'vulnerability')
    
    def run_web_scan(self, target, scan_id):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        return self.fast_web_scan(target, scan_id)
    
    def fast_web_scan(self, target, scan_id):
        vulnerabilities = []
        try:
            curl_cmd = ['curl', '-I', '--connect-timeout', '10', target]
            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                headers = result.stdout.lower()
                
                if 'x-frame-options' not in headers:
                    vulnerabilities.append({
                        'id': f"{scan_id}-web-1",
                        'title': 'Missing X-Frame-Options Header',
                        'description': 'Clickjacking protection is not enabled',
                        'severity': 'medium',
                        'evidence': 'X-Frame-Options header missing',
                        'solution': 'Add X-Frame-Options header to prevent clickjacking',
                        'type': 'web_security'
                    })
                
                if 'x-content-type-options' not in headers:
                    vulnerabilities.append({
                        'id': f"{scan_id}-web-2", 
                        'title': 'Missing X-Content-Type-Options Header',
                        'description': 'MIME type sniffing protection not enabled',
                        'severity': 'low',
                        'evidence': 'X-Content-Type-Options header missing',
                        'solution': 'Add X-Content-Type-Options: nosniff header',
                        'type': 'web_security'
                    })
            
        except Exception as e:
            logger.error(f"Web scan error: {e}")
        
        return vulnerabilities
    
    def execute_scan(self, cmd, target, scan_id, scan_type):
        try:
            logger.info(f"Running {scan_type} scan: {' '.join(cmd)}")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            scan_processes[scan_id] = process
            
            timeouts = {'quick': 90, 'full': 120, 'stealth': 150, 'vulnerability': 180, 'web': 60}
            timeout = timeouts.get(scan_type, 120)
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                
                if process.returncode == 0:
                    return self.parse_scan_output(stdout, target, scan_id, scan_type)
                else:
                    return {'error': f'Scan failed: {stderr}'}
                    
            except subprocess.TimeoutExpired:
                process.kill()
                return {'error': f'Scan timed out after {timeout} seconds'}
                
        except Exception as e:
            return {'error': f'Scan failed: {str(e)}'}
        finally:
            scan_processes.pop(scan_id, None)
    
    def parse_scan_output(self, output, target, scan_id, scan_type):
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\w+.*)', line)
            if port_match and 'open' in line:
                port, protocol, state, service_info = port_match.groups()
                service = service_info.split()[0] if service_info else 'unknown'
                
                severity = self.get_port_severity(port, service)
                
                vuln = {
                    'id': f"{scan_id}-{port}-{int(time.time())}",
                    'title': f'Open {service.upper()} Service',
                    'description': f'Port {port}/{protocol} is open running {service_info}',
                    'severity': severity,
                    'port': port,
                    'protocol': protocol,
                    'service': service,
                    'evidence': line,
                    'solution': self.get_port_solution(port, service),
                    'cve': None,
                    'type': 'open_port'
                }
                vulnerabilities.append(vuln)
                
                service_vulns = self.check_service_vulnerabilities(port, service, scan_id)
                vulnerabilities.extend(service_vulns)
            
            if any(keyword in line.lower() for keyword in ['vulnerable', 'vuln', 'cve-', 'risk']):
                severity = 'medium'
                if 'high' in line.lower():
                    severity = 'high'
                elif 'low' in line.lower():
                    severity = 'low'
                
                vuln = {
                    'id': f"{scan_id}-vuln-{len(vulnerabilities)}",
                    'title': 'Security Finding',
                    'description': line,
                    'severity': severity,
                    'evidence': line,
                    'solution': 'Investigate this security finding',
                    'cve': self.extract_cve(line),
                    'type': 'security_finding'
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_port_severity(self, port, service):
        high_risk_ports = ['21', '22', '23', '25', '53', '110', '135', '139', '143', '443', '993', '995', '1433', '1521', '3306', '3389', '5432', '5900', '6379']
        medium_risk_ports = ['80', '443', '8080', '8443', '8000', '3000', '5000']
        
        if port in high_risk_ports:
            return 'high'
        elif port in medium_risk_ports:
            return 'medium'
        else:
            return 'low'
    
    def get_port_solution(self, port, service):
        solutions = {
            '21': 'Secure FTP configuration or disable if not needed',
            '22': 'Use SSH key authentication and disable root login',
            '23': 'Disable Telnet - use SSH instead', 
            '25': 'Secure SMTP configuration',
            '53': 'Secure DNS server configuration',
            '80': 'Ensure web server is properly secured',
            '443': 'Use HTTPS with proper TLS configuration',
            '3389': 'Secure RDP or use VPN instead',
            '3306': 'Do not expose MySQL to external networks',
            '5432': 'Do not expose PostgreSQL to external networks'
        }
        return solutions.get(port, 'Review if this service needs to be publicly accessible')
    
    def check_service_vulnerabilities(self, port, service, scan_id):
        vulnerabilities = []
        
        if service == 'ssh' and port == '22':
            vulnerabilities.append({
                'id': f"{scan_id}-ssh-{int(time.time())}",
                'title': 'SSH Service Exposed',
                'description': 'SSH service is accessible from network',
                'severity': 'high',
                'port': port,
                'service': service,
                'evidence': f'SSH running on port {port}',
                'solution': 'Restrict SSH access to trusted IPs and use key authentication',
                'type': 'service_exposure'
            })
        
        if service == 'http' and port in ['80', '8080', '8000']:
            vulnerabilities.append({
                'id': f"{scan_id}-http-{int(time.time())}",
                'title': 'HTTP Service (Unencrypted)',
                'description': 'Web service running without encryption',
                'severity': 'medium', 
                'port': port,
                'service': service,
                'evidence': f'HTTP on port {port} - no encryption',
                'solution': 'Use HTTPS with TLS encryption',
                'type': 'encryption'
            })
        
        if service in ['mysql', 'postgresql', 'redis', 'mongodb']:
            vulnerabilities.append({
                'id': f"{scan_id}-db-{int(time.time())}",
                'title': f'Database Service Exposed - {service.upper()}',
                'description': f'Database service {service} is network accessible',
                'severity': 'critical',
                'port': port,
                'service': service,
                'evidence': f'{service} on port {port}',
                'solution': f'Do not expose {service} to external networks. Use VPN or SSH tunneling',
                'type': 'database_exposure'
            })
        
        return vulnerabilities
    
    def extract_cve(self, text):
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = re.findall(cve_pattern, text, re.IGNORECASE)
        return matches[0] if matches else None
    
    def run_scan(self, scan_id, target, scan_type):
        try:
            scan_data = scans_db[scan_id]
            
            stages = {
                'quick': [('Initializing', 10), ('Scanning ports', 40), ('Analyzing services', 70), ('Finalizing', 100)],
                'full': [('Initializing', 10), ('Port discovery', 30), ('Service detection', 60), ('Security analysis', 90), ('Finalizing', 100)],
                'stealth': [('Initializing', 10), ('Stealth scan', 40), ('Service analysis', 70), ('Finalizing', 100)],
                'vulnerability': [('Initializing', 10), ('Port scan', 30), ('Vulnerability check', 70), ('Analysis', 100)],
                'web': [('Initializing', 10), ('HTTP checks', 40), ('Security headers', 70), ('Finalizing', 100)]
            }
            
            current_stages = stages.get(scan_type, stages['quick'])
            
            for stage_name, progress in current_stages:
                if scan_data.get('terminated'):
                    scan_data['status'] = 'terminated'
                    scan_data['error'] = 'Scan terminated by user'
                    return
                
                scan_data['progress'] = progress
                socketio.emit('scan_progress', {
                    'scan_id': scan_id,
                    'progress': progress,
                    'status': stage_name,
                    'stage': stage_name
                })
                
                if progress < 100:
                    time.sleep(1)
            
            vulnerabilities = []
            if scan_type == 'quick':
                result = self.run_quick_scan(target, scan_id)
            elif scan_type == 'full':
                result = self.run_full_scan(target, scan_id)
            elif scan_type == 'stealth':
                result = self.run_stealth_scan(target, scan_id)
            elif scan_type == 'vulnerability':
                result = self.run_vulnerability_scan(target, scan_id)
            elif scan_type == 'web':
                result = self.run_web_scan(target, scan_id)
            else:
                result = self.run_quick_scan(target, scan_id)
            
            if scan_data.get('terminated'):
                return
            
            if 'error' in result:
                scan_data['status'] = 'failed'
                scan_data['error'] = result['error']
                return
            
            vulnerabilities = result
            
            scan_data['progress'] = 100
            scan_data['status'] = 'completed'
            scan_data['vulnerabilities_found'] = len(vulnerabilities)
            scan_data['results'] = vulnerabilities
            scan_data['end_time'] = datetime.now().isoformat()
            
            vulnerabilities_db[scan_id] = vulnerabilities
            
            socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'vulnerabilities_found': len(vulnerabilities)
            })
            
            logger.info(f"Scan {scan_id} completed with {len(vulnerabilities)} findings")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {str(e)}")
            scan_data['status'] = 'failed'
            scan_data['error'] = str(e)
            scan_data['end_time'] = datetime.now().isoformat()

# Initialize scanner
scanner = RealTimeSecurityScanner()
reporter = AdvancedReporter()

@app.route('/api/scan', methods=['POST'])
def start_scan():
    global scan_id_counter
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scanType', 'quick')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        scan_id = scan_id_counter
        scan_id_counter += 1
        
        scans_db[scan_id] = {
            'id': scan_id,
            'target': target,
            'type': scan_type,
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'progress': 0,
            'vulnerabilities_found': 0,
            'results': [],
            'error': None,
            'terminated': False
        }
        
        thread = threading.Thread(
            target=scanner.run_scan,
            args=(scan_id, target, scan_type)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': f'Fast {scan_type} scan started for {target}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>/terminate', methods=['POST'])
def terminate_scan(scan_id):
    try:
        scan_data = scans_db.get(scan_id)
        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan_data['status'] != 'running':
            return jsonify({'error': 'Scan is not running'}), 400
        
        scan_data['terminated'] = True
        scan_data['status'] = 'terminated'
        scan_data['end_time'] = datetime.now().isoformat()
        
        process = scan_processes.get(scan_id)
        if process:
            try:
                process.terminate()
                parent = psutil.Process(process.pid)
                for child in parent.children(recursive=True):
                    child.terminate()
                parent.terminate()
            except:
                pass
        
        socketio.emit('scan_terminated', {'scan_id': scan_id})
        
        return jsonify({'message': 'Scan terminated successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>/report', methods=['POST'])
def generate_report(scan_id):
    try:
        data = request.get_json()
        report_type = data.get('type', 'pdf')  # pdf, json, csv, executive, zip
        
        scan_data = scans_db.get(scan_id)
        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan_data['status'] != 'completed':
            return jsonify({'error': 'Scan must be completed to generate report'}), 400
        
        vulnerabilities = vulnerabilities_db.get(scan_id, [])
        report_id = f"{scan_id}_{int(time.time())}"
        
        # Generate report based on type
        if report_type == 'pdf':
            filename = reporter.generate_pdf_report(scan_data, vulnerabilities, report_id)
        elif report_type == 'json':
            filename = reporter.generate_json_report(scan_data, vulnerabilities, report_id)
        elif report_type == 'csv':
            filename = reporter.generate_csv_report(scan_data, vulnerabilities, report_id)
        elif report_type == 'executive':
            filename = reporter.generate_executive_summary(scan_data, vulnerabilities, report_id)
        elif report_type == 'zip':
            filename = reporter.generate_zip_report(scan_data, vulnerabilities, report_id)
        else:
            return jsonify({'error': 'Invalid report type'}), 400
        
        if not filename or not os.path.exists(filename):
            return jsonify({'error': 'Report generation failed'}), 500
        
        # Store report info
        reports_db[report_id] = {
            'id': report_id,
            'scan_id': scan_id,
            'type': report_type,
            'filename': filename,
            'generated_at': datetime.now().isoformat(),
            'size': os.path.getsize(filename)
        }
        
        return jsonify({
            'report_id': report_id,
            'download_url': f'/api/report/{report_id}/download',
            'filename': os.path.basename(filename),
            'size': os.path.getsize(filename),
            'type': report_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<report_id>/download', methods=['GET'])
def download_report(report_id):
    try:
        report_info = reports_db.get(report_id)
        if not report_info:
            return jsonify({'error': 'Report not found'}), 404
        
        filename = report_info['filename']
        if not os.path.exists(filename):
            return jsonify({'error': 'Report file not found'}), 404
        
        return send_file(filename, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports', methods=['GET'])
def list_reports():
    reports = list(reports_db.values())
    reports.sort(key=lambda x: x['generated_at'], reverse=True)
    return jsonify(reports)

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    scan_data = scans_db.get(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(scan_data)

@app.route('/api/scan/<int:scan_id>/vulnerabilities', methods=['GET'])
def get_scan_vulnerabilities(scan_id):
    vulnerabilities = vulnerabilities_db.get(scan_id, [])
    return jsonify(vulnerabilities)

@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    scans = list(scans_db.values())
    scans.sort(key=lambda x: x['start_time'], reverse=True)
    return jsonify(scans)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    total_scans = len(scans_db)
    completed_scans = len([s for s in scans_db.values() if s['status'] == 'completed'])
    running_scans = len([s for s in scans_db.values() if s['status'] == 'running'])
    failed_scans = len([s for s in scans_db.values() if s['status'] in ['failed', 'terminated']])
    
    vuln_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for scan_id, vulns in vulnerabilities_db.items():
        for vuln in vulns:
            severity = vuln.get('severity', 'medium')
            if severity in vuln_stats:
                vuln_stats[severity] += 1
    
    return jsonify({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'running_scans': running_scans,
        'failed_scans': failed_scans,
        'vulnerabilities': vuln_stats,
        'total_reports': len(reports_db),
        'tools_available': scanner.tools
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'tools': scanner.tools
    })

@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to security scanner'})

if __name__ == '__main__':
    logger.info("🚀 Advanced Security Scanner with Reporting Starting...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)