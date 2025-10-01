import os
import json
from datetime import datetime
from typing import Dict, List, Any
import logging
import base64

logger = logging.getLogger(__name__)

# Try to import PDF libraries with fallbacks
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ReportLab not available: {e}")
    REPORTLAB_AVAILABLE = False

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError as e:
    logger.warning(f"FPDF not available: {e}")
    FPDF_AVAILABLE = False

class ReportGenerator:
    def __init__(self):
        self.styles = None
        self._setup_styles()
    
    def _setup_styles(self):
        """Setup custom styles for PDF reports - only once"""
        if not REPORTLAB_AVAILABLE:
            return
            
        self.styles = getSampleStyleSheet()
        
        # Only add styles if they don't exist
        if 'Title-Custom' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Title-Custom',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2E86AB'),
                spaceAfter=30,
                alignment=TA_CENTER
            ))
        
        if 'Heading2-Custom' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Heading2-Custom',
                parent=self.styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#2E86AB'),
                spaceAfter=12,
                spaceBefore=20
            ))
        
        if 'BodyText-Custom' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='BodyText-Custom',
                parent=self.styles['BodyText'],
                fontSize=10,
                textColor=colors.HexColor('#333333'),
                spaceAfter=6
            ))

    def generate_pdf_report(self, scan_results: Dict, output_path: str = None) -> str:
        """Generate comprehensive PDF report"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is not installed. Please install it with: pip install reportlab")
        
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_target = "".join(c for c in scan_results.get('target', 'unknown') if c.isalnum() or c in ('-', '_'))
                output_path = f"scan_report_{safe_target}_{timestamp}.pdf"
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            story = []
            
            # Add cover page
            self._add_cover_page(story, scan_results)
            
            # Add executive summary
            self._add_executive_summary(story, scan_results)
            
            # Add detailed findings
            self._add_detailed_findings(story, scan_results)
            
            # Add recommendations
            self._add_recommendations(story, scan_results)
            
            # Add technical details
            self._add_technical_details(story, scan_results)
            
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise

    def _add_cover_page(self, story, scan_results):
        """Add cover page to the report"""
        title = Paragraph("VULNERABILITY ASSESSMENT REPORT", self.styles['Title-Custom'])
        story.append(title)
        story.append(Spacer(1, 60))
        
        # Target information
        target_info = [
            ["Target:", scan_results.get('target', 'N/A')],
            ["Scan Type:", scan_results.get('scanType', 'N/A').upper()],
            ["Date:", scan_results.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))],
            ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        
        target_table = Table(target_info, colWidths=[2*inch, 4*inch])
        target_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica-Bold', 12),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#DDDDDD'))
        ]))
        
        story.append(target_table)
        story.append(Spacer(1, 40))
        
        # Risk summary
        vuln_summary = scan_results.get('summary', {}).get('vulnerabilities', {})
        risk_score = self._calculate_risk_score(vuln_summary)
        
        risk_info = [
            ["Overall Risk Score:", f"{risk_score}/10"],
            ["Critical Vulnerabilities:", str(vuln_summary.get('critical', 0))],
            ["High Vulnerabilities:", str(vuln_summary.get('high', 0))],
            ["Medium Vulnerabilities:", str(vuln_summary.get('medium', 0))],
            ["Open Ports:", str(scan_results.get('summary', {}).get('openPorts', 0))]
        ]
        
        risk_table = Table(risk_info, colWidths=[2.5*inch, 1.5*inch])
        risk_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica-Bold', 11),
            ('BACKGROUND', (0, 0), (-1, -1), self._get_risk_color(risk_score)),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(risk_table)

    def _add_executive_summary(self, story, scan_results):
        """Add executive summary section"""
        story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['Heading2-Custom']))
        
        summary = scan_results.get('summary', {})
        vuln_summary = summary.get('vulnerabilities', {})
        
        exec_data = [
            ["Metric", "Count", "Risk Level"],
            ["Critical Vulnerabilities", str(vuln_summary.get('critical', 0)), "Critical"],
            ["High Vulnerabilities", str(vuln_summary.get('high', 0)), "High"],
            ["Medium Vulnerabilities", str(vuln_summary.get('medium', 0)), "Medium"],
            ["Low Vulnerabilities", str(vuln_summary.get('low', 0)), "Low"],
            ["Open Ports", str(summary.get('openPorts', 0)), "Informational"],
            ["Scan Duration", summary.get('scanDuration', 'N/A'), "Timing"]
        ]
        
        exec_table = Table(exec_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
        exec_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 12),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#DDDDDD')),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#FF6B6B')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#FF9E58')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#FFD166')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#06D6A0')),
        ]))
        
        story.append(exec_table)
        story.append(Spacer(1, 20))

    def _add_detailed_findings(self, story, scan_results):
        """Add detailed vulnerability findings"""
        story.append(Paragraph("DETAILED FINDINGS", self.styles['Heading2-Custom']))
        
        # Port findings
        ports = scan_results.get('ports', [])
        if ports:
            story.append(Paragraph("Open Ports", self.styles['Heading2-Custom']))
            port_data = [["Port", "Service", "State", "Version"]]
            for port in ports:
                port_data.append([
                    port.get('number', 'N/A'),
                    port.get('service', 'N/A'),
                    port.get('state', 'N/A'),
                    port.get('version', 'N/A')[:50]  # Truncate long version strings
                ])
            
            port_table = Table(port_data, colWidths=[1*inch, 1.5*inch, 1*inch, 2.5*inch])
            port_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#DDDDDD')),
            ]))
            story.append(port_table)
            story.append(Spacer(1, 20))
        
        # Vulnerability findings
        vulnerabilities = scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            story.append(Paragraph("Vulnerabilities", self.styles['Heading2-Custom']))
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get('severity', 'medium').upper()
                severity_color = self._get_severity_color(severity)
                
                vuln_data = [
                    [f"Vulnerability #{i} - {severity}", ""],
                    ["Description:", vuln.get('description', 'N/A')],
                    ["CVE:", vuln.get('cve', 'N/A')],
                    ["Solution:", vuln.get('solution', 'N/A')],
                    ["Reference:", vuln.get('reference', 'N/A')]
                ]
                
                vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4.5*inch])
                vuln_table.setStyle(TableStyle([
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 11),
                    ('BACKGROUND', (0, 0), (-1, 0), severity_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONT', (0, 1), (0, -1), 'Helvetica-Bold', 9),
                    ('FONT', (1, 1), (1, -1), 'Helvetica', 9),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#DDDDDD')),
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 15))

    def _add_recommendations(self, story, scan_results):
        """Add security recommendations"""
        story.append(Paragraph("SECURITY RECOMMENDATIONS", self.styles['Heading2-Custom']))
        
        recommendations = [
            "1. Immediately address critical and high severity vulnerabilities",
            "2. Close unnecessary open ports and services",
            "3. Implement regular security patch management",
            "4. Conduct periodic vulnerability assessments",
            "5. Implement network segmentation where appropriate",
            "6. Ensure proper logging and monitoring is in place"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['BodyText-Custom']))
            story.append(Spacer(1, 5))

    def _add_technical_details(self, story, scan_results):
        """Add technical details section"""
        story.append(Paragraph("TECHNICAL DETAILS", self.styles['Heading2-Custom']))
        
        tech_data = [
            ["Scan Type:", scan_results.get('scanType', 'N/A')],
            ["Target:", scan_results.get('target', 'N/A')],
            ["Scan Duration:", scan_results.get('summary', {}).get('scanDuration', 'N/A')],
            ["Timestamp:", scan_results.get('timestamp', 'N/A')],
            ["Scanner Version:", "1.0.0"],
            ["Total Vulnerabilities:", str(len(scan_results.get('vulnerabilities', [])))]
        ]
        
        tech_table = Table(tech_data, colWidths=[2*inch, 4*inch])
        tech_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F8F9FA')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#DDDDDD'))
        ]))
        
        story.append(tech_table)

    def _get_severity_color(self, severity: str):
        """Get color based on severity level"""
        colors_map = {
            'CRITICAL': colors.HexColor('#FF6B6B'),
            'HIGH': colors.HexColor('#FF9E58'),
            'MEDIUM': colors.HexColor('#FFD166'),
            'LOW': colors.HexColor('#06D6A0'),
            'INFO': colors.HexColor('#118AB2')
        }
        return colors_map.get(severity.upper(), colors.HexColor('#FFD166'))

    def _get_risk_color(self, risk_score: int):
        """Get color based on risk score"""
        if risk_score >= 8:
            return colors.HexColor('#FF6B6B')  # Red
        elif risk_score >= 6:
            return colors.HexColor('#FF9E58')  # Orange
        elif risk_score >= 4:
            return colors.HexColor('#FFD166')  # Yellow
        elif risk_score >= 2:
            return colors.HexColor('#06D6A0')  # Green
        else:
            return colors.HexColor('#118AB2')  # Blue

    def _calculate_risk_score(self, vuln_summary: Dict) -> int:
        """Calculate overall risk score (0-10)"""
        critical = vuln_summary.get('critical', 0) * 10
        high = vuln_summary.get('high', 0) * 7
        medium = vuln_summary.get('medium', 0) * 4
        low = vuln_summary.get('low', 0) * 1
        
        total = critical + high + medium + low
        return min(10, total // 3 + 1)

    def generate_json_report(self, scan_results: Dict, output_path: str = None) -> str:
        """Generate JSON report"""
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_target = "".join(c for c in scan_results.get('target', 'unknown') if c.isalnum() or c in ('-', '_'))
                output_path = f"scan_report_{safe_target}_{timestamp}.json"
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            report_data = {
                "metadata": {
                    "report_type": "vulnerability_assessment",
                    "generated_at": datetime.now().isoformat(),
                    "scanner_version": "1.0.0",
                    "target": scan_results.get('target'),
                    "scan_type": scan_results.get('scanType')
                },
                "summary": scan_results.get('summary', {}),
                "findings": {
                    "ports": scan_results.get('ports', []),
                    "vulnerabilities": scan_results.get('vulnerabilities', [])
                },
                "risk_assessment": {
                    "overall_risk_score": self._calculate_risk_score(
                        scan_results.get('summary', {}).get('vulnerabilities', {})
                    ),
                    "recommendations": self._generate_recommendations(scan_results)
                }
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise

    def _generate_recommendations(self, scan_results: Dict) -> List[str]:
        """Generate automated recommendations based on findings"""
        recommendations = []
        vuln_summary = scan_results.get('summary', {}).get('vulnerabilities', {})
        
        if vuln_summary.get('critical', 0) > 0:
            recommendations.append("Immediate action required: Address critical vulnerabilities")
        
        if vuln_summary.get('high', 0) > 0:
            recommendations.append("Prioritize remediation of high severity vulnerabilities")
        
        open_ports = scan_results.get('summary', {}).get('openPorts', 0)
        if open_ports > 10:
            recommendations.append("Consider reducing the attack surface by closing unnecessary ports")
        
        return recommendations

# Simple PDF generator using FPDF for lighter reports
class SimplePDFReport:
    def generate_simple_pdf(self, scan_results: Dict, output_path: str = None) -> str:
        """Generate a simple PDF report using FPDF"""
        if not FPDF_AVAILABLE:
            raise ImportError("FPDF is not installed. Please install it with: pip install fpdf2")
        
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_target = "".join(c for c in scan_results.get('target', 'unknown') if c.isalnum() or c in ('-', '_'))
                output_path = f"simple_scan_report_{safe_target}_{timestamp}.pdf"
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
            pdf.ln(10)
            
            # Target info
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 10, f"Target: {scan_results.get('target', 'N/A')}", 0, 1)
            pdf.cell(0, 10, f"Scan Type: {scan_results.get('scanType', 'N/A')}", 0, 1)
            pdf.cell(0, 10, f"Date: {scan_results.get('timestamp', 'N/A')}", 0, 1)
            pdf.ln(10)
            
            # Summary
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Summary', 0, 1)
            pdf.set_font('Arial', '', 12)
            
            summary = scan_results.get('summary', {})
            vuln_summary = summary.get('vulnerabilities', {})
            
            pdf.cell(0, 10, f"Open Ports: {summary.get('openPorts', 0)}", 0, 1)
            pdf.cell(0, 10, f"Critical Vulnerabilities: {vuln_summary.get('critical', 0)}", 0, 1)
            pdf.cell(0, 10, f"High Vulnerabilities: {vuln_summary.get('high', 0)}", 0, 1)
            pdf.cell(0, 10, f"Medium Vulnerabilities: {vuln_summary.get('medium', 0)}", 0, 1)
            pdf.cell(0, 10, f"Low Vulnerabilities: {vuln_summary.get('low', 0)}", 0, 1)
            
            # Add ports if available
            ports = scan_results.get('ports', [])
            if ports:
                pdf.ln(10)
                pdf.set_font('Arial', 'B', 14)
                pdf.cell(0, 10, 'Open Ports:', 0, 1)
                pdf.set_font('Arial', '', 12)
                for port in ports:
                    pdf.cell(0, 10, f"Port {port.get('number', 'N/A')}: {port.get('service', 'N/A')} ({port.get('state', 'N/A')})", 0, 1)
            
            pdf.output(output_path)
            logger.info(f"Simple PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate simple PDF: {e}")
            raise