import os
import openai
from dotenv import load_dotenv
import json
import logging
from typing import List, Dict, Any
import requests

load_dotenv()

logger = logging.getLogger(__name__)

class AISecurityAnalyzer:
    def __init__(self):
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        self.enabled = bool(self.openai_api_key or self.anthropic_api_key)
        
        if self.openai_api_key:
            openai.api_key = self.openai_api_key
        
        logger.info(f"AI Security Analyzer initialized - Enabled: {self.enabled}")
    
    def analyze_vulnerability_context(self, vulnerability: Dict, scan_context: Dict) -> Dict:
        """Use AI to analyze vulnerability in context and provide intelligent insights"""
        if not self.enabled:
            return self._get_fallback_analysis(vulnerability)
        
        try:
            prompt = self._build_vulnerability_analysis_prompt(vulnerability, scan_context)
            
            if self.openai_api_key:
                return self._analyze_with_openai(prompt, vulnerability)
            elif self.anthropic_api_key:
                return self._analyze_with_anthropic(prompt, vulnerability)
            else:
                return self._get_fallback_analysis(vulnerability)
                
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return self._get_fallback_analysis(vulnerability)
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict], business_context: Dict = None) -> List[Dict]:
        """AI-powered vulnerability prioritization based on business context"""
        if not self.enabled or len(vulnerabilities) <= 1:
            return vulnerabilities
        
        try:
            prompt = self._build_prioritization_prompt(vulnerabilities, business_context)
            
            if self.openai_api_key:
                return self._prioritize_with_openai(prompt, vulnerabilities)
            else:
                return self._prioritize_with_rules(vulnerabilities)
                
        except Exception as e:
            logger.error(f"AI prioritization failed: {e}")
            return self._prioritize_with_rules(vulnerabilities)
    
    def generate_remediation_plan(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate intelligent remediation plan with AI"""
        if not self.enabled:
            return self._get_fallback_remediation_plan(vulnerabilities)
        
        try:
            prompt = self._build_remediation_prompt(vulnerabilities)
            
            if self.openai_api_key:
                return self._generate_remediation_with_openai(prompt)
            else:
                return self._get_fallback_remediation_plan(vulnerabilities)
                
        except Exception as e:
            logger.error(f"AI remediation planning failed: {e}")
            return self._get_fallback_remediation_plan(vulnerabilities)
    
    def detect_anomalies(self, current_scan: Dict, historical_scans: List[Dict]) -> List[Dict]:
        """AI-powered anomaly detection in scan results"""
        if not self.enabled or not historical_scans:
            return []
        
        try:
            prompt = self._build_anomaly_detection_prompt(current_scan, historical_scans)
            
            if self.openai_api_key:
                return self._detect_anomalies_with_openai(prompt)
            else:
                return self._detect_anomalies_with_rules(current_scan, historical_scans)
                
        except Exception as e:
            logger.error(f"AI anomaly detection failed: {e}")
            return self._detect_anomalies_with_rules(current_scan, historical_scans)
    
    def _build_vulnerability_analysis_prompt(self, vulnerability: Dict, scan_context: Dict) -> str:
        return f"""
        Analyze this security vulnerability and provide:
        1. Business impact assessment
        2. Exploitation likelihood
        3. Attack vector analysis
        4. Recommended immediate actions
        5. Long-term mitigation strategies

        Vulnerability Details:
        - Title: {vulnerability.get('title', 'Unknown')}
        - Description: {vulnerability.get('description', 'No description')}
        - Severity: {vulnerability.get('severity', 'Unknown')}
        - Service: {vulnerability.get('service', 'Unknown')}
        - Port: {vulnerability.get('port', 'Unknown')}
        - Evidence: {vulnerability.get('evidence', 'No evidence')}

        Scan Context:
        - Target: {scan_context.get('target', 'Unknown')}
        - Scan Type: {scan_context.get('type', 'Unknown')}

        Provide response in JSON format with:
        {{
            "business_impact": "string",
            "exploitation_likelihood": "low|medium|high|critical",
            "attack_vector": "string",
            "immediate_actions": ["action1", "action2"],
            "mitigation_strategies": ["strategy1", "strategy2"],
            "confidence_score": 0.0-1.0
        }}
        """
    
    def _build_prioritization_prompt(self, vulnerabilities: List[Dict], business_context: Dict) -> str:
        vuln_summary = "\n".join([
            f"{i+1}. {v['title']} (Severity: {v['severity']}, Service: {v.get('service', 'Unknown')})"
            for i, v in enumerate(vulnerabilities)
        ])
        
        business_context_str = json.dumps(business_context) if business_context else "No business context provided"
        
        return f"""
        Prioritize these vulnerabilities based on:
        - Severity level
        - Business impact
        - Exploitation ease
        - Asset criticality
        - Available mitigations

        Vulnerabilities to prioritize:
        {vuln_summary}

        Business Context:
        {business_context_str}

        Provide response in JSON format with prioritized list:
        {{
            "prioritized_vulnerabilities": [
                {{
                    "original_index": 0,
                    "priority_score": 0.0-1.0,
                    "reason": "string",
                    "recommended_timeline": "immediate|short_term|medium_term|long_term"
                }}
            ],
            "priority_rationale": "string"
        }}
        """
    
    def _build_remediation_prompt(self, vulnerabilities: List[Dict]) -> str:
        critical_vulns = [v for v in vulnerabilities if v.get('severity') in ['critical', 'high']]
        vuln_summary = "\n".join([
            f"- {v['title']} (Severity: {v['severity']}): {v.get('solution', 'No solution provided')}"
            for v in critical_vulns[:10]  # Limit to top 10 for token efficiency
        ])
        
        return f"""
        Create a comprehensive remediation plan for these critical vulnerabilities:

        {vuln_summary}

        Provide a structured remediation plan with:
        1. Immediate actions (first 24 hours)
        2. Short-term fixes (1 week)
        3. Medium-term improvements (1 month)
        4. Long-term security enhancements (3+ months)
        5. Resource requirements
        6. Success metrics

        Format response as JSON:
        {{
            "immediate_actions": [
                {{
                    "action": "string",
                    "vulnerabilities": ["vuln1", "vuln2"],
                    "estimated_time": "string",
                    "resources_needed": ["resource1", "resource2"]
                }}
            ],
            "short_term_plan": [...],
            "medium_term_plan": [...],
            "long_term_plan": [...],
            "overall_timeline": "string",
            "success_metrics": ["metric1", "metric2"]
        }}
        """
    
    def _analyze_with_openai(self, prompt: str, vulnerability: Dict) -> Dict:
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability analysis and risk assessment."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            analysis_text = response.choices[0].message.content.strip()
            return self._parse_ai_response(analysis_text, vulnerability)
            
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            return self._get_fallback_analysis(vulnerability)
    
    def _prioritize_with_openai(self, prompt: str, vulnerabilities: List[Dict]) -> List[Dict]:
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity risk assessment specialist."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1500
            )
            
            prioritization_text = response.choices[0].message.content.strip()
            return self._parse_prioritization_response(prioritization_text, vulnerabilities)
            
        except Exception as e:
            logger.error(f"OpenAI prioritization failed: {e}")
            return self._prioritize_with_rules(vulnerabilities)
    
    def _parse_ai_response(self, response_text: str, vulnerability: Dict) -> Dict:
        """Parse AI response and fallback to default if parsing fails"""
        try:
            # Try to parse as JSON
            if response_text.startswith('{') and response_text.endswith('}'):
                return json.loads(response_text)
        except:
            pass
        
        # Fallback analysis
        return self._get_fallback_analysis(vulnerability)
    
    def _parse_prioritization_response(self, response_text: str, vulnerabilities: List[Dict]) -> List[Dict]:
        try:
            if response_text.startswith('{') and response_text.endswith('}'):
                data = json.loads(response_text)
                prioritized = data.get('prioritized_vulnerabilities', [])
                
                # Reorder vulnerabilities based on AI prioritization
                reordered_vulns = []
                for priority_item in prioritized:
                    original_index = priority_item.get('original_index', 0)
                    if original_index < len(vulnerabilities):
                        vuln = vulnerabilities[original_index].copy()
                        vuln['ai_priority_score'] = priority_item.get('priority_score', 0.5)
                        vuln['ai_priority_reason'] = priority_item.get('reason', '')
                        vuln['ai_recommended_timeline'] = priority_item.get('recommended_timeline', 'medium_term')
                        reordered_vulns.append(vuln)
                
                # Add any missing vulnerabilities
                added_indices = {item.get('original_index') for item in prioritized}
                for i, vuln in enumerate(vulnerabilities):
                    if i not in added_indices:
                        vuln_copy = vuln.copy()
                        vuln_copy['ai_priority_score'] = 0.3
                        vuln_copy['ai_priority_reason'] = 'Automatically assigned lower priority'
                        vuln_copy['ai_recommended_timeline'] = 'long_term'
                        reordered_vulns.append(vuln_copy)
                
                return reordered_vulns
        except Exception as e:
            logger.error(f"Failed to parse prioritization response: {e}")
        
        return self._prioritize_with_rules(vulnerabilities)
    
    def _get_fallback_analysis(self, vulnerability: Dict) -> Dict:
        """Fallback analysis when AI is not available"""
        severity = vulnerability.get('severity', 'medium')
        
        impact_map = {
            'critical': 'Critical business impact - potential system compromise',
            'high': 'High business impact - sensitive data exposure risk',
            'medium': 'Medium business impact - service disruption possible',
            'low': 'Low business impact - limited business risk'
        }
        
        likelihood_map = {
            'critical': 'high',
            'high': 'high', 
            'medium': 'medium',
            'low': 'low'
        }
        
        return {
            "business_impact": impact_map.get(severity, "Unknown impact"),
            "exploitation_likelihood": likelihood_map.get(severity, "medium"),
            "attack_vector": "Network-based exploitation",
            "immediate_actions": [
                "Review vulnerability details",
                "Assess affected systems",
                "Implement temporary mitigations if available"
            ],
            "mitigation_strategies": [
                "Apply security patches",
                "Implement network segmentation",
                "Enhance monitoring and alerting"
            ],
            "confidence_score": 0.7
        }
    
    def _prioritize_with_rules(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Rule-based prioritization fallback"""
        severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }
        
        prioritized_vulns = []
        for i, vuln in enumerate(vulnerabilities):
            vuln_copy = vuln.copy()
            severity = vuln.get('severity', 'medium')
            
            vuln_copy['ai_priority_score'] = severity_weights.get(severity, 0.5)
            vuln_copy['ai_priority_reason'] = f"Based on severity: {severity}"
            vuln_copy['ai_recommended_timeline'] = (
                'immediate' if severity in ['critical', 'high'] else
                'short_term' if severity == 'medium' else 'long_term'
            )
            prioritized_vulns.append(vuln_copy)
        
        # Sort by priority score descending
        prioritized_vulns.sort(key=lambda x: x['ai_priority_score'], reverse=True)
        return prioritized_vulns
    
    def _get_fallback_remediation_plan(self, vulnerabilities: List[Dict]) -> Dict:
        """Fallback remediation plan"""
        critical_count = len([v for v in vulnerabilities if v.get('severity') in ['critical', 'high']])
        
        return {
            "immediate_actions": [
                {
                    "action": f"Address {critical_count} critical/high vulnerabilities",
                    "vulnerabilities": [v['title'] for v in vulnerabilities if v.get('severity') in ['critical', 'high']][:3],
                    "estimated_time": "24-48 hours",
                    "resources_needed": ["Security team", "System administrators"]
                }
            ],
            "short_term_plan": [
                {
                    "action": "Implement basic security controls",
                    "estimated_time": "1 week",
                    "resources_needed": ["Security team"]
                }
            ],
            "medium_term_plan": [
                {
                    "action": "Enhance security monitoring",
                    "estimated_time": "1 month", 
                    "resources_needed": ["Security team", "IT operations"]
                }
            ],
            "long_term_plan": [
                {
                    "action": "Establish continuous security assessment program",
                    "estimated_time": "3 months",
                    "resources_needed": ["Security team", "Management"]
                }
            ],
            "overall_timeline": "3 months for full remediation",
            "success_metrics": [
                "Reduction in critical vulnerabilities",
                "Improved security posture score",
                "Faster vulnerability remediation times"
            ]
        }
    
    def _detect_anomalies_with_rules(self, current_scan: Dict, historical_scans: List[Dict]) -> List[Dict]:
        """Rule-based anomaly detection"""
        anomalies = []
        current_vuln_count = len(current_scan.get('results', []))
        
        if historical_scans:
            avg_vuln_count = sum(len(scan.get('results', [])) for scan in historical_scans[-5:]) / 5
            
            if current_vuln_count > avg_vuln_count * 2:
                anomalies.append({
                    "type": "unusual_vulnerability_count",
                    "description": f"Current scan found {current_vuln_count} vulnerabilities, significantly higher than historical average of {avg_vuln_count:.1f}",
                    "severity": "high",
                    "recommendation": "Investigate recent changes to the target system"
                })
        
        return anomalies

# Global AI analyzer instance
ai_analyzer = AISecurityAnalyzer()