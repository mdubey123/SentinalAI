"""
Threat Intelligence Agent for SentinelAI v2
AI-powered threat analysis, classification, and storytelling
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import re

from agents.base_agent import BaseAgent
from utils.logger import security_audit

class ThreatIntelligenceAgent(BaseAgent):
    """Agent for AI-powered threat intelligence and analysis"""
    
    def __init__(self, llm_provider: str, llm_model: str):
        super().__init__("threat_intelligence")
        
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        
        # MITRE ATT&CK framework mapping
        self.mitre_tactics = self._load_mitre_tactics()
        
        # NIST CSF functions
        self.nist_functions = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
        
        # Threat classification patterns
        self.threat_patterns = self._load_threat_patterns()
    
    def _load_mitre_tactics(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK tactics and techniques"""
        return {
            'TA0001': {
                'name': 'Initial Access',
                'description': 'Techniques used to gain initial foothold',
                'techniques': ['T1566', 'T1190', 'T1133', 'T1078']
            },
            'TA0002': {
                'name': 'Execution',
                'description': 'Techniques to execute malicious code',
                'techniques': ['T1059', 'T1203', 'T1204', 'T1053']
            },
            'TA0003': {
                'name': 'Persistence',
                'description': 'Techniques to maintain access',
                'techniques': ['T1547', 'T1053', 'T1543', 'T1136']
            },
            'TA0004': {
                'name': 'Privilege Escalation',
                'description': 'Techniques to gain higher privileges',
                'techniques': ['T1548', 'T1055', 'T1068', 'T1134']
            },
            'TA0005': {
                'name': 'Defense Evasion',
                'description': 'Techniques to avoid detection',
                'techniques': ['T1027', 'T1055', 'T1070', 'T1112']
            },
            'TA0006': {
                'name': 'Credential Access',
                'description': 'Techniques to steal credentials',
                'techniques': ['T1003', 'T1110', 'T1555', 'T1212']
            },
            'TA0007': {
                'name': 'Discovery',
                'description': 'Techniques to explore environment',
                'techniques': ['T1083', 'T1057', 'T1018', 'T1082']
            },
            'TA0008': {
                'name': 'Lateral Movement',
                'description': 'Techniques to move through network',
                'techniques': ['T1021', 'T1080', 'T1550', 'T1563']
            },
            'TA0009': {
                'name': 'Collection',
                'description': 'Techniques to gather information',
                'techniques': ['T1005', 'T1039', 'T1056', 'T1113']
            },
            'TA0010': {
                'name': 'Exfiltration',
                'description': 'Techniques to steal data',
                'techniques': ['T1041', 'T1048', 'T1052', 'T1567']
            },
            'TA0011': {
                'name': 'Impact',
                'description': 'Techniques to disrupt operations',
                'techniques': ['T1485', 'T1486', 'T1490', 'T1499']
            }
        }
    
    def _load_threat_patterns(self) -> Dict[str, Any]:
        """Load threat classification patterns"""
        return {
            'ransomware': {
                'keywords': ['encrypt', 'decrypt', 'ransom', 'bitcoin', 'payment', '.locked', '.encrypted'],
                'severity': 'critical',
                'mitre_tactics': ['TA0011'],  # Impact
                'description': 'Malware that encrypts files and demands payment'
            },
            'trojan': {
                'keywords': ['backdoor', 'remote', 'control', 'rat', 'trojan'],
                'severity': 'high',
                'mitre_tactics': ['TA0001', 'TA0003'],  # Initial Access, Persistence
                'description': 'Malware that provides unauthorized remote access'
            },
            'spyware': {
                'keywords': ['keylog', 'screenshot', 'monitor', 'spy', 'steal'],
                'severity': 'high',
                'mitre_tactics': ['TA0006', 'TA0009'],  # Credential Access, Collection
                'description': 'Malware that secretly monitors user activity'
            },
            'worm': {
                'keywords': ['replicate', 'spread', 'network', 'propagate'],
                'severity': 'medium',
                'mitre_tactics': ['TA0008'],  # Lateral Movement
                'description': 'Self-replicating malware that spreads across networks'
            },
            'rootkit': {
                'keywords': ['hide', 'stealth', 'kernel', 'system', 'rootkit'],
                'severity': 'critical',
                'mitre_tactics': ['TA0005'],  # Defense Evasion
                'description': 'Malware that hides its presence on the system'
            },
            'adware': {
                'keywords': ['advertisement', 'popup', 'browser', 'ads'],
                'severity': 'low',
                'mitre_tactics': ['TA0002'],  # Execution
                'description': 'Software that displays unwanted advertisements'
            }
        }
    
    async def execute(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute threat intelligence analysis"""
        self.start_operation("threat_analysis")
        
        try:
            # Aggregate all scan data
            aggregated_data = self._aggregate_scan_data(scan_results)
            
            # Classify threats
            classified_threats = self._classify_threats(aggregated_data)
            
            # Calculate security score
            security_score = self._calculate_security_score(classified_threats, aggregated_data)
            
            # Map to frameworks
            framework_mapping = self._map_to_frameworks(classified_threats)
            
            # Generate AI analysis
            ai_analysis = await self._generate_ai_analysis(aggregated_data, classified_threats)
            
            # Create final analysis
            analysis_results = {
                'threats': classified_threats,
                'security_score': security_score,
                'framework_mapping': framework_mapping,
                'ai_analysis': ai_analysis,
                'summary': self._generate_summary(classified_threats, security_score),
                'recommendations': self._generate_recommendations(classified_threats),
                'analysis_metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'llm_provider': self.llm_provider,
                    'llm_model': self.llm_model,
                    'analysis_version': '2.1.0'
                }
            }
            
            self.end_operation("threat_analysis", True, analysis_results)
            return analysis_results
            
        except Exception as e:
            error_result = self.handle_error(e, "threat_analysis")
            self.end_operation("threat_analysis", False, error_result)
            return error_result
    
    def _aggregate_scan_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate data from all scan sources"""
        aggregated = {
            'local_threats': [],
            'virustotal_threats': [],
            'vapt_vulnerabilities': [],
            'total_files_scanned': 0,
            'total_threats_found': 0,
            'scan_coverage': {}
        }
        
        # Process local scan results
        local_results = scan_results.get('local', {})
        if local_results:
            aggregated['local_threats'] = local_results.get('threats', [])
            aggregated['total_files_scanned'] = len(local_results.get('files', []))
            aggregated['scan_coverage']['local_scan'] = True
        
        # Process VirusTotal results
        vt_results = scan_results.get('virustotal', {})
        if vt_results:
            for file_hash, vt_data in vt_results.get('hash_results', {}).items():
                if vt_data.get('positive_detections', 0) > 0:
                    vt_threat = {
                        'source': 'virustotal',
                        'file_hash': file_hash,
                        'detections': vt_data.get('detections', {}),
                        'detection_ratio': vt_data.get('detection_ratio', '0/0'),
                        'threat_classification': vt_data.get('threat_classification', {})
                    }
                    aggregated['virustotal_threats'].append(vt_threat)
            
            aggregated['scan_coverage']['virustotal'] = True
        
        # Process VAPT results
        vapt_results = scan_results.get('vapt_results', {})
        if vapt_results:
            aggregated['vapt_vulnerabilities'] = vapt_results.get('vulnerabilities', [])
            aggregated['scan_coverage']['vapt'] = True
        
        # Calculate total threats
        aggregated['total_threats_found'] = (
            len(aggregated['local_threats']) +
            len(aggregated['virustotal_threats']) +
            len(aggregated['vapt_vulnerabilities'])
        )
        
        return aggregated
    
    def _classify_threats(self, aggregated_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Classify and normalize threats from all sources"""
        classified_threats = []
        
        # Process local threats
        for threat in aggregated_data.get('local_threats', []):
            classified_threat = self._classify_single_threat(threat, 'local')
            classified_threats.append(classified_threat)
        
        # Process VirusTotal threats
        for threat in aggregated_data.get('virustotal_threats', []):
            classified_threat = self._classify_single_threat(threat, 'virustotal')
            classified_threats.append(classified_threat)
        
        # Process VAPT vulnerabilities
        for vuln in aggregated_data.get('vapt_vulnerabilities', []):
            classified_threat = self._classify_vulnerability(vuln)
            classified_threats.append(classified_threat)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        classified_threats.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 3))
        
        return classified_threats
    
    def _classify_single_threat(self, threat: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Classify a single threat"""
        threat_name = threat.get('threat_name', '').lower()
        description = threat.get('description', '').lower()
        
        # Determine threat type based on patterns
        threat_type = 'malware'  # Default
        severity = threat.get('severity', 'medium')
        confidence = threat.get('confidence', 50)
        
        for pattern_name, pattern_info in self.threat_patterns.items():
            if any(keyword in threat_name or keyword in description 
                   for keyword in pattern_info['keywords']):
                threat_type = pattern_name
                severity = pattern_info['severity']
                confidence = min(95, confidence + 20)
                break
        
        # Map to MITRE ATT&CK
        mitre_tactics = self.threat_patterns.get(threat_type, {}).get('mitre_tactics', [])
        
        return {
            'id': f"{source}_{hash(str(threat))}",
            'name': threat.get('threat_name', 'Unknown Threat'),
            'type': threat_type,
            'severity': severity,
            'confidence': confidence,
            'source': source,
            'description': threat.get('description', ''),
            'file_path': threat.get('file_path', ''),
            'detection_time': threat.get('detection_time', datetime.now().isoformat()),
            'mitre_tactics': mitre_tactics,
            'cvss_score': self._calculate_cvss_score(severity),
            'remediation': self._get_remediation_advice(threat_type),
            'original_data': threat
        }
    
    def _classify_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a VAPT vulnerability as a threat"""
        vuln_type = vulnerability.get('type', 'vulnerability')
        severity = vulnerability.get('severity', 'medium')
        
        return {
            'id': f"vapt_{hash(str(vulnerability))}",
            'name': vulnerability.get('cve_id', vulnerability.get('type', 'Network Vulnerability')),
            'type': 'vulnerability',
            'severity': severity,
            'confidence': 80,
            'source': 'vapt',
            'description': vulnerability.get('description', ''),
            'service': vulnerability.get('service', ''),
            'port': vulnerability.get('port', ''),
            'detection_time': datetime.now().isoformat(),
            'mitre_tactics': ['TA0001'],  # Initial Access (default for network vulns)
            'cvss_score': self._calculate_cvss_score(severity),
            'remediation': vulnerability.get('recommendation', 'Apply security patches'),
            'original_data': vulnerability
        }
    
    def _calculate_security_score(self, threats: List[Dict[str, Any]], aggregated_data: Dict[str, Any]) -> int:
        """Calculate overall security posture score (0-100)"""
        base_score = 100
        
        # Deduct points for threats
        for threat in threats:
            severity = threat.get('severity', 'low')
            confidence = threat.get('confidence', 50)
            
            # Weight by severity and confidence
            if severity == 'critical':
                deduction = 25 * (confidence / 100)
            elif severity == 'high':
                deduction = 15 * (confidence / 100)
            elif severity == 'medium':
                deduction = 8 * (confidence / 100)
            else:  # low
                deduction = 3 * (confidence / 100)
            
            base_score -= deduction
        
        # Bonus for comprehensive scanning
        scan_coverage = aggregated_data.get('scan_coverage', {})
        coverage_bonus = len(scan_coverage) * 2  # 2 points per scan type
        
        # Bonus for clean scans
        if aggregated_data.get('total_threats_found', 0) == 0:
            base_score += 10
        
        final_score = max(0, min(100, int(base_score + coverage_bonus)))
        return final_score
    
    def _map_to_frameworks(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map threats to security frameworks"""
        framework_mapping = {
            'mitre_attack': {
                'tactics_identified': set(),
                'techniques_identified': set(),
                'coverage': {}
            },
            'nist_csf': {
                'functions_affected': set(),
                'recommendations': {}
            },
            'cvss_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Map to MITRE ATT&CK
        for threat in threats:
            mitre_tactics = threat.get('mitre_tactics', [])
            for tactic_id in mitre_tactics:
                if tactic_id in self.mitre_tactics:
                    framework_mapping['mitre_attack']['tactics_identified'].add(tactic_id)
                    
                    # Add techniques
                    techniques = self.mitre_tactics[tactic_id].get('techniques', [])
                    framework_mapping['mitre_attack']['techniques_identified'].update(techniques)
        
        # Map to NIST CSF
        for threat in threats:
            threat_type = threat.get('type', '')
            
            if threat_type in ['ransomware', 'worm']:
                framework_mapping['nist_csf']['functions_affected'].add('Protect')
                framework_mapping['nist_csf']['functions_affected'].add('Recover')
            elif threat_type in ['spyware', 'trojan']:
                framework_mapping['nist_csf']['functions_affected'].add('Detect')
                framework_mapping['nist_csf']['functions_affected'].add('Respond')
            else:
                framework_mapping['nist_csf']['functions_affected'].add('Identify')
        
        # CVSS distribution
        for threat in threats:
            severity = threat.get('severity', 'low')
            framework_mapping['cvss_distribution'][severity] += 1
        
        # Convert sets to lists for JSON serialization
        framework_mapping['mitre_attack']['tactics_identified'] = list(framework_mapping['mitre_attack']['tactics_identified'])
        framework_mapping['mitre_attack']['techniques_identified'] = list(framework_mapping['mitre_attack']['techniques_identified'])
        framework_mapping['nist_csf']['functions_affected'] = list(framework_mapping['nist_csf']['functions_affected'])
        
        return framework_mapping
    
    async def _generate_ai_analysis(self, aggregated_data: Dict[str, Any], threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate AI-powered analysis and storytelling"""
        # This is a simplified version - in production would use actual LLM
        
        threat_count = len(threats)
        critical_threats = [t for t in threats if t.get('severity') == 'critical']
        high_threats = [t for t in threats if t.get('severity') == 'high']
        
        # Generate narrative story
        narrative_story = self._generate_narrative_story(threats)
        
        # Generate analytical breakdown
        analytical_breakdown = self._generate_analytical_breakdown(threats, aggregated_data)
        
        return {
            'narrative_story': narrative_story,
            'analytical_breakdown': analytical_breakdown,
            'key_insights': self._generate_key_insights(threats),
            'attack_timeline': self._generate_attack_timeline(threats),
            'threat_landscape': self._analyze_threat_landscape(threats)
        }
    
    def _generate_narrative_story(self, threats: List[Dict[str, Any]]) -> str:
        """Generate attacker diary / dramatized intrusion story"""
        if not threats:
            return "The digital fortress stands strong. No adversaries have breached the perimeter. The security measures are holding firm, creating an impenetrable barrier against malicious actors."
        
        critical_threats = [t for t in threats if t.get('severity') == 'critical']
        high_threats = [t for t in threats if t.get('severity') == 'high']
        
        if critical_threats:
            story = "**Day 1 - The Breach**\n\n"
            story += "The attacker's eyes gleam as they discover the critical vulnerability. "
            story += f"A {critical_threats[0].get('type', 'malware')} payload has been successfully deployed, "
            story += "giving them a foothold in the system. The digital locks have been picked, "
            story += "and the adversary now moves through the shadows of the network.\n\n"
            
            if high_threats:
                story += "**Day 2 - Escalation**\n\n"
                story += "With initial access secured, the attacker deploys additional tools. "
                story += f"A {high_threats[0].get('type', 'trojan')} establishes persistence, "
                story += "ensuring their presence remains undetected. They begin mapping the network, "
                story += "identifying valuable targets and planning their next moves.\n\n"
            
            story += "**The Stakes**\n\n"
            story += "Critical systems are at risk. Data integrity hangs in the balance. "
            story += "Swift action is required to prevent further compromise and protect valuable assets."
        
        elif high_threats:
            story = "**The Reconnaissance**\n\n"
            story += "An adversary probes the digital perimeter, testing defenses and looking for weaknesses. "
            story += f"A {high_threats[0].get('type', 'malware')} has been detected, suggesting active "
            story += "attempts to compromise the system. While not immediately critical, "
            story += "this represents a clear and present danger that requires immediate attention."
        
        else:
            story = "**Minor Disturbances**\n\n"
            story += "Low-level threats have been detected on the horizon. Like distant storm clouds, "
            story += "they may not pose immediate danger, but vigilance is required. "
            story += "These could be precursors to more serious attacks or simply opportunistic probes."
        
        return story
    
    def _generate_analytical_breakdown(self, threats: List[Dict[str, Any]], aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analytical TTP breakdown"""
        return {
            'attack_vectors': self._identify_attack_vectors(threats),
            'persistence_mechanisms': self._identify_persistence_mechanisms(threats),
            'evasion_techniques': self._identify_evasion_techniques(threats),
            'impact_assessment': self._assess_potential_impact(threats),
            'attribution_indicators': self._analyze_attribution_indicators(threats),
            'timeline_analysis': self._analyze_timeline(threats)
        }
    
    def _generate_key_insights(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Generate key security insights"""
        insights = []
        
        if not threats:
            insights.append("No active threats detected - security posture is strong")
            insights.append("Continue regular monitoring and maintain current security measures")
            return insights
        
        # Threat type analysis
        threat_types = {}
        for threat in threats:
            threat_type = threat.get('type', 'unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        most_common_threat = max(threat_types, key=threat_types.get)
        insights.append(f"Most prevalent threat type: {most_common_threat} ({threat_types[most_common_threat]} instances)")
        
        # Severity analysis
        critical_count = len([t for t in threats if t.get('severity') == 'critical'])
        if critical_count > 0:
            insights.append(f"URGENT: {critical_count} critical threats require immediate attention")
        
        # Source analysis
        sources = {}
        for threat in threats:
            source = threat.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1
        
        if len(sources) > 1:
            insights.append("Multi-vector attack detected - threats from multiple sources")
        
        # Confidence analysis
        high_confidence_threats = [t for t in threats if t.get('confidence', 0) > 80]
        if high_confidence_threats:
            insights.append(f"{len(high_confidence_threats)} high-confidence threat detections")
        
        return insights
    
    def _generate_attack_timeline(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate chronological attack timeline"""
        timeline = []
        
        # Sort threats by detection time
        sorted_threats = sorted(threats, key=lambda x: x.get('detection_time', ''))
        
        for i, threat in enumerate(sorted_threats):
            timeline_entry = {
                'sequence': i + 1,
                'timestamp': threat.get('detection_time', ''),
                'event': f"{threat.get('type', 'threat').title()} detected",
                'description': threat.get('name', 'Unknown threat'),
                'severity': threat.get('severity', 'medium'),
                'source': threat.get('source', 'unknown'),
                'mitre_tactic': threat.get('mitre_tactics', [''])[0] if threat.get('mitre_tactics') else ''
            }
            timeline.append(timeline_entry)
        
        return timeline
    
    def _analyze_threat_landscape(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the overall threat landscape"""
        landscape = {
            'threat_diversity': len(set(t.get('type', 'unknown') for t in threats)),
            'geographic_indicators': [],  # Would be populated with IP geolocation data
            'temporal_patterns': {},
            'attack_sophistication': 'medium',  # Default
            'threat_actor_profile': 'unknown'
        }
        
        # Analyze sophistication
        if any(t.get('type') == 'rootkit' for t in threats):
            landscape['attack_sophistication'] = 'high'
        elif any(t.get('type') in ['ransomware', 'trojan'] for t in threats):
            landscape['attack_sophistication'] = 'medium'
        else:
            landscape['attack_sophistication'] = 'low'
        
        return landscape
    
    def _identify_attack_vectors(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Identify attack vectors from threats"""
        vectors = set()
        
        for threat in threats:
            threat_type = threat.get('type', '')
            
            if threat_type == 'trojan':
                vectors.add('Email attachment')
                vectors.add('Drive-by download')
            elif threat_type == 'worm':
                vectors.add('Network propagation')
            elif threat_type == 'vulnerability':
                vectors.add('Network service exploitation')
            else:
                vectors.add('Unknown vector')
        
        return list(vectors)
    
    def _identify_persistence_mechanisms(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Identify persistence mechanisms"""
        mechanisms = set()
        
        for threat in threats:
            threat_type = threat.get('type', '')
            
            if threat_type in ['trojan', 'rootkit']:
                mechanisms.add('Registry modification')
                mechanisms.add('Service installation')
            elif threat_type == 'spyware':
                mechanisms.add('Startup folder')
        
        return list(mechanisms)
    
    def _identify_evasion_techniques(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Identify evasion techniques"""
        techniques = set()
        
        for threat in threats:
            threat_type = threat.get('type', '')
            
            if threat_type == 'rootkit':
                techniques.add('Kernel-level hiding')
                techniques.add('Process hollowing')
            elif threat_type in ['trojan', 'spyware']:
                techniques.add('Code obfuscation')
                techniques.add('Anti-analysis techniques')
        
        return list(techniques)
    
    def _assess_potential_impact(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess potential impact of threats"""
        impact = {
            'data_confidentiality': 'low',
            'data_integrity': 'low',
            'system_availability': 'low',
            'financial_impact': 'low',
            'reputation_impact': 'low'
        }
        
        for threat in threats:
            threat_type = threat.get('type', '')
            severity = threat.get('severity', 'low')
            
            if threat_type == 'ransomware':
                impact['data_integrity'] = 'high'
                impact['system_availability'] = 'high'
                impact['financial_impact'] = 'high'
            elif threat_type == 'spyware':
                impact['data_confidentiality'] = 'high'
                impact['reputation_impact'] = 'medium'
            elif threat_type == 'trojan':
                impact['data_confidentiality'] = 'medium'
                impact['system_availability'] = 'medium'
        
        return impact
    
    def _analyze_attribution_indicators(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat attribution indicators"""
        return {
            'threat_actor_type': 'unknown',
            'sophistication_level': 'medium',
            'motivation': 'unknown',
            'attribution_confidence': 'low',
            'indicators': []
        }
    
    def _analyze_timeline(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attack timeline patterns"""
        if not threats:
            return {'pattern': 'none', 'duration': 0, 'phases': []}
        
        return {
            'pattern': 'simultaneous' if len(threats) > 1 else 'single_event',
            'duration': 'unknown',
            'phases': ['initial_compromise', 'persistence', 'lateral_movement']
        }
    
    def _calculate_cvss_score(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        severity_mapping = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }
        return severity_mapping.get(severity, 5.0)
    
    def _get_remediation_advice(self, threat_type: str) -> str:
        """Get remediation advice for threat type"""
        remediation_map = {
            'ransomware': 'Isolate affected systems, restore from clean backups, patch vulnerabilities',
            'trojan': 'Remove malicious files, scan for additional payloads, update security policies',
            'spyware': 'Remove spyware, change all passwords, monitor for data exfiltration',
            'worm': 'Isolate network segments, remove worm, patch network vulnerabilities',
            'rootkit': 'Boot from clean media, perform deep system scan, rebuild if necessary',
            'adware': 'Remove adware, update browser security settings, educate users',
            'vulnerability': 'Apply security patches, update configurations, implement compensating controls'
        }
        return remediation_map.get(threat_type, 'Follow standard incident response procedures')
    
    def _generate_summary(self, threats: List[Dict[str, Any]], security_score: int) -> Dict[str, Any]:
        """Generate executive summary"""
        return {
            'total_threats': len(threats),
            'critical_threats': len([t for t in threats if t.get('severity') == 'critical']),
            'high_threats': len([t for t in threats if t.get('severity') == 'high']),
            'security_score': security_score,
            'risk_level': self._determine_risk_level(threats, security_score),
            'immediate_actions_required': len([t for t in threats if t.get('severity') in ['critical', 'high']]) > 0,
            'scan_timestamp': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = set()
        
        if not threats:
            recommendations.add("Maintain current security posture with regular monitoring")
            recommendations.add("Continue scheduled security assessments")
            return list(recommendations)
        
        # Threat-specific recommendations
        for threat in threats:
            threat_type = threat.get('type', '')
            severity = threat.get('severity', 'low')
            
            if severity in ['critical', 'high']:
                recommendations.add(f"URGENT: Address {threat_type} threat immediately")
            
            recommendations.add(threat.get('remediation', 'Apply security best practices'))
        
        # General recommendations
        recommendations.add("Implement defense-in-depth security strategy")
        recommendations.add("Regular security awareness training for users")
        recommendations.add("Keep all systems and software updated")
        recommendations.add("Monitor network traffic for suspicious activity")
        recommendations.add("Maintain offline backups of critical data")
        
        return list(recommendations)
    
    def _determine_risk_level(self, threats: List[Dict[str, Any]], security_score: int) -> str:
        """Determine overall risk level"""
        critical_count = len([t for t in threats if t.get('severity') == 'critical'])
        high_count = len([t for t in threats if t.get('severity') == 'high'])
        
        if critical_count > 0 or security_score < 30:
            return 'critical'
        elif high_count > 0 or security_score < 50:
            return 'high'
        elif len(threats) > 0 or security_score < 70:
            return 'medium'
        else:
            return 'low'
    
    def analyze_threats(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous wrapper for threat analysis"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            return loop.run_until_complete(self.execute(scan_results))
        finally:
            loop.close()
    
    def generate_attacker_narrative(self, analysis_results: Dict[str, Any]) -> str:
        """Generate attacker diary / dramatized intrusion story"""
        threats = analysis_results.get('threats', [])
        return self._generate_narrative_story(threats)
    
    def generate_analytical_breakdown(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analytical TTP breakdown with MITRE ATT&CK mapping"""
        threats = analysis_results.get('threats', [])
        aggregated_data = {
            'threats': threats,
            'total_threats_found': len(threats)
        }
        return self._generate_analytical_breakdown(threats, aggregated_data)
    
    def map_to_frameworks(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Map analysis results to security frameworks (CVSS, MITRE, NIST)"""
        threats = analysis_results.get('threats', [])
        return self._map_to_frameworks(threats)
