"""
Report Generation Agent for SentinelAI v2
Handles PDF and JSON report generation with executive and technical formats
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import base64

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from agents.base_agent import BaseAgent

class ReportAgent(BaseAgent):
    """Agent for generating comprehensive security reports"""
    
    def __init__(self):
        super().__init__("report_generator")
        
        # Report templates
        self.templates = {
            'executive': self._get_executive_template(),
            'technical': self._get_technical_template(),
            'compliance': self._get_compliance_template()
        }
        
        # Report styling
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom report styles"""
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=20,
            textColor=colors.darkblue
        ))
        
        # Threat alert style
        self.styles.add(ParagraphStyle(
            name='ThreatAlert',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.red,
            backColor=colors.lightgrey,
            borderColor=colors.red,
            borderWidth=1,
            leftIndent=10,
            rightIndent=10,
            spaceAfter=10
        ))
        
        # Recommendation style
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.darkgreen,
            leftIndent=20,
            bulletIndent=10
        ))
    
    async def execute(self, analysis_results: Dict[str, Any], report_type: str = "executive") -> Dict[str, Any]:
        """Generate security report"""
        self.start_operation(f"report_generation_{report_type}")
        
        try:
            report_data = {
                'metadata': {
                    'report_type': report_type,
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'SentinelAI v2.1',
                    'analysis_timestamp': analysis_results.get('analysis_metadata', {}).get('timestamp')
                },
                'content': {},
                'files_generated': []
            }
            
            # Generate PDF report
            if REPORTLAB_AVAILABLE:
                pdf_path = await self._generate_pdf_report(analysis_results, report_type)
                if pdf_path:
                    report_data['files_generated'].append({
                        'type': 'pdf',
                        'path': str(pdf_path),
                        'format': report_type
                    })
            
            # Generate JSON report
            json_path = await self._generate_json_report(analysis_results, report_type)
            if json_path:
                report_data['files_generated'].append({
                    'type': 'json',
                    'path': str(json_path),
                    'format': 'technical'
                })
            
            # Generate summary content
            report_data['content'] = self._generate_report_content(analysis_results, report_type)
            
            self.end_operation(f"report_generation_{report_type}", True, report_data)
            return report_data
            
        except Exception as e:
            error_result = self.handle_error(e, f"report_generation_{report_type}")
            self.end_operation(f"report_generation_{report_type}", False, error_result)
            return error_result
    
    async def _generate_pdf_report(self, analysis_results: Dict[str, Any], report_type: str) -> Optional[Path]:
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            self.logger.warning("ReportLab not available - PDF generation disabled")
            return None
        
        try:
            # Create reports directory
            reports_dir = Path.home() / ".sentinelai" / "reports"
            reports_dir.mkdir(exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sentinelai_report_{report_type}_{timestamp}.pdf"
            pdf_path = reports_dir / filename
            
            # Create PDF document
            doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
            story = []
            
            # Generate content based on report type
            if report_type == "executive":
                story.extend(self._generate_executive_pdf_content(analysis_results))
            elif report_type == "technical":
                story.extend(self._generate_technical_pdf_content(analysis_results))
            else:
                story.extend(self._generate_standard_pdf_content(analysis_results))
            
            # Build PDF
            doc.build(story)
            
            self.logger.info(f"PDF report generated: {pdf_path}")
            return pdf_path
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            return None
    
    def _generate_executive_pdf_content(self, analysis_results: Dict[str, Any]) -> List:
        """Generate executive PDF content"""
        story = []
        
        # Title page
        story.append(Paragraph("Security Assessment Report", self.styles['ExecutiveTitle']))
        story.append(Spacer(1, 20))
        
        # Executive summary
        summary = analysis_results.get('summary', {})
        security_score = summary.get('security_score', 0)
        total_threats = summary.get('total_threats', 0)
        critical_threats = summary.get('critical_threats', 0)
        
        story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        
        # Security score
        score_color = colors.red if security_score < 50 else colors.orange if security_score < 75 else colors.green
        story.append(Paragraph(f"<font color='{score_color}'>Security Posture Score: {security_score}/100</font>", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Threat overview
        if total_threats > 0:
            if critical_threats > 0:
                story.append(Paragraph(f"⚠️ CRITICAL: {critical_threats} critical threats require immediate attention", self.styles['ThreatAlert']))
            
            story.append(Paragraph(f"Total threats detected: {total_threats}", self.styles['Normal']))
        else:
            story.append(Paragraph("✅ No active threats detected", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        
        # Key findings
        story.append(Paragraph("Key Findings", self.styles['Heading2']))
        
        key_insights = analysis_results.get('ai_analysis', {}).get('key_insights', [])
        for insight in key_insights[:5]:  # Top 5 insights
            story.append(Paragraph(f"• {insight}", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Priority Recommendations", self.styles['Heading2']))
        
        recommendations = analysis_results.get('recommendations', [])
        for i, recommendation in enumerate(recommendations[:5], 1):
            story.append(Paragraph(f"{i}. {recommendation}", self.styles['Recommendation']))
        
        story.append(PageBreak())
        
        # Risk assessment
        story.append(Paragraph("Risk Assessment", self.styles['Heading2']))
        
        framework_mapping = analysis_results.get('framework_mapping', {})
        cvss_dist = framework_mapping.get('cvss_distribution', {})
        
        if any(cvss_dist.values()):
            # Create risk distribution table
            risk_data = [
                ['Risk Level', 'Count', 'Description'],
                ['Critical', str(cvss_dist.get('critical', 0)), 'Immediate action required'],
                ['High', str(cvss_dist.get('high', 0)), 'Address within 24 hours'],
                ['Medium', str(cvss_dist.get('medium', 0)), 'Address within 1 week'],
                ['Low', str(cvss_dist.get('low', 0)), 'Address during next maintenance window']
            ]
            
            risk_table = Table(risk_data)
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(risk_table)
        
        return story
    
    def _generate_technical_pdf_content(self, analysis_results: Dict[str, Any]) -> List:
        """Generate technical PDF content"""
        story = []
        
        # Title
        story.append(Paragraph("Technical Security Analysis Report", self.styles['Title']))
        story.append(Spacer(1, 20))
        
        # Scan metadata
        metadata = analysis_results.get('analysis_metadata', {})
        story.append(Paragraph("Scan Information", self.styles['Heading2']))
        
        scan_info = [
            ['Parameter', 'Value'],
            ['Scan Date', metadata.get('timestamp', 'Unknown')],
            ['Analysis Version', metadata.get('analysis_version', '2.1.0')],
            ['LLM Provider', metadata.get('llm_provider', 'Unknown')],
            ['LLM Model', metadata.get('llm_model', 'Unknown')]
        ]
        
        scan_table = Table(scan_info)
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(scan_table)
        story.append(Spacer(1, 20))
        
        # Detailed threat analysis
        threats = analysis_results.get('threats', [])
        if threats:
            story.append(Paragraph("Detailed Threat Analysis", self.styles['Heading2']))
            
            for i, threat in enumerate(threats, 1):
                story.append(Paragraph(f"Threat #{i}: {threat.get('name', 'Unknown')}", self.styles['Heading3']))
                
                threat_details = [
                    ['Attribute', 'Value'],
                    ['Type', threat.get('type', 'Unknown')],
                    ['Severity', threat.get('severity', 'Unknown')],
                    ['Confidence', f"{threat.get('confidence', 0)}%"],
                    ['Source', threat.get('source', 'Unknown')],
                    ['CVSS Score', str(threat.get('cvss_score', 'N/A'))],
                    ['File Path', threat.get('file_path', 'N/A')],
                    ['Detection Time', threat.get('detection_time', 'Unknown')]
                ]
                
                threat_table = Table(threat_details)
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(threat_table)
                story.append(Spacer(1, 10))
                
                # Remediation
                remediation = threat.get('remediation', 'No specific remediation available')
                story.append(Paragraph(f"<b>Remediation:</b> {remediation}", self.styles['Normal']))
                story.append(Spacer(1, 15))
        
        # MITRE ATT&CK mapping
        framework_mapping = analysis_results.get('framework_mapping', {})
        mitre_data = framework_mapping.get('mitre_attack', {})
        
        if mitre_data.get('tactics_identified'):
            story.append(PageBreak())
            story.append(Paragraph("MITRE ATT&CK Framework Mapping", self.styles['Heading2']))
            
            tactics = mitre_data.get('tactics_identified', [])
            story.append(Paragraph(f"Identified Tactics: {', '.join(tactics)}", self.styles['Normal']))
            
            techniques = mitre_data.get('techniques_identified', [])
            if techniques:
                story.append(Paragraph(f"Identified Techniques: {', '.join(techniques[:10])}", self.styles['Normal']))
        
        return story
    
    def _generate_standard_pdf_content(self, analysis_results: Dict[str, Any]) -> List:
        """Generate standard PDF content"""
        story = []
        
        story.append(Paragraph("SentinelAI Security Report", self.styles['Title']))
        story.append(Spacer(1, 20))
        
        # Basic summary
        summary = analysis_results.get('summary', {})
        story.append(Paragraph(f"Security Score: {summary.get('security_score', 0)}/100", self.styles['Normal']))
        story.append(Paragraph(f"Total Threats: {summary.get('total_threats', 0)}", self.styles['Normal']))
        
        return story
    
    async def _generate_json_report(self, analysis_results: Dict[str, Any], report_type: str) -> Optional[Path]:
        """Generate JSON report for SIEM integration"""
        try:
            # Create reports directory
            reports_dir = Path.home() / ".sentinelai" / "reports"
            reports_dir.mkdir(exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sentinelai_report_{report_type}_{timestamp}.json"
            json_path = reports_dir / filename
            
            # Prepare JSON data
            json_data = {
                'report_metadata': {
                    'report_type': report_type,
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'SentinelAI v2.1',
                    'format_version': '1.0'
                },
                'analysis_results': analysis_results,
                'siem_integration': {
                    'format': 'CEF',  # Common Event Format
                    'events': self._convert_to_siem_events(analysis_results)
                }
            }
            
            # Write JSON file
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"JSON report generated: {json_path}")
            return json_path
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
            return None
    
    def _convert_to_siem_events(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert analysis results to SIEM-compatible events"""
        events = []
        
        threats = analysis_results.get('threats', [])
        for threat in threats:
            event = {
                'timestamp': threat.get('detection_time', datetime.now().isoformat()),
                'event_type': 'threat_detection',
                'severity': threat.get('severity', 'medium'),
                'source': threat.get('source', 'sentinelai'),
                'threat_name': threat.get('name', 'Unknown Threat'),
                'threat_type': threat.get('type', 'malware'),
                'confidence': threat.get('confidence', 50),
                'file_path': threat.get('file_path', ''),
                'cvss_score': threat.get('cvss_score', 0),
                'mitre_tactics': threat.get('mitre_tactics', []),
                'remediation': threat.get('remediation', ''),
                'raw_data': threat.get('original_data', {})
            }
            events.append(event)
        
        return events
    
    def _generate_report_content(self, analysis_results: Dict[str, Any], report_type: str) -> Dict[str, Any]:
        """Generate report content summary"""
        content = {
            'executive_summary': self._generate_executive_summary(analysis_results),
            'threat_overview': self._generate_threat_overview(analysis_results),
            'recommendations': analysis_results.get('recommendations', []),
            'framework_alignment': self._generate_framework_alignment(analysis_results)
        }
        
        if report_type == 'technical':
            content.update({
                'detailed_analysis': self._generate_detailed_analysis(analysis_results),
                'mitre_mapping': analysis_results.get('framework_mapping', {}).get('mitre_attack', {}),
                'raw_data': analysis_results
            })
        
        return content
    
    def _generate_executive_summary(self, analysis_results: Dict[str, Any]) -> str:
        """Generate executive summary text"""
        summary = analysis_results.get('summary', {})
        security_score = summary.get('security_score', 0)
        total_threats = summary.get('total_threats', 0)
        critical_threats = summary.get('critical_threats', 0)
        
        if total_threats == 0:
            return f"Security assessment completed with a score of {security_score}/100. No active threats detected. The environment appears secure with current protective measures in place."
        
        risk_level = summary.get('risk_level', 'medium')
        
        summary_text = f"Security assessment completed with a score of {security_score}/100. "
        summary_text += f"Analysis identified {total_threats} potential threats"
        
        if critical_threats > 0:
            summary_text += f", including {critical_threats} critical threats requiring immediate attention"
        
        summary_text += f". Overall risk level assessed as {risk_level.upper()}."
        
        return summary_text
    
    def _generate_threat_overview(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat overview statistics"""
        threats = analysis_results.get('threats', [])
        
        overview = {
            'total_count': len(threats),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': {},
            'by_source': {},
            'high_confidence_threats': 0
        }
        
        for threat in threats:
            # Count by severity
            severity = threat.get('severity', 'low')
            overview['by_severity'][severity] += 1
            
            # Count by type
            threat_type = threat.get('type', 'unknown')
            overview['by_type'][threat_type] = overview['by_type'].get(threat_type, 0) + 1
            
            # Count by source
            source = threat.get('source', 'unknown')
            overview['by_source'][source] = overview['by_source'].get(source, 0) + 1
            
            # High confidence threats
            if threat.get('confidence', 0) > 80:
                overview['high_confidence_threats'] += 1
        
        return overview
    
    def _generate_framework_alignment(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security framework alignment summary"""
        framework_mapping = analysis_results.get('framework_mapping', {})
        
        alignment = {
            'mitre_attack': {
                'tactics_covered': len(framework_mapping.get('mitre_attack', {}).get('tactics_identified', [])),
                'techniques_identified': len(framework_mapping.get('mitre_attack', {}).get('techniques_identified', []))
            },
            'nist_csf': {
                'functions_affected': framework_mapping.get('nist_csf', {}).get('functions_affected', [])
            },
            'cvss_distribution': framework_mapping.get('cvss_distribution', {})
        }
        
        return alignment
    
    def _generate_detailed_analysis(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed technical analysis"""
        ai_analysis = analysis_results.get('ai_analysis', {})
        
        return {
            'attack_timeline': ai_analysis.get('attack_timeline', []),
            'threat_landscape': ai_analysis.get('threat_landscape', {}),
            'key_insights': ai_analysis.get('key_insights', []),
            'attribution_analysis': ai_analysis.get('analytical_breakdown', {}).get('attribution_indicators', {}),
            'impact_assessment': ai_analysis.get('analytical_breakdown', {}).get('impact_assessment', {})
        }
    
    def _get_executive_template(self) -> Dict[str, Any]:
        """Get executive report template"""
        return {
            'sections': [
                'executive_summary',
                'security_score',
                'key_findings',
                'risk_assessment',
                'priority_recommendations'
            ],
            'style': 'business',
            'technical_detail': 'minimal'
        }
    
    def _get_technical_template(self) -> Dict[str, Any]:
        """Get technical report template"""
        return {
            'sections': [
                'scan_metadata',
                'detailed_threats',
                'mitre_mapping',
                'vulnerability_analysis',
                'remediation_details',
                'raw_data'
            ],
            'style': 'technical',
            'technical_detail': 'comprehensive'
        }
    
    def _get_compliance_template(self) -> Dict[str, Any]:
        """Get compliance report template"""
        return {
            'sections': [
                'compliance_overview',
                'framework_alignment',
                'gap_analysis',
                'remediation_roadmap'
            ],
            'style': 'compliance',
            'technical_detail': 'moderate'
        }
    
    def generate_executive_report(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive report synchronously"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            return loop.run_until_complete(self.execute(analysis_results, "executive"))
        finally:
            loop.close()
    
    def generate_technical_report(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical report synchronously"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            return loop.run_until_complete(self.execute(analysis_results, "technical"))
        finally:
            loop.close()
