"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - REAL PDF REPORT GENERATOR
Enterprise-grade PDF report generation for security findings

This module provides:
- Professional PDF report generation
- Security scan reports
- Person intelligence reports
- Network analysis reports
- Attack analysis reports
- Vulnerability assessment reports

Classification: TOP SECRET // NSOC // TIER-0
"""

import io
import os
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, ListFlowable, ListItem, HRFlowable
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart


@dataclass
class ReportMetadata:
    title: str
    subtitle: str
    classification: str
    author: str
    organization: str
    date: str
    report_id: str
    version: str


class PDFReportGenerator:
    """Enterprise-grade PDF report generator"""
    
    def __init__(self, output_dir: str = "/tmp/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1a1a2e')
        ))
        
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#4a4a6a')
        ))
        
        self.styles.add(ParagraphStyle(
            name='Classification',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_CENTER,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#1a1a2e'),
            borderWidth=1,
            borderColor=colors.HexColor('#1a1a2e'),
            borderPadding=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
            textColor=colors.HexColor('#2a2a4e')
        ))
        
        if 'BodyText' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='BodyText',
                parent=self.styles['Normal'],
                fontSize=10,
                spaceAfter=8,
                alignment=TA_JUSTIFY,
                leading=14
            ))
        else:
            self.styles['BodyText'].fontSize = 10
            self.styles['BodyText'].spaceAfter = 8
            self.styles['BodyText'].alignment = TA_JUSTIFY
            self.styles['BodyText'].leading = 14
        
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            spaceAfter=5,
            textColor=colors.HexColor('#333333')
        ))
        
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='High',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#ff6600'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Medium',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#ffcc00'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Low',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.green,
            fontName='Helvetica-Bold'
        ))
    
    def _create_header(self, metadata: ReportMetadata) -> List:
        """Create report header elements"""
        elements = []
        
        elements.append(Paragraph(
            f"CLASSIFICATION: {metadata.classification}",
            self.styles['Classification']
        ))
        elements.append(Spacer(1, 20))
        
        elements.append(Paragraph(metadata.title, self.styles['ReportTitle']))
        elements.append(Paragraph(metadata.subtitle, self.styles['ReportSubtitle']))
        
        elements.append(Spacer(1, 30))
        
        info_data = [
            ['Organization:', metadata.organization],
            ['Author:', metadata.author],
            ['Date:', metadata.date],
            ['Report ID:', metadata.report_id],
            ['Version:', metadata.version]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a1a2e')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(info_table)
        
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1a1a2e')))
        elements.append(Spacer(1, 20))
        
        return elements
    
    def _create_executive_summary(self, summary: Dict[str, Any]) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        
        if 'overview' in summary:
            elements.append(Paragraph(summary['overview'], self.styles['BodyText']))
        
        if 'key_findings' in summary:
            elements.append(Paragraph("Key Findings:", self.styles['SubsectionHeader']))
            for finding in summary['key_findings']:
                elements.append(Paragraph(f"• {finding}", self.styles['Finding']))
        
        if 'risk_level' in summary:
            risk_style = self.styles.get(summary['risk_level'], self.styles['BodyText'])
            elements.append(Spacer(1, 10))
            elements.append(Paragraph(
                f"Overall Risk Level: {summary['risk_level'].upper()}",
                risk_style
            ))
        
        if 'statistics' in summary:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Statistics:", self.styles['SubsectionHeader']))
            
            stats_data = [[k, str(v)] for k, v in summary['statistics'].items()]
            stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5f5f5')),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(stats_table)
        
        return elements
    
    def _create_findings_section(self, findings: List[Dict[str, Any]]) -> List:
        """Create detailed findings section"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("DETAILED FINDINGS", self.styles['SectionHeader']))
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))
        
        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.get('severity', 'INFO')
            severity_style = self.styles.get(severity.capitalize(), self.styles['BodyText'])
            
            elements.append(Spacer(1, 15))
            elements.append(Paragraph(
                f"Finding #{i}: {finding.get('title', 'Untitled')}",
                self.styles['SubsectionHeader']
            ))
            
            elements.append(Paragraph(f"Severity: {severity}", severity_style))
            
            if 'description' in finding:
                elements.append(Paragraph(finding['description'], self.styles['BodyText']))
            
            if 'affected_assets' in finding:
                elements.append(Paragraph("Affected Assets:", self.styles['Finding']))
                for asset in finding['affected_assets']:
                    elements.append(Paragraph(f"  • {asset}", self.styles['Finding']))
            
            if 'evidence' in finding:
                elements.append(Paragraph("Evidence:", self.styles['Finding']))
                elements.append(Paragraph(finding['evidence'], self.styles['Finding']))
            
            if 'recommendation' in finding:
                elements.append(Paragraph("Recommendation:", self.styles['Finding']))
                elements.append(Paragraph(finding['recommendation'], self.styles['BodyText']))
            
            if 'cvss_score' in finding:
                elements.append(Paragraph(
                    f"CVSS Score: {finding['cvss_score']}",
                    self.styles['Finding']
                ))
            
            if 'cve_ids' in finding:
                elements.append(Paragraph(
                    f"CVE IDs: {', '.join(finding['cve_ids'])}",
                    self.styles['Finding']
                ))
        
        return elements
    
    def _create_vulnerability_table(self, vulnerabilities: List[Dict[str, Any]]) -> List:
        """Create vulnerability summary table"""
        elements = []
        
        elements.append(Paragraph("VULNERABILITY SUMMARY", self.styles['SectionHeader']))
        
        headers = ['ID', 'Title', 'Severity', 'CVSS', 'Status']
        data = [headers]
        
        for vuln in vulnerabilities:
            data.append([
                vuln.get('id', 'N/A'),
                vuln.get('title', 'Unknown')[:40],
                vuln.get('severity', 'Unknown'),
                str(vuln.get('cvss_score', 'N/A')),
                vuln.get('status', 'Open')
            ])
        
        table = Table(data, colWidths=[1*inch, 2.5*inch, 1*inch, 0.8*inch, 1*inch])
        
        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ('PADDING', (0, 0), (-1, -1), 6),
        ])
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', '').upper()
            if severity == 'CRITICAL':
                style.add('TEXTCOLOR', (2, i), (2, i), colors.red)
            elif severity == 'HIGH':
                style.add('TEXTCOLOR', (2, i), (2, i), colors.HexColor('#ff6600'))
            elif severity == 'MEDIUM':
                style.add('TEXTCOLOR', (2, i), (2, i), colors.HexColor('#cc9900'))
            elif severity == 'LOW':
                style.add('TEXTCOLOR', (2, i), (2, i), colors.green)
        
        table.setStyle(style)
        elements.append(table)
        
        return elements
    
    def _create_network_diagram_section(self, network_data: Dict[str, Any]) -> List:
        """Create network topology section"""
        elements = []
        
        elements.append(Paragraph("NETWORK TOPOLOGY", self.styles['SectionHeader']))
        
        if 'hosts' in network_data:
            elements.append(Paragraph("Discovered Hosts:", self.styles['SubsectionHeader']))
            
            headers = ['IP Address', 'Hostname', 'OS', 'Open Ports', 'Services']
            data = [headers]
            
            for host in network_data['hosts']:
                data.append([
                    host.get('ip', 'N/A'),
                    host.get('hostname', 'Unknown'),
                    host.get('os', 'Unknown'),
                    str(host.get('open_ports', 0)),
                    ', '.join(host.get('services', []))[:30]
                ])
            
            table = Table(data, colWidths=[1.2*inch, 1.5*inch, 1.2*inch, 0.8*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(table)
        
        return elements
    
    def _create_person_intelligence_section(self, person_data: Dict[str, Any]) -> List:
        """Create person intelligence report section"""
        elements = []
        
        elements.append(Paragraph("PERSON INTELLIGENCE REPORT", self.styles['SectionHeader']))
        
        if 'subject' in person_data:
            subject = person_data['subject']
            elements.append(Paragraph("Subject Information:", self.styles['SubsectionHeader']))
            
            info_data = [
                ['Name:', subject.get('name', 'Unknown')],
                ['Known Aliases:', ', '.join(subject.get('aliases', []))],
                ['Date of Birth:', subject.get('dob', 'Unknown')],
                ['Location:', subject.get('location', 'Unknown')],
                ['Nationality:', subject.get('nationality', 'Unknown')],
                ['Risk Level:', subject.get('risk_level', 'Unknown')],
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5f5f5')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(info_table)
        
        if 'social_profiles' in person_data:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Social Media Profiles:", self.styles['SubsectionHeader']))
            
            for profile in person_data['social_profiles']:
                elements.append(Paragraph(
                    f"• {profile.get('platform', 'Unknown')}: {profile.get('username', 'N/A')} "
                    f"(Followers: {profile.get('followers', 'N/A')})",
                    self.styles['Finding']
                ))
        
        if 'connections' in person_data:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Known Connections:", self.styles['SubsectionHeader']))
            
            headers = ['Name', 'Relationship', 'Confidence', 'Notes']
            data = [headers]
            
            for conn in person_data['connections']:
                data.append([
                    conn.get('name', 'Unknown'),
                    conn.get('relationship', 'Unknown'),
                    conn.get('confidence', 'Low'),
                    conn.get('notes', '')[:30]
                ])
            
            table = Table(data, colWidths=[1.5*inch, 1.2*inch, 1*inch, 2.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(table)
        
        if 'timeline' in person_data:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Activity Timeline:", self.styles['SubsectionHeader']))
            
            for event in person_data['timeline']:
                elements.append(Paragraph(
                    f"[{event.get('date', 'Unknown')}] {event.get('event', 'Unknown event')}",
                    self.styles['Finding']
                ))
        
        return elements
    
    def _create_attack_analysis_section(self, attack_data: Dict[str, Any]) -> List:
        """Create attack analysis report section"""
        elements = []
        
        elements.append(Paragraph("ATTACK ANALYSIS REPORT", self.styles['SectionHeader']))
        
        if 'attack_summary' in attack_data:
            summary = attack_data['attack_summary']
            elements.append(Paragraph("Attack Summary:", self.styles['SubsectionHeader']))
            
            info_data = [
                ['Attack Type:', summary.get('type', 'Unknown')],
                ['Attack Vector:', summary.get('vector', 'Unknown')],
                ['Source IP:', summary.get('source_ip', 'Unknown')],
                ['Target:', summary.get('target', 'Unknown')],
                ['Timestamp:', summary.get('timestamp', 'Unknown')],
                ['Severity:', summary.get('severity', 'Unknown')],
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fff0f0')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.red),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(info_table)
        
        if 'malware_analysis' in attack_data:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Malware Analysis:", self.styles['SubsectionHeader']))
            
            malware = attack_data['malware_analysis']
            elements.append(Paragraph(f"File Hash (SHA256): {malware.get('sha256', 'N/A')}", self.styles['Finding']))
            elements.append(Paragraph(f"File Type: {malware.get('file_type', 'N/A')}", self.styles['Finding']))
            elements.append(Paragraph(f"Detection Rate: {malware.get('detection_rate', 'N/A')}", self.styles['Finding']))
            
            if 'behaviors' in malware:
                elements.append(Paragraph("Observed Behaviors:", self.styles['Finding']))
                for behavior in malware['behaviors']:
                    elements.append(Paragraph(f"  • {behavior}", self.styles['Finding']))
            
            if 'iocs' in malware:
                elements.append(Paragraph("Indicators of Compromise (IOCs):", self.styles['Finding']))
                for ioc in malware['iocs']:
                    elements.append(Paragraph(f"  • [{ioc.get('type', 'Unknown')}] {ioc.get('value', 'N/A')}", self.styles['Finding']))
        
        if 'attack_chain' in attack_data:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Attack Chain (Kill Chain):", self.styles['SubsectionHeader']))
            
            for i, stage in enumerate(attack_data['attack_chain'], 1):
                elements.append(Paragraph(
                    f"{i}. {stage.get('stage', 'Unknown')}: {stage.get('description', 'N/A')}",
                    self.styles['Finding']
                ))
        
        return elements
    
    def _create_footer(self, metadata: ReportMetadata) -> List:
        """Create report footer"""
        elements = []
        
        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        elements.append(Spacer(1, 10))
        
        elements.append(Paragraph(
            f"Report generated by GLOBAL INTELLIGENCE SECURITY COMMAND CENTER",
            self.styles['Finding']
        ))
        elements.append(Paragraph(
            f"Classification: {metadata.classification} | Report ID: {metadata.report_id}",
            self.styles['Classification']
        ))
        
        return elements
    
    def generate_security_scan_report(
        self,
        metadata: ReportMetadata,
        summary: Dict[str, Any],
        findings: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        network_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate comprehensive security scan report"""
        
        filename = f"security_scan_{metadata.report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        elements = []
        
        elements.extend(self._create_header(metadata))
        elements.extend(self._create_executive_summary(summary))
        
        if vulnerabilities:
            elements.append(PageBreak())
            elements.extend(self._create_vulnerability_table(vulnerabilities))
        
        if findings:
            elements.extend(self._create_findings_section(findings))
        
        if network_data:
            elements.append(PageBreak())
            elements.extend(self._create_network_diagram_section(network_data))
        
        elements.extend(self._create_footer(metadata))
        
        doc.build(elements)
        
        return filepath
    
    def generate_person_intelligence_report(
        self,
        metadata: ReportMetadata,
        person_data: Dict[str, Any]
    ) -> str:
        """Generate person intelligence report"""
        
        filename = f"person_intel_{metadata.report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        elements = []
        
        elements.extend(self._create_header(metadata))
        elements.extend(self._create_person_intelligence_section(person_data))
        elements.extend(self._create_footer(metadata))
        
        doc.build(elements)
        
        return filepath
    
    def generate_attack_analysis_report(
        self,
        metadata: ReportMetadata,
        attack_data: Dict[str, Any]
    ) -> str:
        """Generate attack analysis report"""
        
        filename = f"attack_analysis_{metadata.report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        elements = []
        
        elements.extend(self._create_header(metadata))
        elements.extend(self._create_attack_analysis_section(attack_data))
        elements.extend(self._create_footer(metadata))
        
        doc.build(elements)
        
        return filepath
    
    def generate_combined_report(
        self,
        metadata: ReportMetadata,
        summary: Dict[str, Any],
        findings: List[Dict[str, Any]] = None,
        vulnerabilities: List[Dict[str, Any]] = None,
        network_data: Dict[str, Any] = None,
        person_data: Dict[str, Any] = None,
        attack_data: Dict[str, Any] = None
    ) -> str:
        """Generate comprehensive combined report"""
        
        filename = f"combined_report_{metadata.report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        elements = []
        
        elements.extend(self._create_header(metadata))
        elements.extend(self._create_executive_summary(summary))
        
        if vulnerabilities:
            elements.append(PageBreak())
            elements.extend(self._create_vulnerability_table(vulnerabilities))
        
        if findings:
            elements.extend(self._create_findings_section(findings))
        
        if network_data:
            elements.append(PageBreak())
            elements.extend(self._create_network_diagram_section(network_data))
        
        if person_data:
            elements.append(PageBreak())
            elements.extend(self._create_person_intelligence_section(person_data))
        
        if attack_data:
            elements.append(PageBreak())
            elements.extend(self._create_attack_analysis_section(attack_data))
        
        elements.extend(self._create_footer(metadata))
        
        doc.build(elements)
        
        return filepath


def create_pdf_generator(output_dir: str = "/tmp/reports") -> PDFReportGenerator:
    """Factory function to create PDF generator instance"""
    return PDFReportGenerator(output_dir)
