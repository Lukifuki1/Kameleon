"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - BLUE TEAM OPERATIONS MODULE
Complete implementation of blue-team-operations.ts.predloga

This module implements:
- Threat Hunting (hypothesis-driven, IOC-based, anomaly-based)
- Incident Response (detection, containment, eradication, recovery)
- Digital Forensics (disk, memory, network, malware)
- YARA Rules Engine
- Sigma Rules Engine
- IOC Management
- Threat Intelligence Integration
- SOC Automation

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import socket
import time
import json
import base64
import secrets
import re
import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class DefensiveOperationType(str, Enum):
    THREAT_HUNTING = "THREAT_HUNTING"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    FORENSIC_ANALYSIS = "FORENSIC_ANALYSIS"
    MALWARE_ANALYSIS = "MALWARE_ANALYSIS"
    VULNERABILITY_MANAGEMENT = "VULNERABILITY_MANAGEMENT"
    SECURITY_MONITORING = "SECURITY_MONITORING"
    LOG_ANALYSIS = "LOG_ANALYSIS"
    NETWORK_DEFENSE = "NETWORK_DEFENSE"
    ENDPOINT_PROTECTION = "ENDPOINT_PROTECTION"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"


class DetectionType(str, Enum):
    SIGNATURE_BASED = "SIGNATURE_BASED"
    ANOMALY_BASED = "ANOMALY_BASED"
    BEHAVIOR_BASED = "BEHAVIOR_BASED"
    HEURISTIC = "HEURISTIC"
    MACHINE_LEARNING = "MACHINE_LEARNING"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    IOC_MATCHING = "IOC_MATCHING"
    YARA_RULE = "YARA_RULE"
    SIGMA_RULE = "SIGMA_RULE"
    CUSTOM_RULE = "CUSTOM_RULE"


class ThreatCategory(str, Enum):
    MALWARE = "MALWARE"
    RANSOMWARE = "RANSOMWARE"
    APT = "APT"
    PHISHING = "PHISHING"
    INSIDER_THREAT = "INSIDER_THREAT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXPLOITATION = "EXPLOITATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    PERSISTENCE = "PERSISTENCE"
    DEFENSE_EVASION = "DEFENSE_EVASION"


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentPhase(str, Enum):
    PREPARATION = "PREPARATION"
    DETECTION = "DETECTION"
    ANALYSIS = "ANALYSIS"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    POST_INCIDENT = "POST_INCIDENT"
    CLOSED = "CLOSED"


class ForensicArtifactType(str, Enum):
    FILE_SYSTEM = "FILE_SYSTEM"
    REGISTRY = "REGISTRY"
    MEMORY = "MEMORY"
    NETWORK = "NETWORK"
    LOG = "LOG"
    BROWSER = "BROWSER"
    EMAIL = "EMAIL"
    PROCESS = "PROCESS"
    SERVICE = "SERVICE"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    USER_ACTIVITY = "USER_ACTIVITY"
    PERSISTENCE = "PERSISTENCE"
    MALWARE = "MALWARE"


class HuntingHypothesisType(str, Enum):
    INTELLIGENCE_DRIVEN = "INTELLIGENCE_DRIVEN"
    SITUATIONAL_AWARENESS = "SITUATIONAL_AWARENESS"
    DOMAIN_EXPERTISE = "DOMAIN_EXPERTISE"
    ANALYTICS_DRIVEN = "ANALYTICS_DRIVEN"
    TTP_BASED = "TTP_BASED"


@dataclass
class IOC:
    ioc_id: str
    ioc_type: str
    value: str
    confidence: float
    severity: AlertSeverity
    source: str
    first_seen: str
    last_seen: str
    tags: List[str]
    context: Dict[str, Any]
    related_iocs: List[str]


@dataclass
class YARARule:
    rule_id: str
    name: str
    description: str
    author: str
    date: str
    reference: List[str]
    tags: List[str]
    rule_content: str
    severity: AlertSeverity
    enabled: bool


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    author: str
    date: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    condition: str
    level: str
    tags: List[str]
    references: List[str]
    enabled: bool


@dataclass
class ThreatHunt:
    hunt_id: str
    name: str
    hypothesis: str
    hypothesis_type: HuntingHypothesisType
    data_sources: List[str]
    techniques: List[str]
    queries: List[Dict[str, str]]
    findings: List[Dict[str, Any]]
    status: str
    created_at: str
    completed_at: Optional[str]
    analyst: str


@dataclass
class Incident:
    incident_id: str
    title: str
    description: str
    severity: AlertSeverity
    category: ThreatCategory
    phase: IncidentPhase
    affected_assets: List[str]
    indicators: List[IOC]
    timeline: List[Dict[str, Any]]
    containment_actions: List[Dict[str, Any]]
    eradication_actions: List[Dict[str, Any]]
    recovery_actions: List[Dict[str, Any]]
    lessons_learned: List[str]
    created_at: str
    updated_at: str
    closed_at: Optional[str]
    assigned_to: List[str]


@dataclass
class ForensicCase:
    case_id: str
    name: str
    description: str
    case_type: str
    status: str
    evidence: List[Dict[str, Any]]
    artifacts: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    chain_of_custody: List[Dict[str, Any]]
    created_at: str
    updated_at: str
    analyst: str


class IOCManager:
    """Indicator of Compromise management"""
    
    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self.ioc_types = [
            "ip", "domain", "url", "email", "hash_md5", "hash_sha1", "hash_sha256",
            "filename", "filepath", "registry", "mutex", "user_agent", "ja3",
            "ja3s", "jarm", "bitcoin", "ethereum", "monero", "yara", "sigma"
        ]
    
    def add_ioc(self, ioc_type: str, value: str, confidence: float,
                severity: AlertSeverity, source: str, tags: List[str] = None,
                context: Dict[str, Any] = None) -> IOC:
        """Add new IOC"""
        ioc = IOC(
            ioc_id=f"IOC-{secrets.token_hex(8).upper()}",
            ioc_type=ioc_type,
            value=value,
            confidence=confidence,
            severity=severity,
            source=source,
            first_seen=datetime.utcnow().isoformat(),
            last_seen=datetime.utcnow().isoformat(),
            tags=tags or [],
            context=context or {},
            related_iocs=[]
        )
        self.iocs[ioc.ioc_id] = ioc
        return ioc
    
    def search_iocs(self, query: str, ioc_type: str = None) -> List[IOC]:
        """Search IOCs"""
        results = []
        for ioc in self.iocs.values():
            if ioc_type and ioc.ioc_type != ioc_type:
                continue
            if query.lower() in ioc.value.lower():
                results.append(ioc)
        return results
    
    def match_ioc(self, value: str) -> Optional[IOC]:
        """Check if value matches any IOC"""
        for ioc in self.iocs.values():
            if ioc.value.lower() == value.lower():
                ioc.last_seen = datetime.utcnow().isoformat()
                return ioc
        return None
    
    def bulk_import(self, iocs_data: List[Dict[str, Any]], source: str) -> int:
        """Bulk import IOCs"""
        imported = 0
        for data in iocs_data:
            try:
                self.add_ioc(
                    ioc_type=data.get("type", "unknown"),
                    value=data.get("value", ""),
                    confidence=data.get("confidence", 0.5),
                    severity=AlertSeverity(data.get("severity", "MEDIUM")),
                    source=source,
                    tags=data.get("tags", []),
                    context=data.get("context", {})
                )
                imported += 1
            except ValueError as e:
                logger.debug(f"Failed to import IOC: {e}")
            except KeyError as e:
                logger.debug(f"Missing required field in IOC data: {e}")
        return imported
    
    def export_iocs(self, format: str = "json") -> str:
        """Export IOCs"""
        if format == "json":
            return json.dumps([asdict(ioc) for ioc in self.iocs.values()], indent=2)
        elif format == "csv":
            lines = ["type,value,confidence,severity,source,first_seen,last_seen"]
            for ioc in self.iocs.values():
                lines.append(f"{ioc.ioc_type},{ioc.value},{ioc.confidence},{ioc.severity.value},{ioc.source},{ioc.first_seen},{ioc.last_seen}")
            return "\n".join(lines)
        elif format == "stix":
            # STIX 2.1 format
            bundle = {
                "type": "bundle",
                "id": f"bundle--{secrets.token_hex(16)}",
                "objects": []
            }
            for ioc in self.iocs.values():
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--{secrets.token_hex(16)}",
                    "created": ioc.first_seen,
                    "modified": ioc.last_seen,
                    "pattern": f"[{ioc.ioc_type}:value = '{ioc.value}']",
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen
                }
                bundle["objects"].append(indicator)
            return json.dumps(bundle, indent=2)
        return ""


class YARARulesEngine:
    """YARA rules management and matching"""
    
    def __init__(self):
        self.rules: Dict[str, YARARule] = {}
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default YARA rules"""
        default_rules = [
            {
                "name": "suspicious_powershell",
                "description": "Detects suspicious PowerShell commands",
                "tags": ["powershell", "execution"],
                "rule_content": '''
rule suspicious_powershell {
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "GISC"
        severity = "HIGH"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "-encodedcommand" nocase
        $ps4 = "bypass" nocase
        $ps5 = "hidden" nocase
        $ps6 = "invoke-expression" nocase
        $ps7 = "downloadstring" nocase
        $ps8 = "webclient" nocase
    condition:
        $ps1 and (2 of ($ps2, $ps3, $ps4, $ps5, $ps6, $ps7, $ps8))
}
'''
            },
            {
                "name": "mimikatz_strings",
                "description": "Detects Mimikatz strings",
                "tags": ["mimikatz", "credential_theft"],
                "rule_content": '''
rule mimikatz_strings {
    meta:
        description = "Detects Mimikatz strings"
        author = "GISC"
        severity = "CRITICAL"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa" nocase
        $m3 = "kerberos::list" nocase
        $m4 = "lsadump::sam" nocase
        $m5 = "privilege::debug" nocase
        $m6 = "token::elevate" nocase
    condition:
        2 of them
}
'''
            },
            {
                "name": "webshell_generic",
                "description": "Detects generic webshell patterns",
                "tags": ["webshell", "persistence"],
                "rule_content": '''
rule webshell_generic {
    meta:
        description = "Detects generic webshell patterns"
        author = "GISC"
        severity = "HIGH"
    strings:
        $php1 = "<?php" nocase
        $php2 = "eval(" nocase
        $php3 = "base64_decode(" nocase
        $php4 = "shell_exec(" nocase
        $php5 = "system(" nocase
        $php6 = "passthru(" nocase
        $php7 = "exec(" nocase
        $asp1 = "<%@ " nocase
        $asp2 = "execute(" nocase
        $jsp1 = "<%@ page" nocase
        $jsp2 = "Runtime.getRuntime()" nocase
    condition:
        ($php1 and 2 of ($php2, $php3, $php4, $php5, $php6, $php7)) or
        ($asp1 and $asp2) or
        ($jsp1 and $jsp2)
}
'''
            },
            {
                "name": "ransomware_note",
                "description": "Detects ransomware note patterns",
                "tags": ["ransomware", "impact"],
                "rule_content": '''
rule ransomware_note {
    meta:
        description = "Detects ransomware note patterns"
        author = "GISC"
        severity = "CRITICAL"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "bitcoin" nocase
        $r3 = "decrypt" nocase
        $r4 = "ransom" nocase
        $r5 = "pay" nocase
        $r6 = "wallet" nocase
        $r7 = "tor browser" nocase
        $r8 = ".onion" nocase
    condition:
        3 of them
}
'''
            }
        ]
        
        for rule_data in default_rules:
            rule = YARARule(
                rule_id=f"YARA-{secrets.token_hex(8).upper()}",
                name=rule_data["name"],
                description=rule_data["description"],
                author="GISC",
                date=datetime.utcnow().strftime("%Y-%m-%d"),
                reference=[],
                tags=rule_data["tags"],
                rule_content=rule_data["rule_content"],
                severity=AlertSeverity.HIGH,
                enabled=True
            )
            self.rules[rule.rule_id] = rule
    
    def add_rule(self, name: str, description: str, rule_content: str,
                 tags: List[str], severity: AlertSeverity) -> YARARule:
        """Add new YARA rule"""
        rule = YARARule(
            rule_id=f"YARA-{secrets.token_hex(8).upper()}",
            name=name,
            description=description,
            author="GISC",
            date=datetime.utcnow().strftime("%Y-%m-%d"),
            reference=[],
            tags=tags,
            rule_content=rule_content,
            severity=severity,
            enabled=True
        )
        self.rules[rule.rule_id] = rule
        return rule
    
    def match_content(self, content: str) -> List[Dict[str, Any]]:
        """Match content against YARA rules"""
        matches = []
        content_lower = content.lower()
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            # Extract strings from rule
            strings_match = re.findall(r'\$\w+\s*=\s*"([^"]+)"', rule.rule_content)
            
            matched_strings = []
            for pattern in strings_match:
                if pattern.lower() in content_lower:
                    matched_strings.append(pattern)
            
            # Simple condition evaluation (at least 2 matches)
            if len(matched_strings) >= 2:
                matches.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity.value,
                    "matched_strings": matched_strings,
                    "tags": rule.tags
                })
        
        return matches
    
    def list_rules(self) -> List[YARARule]:
        """List all YARA rules"""
        return list(self.rules.values())


class SigmaRulesEngine:
    """Sigma rules management and matching"""
    
    def __init__(self):
        self.rules: Dict[str, SigmaRule] = {}
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default Sigma rules"""
        default_rules = [
            {
                "title": "Suspicious PowerShell Download",
                "description": "Detects PowerShell download cradles",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "CommandLine|contains|all": ["powershell", "downloadstring"]
                    }
                },
                "condition": "selection",
                "level": "high",
                "tags": ["attack.execution", "attack.t1059.001"]
            },
            {
                "title": "Mimikatz Command Line",
                "description": "Detects Mimikatz command line usage",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "CommandLine|contains": ["sekurlsa", "lsadump", "kerberos::"]
                    }
                },
                "condition": "selection",
                "level": "critical",
                "tags": ["attack.credential_access", "attack.t1003"]
            },
            {
                "title": "Suspicious Scheduled Task Creation",
                "description": "Detects suspicious scheduled task creation",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "CommandLine|contains|all": ["schtasks", "/create"]
                    },
                    "filter": {
                        "User": ["SYSTEM", "NT AUTHORITY\\SYSTEM"]
                    }
                },
                "condition": "selection and not filter",
                "level": "medium",
                "tags": ["attack.persistence", "attack.t1053.005"]
            },
            {
                "title": "Lateral Movement via PsExec",
                "description": "Detects PsExec usage for lateral movement",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image|endswith": "\\psexec.exe"
                    }
                },
                "condition": "selection",
                "level": "high",
                "tags": ["attack.lateral_movement", "attack.t1570"]
            }
        ]
        
        for rule_data in default_rules:
            rule = SigmaRule(
                rule_id=f"SIGMA-{secrets.token_hex(8).upper()}",
                title=rule_data["title"],
                description=rule_data["description"],
                author="GISC",
                date=datetime.utcnow().strftime("%Y/%m/%d"),
                logsource=rule_data["logsource"],
                detection=rule_data["detection"],
                condition=rule_data["condition"],
                level=rule_data["level"],
                tags=rule_data["tags"],
                references=[],
                enabled=True
            )
            self.rules[rule.rule_id] = rule
    
    def add_rule(self, title: str, description: str, logsource: Dict[str, str],
                 detection: Dict[str, Any], condition: str, level: str,
                 tags: List[str]) -> SigmaRule:
        """Add new Sigma rule"""
        rule = SigmaRule(
            rule_id=f"SIGMA-{secrets.token_hex(8).upper()}",
            title=title,
            description=description,
            author="GISC",
            date=datetime.utcnow().strftime("%Y/%m/%d"),
            logsource=logsource,
            detection=detection,
            condition=condition,
            level=level,
            tags=tags,
            references=[],
            enabled=True
        )
        self.rules[rule.rule_id] = rule
        return rule
    
    def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match event against Sigma rules"""
        matches = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            # Simple matching logic
            detection = rule.detection
            if "selection" in detection:
                selection = detection["selection"]
                matched = True
                
                for key, value in selection.items():
                    # Handle contains modifier
                    if "|contains" in key:
                        field = key.split("|")[0]
                        event_value = str(event.get(field, "")).lower()
                        
                        if isinstance(value, list):
                            if "|all" in key:
                                if not all(v.lower() in event_value for v in value):
                                    matched = False
                            else:
                                if not any(v.lower() in event_value for v in value):
                                    matched = False
                        else:
                            if value.lower() not in event_value:
                                matched = False
                    else:
                        if event.get(key) != value:
                            matched = False
                
                if matched:
                    matches.append({
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "level": rule.level,
                        "tags": rule.tags,
                        "description": rule.description
                    })
        
        return matches
    
    def list_rules(self) -> List[SigmaRule]:
        """List all Sigma rules"""
        return list(self.rules.values())


class ThreatHuntingEngine:
    """Threat hunting operations"""
    
    def __init__(self):
        self.hunts: Dict[str, ThreatHunt] = {}
        self.hunting_playbooks = self._initialize_playbooks()
    
    def _initialize_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize hunting playbooks"""
        return {
            "lateral_movement": {
                "name": "Lateral Movement Hunt",
                "hypothesis": "Adversaries may be using lateral movement techniques to spread across the network",
                "data_sources": ["Windows Security Logs", "Network Traffic", "EDR Telemetry"],
                "techniques": ["T1021", "T1570", "T1080"],
                "queries": [
                    {"type": "windows_event", "query": "EventID:4624 AND LogonType:3"},
                    {"type": "network", "query": "dst_port:(445 OR 135 OR 5985 OR 5986)"},
                    {"type": "process", "query": "process_name:(psexec.exe OR wmic.exe OR winrm.cmd)"}
                ]
            },
            "credential_theft": {
                "name": "Credential Theft Hunt",
                "hypothesis": "Adversaries may be attempting to steal credentials from memory or credential stores",
                "data_sources": ["Windows Security Logs", "Sysmon", "EDR Telemetry"],
                "techniques": ["T1003", "T1555", "T1552"],
                "queries": [
                    {"type": "process", "query": "process_name:lsass.exe AND access_mask:0x1010"},
                    {"type": "windows_event", "query": "EventID:4656 AND ObjectName:*SAM*"},
                    {"type": "file", "query": "file_path:*\\AppData\\*\\Login Data"}
                ]
            },
            "persistence": {
                "name": "Persistence Hunt",
                "hypothesis": "Adversaries may have established persistence mechanisms",
                "data_sources": ["Windows Registry", "Scheduled Tasks", "Services"],
                "techniques": ["T1547", "T1053", "T1543"],
                "queries": [
                    {"type": "registry", "query": "path:*\\Run* OR path:*\\RunOnce*"},
                    {"type": "scheduled_task", "query": "action:create"},
                    {"type": "service", "query": "start_type:auto AND path:*\\temp\\*"}
                ]
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Hunt",
                "hypothesis": "Adversaries may be exfiltrating data from the network",
                "data_sources": ["Network Traffic", "DNS Logs", "Proxy Logs"],
                "techniques": ["T1041", "T1048", "T1567"],
                "queries": [
                    {"type": "network", "query": "bytes_out:>10000000"},
                    {"type": "dns", "query": "query_length:>50"},
                    {"type": "proxy", "query": "category:file_sharing OR category:cloud_storage"}
                ]
            },
            "command_and_control": {
                "name": "C2 Communication Hunt",
                "hypothesis": "Adversaries may have established C2 channels",
                "data_sources": ["Network Traffic", "DNS Logs", "Proxy Logs"],
                "techniques": ["T1071", "T1095", "T1572"],
                "queries": [
                    {"type": "network", "query": "dst_port:(443 OR 80) AND bytes_ratio:<0.1"},
                    {"type": "dns", "query": "query_type:TXT AND response_length:>100"},
                    {"type": "beacon", "query": "interval_variance:<0.1"}
                ]
            }
        }
    
    def create_hunt(self, name: str, hypothesis: str, hypothesis_type: HuntingHypothesisType,
                   data_sources: List[str], techniques: List[str], analyst: str) -> ThreatHunt:
        """Create new threat hunt"""
        hunt = ThreatHunt(
            hunt_id=f"HUNT-{secrets.token_hex(8).upper()}",
            name=name,
            hypothesis=hypothesis,
            hypothesis_type=hypothesis_type,
            data_sources=data_sources,
            techniques=techniques,
            queries=[],
            findings=[],
            status="active",
            created_at=datetime.utcnow().isoformat(),
            completed_at=None,
            analyst=analyst
        )
        self.hunts[hunt.hunt_id] = hunt
        return hunt
    
    def execute_playbook(self, playbook_name: str, analyst: str) -> ThreatHunt:
        """Execute a hunting playbook"""
        playbook = self.hunting_playbooks.get(playbook_name)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_name}")
        
        hunt = ThreatHunt(
            hunt_id=f"HUNT-{secrets.token_hex(8).upper()}",
            name=playbook["name"],
            hypothesis=playbook["hypothesis"],
            hypothesis_type=HuntingHypothesisType.TTP_BASED,
            data_sources=playbook["data_sources"],
            techniques=playbook["techniques"],
            queries=playbook["queries"],
            findings=[],
            status="active",
            created_at=datetime.utcnow().isoformat(),
            completed_at=None,
            analyst=analyst
        )
        self.hunts[hunt.hunt_id] = hunt
        return hunt
    
    def add_finding(self, hunt_id: str, finding: Dict[str, Any]) -> None:
        """Add finding to hunt"""
        if hunt_id in self.hunts:
            finding["timestamp"] = datetime.utcnow().isoformat()
            self.hunts[hunt_id].findings.append(finding)
    
    def complete_hunt(self, hunt_id: str) -> ThreatHunt:
        """Complete a threat hunt"""
        if hunt_id in self.hunts:
            self.hunts[hunt_id].status = "completed"
            self.hunts[hunt_id].completed_at = datetime.utcnow().isoformat()
            return self.hunts[hunt_id]
        raise ValueError(f"Hunt not found: {hunt_id}")
    
    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List available hunting playbooks"""
        return [{"name": k, **v} for k, v in self.hunting_playbooks.items()]


class IncidentResponseEngine:
    """Incident response operations"""
    
    def __init__(self):
        self.incidents: Dict[str, Incident] = {}
        self.response_playbooks = self._initialize_playbooks()
    
    def _initialize_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize IR playbooks"""
        return {
            "ransomware": {
                "name": "Ransomware Response",
                "containment": [
                    "Isolate affected systems from network",
                    "Disable network shares",
                    "Block C2 domains/IPs at firewall",
                    "Disable compromised accounts"
                ],
                "eradication": [
                    "Identify and remove ransomware binary",
                    "Remove persistence mechanisms",
                    "Scan all systems for IOCs",
                    "Reset compromised credentials"
                ],
                "recovery": [
                    "Restore from clean backups",
                    "Verify system integrity",
                    "Re-enable network connectivity",
                    "Monitor for reinfection"
                ]
            },
            "data_breach": {
                "name": "Data Breach Response",
                "containment": [
                    "Identify scope of breach",
                    "Revoke compromised access",
                    "Block exfiltration channels",
                    "Preserve evidence"
                ],
                "eradication": [
                    "Remove attacker access",
                    "Patch exploited vulnerabilities",
                    "Reset all potentially compromised credentials",
                    "Review and update access controls"
                ],
                "recovery": [
                    "Restore affected systems",
                    "Implement additional monitoring",
                    "Notify affected parties",
                    "Update security controls"
                ]
            },
            "malware": {
                "name": "Malware Incident Response",
                "containment": [
                    "Isolate infected systems",
                    "Block malware C2 infrastructure",
                    "Identify all infected systems",
                    "Preserve malware samples"
                ],
                "eradication": [
                    "Remove malware from all systems",
                    "Remove persistence mechanisms",
                    "Patch exploitation vectors",
                    "Update AV signatures"
                ],
                "recovery": [
                    "Restore systems from clean state",
                    "Verify removal of malware",
                    "Re-enable network access",
                    "Enhanced monitoring"
                ]
            }
        }
    
    def create_incident(self, title: str, description: str, severity: AlertSeverity,
                       category: ThreatCategory, affected_assets: List[str],
                       assigned_to: List[str]) -> Incident:
        """Create new incident"""
        incident = Incident(
            incident_id=f"INC-{secrets.token_hex(8).upper()}",
            title=title,
            description=description,
            severity=severity,
            category=category,
            phase=IncidentPhase.DETECTION,
            affected_assets=affected_assets,
            indicators=[],
            timeline=[{
                "timestamp": datetime.utcnow().isoformat(),
                "action": "Incident created",
                "user": assigned_to[0] if assigned_to else "system"
            }],
            containment_actions=[],
            eradication_actions=[],
            recovery_actions=[],
            lessons_learned=[],
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
            closed_at=None,
            assigned_to=assigned_to
        )
        self.incidents[incident.incident_id] = incident
        return incident
    
    def update_phase(self, incident_id: str, phase: IncidentPhase, user: str) -> Incident:
        """Update incident phase"""
        if incident_id not in self.incidents:
            raise ValueError(f"Incident not found: {incident_id}")
        
        incident = self.incidents[incident_id]
        incident.phase = phase
        incident.updated_at = datetime.utcnow().isoformat()
        incident.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": f"Phase changed to {phase.value}",
            "user": user
        })
        
        if phase == IncidentPhase.CLOSED:
            incident.closed_at = datetime.utcnow().isoformat()
        
        return incident
    
    def add_containment_action(self, incident_id: str, action: str, user: str) -> None:
        """Add containment action"""
        if incident_id in self.incidents:
            self.incidents[incident_id].containment_actions.append({
                "action": action,
                "timestamp": datetime.utcnow().isoformat(),
                "user": user,
                "status": "completed"
            })
            self.incidents[incident_id].timeline.append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": f"Containment: {action}",
                "user": user
            })
    
    def get_playbook(self, playbook_name: str) -> Dict[str, Any]:
        """Get IR playbook"""
        return self.response_playbooks.get(playbook_name, {})
    
    def list_incidents(self, status: str = None) -> List[Incident]:
        """List incidents"""
        incidents = list(self.incidents.values())
        if status:
            incidents = [i for i in incidents if i.phase.value == status]
        return incidents


class BlueTeamOperationsEngine:
    """Main Blue Team operations engine"""
    
    def __init__(self):
        self.ioc_manager = IOCManager()
        self.yara_engine = YARARulesEngine()
        self.sigma_engine = SigmaRulesEngine()
        self.hunting_engine = ThreatHuntingEngine()
        self.ir_engine = IncidentResponseEngine()
    
    def analyze_artifact(self, artifact_type: str, content: str) -> Dict[str, Any]:
        """Analyze artifact for threats"""
        analysis = {
            "artifact_type": artifact_type,
            "timestamp": datetime.utcnow().isoformat(),
            "yara_matches": [],
            "ioc_matches": [],
            "threat_score": 0
        }
        
        # YARA matching
        yara_matches = self.yara_engine.match_content(content)
        analysis["yara_matches"] = yara_matches
        
        # IOC matching
        # Extract potential IOCs from content
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        domain_pattern = re.compile(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b')
        hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
        
        for match in ip_pattern.finditer(content):
            ioc = self.ioc_manager.match_ioc(match.group())
            if ioc:
                analysis["ioc_matches"].append(asdict(ioc))
        
        for match in domain_pattern.finditer(content):
            ioc = self.ioc_manager.match_ioc(match.group())
            if ioc:
                analysis["ioc_matches"].append(asdict(ioc))
        
        for match in hash_pattern.finditer(content):
            ioc = self.ioc_manager.match_ioc(match.group())
            if ioc:
                analysis["ioc_matches"].append(asdict(ioc))
        
        # Calculate threat score
        score = 0
        for match in yara_matches:
            if match["severity"] == "CRITICAL":
                score += 40
            elif match["severity"] == "HIGH":
                score += 25
            elif match["severity"] == "MEDIUM":
                score += 15
            else:
                score += 5
        
        for ioc in analysis["ioc_matches"]:
            score += int(ioc["confidence"] * 20)
        
        analysis["threat_score"] = min(score, 100)
        
        return analysis
    
    def get_blueteam_status(self) -> Dict[str, Any]:
        """Get blue team operations status"""
        return {
            "status": "OPERATIONAL",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "ioc_manager": {
                    "status": "active",
                    "ioc_count": len(self.ioc_manager.iocs)
                },
                "yara_engine": {
                    "status": "active",
                    "rules_count": len(self.yara_engine.rules)
                },
                "sigma_engine": {
                    "status": "active",
                    "rules_count": len(self.sigma_engine.rules)
                },
                "hunting_engine": {
                    "status": "active",
                    "playbooks_count": len(self.hunting_engine.hunting_playbooks)
                },
                "ir_engine": {
                    "status": "active",
                    "incidents_count": len(self.ir_engine.incidents)
                }
            },
            "capabilities": [
                "IOC Management",
                "YARA Rule Matching",
                "Sigma Rule Detection",
                "Threat Hunting",
                "Incident Response"
            ]
        }

    def get_mitre_mapping(self, technique_id: str) -> Dict[str, Any]:
        """Get MITRE ATT&CK mapping"""
        mitre_db = {
            "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
            "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
            "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
            "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
            "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
            "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
            "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
            "T1078": {"name": "Valid Accounts", "tactic": "Persistence"},
            "T1080": {"name": "Taint Shared Content", "tactic": "Lateral Movement"},
            "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
            "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
            "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
            "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
            "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
            "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
            "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
            "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
            "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control"}
        }
        return mitre_db.get(technique_id, {"name": "Unknown", "tactic": "Unknown"})


# Factory function for API use
def create_blueteam_engine() -> BlueTeamOperationsEngine:
    """Create blue team operations engine instance"""
    return BlueTeamOperationsEngine()
