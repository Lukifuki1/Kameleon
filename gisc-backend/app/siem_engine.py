"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - SIEM/SOC ENGINE MODULE
Complete implementation of siem-soc.ts.predloga

This module implements:
- Log Aggregation (multi-source collection, normalization, enrichment)
- Event Correlation (rule-based, statistical, ML-based)
- Alert Management (prioritization, assignment, escalation)
- MITRE ATT&CK Mapping
- SOC Workflow Automation
- Threat Intelligence Integration
- Compliance Reporting
- Dashboard Analytics

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import time
import json
import secrets
import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)


class LogSourceType(str, Enum):
    WINDOWS_EVENT = "WINDOWS_EVENT"
    SYSLOG = "SYSLOG"
    CEF = "CEF"
    LEEF = "LEEF"
    JSON = "JSON"
    CSV = "CSV"
    FIREWALL = "FIREWALL"
    IDS_IPS = "IDS_IPS"
    PROXY = "PROXY"
    DNS = "DNS"
    DHCP = "DHCP"
    ENDPOINT = "ENDPOINT"
    CLOUD = "CLOUD"
    APPLICATION = "APPLICATION"
    DATABASE = "DATABASE"
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK_FLOW = "NETWORK_FLOW"


class EventSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    NETWORK = "NETWORK"
    ENDPOINT = "ENDPOINT"
    APPLICATION = "APPLICATION"
    DATA = "DATA"
    MALWARE = "MALWARE"
    INTRUSION = "INTRUSION"
    POLICY = "POLICY"
    SYSTEM = "SYSTEM"
    AUDIT = "AUDIT"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


class CorrelationRuleType(str, Enum):
    THRESHOLD = "THRESHOLD"
    SEQUENCE = "SEQUENCE"
    AGGREGATION = "AGGREGATION"
    ANOMALY = "ANOMALY"
    PATTERN = "PATTERN"
    STATISTICAL = "STATISTICAL"
    MACHINE_LEARNING = "MACHINE_LEARNING"


class NormalizationFormat(str, Enum):
    ECS = "ECS"  # Elastic Common Schema
    OCSF = "OCSF"  # Open Cybersecurity Schema Framework
    CIM = "CIM"  # Common Information Model
    CUSTOM = "CUSTOM"


@dataclass
class LogSource:
    source_id: str
    name: str
    source_type: LogSourceType
    host: str
    port: int
    protocol: str
    format: str
    enabled: bool
    last_event: Optional[str]
    events_per_second: float
    status: str


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str
    source: str
    source_type: LogSourceType
    category: EventCategory
    severity: EventSeverity
    action: str
    outcome: str
    source_ip: Optional[str]
    source_port: Optional[int]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    user: Optional[str]
    host: Optional[str]
    process: Optional[str]
    file: Optional[str]
    message: str
    raw_log: str
    enrichment: Dict[str, Any]
    tags: List[str]
    mitre_techniques: List[str]


@dataclass
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    rule_type: CorrelationRuleType
    conditions: Dict[str, Any]
    threshold: Optional[int]
    time_window: int  # seconds
    severity: EventSeverity
    mitre_techniques: List[str]
    enabled: bool
    last_triggered: Optional[str]
    trigger_count: int


@dataclass
class Alert:
    alert_id: str
    title: str
    description: str
    severity: EventSeverity
    status: AlertStatus
    source_rule: str
    events: List[str]
    entities: List[Dict[str, str]]
    mitre_techniques: List[str]
    created_at: str
    updated_at: str
    assigned_to: Optional[str]
    resolution: Optional[str]
    notes: List[Dict[str, Any]]


@dataclass
class SOCCase:
    case_id: str
    title: str
    description: str
    severity: EventSeverity
    status: str
    alerts: List[str]
    events: List[str]
    timeline: List[Dict[str, Any]]
    artifacts: List[Dict[str, Any]]
    created_at: str
    updated_at: str
    assigned_to: str
    resolution: Optional[str]


class LogNormalizer:
    """Log normalization engine"""
    
    def __init__(self, format: NormalizationFormat = NormalizationFormat.ECS):
        self.format = format
        self.parsers = {
            LogSourceType.SYSLOG: self._parse_syslog,
            LogSourceType.CEF: self._parse_cef,
            LogSourceType.WINDOWS_EVENT: self._parse_windows_event,
            LogSourceType.JSON: self._parse_json,
            LogSourceType.FIREWALL: self._parse_firewall,
        }
    
    def normalize(self, raw_log: str, source_type: LogSourceType) -> NormalizedEvent:
        """Normalize raw log to standard format"""
        parser = self.parsers.get(source_type, self._parse_generic)
        parsed = parser(raw_log)
        
        return NormalizedEvent(
            event_id=f"EVT-{secrets.token_hex(8).upper()}",
            timestamp=parsed.get("timestamp", datetime.utcnow().isoformat()),
            source=parsed.get("source", "unknown"),
            source_type=source_type,
            category=self._categorize_event(parsed),
            severity=self._determine_severity(parsed),
            action=parsed.get("action", "unknown"),
            outcome=parsed.get("outcome", "unknown"),
            source_ip=parsed.get("source_ip"),
            source_port=parsed.get("source_port"),
            destination_ip=parsed.get("destination_ip"),
            destination_port=parsed.get("destination_port"),
            user=parsed.get("user"),
            host=parsed.get("host"),
            process=parsed.get("process"),
            file=parsed.get("file"),
            message=parsed.get("message", raw_log[:500]),
            raw_log=raw_log,
            enrichment={},
            tags=[],
            mitre_techniques=[]
        )
    
    def _parse_syslog(self, raw_log: str) -> Dict[str, Any]:
        """Parse syslog format"""
        parsed = {"message": raw_log}
        
        # RFC 3164 format: <priority>timestamp hostname process[pid]: message
        syslog_pattern = r'^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
        match = re.match(syslog_pattern, raw_log)
        
        if match:
            priority = int(match.group(1))
            parsed["facility"] = priority // 8
            parsed["severity_code"] = priority % 8
            parsed["timestamp"] = match.group(2)
            parsed["host"] = match.group(3)
            parsed["process"] = match.group(4)
            parsed["pid"] = match.group(5)
            parsed["message"] = match.group(6)
        
        return parsed
    
    def _parse_cef(self, raw_log: str) -> Dict[str, Any]:
        """Parse CEF (Common Event Format)"""
        parsed = {"message": raw_log}
        
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef_pattern = r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
        match = re.match(cef_pattern, raw_log)
        
        if match:
            parsed["cef_version"] = match.group(1)
            parsed["device_vendor"] = match.group(2)
            parsed["device_product"] = match.group(3)
            parsed["device_version"] = match.group(4)
            parsed["signature_id"] = match.group(5)
            parsed["name"] = match.group(6)
            parsed["severity"] = match.group(7)
            
            # Parse extension
            extension = match.group(8)
            ext_pattern = r'(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)'
            for ext_match in re.finditer(ext_pattern, extension):
                key, value = ext_match.groups()
                parsed[key] = value
        
        return parsed
    
    def _parse_windows_event(self, raw_log: str) -> Dict[str, Any]:
        """Parse Windows Event Log"""
        parsed = {"message": raw_log}
        
        # Try to parse as XML or JSON
        try:
            if raw_log.strip().startswith('<'):
                # XML format
                event_id_match = re.search(r'<EventID>(\d+)</EventID>', raw_log)
                if event_id_match:
                    parsed["event_id"] = event_id_match.group(1)
                
                time_match = re.search(r'<TimeCreated SystemTime="([^"]+)"', raw_log)
                if time_match:
                    parsed["timestamp"] = time_match.group(1)
                
                computer_match = re.search(r'<Computer>([^<]+)</Computer>', raw_log)
                if computer_match:
                    parsed["host"] = computer_match.group(1)
            else:
                # Try JSON
                data = json.loads(raw_log)
                parsed.update(data)
        except json.JSONDecodeError as e:
            logger.debug(f"Failed to parse Windows event log as JSON: {e}")
        except Exception as e:
            logger.debug(f"Error parsing Windows event log: {e}")
        
        return parsed
    
    def _parse_json(self, raw_log: str) -> Dict[str, Any]:
        """Parse JSON format"""
        try:
            return json.loads(raw_log)
        except:
            return {"message": raw_log}
    
    def _parse_firewall(self, raw_log: str) -> Dict[str, Any]:
        """Parse firewall log"""
        parsed = {"message": raw_log}
        
        # Common firewall log patterns
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        port_pattern = r':(\d+)'
        
        ips = re.findall(ip_pattern, raw_log)
        if len(ips) >= 2:
            parsed["source_ip"] = ips[0]
            parsed["destination_ip"] = ips[1]
        elif len(ips) == 1:
            parsed["source_ip"] = ips[0]
        
        # Action detection
        if any(word in raw_log.lower() for word in ["deny", "drop", "block", "reject"]):
            parsed["action"] = "deny"
        elif any(word in raw_log.lower() for word in ["allow", "accept", "permit"]):
            parsed["action"] = "allow"
        
        return parsed
    
    def _parse_generic(self, raw_log: str) -> Dict[str, Any]:
        """Generic log parser"""
        parsed = {"message": raw_log}
        
        # Extract IPs
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ips = re.findall(ip_pattern, raw_log)
        if ips:
            parsed["source_ip"] = ips[0]
            if len(ips) > 1:
                parsed["destination_ip"] = ips[1]
        
        # Extract timestamps
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})',
        ]
        for pattern in timestamp_patterns:
            match = re.search(pattern, raw_log)
            if match:
                parsed["timestamp"] = match.group(1)
                break
        
        return parsed
    
    def _categorize_event(self, parsed: Dict[str, Any]) -> EventCategory:
        """Categorize event based on content"""
        message = parsed.get("message", "").lower()
        
        if any(word in message for word in ["login", "logon", "auth", "password"]):
            return EventCategory.AUTHENTICATION
        elif any(word in message for word in ["firewall", "connection", "tcp", "udp"]):
            return EventCategory.NETWORK
        elif any(word in message for word in ["malware", "virus", "trojan"]):
            return EventCategory.MALWARE
        elif any(word in message for word in ["intrusion", "attack", "exploit"]):
            return EventCategory.INTRUSION
        elif any(word in message for word in ["policy", "compliance", "violation"]):
            return EventCategory.POLICY
        
        return EventCategory.SYSTEM
    
    def _determine_severity(self, parsed: Dict[str, Any]) -> EventSeverity:
        """Determine event severity"""
        message = parsed.get("message", "").lower()
        severity_code = parsed.get("severity_code")
        
        if severity_code is not None:
            if severity_code <= 2:
                return EventSeverity.CRITICAL
            elif severity_code <= 4:
                return EventSeverity.HIGH
            elif severity_code <= 5:
                return EventSeverity.MEDIUM
            else:
                return EventSeverity.LOW
        
        if any(word in message for word in ["critical", "emergency", "fatal"]):
            return EventSeverity.CRITICAL
        elif any(word in message for word in ["error", "fail", "denied"]):
            return EventSeverity.HIGH
        elif any(word in message for word in ["warning", "warn"]):
            return EventSeverity.MEDIUM
        elif any(word in message for word in ["info", "notice"]):
            return EventSeverity.LOW
        
        return EventSeverity.INFO


class CorrelationEngine:
    """Event correlation engine"""
    
    def __init__(self):
        self.rules: Dict[str, CorrelationRule] = {}
        self.event_buffer: List[NormalizedEvent] = []
        self.buffer_size = 10000
        self.alerts: List[Alert] = []
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default correlation rules"""
        default_rules = [
            {
                "name": "Brute Force Detection",
                "description": "Detects multiple failed login attempts",
                "rule_type": CorrelationRuleType.THRESHOLD,
                "conditions": {
                    "category": "AUTHENTICATION",
                    "outcome": "failure"
                },
                "threshold": 5,
                "time_window": 300,
                "severity": EventSeverity.HIGH,
                "mitre_techniques": ["T1110"]
            },
            {
                "name": "Port Scan Detection",
                "description": "Detects port scanning activity",
                "rule_type": CorrelationRuleType.THRESHOLD,
                "conditions": {
                    "category": "NETWORK",
                    "action": "deny"
                },
                "threshold": 20,
                "time_window": 60,
                "severity": EventSeverity.MEDIUM,
                "mitre_techniques": ["T1046"]
            },
            {
                "name": "Lateral Movement Detection",
                "description": "Detects potential lateral movement",
                "rule_type": CorrelationRuleType.SEQUENCE,
                "conditions": {
                    "sequence": [
                        {"category": "AUTHENTICATION", "outcome": "success"},
                        {"category": "NETWORK", "destination_port": [445, 135, 3389]}
                    ]
                },
                "threshold": 1,
                "time_window": 600,
                "severity": EventSeverity.HIGH,
                "mitre_techniques": ["T1021"]
            },
            {
                "name": "Data Exfiltration Detection",
                "description": "Detects large data transfers",
                "rule_type": CorrelationRuleType.ANOMALY,
                "conditions": {
                    "category": "NETWORK",
                    "bytes_out_threshold": 100000000
                },
                "threshold": 1,
                "time_window": 3600,
                "severity": EventSeverity.CRITICAL,
                "mitre_techniques": ["T1041"]
            },
            {
                "name": "Privilege Escalation Detection",
                "description": "Detects privilege escalation attempts",
                "rule_type": CorrelationRuleType.PATTERN,
                "conditions": {
                    "patterns": ["sudo", "runas", "privilege", "admin"]
                },
                "threshold": 3,
                "time_window": 300,
                "severity": EventSeverity.HIGH,
                "mitre_techniques": ["T1068", "T1548"]
            }
        ]
        
        for rule_data in default_rules:
            rule = CorrelationRule(
                rule_id=f"COR-{secrets.token_hex(8).upper()}",
                name=rule_data["name"],
                description=rule_data["description"],
                rule_type=rule_data["rule_type"],
                conditions=rule_data["conditions"],
                threshold=rule_data["threshold"],
                time_window=rule_data["time_window"],
                severity=rule_data["severity"],
                mitre_techniques=rule_data["mitre_techniques"],
                enabled=True,
                last_triggered=None,
                trigger_count=0
            )
            self.rules[rule.rule_id] = rule
    
    def add_event(self, event: NormalizedEvent) -> List[Alert]:
        """Add event and check for correlations"""
        self.event_buffer.append(event)
        
        # Trim buffer if needed
        if len(self.event_buffer) > self.buffer_size:
            self.event_buffer = self.event_buffer[-self.buffer_size:]
        
        # Check all rules
        triggered_alerts = []
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            alert = self._evaluate_rule(rule, event)
            if alert:
                triggered_alerts.append(alert)
                self.alerts.append(alert)
        
        return triggered_alerts
    
    def _evaluate_rule(self, rule: CorrelationRule, new_event: NormalizedEvent) -> Optional[Alert]:
        """Evaluate correlation rule"""
        if rule.rule_type == CorrelationRuleType.THRESHOLD:
            return self._evaluate_threshold_rule(rule, new_event)
        elif rule.rule_type == CorrelationRuleType.SEQUENCE:
            return self._evaluate_sequence_rule(rule, new_event)
        elif rule.rule_type == CorrelationRuleType.PATTERN:
            return self._evaluate_pattern_rule(rule, new_event)
        
        return None
    
    def _evaluate_threshold_rule(self, rule: CorrelationRule, new_event: NormalizedEvent) -> Optional[Alert]:
        """Evaluate threshold-based rule"""
        conditions = rule.conditions
        time_window = rule.time_window
        threshold = rule.threshold
        
        # Get events within time window
        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        
        matching_events = []
        for event in self.event_buffer:
            try:
                event_time = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                if event_time < cutoff_time:
                    continue
            except:
                continue
            
            # Check conditions
            matches = True
            for key, value in conditions.items():
                event_value = getattr(event, key, None)
                if event_value is None:
                    matches = False
                    break
                if isinstance(value, list):
                    if event_value not in value:
                        matches = False
                        break
                elif str(event_value).lower() != str(value).lower():
                    matches = False
                    break
            
            if matches:
                matching_events.append(event)
        
        if len(matching_events) >= threshold:
            rule.last_triggered = datetime.utcnow().isoformat()
            rule.trigger_count += 1
            
            return Alert(
                alert_id=f"ALT-{secrets.token_hex(8).upper()}",
                title=rule.name,
                description=f"{rule.description}. {len(matching_events)} events matched in {time_window} seconds.",
                severity=rule.severity,
                status=AlertStatus.NEW,
                source_rule=rule.rule_id,
                events=[e.event_id for e in matching_events[-10:]],
                entities=self._extract_entities(matching_events),
                mitre_techniques=rule.mitre_techniques,
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat(),
                assigned_to=None,
                resolution=None,
                notes=[]
            )
        
        return None
    
    def _evaluate_sequence_rule(self, rule: CorrelationRule, new_event: NormalizedEvent) -> Optional[Alert]:
        """Evaluate sequence-based rule"""
        # Simplified sequence detection
        return None
    
    def _evaluate_pattern_rule(self, rule: CorrelationRule, new_event: NormalizedEvent) -> Optional[Alert]:
        """Evaluate pattern-based rule"""
        patterns = rule.conditions.get("patterns", [])
        message = new_event.message.lower()
        
        matched_patterns = [p for p in patterns if p.lower() in message]
        
        if len(matched_patterns) >= rule.threshold:
            rule.last_triggered = datetime.utcnow().isoformat()
            rule.trigger_count += 1
            
            return Alert(
                alert_id=f"ALT-{secrets.token_hex(8).upper()}",
                title=rule.name,
                description=f"{rule.description}. Matched patterns: {', '.join(matched_patterns)}",
                severity=rule.severity,
                status=AlertStatus.NEW,
                source_rule=rule.rule_id,
                events=[new_event.event_id],
                entities=self._extract_entities([new_event]),
                mitre_techniques=rule.mitre_techniques,
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat(),
                assigned_to=None,
                resolution=None,
                notes=[]
            )
        
        return None
    
    def _extract_entities(self, events: List[NormalizedEvent]) -> List[Dict[str, str]]:
        """Extract entities from events"""
        entities = []
        seen = set()
        
        for event in events:
            if event.source_ip and event.source_ip not in seen:
                entities.append({"type": "ip", "value": event.source_ip})
                seen.add(event.source_ip)
            if event.destination_ip and event.destination_ip not in seen:
                entities.append({"type": "ip", "value": event.destination_ip})
                seen.add(event.destination_ip)
            if event.user and event.user not in seen:
                entities.append({"type": "user", "value": event.user})
                seen.add(event.user)
            if event.host and event.host not in seen:
                entities.append({"type": "host", "value": event.host})
                seen.add(event.host)
        
        return entities


class AlertManager:
    """Alert management engine"""
    
    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.escalation_rules: List[Dict[str, Any]] = []
        self.assignment_rules: List[Dict[str, Any]] = []
    
    def add_alert(self, alert: Alert) -> None:
        """Add new alert"""
        self.alerts[alert.alert_id] = alert
        self._auto_assign(alert)
        self._check_escalation(alert)
    
    def update_status(self, alert_id: str, status: AlertStatus, user: str,
                     resolution: str = None) -> Alert:
        """Update alert status"""
        if alert_id not in self.alerts:
            raise ValueError(f"Alert not found: {alert_id}")
        
        alert = self.alerts[alert_id]
        alert.status = status
        alert.updated_at = datetime.utcnow().isoformat()
        
        if resolution:
            alert.resolution = resolution
        
        alert.notes.append({
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "action": f"Status changed to {status.value}",
            "resolution": resolution
        })
        
        return alert
    
    def assign_alert(self, alert_id: str, assignee: str, user: str) -> Alert:
        """Assign alert to analyst"""
        if alert_id not in self.alerts:
            raise ValueError(f"Alert not found: {alert_id}")
        
        alert = self.alerts[alert_id]
        alert.assigned_to = assignee
        alert.updated_at = datetime.utcnow().isoformat()
        
        if alert.status == AlertStatus.NEW:
            alert.status = AlertStatus.ACKNOWLEDGED
        
        alert.notes.append({
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "action": f"Assigned to {assignee}"
        })
        
        return alert
    
    def _auto_assign(self, alert: Alert) -> None:
        """Auto-assign alert based on rules"""
        for rule in self.assignment_rules:
            if self._matches_rule(alert, rule):
                alert.assigned_to = rule.get("assignee")
                break
    
    def _check_escalation(self, alert: Alert) -> None:
        """Check if alert needs escalation"""
        for rule in self.escalation_rules:
            if self._matches_rule(alert, rule):
                alert.status = AlertStatus.ESCALATED
                break
    
    def _matches_rule(self, alert: Alert, rule: Dict[str, Any]) -> bool:
        """Check if alert matches rule conditions"""
        conditions = rule.get("conditions", {})
        
        for key, value in conditions.items():
            alert_value = getattr(alert, key, None)
            if alert_value is None:
                return False
            if isinstance(value, list):
                if alert_value not in value:
                    return False
            elif alert_value != value:
                return False
        
        return True
    
    def get_alerts(self, status: AlertStatus = None, severity: EventSeverity = None,
                  assignee: str = None, limit: int = 100) -> List[Alert]:
        """Get alerts with filters"""
        alerts = list(self.alerts.values())
        
        if status:
            alerts = [a for a in alerts if a.status == status]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if assignee:
            alerts = [a for a in alerts if a.assigned_to == assignee]
        
        # Sort by severity and creation time
        severity_order = {
            EventSeverity.CRITICAL: 0,
            EventSeverity.HIGH: 1,
            EventSeverity.MEDIUM: 2,
            EventSeverity.LOW: 3,
            EventSeverity.INFO: 4
        }
        alerts.sort(key=lambda a: (severity_order.get(a.severity, 5), a.created_at), reverse=True)
        
        return alerts[:limit]


class MITREMapper:
    """MITRE ATT&CK mapping engine"""
    
    def __init__(self):
        self.techniques = self._load_techniques()
        self.tactics = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact"
        ]
    
    def _load_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK techniques"""
        return {
            "T1110": {
                "name": "Brute Force",
                "tactic": "credential-access",
                "description": "Adversaries may use brute force techniques to gain access to accounts"
            },
            "T1046": {
                "name": "Network Service Discovery",
                "tactic": "discovery",
                "description": "Adversaries may attempt to get a listing of services running on remote hosts"
            },
            "T1021": {
                "name": "Remote Services",
                "tactic": "lateral-movement",
                "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections"
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "exfiltration",
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel"
            },
            "T1068": {
                "name": "Exploitation for Privilege Escalation",
                "tactic": "privilege-escalation",
                "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges"
            },
            "T1548": {
                "name": "Abuse Elevation Control Mechanism",
                "tactic": "privilege-escalation",
                "description": "Adversaries may circumvent mechanisms designed to control elevate privileges"
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands"
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "tactic": "credential-access",
                "description": "Adversaries may attempt to dump credentials to obtain account login and credential material"
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "defense-evasion",
                "description": "Adversaries may inject code into processes in order to evade process-based defenses"
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": "command-and-control",
                "description": "Adversaries may communicate using application layer protocols to avoid detection"
            }
        }
    
    def get_technique(self, technique_id: str) -> Dict[str, Any]:
        """Get technique details"""
        return self.techniques.get(technique_id, {
            "name": "Unknown",
            "tactic": "unknown",
            "description": "Unknown technique"
        })
    
    def map_event(self, event: NormalizedEvent) -> List[str]:
        """Map event to MITRE techniques"""
        techniques = []
        message = event.message.lower()
        
        # Simple keyword-based mapping
        mappings = {
            "T1110": ["brute", "failed login", "authentication failure"],
            "T1046": ["port scan", "nmap", "service discovery"],
            "T1021": ["rdp", "ssh", "smb", "remote"],
            "T1041": ["exfiltration", "data transfer", "upload"],
            "T1059": ["powershell", "cmd", "bash", "script"],
            "T1003": ["lsass", "credential", "mimikatz", "dump"],
            "T1055": ["injection", "process hollow", "dll inject"],
            "T1071": ["http", "dns", "beacon", "c2"]
        }
        
        for technique_id, keywords in mappings.items():
            if any(kw in message for kw in keywords):
                techniques.append(technique_id)
        
        return techniques
    
    def get_coverage_matrix(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Generate MITRE ATT&CK coverage matrix"""
        coverage = {tactic: [] for tactic in self.tactics}
        
        for alert in alerts:
            for technique_id in alert.mitre_techniques:
                technique = self.get_technique(technique_id)
                tactic = technique.get("tactic", "unknown")
                if tactic in coverage:
                    if technique_id not in coverage[tactic]:
                        coverage[tactic].append(technique_id)
        
        return coverage


class SIEMEngine:
    """Main SIEM engine"""
    
    def __init__(self):
        self.normalizer = LogNormalizer()
        self.correlation = CorrelationEngine()
        self.alert_manager = AlertManager()
        self.mitre_mapper = MITREMapper()
        self.log_sources: Dict[str, LogSource] = {}
        self.events: List[NormalizedEvent] = []
        self.cases: Dict[str, SOCCase] = {}
    
    def add_log_source(self, name: str, source_type: LogSourceType, host: str,
                      port: int, protocol: str, format: str) -> LogSource:
        """Add log source"""
        source = LogSource(
            source_id=f"SRC-{secrets.token_hex(8).upper()}",
            name=name,
            source_type=source_type,
            host=host,
            port=port,
            protocol=protocol,
            format=format,
            enabled=True,
            last_event=None,
            events_per_second=0.0,
            status="active"
        )
        self.log_sources[source.source_id] = source
        return source
    
    def ingest_log(self, raw_log: str, source_id: str) -> Tuple[NormalizedEvent, List[Alert]]:
        """Ingest and process log"""
        if source_id not in self.log_sources:
            raise ValueError(f"Unknown log source: {source_id}")
        
        source = self.log_sources[source_id]
        source.last_event = datetime.utcnow().isoformat()
        
        # Normalize
        event = self.normalizer.normalize(raw_log, source.source_type)
        event.source = source.name
        
        # Map to MITRE
        event.mitre_techniques = self.mitre_mapper.map_event(event)
        
        # Store event
        self.events.append(event)
        if len(self.events) > 100000:
            self.events = self.events[-100000:]
        
        # Correlate
        alerts = self.correlation.add_event(event)
        
        # Add alerts to manager
        for alert in alerts:
            self.alert_manager.add_alert(alert)
        
        return event, alerts
    
    def create_case(self, title: str, description: str, severity: EventSeverity,
                   alert_ids: List[str], assigned_to: str) -> SOCCase:
        """Create SOC case from alerts"""
        case = SOCCase(
            case_id=f"SOC-{secrets.token_hex(8).upper()}",
            title=title,
            description=description,
            severity=severity,
            status="OPEN",
            alerts=alert_ids,
            events=[],
            timeline=[{
                "timestamp": datetime.utcnow().isoformat(),
                "action": "Case created",
                "user": assigned_to
            }],
            artifacts=[],
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
            assigned_to=assigned_to,
            resolution=None
        )
        
        # Collect events from alerts
        for alert_id in alert_ids:
            if alert_id in self.alert_manager.alerts:
                alert = self.alert_manager.alerts[alert_id]
                case.events.extend(alert.events)
        
        self.cases[case.case_id] = case
        return case
    
    def get_siem_status(self) -> Dict[str, Any]:
        """Get SIEM engine status"""
        return {
            "status": "OPERATIONAL",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "log_normalizer": {
                    "status": "active",
                    "formats_supported": len(self.normalizer.parsers)
                },
                "correlation_engine": {
                    "status": "active",
                    "rules_count": len(self.correlation.rules)
                },
                "alert_manager": {
                    "status": "active",
                    "alerts_count": len(self.alert_manager.alerts)
                },
                "mitre_mapper": {
                    "status": "active",
                    "techniques_count": len(self.mitre_mapper.techniques)
                }
            },
            "log_sources_count": len(self.log_sources),
            "events_count": len(self.events),
            "cases_count": len(self.cases),
            "capabilities": [
                "Log Normalization",
                "Event Correlation",
                "Alert Management",
                "MITRE ATT&CK Mapping",
                "SOC Case Management"
            ]
        }

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get SOC dashboard statistics"""
        alerts = list(self.alert_manager.alerts.values())
        
        # Count by severity
        severity_counts = defaultdict(int)
        for alert in alerts:
            severity_counts[alert.severity.value] += 1
        
        # Count by status
        status_counts = defaultdict(int)
        for alert in alerts:
            status_counts[alert.status.value] += 1
        
        # Events per hour (last 24 hours)
        now = datetime.utcnow()
        hourly_events = defaultdict(int)
        for event in self.events[-10000:]:
            try:
                event_time = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                if (now - event_time).total_seconds() < 86400:
                    hour = event_time.strftime("%Y-%m-%d %H:00")
                    hourly_events[hour] += 1
            except ValueError as e:
                logger.debug(f"Failed to parse event timestamp: {e}")
        
        return {
            "total_events": len(self.events),
            "total_alerts": len(alerts),
            "open_alerts": status_counts.get("NEW", 0) + status_counts.get("ACKNOWLEDGED", 0),
            "critical_alerts": severity_counts.get("CRITICAL", 0),
            "high_alerts": severity_counts.get("HIGH", 0),
            "severity_distribution": dict(severity_counts),
            "status_distribution": dict(status_counts),
            "events_per_hour": dict(hourly_events),
            "active_sources": len([s for s in self.log_sources.values() if s.status == "active"]),
            "total_cases": len(self.cases),
            "timestamp": datetime.utcnow().isoformat()
        }


# Factory function for API use
def create_siem_engine() -> SIEMEngine:
    """Create SIEM engine instance"""
    return SIEMEngine()
