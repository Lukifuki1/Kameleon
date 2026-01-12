"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - THREAT HUNTING ENGINE
Advanced Threat Hunting Platform with Hypothesis-Driven Detection

This module implements:
- Hypothesis-driven threat hunting workflows
- Hunt query language for log analysis
- Behavioral analytics and anomaly detection
- IOC correlation across multiple data sources
- Hunt campaign management
- Threat actor tracking
- Kill chain analysis
- ATT&CK-based hunting techniques
- Evidence collection and timeline reconstruction

100% opensource - NO external API dependencies
Uses local data sources: logs, network captures, system events

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import re
import json
import hashlib
import logging
import threading
import sqlite3
import statistics
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, Counter
from pathlib import Path
import fnmatch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


HUNT_DB_PATH = os.environ.get("HUNT_DB_PATH", "/var/lib/tyranthos/threat_hunting.db")
LOG_SOURCES_DIR = os.environ.get("LOG_SOURCES_DIR", "/var/log")
PCAP_DIR = os.environ.get("PCAP_DIR", "/var/lib/tyranthos/pcap")


class HuntStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class HuntPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DataSourceType(str, Enum):
    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    AUDIT_LOG = "audit_log"
    NETWORK_LOG = "network_log"
    FIREWALL_LOG = "firewall_log"
    DNS_LOG = "dns_log"
    PROXY_LOG = "proxy_log"
    ENDPOINT_LOG = "endpoint_log"
    APPLICATION_LOG = "application_log"
    PCAP = "pcap"
    NETFLOW = "netflow"
    ZEEK_LOG = "zeek_log"
    SURICATA_LOG = "suricata_log"


class MITRETactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class HuntHypothesis:
    hypothesis_id: str
    title: str
    description: str
    threat_actor: Optional[str]
    mitre_tactics: List[MITRETactic]
    mitre_techniques: List[str]
    data_sources: List[DataSourceType]
    indicators: List[Dict[str, Any]]
    detection_logic: str
    false_positive_guidance: str
    references: List[str]


@dataclass
class HuntQuery:
    query_id: str
    name: str
    description: str
    query_type: str
    query_string: str
    data_source: DataSourceType
    parameters: Dict[str, Any]
    expected_fields: List[str]


@dataclass
class HuntFinding:
    finding_id: str
    hunt_id: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: float
    evidence: List[Dict[str, Any]]
    affected_assets: List[str]
    indicators: List[Dict[str, Any]]
    mitre_mapping: List[Dict[str, str]]
    timeline: List[Dict[str, Any]]
    recommendations: List[str]
    found_at: datetime
    analyst: str
    status: str


@dataclass
class HuntCampaign:
    campaign_id: str
    name: str
    description: str
    status: HuntStatus
    priority: HuntPriority
    hypotheses: List[HuntHypothesis]
    queries: List[HuntQuery]
    findings: List[str]
    start_date: datetime
    end_date: Optional[datetime]
    assigned_analysts: List[str]
    tags: List[str]
    notes: List[Dict[str, Any]]
    metrics: Dict[str, Any]


@dataclass
class ThreatActor:
    actor_id: str
    name: str
    aliases: List[str]
    description: str
    motivation: str
    sophistication: str
    target_sectors: List[str]
    target_regions: List[str]
    known_ttps: List[Dict[str, str]]
    known_tools: List[str]
    known_infrastructure: List[str]
    first_seen: datetime
    last_seen: datetime
    references: List[str]


@dataclass
class BehaviorBaseline:
    baseline_id: str
    entity_type: str
    entity_id: str
    metric_name: str
    mean: float
    std_dev: float
    min_value: float
    max_value: float
    percentile_95: float
    percentile_99: float
    sample_count: int
    last_updated: datetime


@dataclass
class AnomalyDetection:
    anomaly_id: str
    entity_type: str
    entity_id: str
    metric_name: str
    observed_value: float
    expected_range: Tuple[float, float]
    deviation_score: float
    detected_at: datetime
    context: Dict[str, Any]


class HuntDatabase:
    """SQLite database for threat hunting data"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or HUNT_DB_PATH
        self._ensure_directory()
        self._init_database()
        self._lock = threading.Lock()
    
    def _ensure_directory(self):
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_database(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    hypotheses TEXT,
                    queries TEXT,
                    findings TEXT,
                    start_date TEXT NOT NULL,
                    end_date TEXT,
                    assigned_analysts TEXT,
                    tags TEXT,
                    notes TEXT,
                    metrics TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    hunt_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    evidence TEXT,
                    affected_assets TEXT,
                    indicators TEXT,
                    mitre_mapping TEXT,
                    timeline TEXT,
                    recommendations TEXT,
                    found_at TEXT NOT NULL,
                    analyst TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_actors (
                    actor_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    aliases TEXT,
                    description TEXT,
                    motivation TEXT,
                    sophistication TEXT,
                    target_sectors TEXT,
                    target_regions TEXT,
                    known_ttps TEXT,
                    known_tools TEXT,
                    known_infrastructure TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    references_list TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    baseline_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    mean REAL NOT NULL,
                    std_dev REAL NOT NULL,
                    min_value REAL NOT NULL,
                    max_value REAL NOT NULL,
                    percentile_95 REAL NOT NULL,
                    percentile_99 REAL NOT NULL,
                    sample_count INTEGER NOT NULL,
                    last_updated TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    anomaly_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    observed_value REAL NOT NULL,
                    expected_min REAL NOT NULL,
                    expected_max REAL NOT NULL,
                    deviation_score REAL NOT NULL,
                    detected_at TEXT NOT NULL,
                    context TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hunt_logs (
                    log_id TEXT PRIMARY KEY,
                    campaign_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    analyst TEXT,
                    timestamp TEXT NOT NULL
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_hunt ON findings(hunt_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_entity ON baselines(entity_type, entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_entity ON anomalies(entity_type, entity_id)")
            
            conn.commit()
    
    def save_campaign(self, campaign: HuntCampaign) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO campaigns
                        (campaign_id, name, description, status, priority, hypotheses,
                         queries, findings, start_date, end_date, assigned_analysts,
                         tags, notes, metrics)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        campaign.campaign_id,
                        campaign.name,
                        campaign.description,
                        campaign.status.value,
                        campaign.priority.value,
                        json.dumps([asdict(h) for h in campaign.hypotheses]),
                        json.dumps([asdict(q) for q in campaign.queries]),
                        json.dumps(campaign.findings),
                        campaign.start_date.isoformat(),
                        campaign.end_date.isoformat() if campaign.end_date else None,
                        json.dumps(campaign.assigned_analysts),
                        json.dumps(campaign.tags),
                        json.dumps(campaign.notes),
                        json.dumps(campaign.metrics)
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save campaign: {e}")
                return False
    
    def get_campaign(self, campaign_id: str) -> Optional[HuntCampaign]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_campaign(row)
        except Exception as e:
            logger.error(f"Failed to get campaign: {e}")
        return None
    
    def _row_to_campaign(self, row: sqlite3.Row) -> HuntCampaign:
        hypotheses_data = json.loads(row["hypotheses"]) if row["hypotheses"] else []
        hypotheses = []
        for h in hypotheses_data:
            hypotheses.append(HuntHypothesis(
                hypothesis_id=h["hypothesis_id"],
                title=h["title"],
                description=h["description"],
                threat_actor=h.get("threat_actor"),
                mitre_tactics=[MITRETactic(t) for t in h.get("mitre_tactics", [])],
                mitre_techniques=h.get("mitre_techniques", []),
                data_sources=[DataSourceType(d) for d in h.get("data_sources", [])],
                indicators=h.get("indicators", []),
                detection_logic=h.get("detection_logic", ""),
                false_positive_guidance=h.get("false_positive_guidance", ""),
                references=h.get("references", [])
            ))
        
        queries_data = json.loads(row["queries"]) if row["queries"] else []
        queries = []
        for q in queries_data:
            queries.append(HuntQuery(
                query_id=q["query_id"],
                name=q["name"],
                description=q["description"],
                query_type=q["query_type"],
                query_string=q["query_string"],
                data_source=DataSourceType(q["data_source"]),
                parameters=q.get("parameters", {}),
                expected_fields=q.get("expected_fields", [])
            ))
        
        return HuntCampaign(
            campaign_id=row["campaign_id"],
            name=row["name"],
            description=row["description"] or "",
            status=HuntStatus(row["status"]),
            priority=HuntPriority(row["priority"]),
            hypotheses=hypotheses,
            queries=queries,
            findings=json.loads(row["findings"]) if row["findings"] else [],
            start_date=datetime.fromisoformat(row["start_date"]),
            end_date=datetime.fromisoformat(row["end_date"]) if row["end_date"] else None,
            assigned_analysts=json.loads(row["assigned_analysts"]) if row["assigned_analysts"] else [],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            notes=json.loads(row["notes"]) if row["notes"] else [],
            metrics=json.loads(row["metrics"]) if row["metrics"] else {}
        )
    
    def save_finding(self, finding: HuntFinding) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO findings
                        (finding_id, hunt_id, title, description, severity, confidence,
                         evidence, affected_assets, indicators, mitre_mapping, timeline,
                         recommendations, found_at, analyst, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        finding.finding_id,
                        finding.hunt_id,
                        finding.title,
                        finding.description,
                        finding.severity.value,
                        finding.confidence,
                        json.dumps(finding.evidence),
                        json.dumps(finding.affected_assets),
                        json.dumps(finding.indicators),
                        json.dumps(finding.mitre_mapping),
                        json.dumps(finding.timeline),
                        json.dumps(finding.recommendations),
                        finding.found_at.isoformat(),
                        finding.analyst,
                        finding.status
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save finding: {e}")
                return False
    
    def get_findings_by_hunt(self, hunt_id: str) -> List[HuntFinding]:
        findings = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM findings WHERE hunt_id = ?", (hunt_id,))
                for row in cursor.fetchall():
                    findings.append(self._row_to_finding(row))
        except Exception as e:
            logger.error(f"Failed to get findings: {e}")
        return findings
    
    def _row_to_finding(self, row: sqlite3.Row) -> HuntFinding:
        return HuntFinding(
            finding_id=row["finding_id"],
            hunt_id=row["hunt_id"],
            title=row["title"],
            description=row["description"] or "",
            severity=FindingSeverity(row["severity"]),
            confidence=row["confidence"],
            evidence=json.loads(row["evidence"]) if row["evidence"] else [],
            affected_assets=json.loads(row["affected_assets"]) if row["affected_assets"] else [],
            indicators=json.loads(row["indicators"]) if row["indicators"] else [],
            mitre_mapping=json.loads(row["mitre_mapping"]) if row["mitre_mapping"] else [],
            timeline=json.loads(row["timeline"]) if row["timeline"] else [],
            recommendations=json.loads(row["recommendations"]) if row["recommendations"] else [],
            found_at=datetime.fromisoformat(row["found_at"]),
            analyst=row["analyst"],
            status=row["status"]
        )
    
    def save_baseline(self, baseline: BehaviorBaseline) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO baselines
                        (baseline_id, entity_type, entity_id, metric_name, mean, std_dev,
                         min_value, max_value, percentile_95, percentile_99, sample_count, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        baseline.baseline_id,
                        baseline.entity_type,
                        baseline.entity_id,
                        baseline.metric_name,
                        baseline.mean,
                        baseline.std_dev,
                        baseline.min_value,
                        baseline.max_value,
                        baseline.percentile_95,
                        baseline.percentile_99,
                        baseline.sample_count,
                        baseline.last_updated.isoformat()
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save baseline: {e}")
                return False
    
    def get_baseline(self, entity_type: str, entity_id: str, metric_name: str) -> Optional[BehaviorBaseline]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM baselines 
                    WHERE entity_type = ? AND entity_id = ? AND metric_name = ?
                """, (entity_type, entity_id, metric_name))
                row = cursor.fetchone()
                if row:
                    return BehaviorBaseline(
                        baseline_id=row["baseline_id"],
                        entity_type=row["entity_type"],
                        entity_id=row["entity_id"],
                        metric_name=row["metric_name"],
                        mean=row["mean"],
                        std_dev=row["std_dev"],
                        min_value=row["min_value"],
                        max_value=row["max_value"],
                        percentile_95=row["percentile_95"],
                        percentile_99=row["percentile_99"],
                        sample_count=row["sample_count"],
                        last_updated=datetime.fromisoformat(row["last_updated"])
                    )
        except Exception as e:
            logger.error(f"Failed to get baseline: {e}")
        return None
    
    def save_anomaly(self, anomaly: AnomalyDetection) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO anomalies
                        (anomaly_id, entity_type, entity_id, metric_name, observed_value,
                         expected_min, expected_max, deviation_score, detected_at, context)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        anomaly.anomaly_id,
                        anomaly.entity_type,
                        anomaly.entity_id,
                        anomaly.metric_name,
                        anomaly.observed_value,
                        anomaly.expected_range[0],
                        anomaly.expected_range[1],
                        anomaly.deviation_score,
                        anomaly.detected_at.isoformat(),
                        json.dumps(anomaly.context)
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save anomaly: {e}")
                return False
    
    def save_threat_actor(self, actor: ThreatActor) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO threat_actors
                        (actor_id, name, aliases, description, motivation, sophistication,
                         target_sectors, target_regions, known_ttps, known_tools,
                         known_infrastructure, first_seen, last_seen, references_list)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        actor.actor_id,
                        actor.name,
                        json.dumps(actor.aliases),
                        actor.description,
                        actor.motivation,
                        actor.sophistication,
                        json.dumps(actor.target_sectors),
                        json.dumps(actor.target_regions),
                        json.dumps(actor.known_ttps),
                        json.dumps(actor.known_tools),
                        json.dumps(actor.known_infrastructure),
                        actor.first_seen.isoformat(),
                        actor.last_seen.isoformat(),
                        json.dumps(actor.references)
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save threat actor: {e}")
                return False


class LogParser:
    """Parses various log formats"""
    
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)$'
    )
    
    AUTH_LOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)$'
    )
    
    APACHE_LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\S+)'
    )
    
    NGINX_LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )
    
    def parse_line(self, line: str, log_type: DataSourceType) -> Optional[Dict[str, Any]]:
        """Parse single log line"""
        if log_type == DataSourceType.SYSLOG:
            return self._parse_syslog(line)
        elif log_type == DataSourceType.AUTH_LOG:
            return self._parse_auth_log(line)
        elif log_type == DataSourceType.APPLICATION_LOG:
            return self._parse_application_log(line)
        else:
            return {"raw": line, "timestamp": datetime.utcnow().isoformat()}
    
    def _parse_syslog(self, line: str) -> Optional[Dict[str, Any]]:
        match = self.SYSLOG_PATTERN.match(line)
        if match:
            return {
                "timestamp": match.group("timestamp"),
                "hostname": match.group("hostname"),
                "program": match.group("program"),
                "pid": match.group("pid"),
                "message": match.group("message"),
                "raw": line
            }
        return {"raw": line}
    
    def _parse_auth_log(self, line: str) -> Optional[Dict[str, Any]]:
        match = self.AUTH_LOG_PATTERN.match(line)
        if match:
            parsed = {
                "timestamp": match.group("timestamp"),
                "hostname": match.group("hostname"),
                "service": match.group("service"),
                "pid": match.group("pid"),
                "message": match.group("message"),
                "raw": line
            }
            
            message = match.group("message")
            
            if "Failed password" in message:
                parsed["event_type"] = "failed_login"
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
                if ip_match:
                    parsed["source_ip"] = ip_match.group(1)
                user_match = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', message)
                if user_match:
                    parsed["username"] = user_match.group(1)
            
            elif "Accepted" in message:
                parsed["event_type"] = "successful_login"
                ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
                if ip_match:
                    parsed["source_ip"] = ip_match.group(1)
                user_match = re.search(r'for\s+(\S+)', message)
                if user_match:
                    parsed["username"] = user_match.group(1)
            
            elif "session opened" in message:
                parsed["event_type"] = "session_opened"
                user_match = re.search(r'for\s+user\s+(\S+)', message)
                if user_match:
                    parsed["username"] = user_match.group(1)
            
            elif "session closed" in message:
                parsed["event_type"] = "session_closed"
                user_match = re.search(r'for\s+user\s+(\S+)', message)
                if user_match:
                    parsed["username"] = user_match.group(1)
            
            return parsed
        return {"raw": line}
    
    def _parse_application_log(self, line: str) -> Optional[Dict[str, Any]]:
        apache_match = self.APACHE_LOG_PATTERN.match(line)
        if apache_match:
            return {
                "source_ip": apache_match.group("ip"),
                "user": apache_match.group("user"),
                "timestamp": apache_match.group("timestamp"),
                "method": apache_match.group("method"),
                "path": apache_match.group("path"),
                "protocol": apache_match.group("protocol"),
                "status": int(apache_match.group("status")),
                "size": apache_match.group("size"),
                "raw": line
            }
        
        nginx_match = self.NGINX_LOG_PATTERN.match(line)
        if nginx_match:
            request = nginx_match.group("request")
            parts = request.split()
            return {
                "source_ip": nginx_match.group("ip"),
                "user": nginx_match.group("user"),
                "timestamp": nginx_match.group("timestamp"),
                "method": parts[0] if parts else "",
                "path": parts[1] if len(parts) > 1 else "",
                "status": int(nginx_match.group("status")),
                "size": int(nginx_match.group("size")),
                "referer": nginx_match.group("referer"),
                "user_agent": nginx_match.group("user_agent"),
                "raw": line
            }
        
        return {"raw": line}


class HuntQueryEngine:
    """Executes hunt queries against log data"""
    
    def __init__(self, log_parser: LogParser):
        self.log_parser = log_parser
        self._log_paths = {
            DataSourceType.SYSLOG: ["/var/log/syslog", "/var/log/messages"],
            DataSourceType.AUTH_LOG: ["/var/log/auth.log", "/var/log/secure"],
            DataSourceType.AUDIT_LOG: ["/var/log/audit/audit.log"],
            DataSourceType.FIREWALL_LOG: ["/var/log/ufw.log", "/var/log/firewall"],
            DataSourceType.APPLICATION_LOG: ["/var/log/apache2/access.log", "/var/log/nginx/access.log"],
            DataSourceType.ZEEK_LOG: ["/opt/zeek/logs/current"],
            DataSourceType.SURICATA_LOG: ["/var/log/suricata/eve.json"],
        }
    
    def execute_query(self, query: HuntQuery, time_range: Tuple[datetime, datetime] = None) -> List[Dict[str, Any]]:
        """Execute hunt query"""
        results = []
        
        log_paths = self._log_paths.get(query.data_source, [])
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                if os.path.isdir(log_path):
                    for root, dirs, files in os.walk(log_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            results.extend(self._search_file(file_path, query, time_range))
                else:
                    results.extend(self._search_file(log_path, query, time_range))
        
        return results
    
    def _search_file(self, file_path: str, query: HuntQuery,
                     time_range: Tuple[datetime, datetime] = None) -> List[Dict[str, Any]]:
        """Search single file"""
        results = []
        
        try:
            if file_path.endswith(".json"):
                results.extend(self._search_json_file(file_path, query))
            else:
                results.extend(self._search_text_file(file_path, query))
        except Exception as e:
            logger.error(f"Error searching file {file_path}: {e}")
        
        return results
    
    def _search_text_file(self, file_path: str, query: HuntQuery) -> List[Dict[str, Any]]:
        """Search text log file"""
        results = []
        
        try:
            with open(file_path, "r", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    if self._matches_query(line, query):
                        parsed = self.log_parser.parse_line(line, query.data_source)
                        if parsed:
                            parsed["_file"] = file_path
                            parsed["_line"] = line_num
                            results.append(parsed)
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
        
        return results
    
    def _search_json_file(self, file_path: str, query: HuntQuery) -> List[Dict[str, Any]]:
        """Search JSON log file (like Suricata EVE)"""
        results = []
        
        try:
            with open(file_path, "r", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        record = json.loads(line)
                        if self._matches_json_query(record, query):
                            record["_file"] = file_path
                            record["_line"] = line_num
                            results.append(record)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error reading JSON file {file_path}: {e}")
        
        return results
    
    def _matches_query(self, line: str, query: HuntQuery) -> bool:
        """Check if line matches query"""
        query_string = query.query_string
        
        if query.query_type == "regex":
            try:
                return bool(re.search(query_string, line, re.IGNORECASE))
            except re.error:
                return False
        
        elif query.query_type == "contains":
            return query_string.lower() in line.lower()
        
        elif query.query_type == "glob":
            return fnmatch.fnmatch(line.lower(), query_string.lower())
        
        elif query.query_type == "exact":
            return query_string == line
        
        return False
    
    def _matches_json_query(self, record: Dict[str, Any], query: HuntQuery) -> bool:
        """Check if JSON record matches query"""
        query_string = query.query_string
        
        if query.query_type == "field":
            field_name, operator, value = self._parse_field_query(query_string)
            if field_name and field_name in record:
                return self._compare_values(record[field_name], operator, value)
        
        elif query.query_type == "contains":
            record_str = json.dumps(record).lower()
            return query_string.lower() in record_str
        
        elif query.query_type == "regex":
            record_str = json.dumps(record)
            try:
                return bool(re.search(query_string, record_str, re.IGNORECASE))
            except re.error:
                return False
        
        return False
    
    def _parse_field_query(self, query_string: str) -> Tuple[str, str, str]:
        """Parse field query like 'event_type == alert'"""
        operators = ["==", "!=", ">=", "<=", ">", "<", "contains", "startswith", "endswith"]
        
        for op in operators:
            if op in query_string:
                parts = query_string.split(op, 1)
                if len(parts) == 2:
                    return parts[0].strip(), op, parts[1].strip().strip("'\"")
        
        return None, None, None
    
    def _compare_values(self, field_value: Any, operator: str, query_value: str) -> bool:
        """Compare field value with query value"""
        if operator == "==":
            return str(field_value).lower() == query_value.lower()
        elif operator == "!=":
            return str(field_value).lower() != query_value.lower()
        elif operator == "contains":
            return query_value.lower() in str(field_value).lower()
        elif operator == "startswith":
            return str(field_value).lower().startswith(query_value.lower())
        elif operator == "endswith":
            return str(field_value).lower().endswith(query_value.lower())
        elif operator in [">", "<", ">=", "<="]:
            try:
                fv = float(field_value)
                qv = float(query_value)
                if operator == ">":
                    return fv > qv
                elif operator == "<":
                    return fv < qv
                elif operator == ">=":
                    return fv >= qv
                elif operator == "<=":
                    return fv <= qv
            except ValueError:
                return False
        
        return False


class BehaviorAnalyzer:
    """Analyzes behavior patterns and detects anomalies"""
    
    def __init__(self, database: HuntDatabase):
        self.database = database
        self._metrics_cache: Dict[str, List[float]] = defaultdict(list)
    
    def update_baseline(self, entity_type: str, entity_id: str, metric_name: str,
                        values: List[float]) -> BehaviorBaseline:
        """Update or create baseline from values"""
        if len(values) < 10:
            raise ValueError("Need at least 10 samples for baseline")
        
        sorted_values = sorted(values)
        
        baseline = BehaviorBaseline(
            baseline_id=f"BL-{hashlib.sha256(f'{entity_type}{entity_id}{metric_name}'.encode()).hexdigest()[:12].upper()}",
            entity_type=entity_type,
            entity_id=entity_id,
            metric_name=metric_name,
            mean=statistics.mean(values),
            std_dev=statistics.stdev(values) if len(values) > 1 else 0,
            min_value=min(values),
            max_value=max(values),
            percentile_95=sorted_values[int(len(sorted_values) * 0.95)],
            percentile_99=sorted_values[int(len(sorted_values) * 0.99)],
            sample_count=len(values),
            last_updated=datetime.utcnow()
        )
        
        self.database.save_baseline(baseline)
        return baseline
    
    def detect_anomaly(self, entity_type: str, entity_id: str, metric_name: str,
                       observed_value: float, threshold_std: float = 3.0) -> Optional[AnomalyDetection]:
        """Detect if observed value is anomalous"""
        baseline = self.database.get_baseline(entity_type, entity_id, metric_name)
        
        if not baseline:
            return None
        
        if baseline.std_dev == 0:
            if observed_value != baseline.mean:
                deviation_score = 100.0
            else:
                return None
        else:
            deviation_score = abs(observed_value - baseline.mean) / baseline.std_dev
        
        if deviation_score >= threshold_std:
            expected_min = baseline.mean - (threshold_std * baseline.std_dev)
            expected_max = baseline.mean + (threshold_std * baseline.std_dev)
            
            anomaly = AnomalyDetection(
                anomaly_id=f"ANOM-{hashlib.sha256(f'{entity_type}{entity_id}{metric_name}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}",
                entity_type=entity_type,
                entity_id=entity_id,
                metric_name=metric_name,
                observed_value=observed_value,
                expected_range=(expected_min, expected_max),
                deviation_score=deviation_score,
                detected_at=datetime.utcnow(),
                context={
                    "baseline_mean": baseline.mean,
                    "baseline_std": baseline.std_dev,
                    "threshold": threshold_std
                }
            )
            
            self.database.save_anomaly(anomaly)
            return anomaly
        
        return None
    
    def analyze_login_patterns(self, auth_logs: List[Dict[str, Any]]) -> List[AnomalyDetection]:
        """Analyze login patterns for anomalies"""
        anomalies = []
        
        user_logins: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for log in auth_logs:
            if log.get("event_type") in ["successful_login", "failed_login"]:
                username = log.get("username", "unknown")
                user_logins[username].append(log)
        
        for username, logins in user_logins.items():
            failed_count = sum(1 for l in logins if l.get("event_type") == "failed_login")
            
            anomaly = self.detect_anomaly("user", username, "failed_logins_per_hour", failed_count)
            if anomaly:
                anomalies.append(anomaly)
            
            source_ips = set(l.get("source_ip") for l in logins if l.get("source_ip"))
            anomaly = self.detect_anomaly("user", username, "unique_source_ips", len(source_ips))
            if anomaly:
                anomalies.append(anomaly)
        
        return anomalies
    
    def analyze_network_patterns(self, network_logs: List[Dict[str, Any]]) -> List[AnomalyDetection]:
        """Analyze network patterns for anomalies"""
        anomalies = []
        
        ip_connections: Dict[str, int] = Counter()
        ip_bytes: Dict[str, int] = defaultdict(int)
        
        for log in network_logs:
            src_ip = log.get("source_ip") or log.get("src_ip")
            if src_ip:
                ip_connections[src_ip] += 1
                ip_bytes[src_ip] += log.get("bytes", 0) or log.get("size", 0) or 0
        
        for ip, conn_count in ip_connections.items():
            anomaly = self.detect_anomaly("ip", ip, "connections_per_hour", conn_count)
            if anomaly:
                anomalies.append(anomaly)
        
        for ip, byte_count in ip_bytes.items():
            anomaly = self.detect_anomaly("ip", ip, "bytes_per_hour", byte_count)
            if anomaly:
                anomalies.append(anomaly)
        
        return anomalies


class KillChainAnalyzer:
    """Analyzes events against cyber kill chain"""
    
    KILL_CHAIN_PHASES = [
        "reconnaissance",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "command_and_control",
        "actions_on_objectives"
    ]
    
    PHASE_INDICATORS = {
        "reconnaissance": [
            r"nmap",
            r"port\s*scan",
            r"vulnerability\s*scan",
            r"directory\s*brute",
            r"gobuster",
            r"nikto",
            r"masscan"
        ],
        "delivery": [
            r"phishing",
            r"malicious\s*attachment",
            r"drive-by",
            r"watering\s*hole",
            r"usb\s*drop"
        ],
        "exploitation": [
            r"exploit",
            r"buffer\s*overflow",
            r"sql\s*injection",
            r"xss",
            r"rce",
            r"remote\s*code\s*execution",
            r"cve-\d{4}-\d+"
        ],
        "installation": [
            r"persistence",
            r"registry\s*modification",
            r"scheduled\s*task",
            r"service\s*creation",
            r"startup\s*entry",
            r"cron\s*job"
        ],
        "command_and_control": [
            r"c2",
            r"c&c",
            r"beacon",
            r"callback",
            r"reverse\s*shell",
            r"dns\s*tunnel",
            r"http\s*tunnel"
        ],
        "actions_on_objectives": [
            r"exfiltration",
            r"data\s*theft",
            r"ransomware",
            r"encryption",
            r"destruction",
            r"lateral\s*movement"
        ]
    }
    
    def analyze_events(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze events and map to kill chain phases"""
        phase_events = {phase: [] for phase in self.KILL_CHAIN_PHASES}
        
        for event in events:
            event_str = json.dumps(event).lower()
            
            for phase, indicators in self.PHASE_INDICATORS.items():
                for indicator in indicators:
                    if re.search(indicator, event_str, re.IGNORECASE):
                        phase_events[phase].append({
                            "event": event,
                            "matched_indicator": indicator,
                            "phase": phase
                        })
                        break
        
        return phase_events
    
    def get_attack_progression(self, phase_events: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        """Get attack progression through kill chain"""
        progression = []
        
        for phase in self.KILL_CHAIN_PHASES:
            if phase_events.get(phase):
                progression.append(phase)
        
        return progression
    
    def calculate_threat_score(self, phase_events: Dict[str, List[Dict[str, Any]]]) -> float:
        """Calculate threat score based on kill chain coverage"""
        phase_weights = {
            "reconnaissance": 0.05,
            "weaponization": 0.10,
            "delivery": 0.15,
            "exploitation": 0.20,
            "installation": 0.20,
            "command_and_control": 0.15,
            "actions_on_objectives": 0.15
        }
        
        score = 0.0
        for phase, weight in phase_weights.items():
            if phase_events.get(phase):
                event_count = len(phase_events[phase])
                phase_score = min(1.0, event_count / 5.0)
                score += weight * phase_score * 100
        
        return score


class ATTACKHunter:
    """Hunt based on MITRE ATT&CK techniques"""
    
    TECHNIQUE_QUERIES = {
        "T1566.001": {
            "name": "Spearphishing Attachment",
            "query_type": "regex",
            "query": r"(\.exe|\.dll|\.scr|\.bat|\.ps1|\.vbs|\.js)\s*(attached|attachment|download)",
            "data_sources": [DataSourceType.APPLICATION_LOG, DataSourceType.SYSLOG]
        },
        "T1059.001": {
            "name": "PowerShell",
            "query_type": "regex",
            "query": r"powershell.*(-enc|-encodedcommand|-e\s|invoke-|iex\s|downloadstring)",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.AUDIT_LOG]
        },
        "T1059.003": {
            "name": "Windows Command Shell",
            "query_type": "regex",
            "query": r"cmd\.exe.*/c\s|cmd\.exe.*&&",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.AUDIT_LOG]
        },
        "T1053.005": {
            "name": "Scheduled Task",
            "query_type": "regex",
            "query": r"(schtasks|at\s+\d|crontab|systemd-timer)",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.AUDIT_LOG]
        },
        "T1547.001": {
            "name": "Registry Run Keys",
            "query_type": "regex",
            "query": r"(HKLM|HKCU).*\\(Run|RunOnce)",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.AUDIT_LOG]
        },
        "T1078": {
            "name": "Valid Accounts",
            "query_type": "regex",
            "query": r"(successful|accepted)\s*(login|authentication).*admin|root",
            "data_sources": [DataSourceType.AUTH_LOG]
        },
        "T1110": {
            "name": "Brute Force",
            "query_type": "regex",
            "query": r"(failed|invalid)\s*(password|login|authentication)",
            "data_sources": [DataSourceType.AUTH_LOG]
        },
        "T1071.001": {
            "name": "Web Protocols C2",
            "query_type": "regex",
            "query": r"(beacon|callback|c2|command.*control).*http",
            "data_sources": [DataSourceType.NETWORK_LOG, DataSourceType.PROXY_LOG]
        },
        "T1071.004": {
            "name": "DNS C2",
            "query_type": "regex",
            "query": r"(dns.*tunnel|txt.*record.*large|unusual.*subdomain)",
            "data_sources": [DataSourceType.DNS_LOG, DataSourceType.NETWORK_LOG]
        },
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "query_type": "regex",
            "query": r"(dns.*exfil|icmp.*data|large.*upload)",
            "data_sources": [DataSourceType.NETWORK_LOG, DataSourceType.FIREWALL_LOG]
        },
        "T1486": {
            "name": "Data Encrypted for Impact",
            "query_type": "regex",
            "query": r"(ransomware|encrypt.*files|\.locked|\.encrypted|ransom.*note)",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.ENDPOINT_LOG]
        },
        "T1021.002": {
            "name": "SMB/Windows Admin Shares",
            "query_type": "regex",
            "query": r"(\\\\.*\\(admin\$|c\$|ipc\$)|smb.*lateral)",
            "data_sources": [DataSourceType.NETWORK_LOG, DataSourceType.AUDIT_LOG]
        },
        "T1055": {
            "name": "Process Injection",
            "query_type": "regex",
            "query": r"(process.*inject|dll.*inject|hollowing|createremotethread)",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.ENDPOINT_LOG]
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "query_type": "regex",
            "query": r"(mimikatz|lsass.*dump|sam.*dump|ntds\.dit|secretsdump)",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.AUDIT_LOG]
        },
        "T1087": {
            "name": "Account Discovery",
            "query_type": "regex",
            "query": r"(net\s+user|whoami|id\s|getent\s+passwd|cat\s+/etc/passwd)",
            "data_sources": [DataSourceType.SYSLOG, DataSourceType.AUDIT_LOG]
        }
    }
    
    def __init__(self, query_engine: HuntQueryEngine):
        self.query_engine = query_engine
    
    def hunt_technique(self, technique_id: str, time_range: Tuple[datetime, datetime] = None) -> List[Dict[str, Any]]:
        """Hunt for specific ATT&CK technique"""
        technique = self.TECHNIQUE_QUERIES.get(technique_id)
        if not technique:
            return []
        
        all_results = []
        
        for data_source in technique["data_sources"]:
            query = HuntQuery(
                query_id=f"ATTACK-{technique_id}",
                name=technique["name"],
                description=f"Hunt for {technique['name']} ({technique_id})",
                query_type=technique["query_type"],
                query_string=technique["query"],
                data_source=data_source,
                parameters={},
                expected_fields=[]
            )
            
            results = self.query_engine.execute_query(query, time_range)
            for result in results:
                result["technique_id"] = technique_id
                result["technique_name"] = technique["name"]
            all_results.extend(results)
        
        return all_results
    
    def hunt_all_techniques(self, time_range: Tuple[datetime, datetime] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Hunt for all known techniques"""
        results = {}
        
        for technique_id in self.TECHNIQUE_QUERIES:
            technique_results = self.hunt_technique(technique_id, time_range)
            if technique_results:
                results[technique_id] = technique_results
        
        return results
    
    def get_technique_coverage(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Get ATT&CK technique coverage from hunt results"""
        tactics = defaultdict(list)
        
        tactic_mapping = {
            "T1566": "initial-access",
            "T1059": "execution",
            "T1053": "persistence",
            "T1547": "persistence",
            "T1078": "initial-access",
            "T1110": "credential-access",
            "T1071": "command-and-control",
            "T1048": "exfiltration",
            "T1486": "impact",
            "T1021": "lateral-movement",
            "T1055": "defense-evasion",
            "T1003": "credential-access",
            "T1087": "discovery"
        }
        
        for technique_id, technique_results in results.items():
            base_technique = technique_id.split(".")[0]
            tactic = tactic_mapping.get(base_technique, "unknown")
            tactics[tactic].append({
                "technique_id": technique_id,
                "hit_count": len(technique_results)
            })
        
        return {
            "tactics_detected": list(tactics.keys()),
            "technique_count": len(results),
            "total_hits": sum(len(r) for r in results.values()),
            "by_tactic": dict(tactics)
        }


class ThreatHuntingEngine:
    """Main threat hunting engine"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.database = HuntDatabase()
        self.log_parser = LogParser()
        self.query_engine = HuntQueryEngine(self.log_parser)
        self.behavior_analyzer = BehaviorAnalyzer(self.database)
        self.kill_chain_analyzer = KillChainAnalyzer()
        self.attack_hunter = ATTACKHunter(self.query_engine)
        
        self._load_default_threat_actors()
    
    def _load_default_threat_actors(self):
        """Load known threat actors"""
        default_actors = [
            ThreatActor(
                actor_id="TA-APT28",
                name="APT28",
                aliases=["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
                description="Russian state-sponsored threat group",
                motivation="espionage",
                sophistication="advanced",
                target_sectors=["government", "military", "defense", "media"],
                target_regions=["europe", "north-america", "middle-east"],
                known_ttps=[
                    {"tactic": "initial-access", "technique": "T1566.001"},
                    {"tactic": "execution", "technique": "T1059.001"},
                    {"tactic": "persistence", "technique": "T1547.001"},
                    {"tactic": "credential-access", "technique": "T1003"}
                ],
                known_tools=["X-Agent", "Zebrocy", "Koadic", "Mimikatz"],
                known_infrastructure=[],
                first_seen=datetime(2004, 1, 1),
                last_seen=datetime.utcnow(),
                references=["https://attack.mitre.org/groups/G0007/"]
            ),
            ThreatActor(
                actor_id="TA-APT29",
                name="APT29",
                aliases=["Cozy Bear", "The Dukes", "NOBELIUM"],
                description="Russian state-sponsored threat group",
                motivation="espionage",
                sophistication="advanced",
                target_sectors=["government", "think-tanks", "healthcare"],
                target_regions=["north-america", "europe"],
                known_ttps=[
                    {"tactic": "initial-access", "technique": "T1195.002"},
                    {"tactic": "execution", "technique": "T1059.001"},
                    {"tactic": "defense-evasion", "technique": "T1027"},
                    {"tactic": "command-and-control", "technique": "T1071.001"}
                ],
                known_tools=["SUNBURST", "TEARDROP", "Cobalt Strike"],
                known_infrastructure=[],
                first_seen=datetime(2008, 1, 1),
                last_seen=datetime.utcnow(),
                references=["https://attack.mitre.org/groups/G0016/"]
            ),
            ThreatActor(
                actor_id="TA-LAZARUS",
                name="Lazarus Group",
                aliases=["HIDDEN COBRA", "Guardians of Peace", "APT38"],
                description="North Korean state-sponsored threat group",
                motivation="financial",
                sophistication="advanced",
                target_sectors=["financial", "cryptocurrency", "entertainment"],
                target_regions=["global"],
                known_ttps=[
                    {"tactic": "initial-access", "technique": "T1566.001"},
                    {"tactic": "execution", "technique": "T1059.003"},
                    {"tactic": "impact", "technique": "T1486"},
                    {"tactic": "collection", "technique": "T1005"}
                ],
                known_tools=["HOPLIGHT", "ELECTRICFISH", "FASTCash"],
                known_infrastructure=[],
                first_seen=datetime(2009, 1, 1),
                last_seen=datetime.utcnow(),
                references=["https://attack.mitre.org/groups/G0032/"]
            )
        ]
        
        for actor in default_actors:
            self.database.save_threat_actor(actor)
    
    def create_campaign(self, name: str, description: str, priority: HuntPriority,
                        analysts: List[str] = None) -> HuntCampaign:
        """Create new hunt campaign"""
        campaign_id = f"HUNT-{hashlib.sha256(f'{name}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        campaign = HuntCampaign(
            campaign_id=campaign_id,
            name=name,
            description=description,
            status=HuntStatus.DRAFT,
            priority=priority,
            hypotheses=[],
            queries=[],
            findings=[],
            start_date=datetime.utcnow(),
            end_date=None,
            assigned_analysts=analysts or [],
            tags=[],
            notes=[],
            metrics={}
        )
        
        self.database.save_campaign(campaign)
        return campaign
    
    def add_hypothesis(self, campaign_id: str, hypothesis: HuntHypothesis) -> bool:
        """Add hypothesis to campaign"""
        campaign = self.database.get_campaign(campaign_id)
        if not campaign:
            return False
        
        campaign.hypotheses.append(hypothesis)
        return self.database.save_campaign(campaign)
    
    def add_query(self, campaign_id: str, query: HuntQuery) -> bool:
        """Add query to campaign"""
        campaign = self.database.get_campaign(campaign_id)
        if not campaign:
            return False
        
        campaign.queries.append(query)
        return self.database.save_campaign(campaign)
    
    def execute_campaign_queries(self, campaign_id: str,
                                  time_range: Tuple[datetime, datetime] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Execute all queries in campaign"""
        campaign = self.database.get_campaign(campaign_id)
        if not campaign:
            return {}
        
        results = {}
        for query in campaign.queries:
            query_results = self.query_engine.execute_query(query, time_range)
            results[query.query_id] = query_results
        
        return results
    
    def create_finding(self, hunt_id: str, title: str, description: str,
                       severity: FindingSeverity, evidence: List[Dict[str, Any]],
                       analyst: str) -> HuntFinding:
        """Create hunt finding"""
        finding_id = f"FIND-{hashlib.sha256(f'{hunt_id}{title}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        finding = HuntFinding(
            finding_id=finding_id,
            hunt_id=hunt_id,
            title=title,
            description=description,
            severity=severity,
            confidence=0.8,
            evidence=evidence,
            affected_assets=[],
            indicators=[],
            mitre_mapping=[],
            timeline=[],
            recommendations=[],
            found_at=datetime.utcnow(),
            analyst=analyst,
            status="new"
        )
        
        self.database.save_finding(finding)
        
        campaign = self.database.get_campaign(hunt_id)
        if campaign:
            campaign.findings.append(finding_id)
            self.database.save_campaign(campaign)
        
        return finding
    
    def hunt_for_technique(self, technique_id: str,
                           time_range: Tuple[datetime, datetime] = None) -> List[Dict[str, Any]]:
        """Hunt for specific ATT&CK technique"""
        return self.attack_hunter.hunt_technique(technique_id, time_range)
    
    def hunt_all_techniques(self, time_range: Tuple[datetime, datetime] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Hunt for all known techniques"""
        return self.attack_hunter.hunt_all_techniques(time_range)
    
    def analyze_kill_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze events against kill chain"""
        phase_events = self.kill_chain_analyzer.analyze_events(events)
        progression = self.kill_chain_analyzer.get_attack_progression(phase_events)
        threat_score = self.kill_chain_analyzer.calculate_threat_score(phase_events)
        
        return {
            "phase_events": phase_events,
            "progression": progression,
            "threat_score": threat_score,
            "phases_detected": len(progression),
            "total_phases": len(self.kill_chain_analyzer.KILL_CHAIN_PHASES)
        }
    
    def detect_anomalies(self, entity_type: str, entity_id: str, metric_name: str,
                         observed_value: float) -> Optional[AnomalyDetection]:
        """Detect behavioral anomalies"""
        return self.behavior_analyzer.detect_anomaly(entity_type, entity_id, metric_name, observed_value)
    
    def update_baseline(self, entity_type: str, entity_id: str, metric_name: str,
                        values: List[float]) -> BehaviorBaseline:
        """Update behavioral baseline"""
        return self.behavior_analyzer.update_baseline(entity_type, entity_id, metric_name, values)
    
    def search_logs(self, query_string: str, query_type: str = "contains",
                    data_source: DataSourceType = DataSourceType.SYSLOG,
                    time_range: Tuple[datetime, datetime] = None) -> List[Dict[str, Any]]:
        """Search logs with custom query"""
        query = HuntQuery(
            query_id=f"ADHOC-{hashlib.sha256(query_string.encode()).hexdigest()[:8]}",
            name="Ad-hoc Query",
            description="Ad-hoc search query",
            query_type=query_type,
            query_string=query_string,
            data_source=data_source,
            parameters={},
            expected_fields=[]
        )
        
        return self.query_engine.execute_query(query, time_range)
    
    def get_campaign(self, campaign_id: str) -> Optional[HuntCampaign]:
        """Get campaign by ID"""
        return self.database.get_campaign(campaign_id)
    
    def get_findings(self, hunt_id: str) -> List[HuntFinding]:
        """Get findings for hunt"""
        return self.database.get_findings_by_hunt(hunt_id)
    
    def get_attack_coverage(self) -> Dict[str, Any]:
        """Get current ATT&CK technique coverage"""
        results = self.hunt_all_techniques()
        return self.attack_hunter.get_technique_coverage(results)


def get_threat_hunting_engine() -> ThreatHuntingEngine:
    """Get singleton instance of ThreatHuntingEngine"""
    return ThreatHuntingEngine()
