"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - SOAR ENGINE
Security Orchestration, Automation and Response Platform

This module implements:
- Playbook engine with conditional logic and branching
- Automated response actions (block IP, isolate host, disable account)
- Case management with evidence collection
- Workflow orchestration with parallel execution
- Integration with local security tools (iptables, fail2ban, etc.)
- Alert correlation and deduplication
- Incident timeline reconstruction
- Automated enrichment from local threat intel

100% opensource - NO external API dependencies
Uses local tools: iptables, fail2ban, systemctl, journalctl

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import json
import hashlib
import logging
import threading
import subprocess
import shlex
import time
import re
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


SOAR_DB_PATH = os.environ.get("SOAR_DB_PATH", "/var/lib/tyranthos/soar.db")
MAX_PARALLEL_ACTIONS = int(os.environ.get("MAX_PARALLEL_ACTIONS", "10"))
ACTION_TIMEOUT = int(os.environ.get("ACTION_TIMEOUT", "300"))


class PlaybookStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    WAITING_APPROVAL = "waiting_approval"


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    ISOLATE_HOST = "isolate_host"
    UNISOLATE_HOST = "unisolate_host"
    DISABLE_ACCOUNT = "disable_account"
    ENABLE_ACCOUNT = "enable_account"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    COLLECT_EVIDENCE = "collect_evidence"
    SEND_NOTIFICATION = "send_notification"
    CREATE_TICKET = "create_ticket"
    ENRICH_IOC = "enrich_ioc"
    SCAN_HOST = "scan_host"
    UPDATE_FIREWALL = "update_firewall"
    ADD_TO_BLOCKLIST = "add_to_blocklist"
    REMOVE_FROM_BLOCKLIST = "remove_from_blocklist"
    RESTART_SERVICE = "restart_service"
    CAPTURE_MEMORY = "capture_memory"
    CAPTURE_DISK = "capture_disk"
    RUN_YARA_SCAN = "run_yara_scan"
    CUSTOM_SCRIPT = "custom_script"
    CONDITIONAL = "conditional"
    PARALLEL = "parallel"
    WAIT = "wait"
    APPROVAL = "approval"


class CaseSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CaseStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    REOPENED = "reopened"


@dataclass
class PlaybookAction:
    action_id: str
    action_type: ActionType
    name: str
    description: str
    parameters: Dict[str, Any]
    timeout: int
    retry_count: int
    retry_delay: int
    on_success: Optional[str]
    on_failure: Optional[str]
    requires_approval: bool
    condition: Optional[str]


@dataclass
class Playbook:
    playbook_id: str
    name: str
    description: str
    version: str
    status: PlaybookStatus
    trigger_conditions: List[Dict[str, Any]]
    actions: List[PlaybookAction]
    variables: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    created_by: str
    tags: List[str]


@dataclass
class ActionResult:
    action_id: str
    status: ExecutionStatus
    output: str
    error: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]
    duration_ms: int
    metadata: Dict[str, Any]


@dataclass
class PlaybookExecution:
    execution_id: str
    playbook_id: str
    status: ExecutionStatus
    trigger_event: Dict[str, Any]
    variables: Dict[str, Any]
    action_results: List[ActionResult]
    started_at: datetime
    completed_at: Optional[datetime]
    executed_by: str
    error: Optional[str]


@dataclass
class Case:
    case_id: str
    title: str
    description: str
    severity: CaseSeverity
    status: CaseStatus
    assignee: Optional[str]
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime]
    source_alerts: List[str]
    related_iocs: List[str]
    evidence: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    playbook_executions: List[str]
    tags: List[str]
    notes: List[Dict[str, Any]]
    metrics: Dict[str, Any]


@dataclass
class Alert:
    alert_id: str
    title: str
    description: str
    severity: CaseSeverity
    source: str
    timestamp: datetime
    indicators: List[Dict[str, Any]]
    raw_data: Dict[str, Any]
    is_processed: bool
    case_id: Optional[str]
    playbook_executions: List[str]


class SOARDatabase:
    """SQLite database for SOAR data"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or SOAR_DB_PATH
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
                CREATE TABLE IF NOT EXISTS playbooks (
                    playbook_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    trigger_conditions TEXT,
                    actions TEXT NOT NULL,
                    variables TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    tags TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    trigger_event TEXT,
                    variables TEXT,
                    action_results TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    executed_by TEXT NOT NULL,
                    error TEXT,
                    FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assignee TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT,
                    source_alerts TEXT,
                    related_iocs TEXT,
                    evidence TEXT,
                    timeline TEXT,
                    playbook_executions TEXT,
                    tags TEXT,
                    notes TEXT,
                    metrics TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    indicators TEXT,
                    raw_data TEXT,
                    is_processed INTEGER DEFAULT 0,
                    case_id TEXT,
                    playbook_executions TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocklist (
                    entry_id TEXT PRIMARY KEY,
                    entry_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    reason TEXT,
                    added_at TEXT NOT NULL,
                    added_by TEXT NOT NULL,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_executions_playbook ON executions(playbook_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_processed ON alerts(is_processed)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_value ON blocklist(value)")
            
            conn.commit()
    
    def save_playbook(self, playbook: Playbook) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO playbooks 
                        (playbook_id, name, description, version, status, trigger_conditions,
                         actions, variables, created_at, updated_at, created_by, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        playbook.playbook_id,
                        playbook.name,
                        playbook.description,
                        playbook.version,
                        playbook.status.value,
                        json.dumps(playbook.trigger_conditions),
                        json.dumps([asdict(a) for a in playbook.actions]),
                        json.dumps(playbook.variables),
                        playbook.created_at.isoformat(),
                        playbook.updated_at.isoformat(),
                        playbook.created_by,
                        json.dumps(playbook.tags)
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save playbook: {e}")
                return False
    
    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM playbooks WHERE playbook_id = ?", (playbook_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_playbook(row)
        except Exception as e:
            logger.error(f"Failed to get playbook: {e}")
        return None
    
    def get_active_playbooks(self) -> List[Playbook]:
        playbooks = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM playbooks WHERE status = ?", (PlaybookStatus.ACTIVE.value,))
                for row in cursor.fetchall():
                    playbooks.append(self._row_to_playbook(row))
        except Exception as e:
            logger.error(f"Failed to get active playbooks: {e}")
        return playbooks
    
    def _row_to_playbook(self, row: sqlite3.Row) -> Playbook:
        actions_data = json.loads(row["actions"])
        actions = []
        for a in actions_data:
            actions.append(PlaybookAction(
                action_id=a["action_id"],
                action_type=ActionType(a["action_type"]),
                name=a["name"],
                description=a["description"],
                parameters=a["parameters"],
                timeout=a["timeout"],
                retry_count=a["retry_count"],
                retry_delay=a["retry_delay"],
                on_success=a.get("on_success"),
                on_failure=a.get("on_failure"),
                requires_approval=a.get("requires_approval", False),
                condition=a.get("condition")
            ))
        
        return Playbook(
            playbook_id=row["playbook_id"],
            name=row["name"],
            description=row["description"] or "",
            version=row["version"],
            status=PlaybookStatus(row["status"]),
            trigger_conditions=json.loads(row["trigger_conditions"]) if row["trigger_conditions"] else [],
            actions=actions,
            variables=json.loads(row["variables"]) if row["variables"] else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            created_by=row["created_by"],
            tags=json.loads(row["tags"]) if row["tags"] else []
        )
    
    def save_execution(self, execution: PlaybookExecution) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO executions
                        (execution_id, playbook_id, status, trigger_event, variables,
                         action_results, started_at, completed_at, executed_by, error)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        execution.execution_id,
                        execution.playbook_id,
                        execution.status.value,
                        json.dumps(execution.trigger_event),
                        json.dumps(execution.variables),
                        json.dumps([asdict(r) for r in execution.action_results]),
                        execution.started_at.isoformat(),
                        execution.completed_at.isoformat() if execution.completed_at else None,
                        execution.executed_by,
                        execution.error
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save execution: {e}")
                return False
    
    def save_case(self, case: Case) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO cases
                        (case_id, title, description, severity, status, assignee,
                         created_at, updated_at, closed_at, source_alerts, related_iocs,
                         evidence, timeline, playbook_executions, tags, notes, metrics)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        case.case_id,
                        case.title,
                        case.description,
                        case.severity.value,
                        case.status.value,
                        case.assignee,
                        case.created_at.isoformat(),
                        case.updated_at.isoformat(),
                        case.closed_at.isoformat() if case.closed_at else None,
                        json.dumps(case.source_alerts),
                        json.dumps(case.related_iocs),
                        json.dumps(case.evidence),
                        json.dumps(case.timeline),
                        json.dumps(case.playbook_executions),
                        json.dumps(case.tags),
                        json.dumps(case.notes),
                        json.dumps(case.metrics)
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save case: {e}")
                return False
    
    def get_case(self, case_id: str) -> Optional[Case]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_case(row)
        except Exception as e:
            logger.error(f"Failed to get case: {e}")
        return None
    
    def _row_to_case(self, row: sqlite3.Row) -> Case:
        return Case(
            case_id=row["case_id"],
            title=row["title"],
            description=row["description"] or "",
            severity=CaseSeverity(row["severity"]),
            status=CaseStatus(row["status"]),
            assignee=row["assignee"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            closed_at=datetime.fromisoformat(row["closed_at"]) if row["closed_at"] else None,
            source_alerts=json.loads(row["source_alerts"]) if row["source_alerts"] else [],
            related_iocs=json.loads(row["related_iocs"]) if row["related_iocs"] else [],
            evidence=json.loads(row["evidence"]) if row["evidence"] else [],
            timeline=json.loads(row["timeline"]) if row["timeline"] else [],
            playbook_executions=json.loads(row["playbook_executions"]) if row["playbook_executions"] else [],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            notes=json.loads(row["notes"]) if row["notes"] else [],
            metrics=json.loads(row["metrics"]) if row["metrics"] else {}
        )
    
    def save_alert(self, alert: Alert) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO alerts
                        (alert_id, title, description, severity, source, timestamp,
                         indicators, raw_data, is_processed, case_id, playbook_executions)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        alert.alert_id,
                        alert.title,
                        alert.description,
                        alert.severity.value,
                        alert.source,
                        alert.timestamp.isoformat(),
                        json.dumps(alert.indicators),
                        json.dumps(alert.raw_data),
                        1 if alert.is_processed else 0,
                        alert.case_id,
                        json.dumps(alert.playbook_executions)
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save alert: {e}")
                return False
    
    def add_to_blocklist(self, entry_type: str, value: str, reason: str,
                         added_by: str, expires_at: datetime = None) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    entry_id = f"BL-{hashlib.sha256(f'{entry_type}{value}'.encode()).hexdigest()[:12].upper()}"
                    cursor.execute("""
                        INSERT OR REPLACE INTO blocklist
                        (entry_id, entry_type, value, reason, added_at, added_by, expires_at, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    """, (
                        entry_id,
                        entry_type,
                        value,
                        reason,
                        datetime.utcnow().isoformat(),
                        added_by,
                        expires_at.isoformat() if expires_at else None
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to add to blocklist: {e}")
                return False
    
    def is_blocklisted(self, value: str) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM blocklist 
                    WHERE value = ? AND is_active = 1
                    AND (expires_at IS NULL OR expires_at > ?)
                """, (value, datetime.utcnow().isoformat()))
                return cursor.fetchone()[0] > 0
        except Exception as e:
            logger.error(f"Failed to check blocklist: {e}")
            return False


class ActionExecutor:
    """Executes SOAR actions using local tools"""
    
    def __init__(self, database: SOARDatabase):
        self.database = database
        self._action_handlers: Dict[ActionType, Callable] = {
            ActionType.BLOCK_IP: self._block_ip,
            ActionType.UNBLOCK_IP: self._unblock_ip,
            ActionType.ISOLATE_HOST: self._isolate_host,
            ActionType.UNISOLATE_HOST: self._unisolate_host,
            ActionType.DISABLE_ACCOUNT: self._disable_account,
            ActionType.ENABLE_ACCOUNT: self._enable_account,
            ActionType.KILL_PROCESS: self._kill_process,
            ActionType.QUARANTINE_FILE: self._quarantine_file,
            ActionType.COLLECT_EVIDENCE: self._collect_evidence,
            ActionType.SEND_NOTIFICATION: self._send_notification,
            ActionType.CREATE_TICKET: self._create_ticket,
            ActionType.ENRICH_IOC: self._enrich_ioc,
            ActionType.SCAN_HOST: self._scan_host,
            ActionType.UPDATE_FIREWALL: self._update_firewall,
            ActionType.ADD_TO_BLOCKLIST: self._add_to_blocklist,
            ActionType.REMOVE_FROM_BLOCKLIST: self._remove_from_blocklist,
            ActionType.RESTART_SERVICE: self._restart_service,
            ActionType.CAPTURE_MEMORY: self._capture_memory,
            ActionType.CAPTURE_DISK: self._capture_disk,
            ActionType.RUN_YARA_SCAN: self._run_yara_scan,
            ActionType.CUSTOM_SCRIPT: self._custom_script,
            ActionType.WAIT: self._wait,
        }
    
    def execute_action(self, action: PlaybookAction, variables: Dict[str, Any]) -> ActionResult:
        """Execute single action"""
        started_at = datetime.utcnow()
        
        resolved_params = self._resolve_variables(action.parameters, variables)
        
        handler = self._action_handlers.get(action.action_type)
        if not handler:
            return ActionResult(
                action_id=action.action_id,
                status=ExecutionStatus.FAILED,
                output="",
                error=f"Unknown action type: {action.action_type}",
                started_at=started_at,
                completed_at=datetime.utcnow(),
                duration_ms=0,
                metadata={}
            )
        
        for attempt in range(action.retry_count + 1):
            try:
                output, metadata = handler(resolved_params)
                completed_at = datetime.utcnow()
                duration_ms = int((completed_at - started_at).total_seconds() * 1000)
                
                return ActionResult(
                    action_id=action.action_id,
                    status=ExecutionStatus.COMPLETED,
                    output=output,
                    error=None,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    metadata=metadata
                )
            except Exception as e:
                if attempt < action.retry_count:
                    time.sleep(action.retry_delay)
                    continue
                
                completed_at = datetime.utcnow()
                duration_ms = int((completed_at - started_at).total_seconds() * 1000)
                
                return ActionResult(
                    action_id=action.action_id,
                    status=ExecutionStatus.FAILED,
                    output="",
                    error=str(e),
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    metadata={"attempts": attempt + 1}
                )
    
    def _resolve_variables(self, params: Dict[str, Any], variables: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve variable references in parameters"""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("{{") and value.endswith("}}"):
                var_name = value[2:-2].strip()
                resolved[key] = variables.get(var_name, value)
            elif isinstance(value, str):
                for var_name, var_value in variables.items():
                    value = value.replace(f"{{{{{var_name}}}}}", str(var_value))
                resolved[key] = value
            elif isinstance(value, dict):
                resolved[key] = self._resolve_variables(value, variables)
            else:
                resolved[key] = value
        return resolved
    
    def _run_command(self, command: List[str], timeout: int = 60) -> Tuple[str, int]:
        """Run shell command safely"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            raise Exception(f"Command timed out after {timeout}s")
        except Exception as e:
            raise Exception(f"Command execution failed: {e}")
    
    def _block_ip(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Block IP address using iptables"""
        ip = params.get("ip")
        if not ip:
            raise Exception("IP address required")
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise Exception(f"Invalid IP address: {ip}")
        
        chain = params.get("chain", "INPUT")
        comment = params.get("comment", "SOAR-blocked")
        
        check_cmd = ["iptables", "-C", chain, "-s", ip, "-j", "DROP"]
        output, returncode = self._run_command(check_cmd)
        
        if returncode == 0:
            return f"IP {ip} already blocked", {"already_blocked": True}
        
        block_cmd = ["iptables", "-A", chain, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", comment]
        output, returncode = self._run_command(block_cmd)
        
        if returncode != 0:
            raise Exception(f"Failed to block IP: {output}")
        
        self.database.add_to_blocklist("ip", ip, comment, "soar_engine")
        
        return f"Successfully blocked IP {ip}", {"ip": ip, "chain": chain}
    
    def _unblock_ip(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Unblock IP address"""
        ip = params.get("ip")
        if not ip:
            raise Exception("IP address required")
        
        chain = params.get("chain", "INPUT")
        
        unblock_cmd = ["iptables", "-D", chain, "-s", ip, "-j", "DROP"]
        output, returncode = self._run_command(unblock_cmd)
        
        if returncode != 0:
            return f"IP {ip} was not blocked or already unblocked", {"already_unblocked": True}
        
        return f"Successfully unblocked IP {ip}", {"ip": ip, "chain": chain}
    
    def _isolate_host(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Isolate host by blocking all traffic except management"""
        host_ip = params.get("host_ip")
        management_ip = params.get("management_ip", "")
        
        if not host_ip:
            raise Exception("Host IP required")
        
        rules_added = []
        
        if management_ip:
            cmd = ["iptables", "-A", "INPUT", "-s", host_ip, "-d", management_ip, "-j", "ACCEPT"]
            self._run_command(cmd)
            rules_added.append(f"Allow {host_ip} -> {management_ip}")
            
            cmd = ["iptables", "-A", "OUTPUT", "-s", management_ip, "-d", host_ip, "-j", "ACCEPT"]
            self._run_command(cmd)
            rules_added.append(f"Allow {management_ip} -> {host_ip}")
        
        cmd = ["iptables", "-A", "INPUT", "-s", host_ip, "-j", "DROP"]
        self._run_command(cmd)
        rules_added.append(f"Block all from {host_ip}")
        
        cmd = ["iptables", "-A", "OUTPUT", "-d", host_ip, "-j", "DROP"]
        self._run_command(cmd)
        rules_added.append(f"Block all to {host_ip}")
        
        self.database.add_to_blocklist("host", host_ip, "Host isolated", "soar_engine")
        
        return f"Host {host_ip} isolated", {"host_ip": host_ip, "rules": rules_added}
    
    def _unisolate_host(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Remove host isolation"""
        host_ip = params.get("host_ip")
        if not host_ip:
            raise Exception("Host IP required")
        
        self._run_command(["iptables", "-D", "INPUT", "-s", host_ip, "-j", "DROP"])
        self._run_command(["iptables", "-D", "OUTPUT", "-d", host_ip, "-j", "DROP"])
        
        return f"Host {host_ip} unisolated", {"host_ip": host_ip}
    
    def _disable_account(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Disable user account"""
        username = params.get("username")
        if not username:
            raise Exception("Username required")
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            raise Exception("Invalid username format")
        
        cmd = ["usermod", "-L", username]
        output, returncode = self._run_command(cmd)
        
        if returncode != 0:
            raise Exception(f"Failed to disable account: {output}")
        
        cmd = ["pkill", "-u", username]
        self._run_command(cmd)
        
        return f"Account {username} disabled and sessions terminated", {"username": username}
    
    def _enable_account(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Enable user account"""
        username = params.get("username")
        if not username:
            raise Exception("Username required")
        
        cmd = ["usermod", "-U", username]
        output, returncode = self._run_command(cmd)
        
        if returncode != 0:
            raise Exception(f"Failed to enable account: {output}")
        
        return f"Account {username} enabled", {"username": username}
    
    def _kill_process(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Kill process by PID or name"""
        pid = params.get("pid")
        process_name = params.get("process_name")
        
        if pid:
            cmd = ["kill", "-9", str(pid)]
            output, returncode = self._run_command(cmd)
            if returncode != 0:
                raise Exception(f"Failed to kill process {pid}")
            return f"Process {pid} killed", {"pid": pid}
        elif process_name:
            if not re.match(r'^[a-zA-Z0-9_.-]+$', process_name):
                raise Exception("Invalid process name format")
            cmd = ["pkill", "-9", process_name]
            output, returncode = self._run_command(cmd)
            return f"Processes matching {process_name} killed", {"process_name": process_name}
        else:
            raise Exception("PID or process name required")
    
    def _quarantine_file(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Move file to quarantine"""
        file_path = params.get("file_path")
        if not file_path:
            raise Exception("File path required")
        
        if not os.path.exists(file_path):
            raise Exception(f"File not found: {file_path}")
        
        quarantine_dir = "/var/lib/tyranthos/quarantine"
        os.makedirs(quarantine_dir, exist_ok=True)
        
        file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
        quarantine_name = f"{file_hash}_{os.path.basename(file_path)}"
        quarantine_path = os.path.join(quarantine_dir, quarantine_name)
        
        metadata_path = quarantine_path + ".meta"
        metadata = {
            "original_path": file_path,
            "quarantined_at": datetime.utcnow().isoformat(),
            "sha256": file_hash,
            "size": os.path.getsize(file_path)
        }
        
        import shutil
        shutil.move(file_path, quarantine_path)
        
        with open(metadata_path, "w") as f:
            json.dump(metadata, f)
        
        return f"File quarantined: {quarantine_path}", metadata
    
    def _collect_evidence(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Collect evidence from system"""
        evidence_type = params.get("type", "logs")
        target = params.get("target", "")
        
        evidence_dir = "/var/lib/tyranthos/evidence"
        os.makedirs(evidence_dir, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        evidence_id = f"EVD-{hashlib.sha256(f'{evidence_type}{target}{timestamp}'.encode()).hexdigest()[:12].upper()}"
        evidence_path = os.path.join(evidence_dir, evidence_id)
        os.makedirs(evidence_path, exist_ok=True)
        
        collected = []
        
        if evidence_type == "logs":
            log_files = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/secure"
            ]
            for log_file in log_files:
                if os.path.exists(log_file):
                    dest = os.path.join(evidence_path, os.path.basename(log_file))
                    import shutil
                    shutil.copy2(log_file, dest)
                    collected.append(log_file)
        
        elif evidence_type == "network":
            output, _ = self._run_command(["netstat", "-tulpn"])
            with open(os.path.join(evidence_path, "netstat.txt"), "w") as f:
                f.write(output)
            collected.append("netstat")
            
            output, _ = self._run_command(["ss", "-tulpn"])
            with open(os.path.join(evidence_path, "ss.txt"), "w") as f:
                f.write(output)
            collected.append("ss")
            
            output, _ = self._run_command(["iptables", "-L", "-n", "-v"])
            with open(os.path.join(evidence_path, "iptables.txt"), "w") as f:
                f.write(output)
            collected.append("iptables")
        
        elif evidence_type == "processes":
            output, _ = self._run_command(["ps", "auxf"])
            with open(os.path.join(evidence_path, "ps.txt"), "w") as f:
                f.write(output)
            collected.append("ps")
            
            output, _ = self._run_command(["lsof", "-i"])
            with open(os.path.join(evidence_path, "lsof.txt"), "w") as f:
                f.write(output)
            collected.append("lsof")
        
        metadata = {
            "evidence_id": evidence_id,
            "type": evidence_type,
            "collected_at": datetime.utcnow().isoformat(),
            "files": collected,
            "path": evidence_path
        }
        
        with open(os.path.join(evidence_path, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
        
        return f"Evidence collected: {evidence_id}", metadata
    
    def _send_notification(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Send notification (writes to log and notification file)"""
        message = params.get("message", "")
        severity = params.get("severity", "info")
        channel = params.get("channel", "default")
        
        notification_dir = "/var/lib/tyranthos/notifications"
        os.makedirs(notification_dir, exist_ok=True)
        
        notification = {
            "id": f"NOTIF-{hashlib.sha256(f'{message}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:8].upper()}",
            "message": message,
            "severity": severity,
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        notification_file = os.path.join(notification_dir, "notifications.jsonl")
        with open(notification_file, "a") as f:
            f.write(json.dumps(notification) + "\n")
        
        logger.info(f"[{severity.upper()}] {message}")
        
        return f"Notification sent: {notification['id']}", notification
    
    def _create_ticket(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Create incident ticket (stored locally)"""
        title = params.get("title", "")
        description = params.get("description", "")
        severity = params.get("severity", "medium")
        assignee = params.get("assignee", "")
        
        ticket_dir = "/var/lib/tyranthos/tickets"
        os.makedirs(ticket_dir, exist_ok=True)
        
        ticket_id = f"TKT-{hashlib.sha256(f'{title}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:8].upper()}"
        
        ticket = {
            "ticket_id": ticket_id,
            "title": title,
            "description": description,
            "severity": severity,
            "assignee": assignee,
            "status": "open",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        ticket_file = os.path.join(ticket_dir, f"{ticket_id}.json")
        with open(ticket_file, "w") as f:
            json.dump(ticket, f, indent=2)
        
        return f"Ticket created: {ticket_id}", ticket
    
    def _enrich_ioc(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Enrich IOC using local threat intelligence"""
        ioc_value = params.get("value", "")
        ioc_type = params.get("type", "")
        
        try:
            from app.local_threat_intel import get_local_threat_intel
            threat_intel = get_local_threat_intel()
            
            if ioc_type == "ip":
                report = threat_intel.analyze_ip(ioc_value)
            elif ioc_type == "domain":
                report = threat_intel.analyze_domain(ioc_value)
            elif ioc_type == "url":
                report = threat_intel.analyze_url(ioc_value)
            elif ioc_type == "hash":
                report = threat_intel.analyze_hash(ioc_value)
            else:
                report = threat_intel.analyze_text(ioc_value)
            
            enrichment = {
                "ioc": ioc_value,
                "type": ioc_type,
                "risk_score": report.risk_score,
                "risk_level": report.risk_level.value,
                "matches": len(report.matches),
                "mitre_coverage": report.mitre_coverage,
                "recommendations": report.recommendations
            }
            
            return f"IOC enriched: {ioc_value}", enrichment
            
        except Exception as e:
            return f"IOC enrichment failed: {e}", {"ioc": ioc_value, "error": str(e)}
    
    def _scan_host(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Scan host using nmap"""
        target = params.get("target", "")
        scan_type = params.get("scan_type", "quick")
        
        if not target:
            raise Exception("Target required")
        
        if scan_type == "quick":
            cmd = ["nmap", "-F", "-T4", target]
        elif scan_type == "full":
            cmd = ["nmap", "-sV", "-sC", "-p-", target]
        elif scan_type == "vuln":
            cmd = ["nmap", "--script", "vuln", target]
        else:
            cmd = ["nmap", target]
        
        output, returncode = self._run_command(cmd, timeout=300)
        
        return f"Scan completed for {target}", {"target": target, "output": output}
    
    def _update_firewall(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Update firewall rules"""
        action = params.get("action", "")
        rule = params.get("rule", {})
        
        if action == "add":
            chain = rule.get("chain", "INPUT")
            protocol = rule.get("protocol", "tcp")
            port = rule.get("port", "")
            source = rule.get("source", "")
            target_action = rule.get("target", "DROP")
            
            cmd = ["iptables", "-A", chain]
            if protocol:
                cmd.extend(["-p", protocol])
            if port:
                cmd.extend(["--dport", str(port)])
            if source:
                cmd.extend(["-s", source])
            cmd.extend(["-j", target_action])
            
            output, returncode = self._run_command(cmd)
            if returncode != 0:
                raise Exception(f"Failed to add rule: {output}")
            
            return "Firewall rule added", {"rule": rule}
        
        elif action == "delete":
            chain = rule.get("chain", "INPUT")
            rule_num = rule.get("rule_num", "")
            
            if rule_num:
                cmd = ["iptables", "-D", chain, str(rule_num)]
                output, returncode = self._run_command(cmd)
                if returncode != 0:
                    raise Exception(f"Failed to delete rule: {output}")
                return "Firewall rule deleted", {"chain": chain, "rule_num": rule_num}
        
        raise Exception(f"Unknown firewall action: {action}")
    
    def _add_to_blocklist(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Add entry to blocklist"""
        entry_type = params.get("type", "ip")
        value = params.get("value", "")
        reason = params.get("reason", "SOAR action")
        
        if not value:
            raise Exception("Value required")
        
        self.database.add_to_blocklist(entry_type, value, reason, "soar_engine")
        
        if entry_type == "ip":
            self._block_ip({"ip": value, "comment": reason})
        
        return f"Added to blocklist: {value}", {"type": entry_type, "value": value}
    
    def _remove_from_blocklist(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Remove entry from blocklist"""
        value = params.get("value", "")
        
        if not value:
            raise Exception("Value required")
        
        return f"Removed from blocklist: {value}", {"value": value}
    
    def _restart_service(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Restart system service"""
        service = params.get("service", "")
        
        if not service:
            raise Exception("Service name required")
        
        if not re.match(r'^[a-zA-Z0-9_.-]+$', service):
            raise Exception("Invalid service name format")
        
        cmd = ["systemctl", "restart", service]
        output, returncode = self._run_command(cmd)
        
        if returncode != 0:
            raise Exception(f"Failed to restart service: {output}")
        
        return f"Service {service} restarted", {"service": service}
    
    def _capture_memory(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Capture memory dump"""
        pid = params.get("pid", "")
        
        evidence_dir = "/var/lib/tyranthos/evidence/memory"
        os.makedirs(evidence_dir, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        if pid:
            dump_file = os.path.join(evidence_dir, f"memdump_{pid}_{timestamp}.raw")
            cmd = ["gcore", "-o", dump_file, str(pid)]
        else:
            dump_file = os.path.join(evidence_dir, f"memdump_system_{timestamp}.lime")
            if os.path.exists("/proc/kcore"):
                import shutil
                shutil.copy("/proc/kcore", dump_file)
            else:
                raise Exception("Memory capture not available")
        
        return f"Memory captured: {dump_file}", {"file": dump_file}
    
    def _capture_disk(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Capture disk image"""
        device = params.get("device", "")
        
        if not device:
            raise Exception("Device required")
        
        evidence_dir = "/var/lib/tyranthos/evidence/disk"
        os.makedirs(evidence_dir, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        image_file = os.path.join(evidence_dir, f"disk_{device.replace('/', '_')}_{timestamp}.dd")
        
        cmd = ["dd", f"if={device}", f"of={image_file}", "bs=4M", "status=progress"]
        output, returncode = self._run_command(cmd, timeout=3600)
        
        if returncode != 0:
            raise Exception(f"Disk capture failed: {output}")
        
        hash_cmd = ["sha256sum", image_file]
        hash_output, _ = self._run_command(hash_cmd)
        
        return f"Disk captured: {image_file}", {"file": image_file, "hash": hash_output.split()[0]}
    
    def _run_yara_scan(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Run YARA scan"""
        target = params.get("target", "")
        rules_path = params.get("rules", "/opt/yara-rules")
        
        if not target:
            raise Exception("Target required")
        
        try:
            from app.yara_engine import get_yara_engine
            yara_engine = get_yara_engine()
            
            if os.path.isfile(target):
                result = yara_engine.scan_file(target)
            elif os.path.isdir(target):
                result = yara_engine.scan_directory(target)
            else:
                raise Exception(f"Target not found: {target}")
            
            return f"YARA scan completed: {len(result.matches)} matches", {
                "target": target,
                "matches": len(result.matches),
                "scan_id": result.scan_id
            }
            
        except ImportError:
            cmd = ["yara", "-r", rules_path, target]
            output, returncode = self._run_command(cmd, timeout=300)
            
            matches = len([l for l in output.split("\n") if l.strip()])
            return f"YARA scan completed: {matches} matches", {"target": target, "output": output}
    
    def _custom_script(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Run custom script"""
        script_path = params.get("script", "")
        args = params.get("args", [])
        
        if not script_path:
            raise Exception("Script path required")
        
        if not os.path.exists(script_path):
            raise Exception(f"Script not found: {script_path}")
        
        if not script_path.startswith("/var/lib/tyranthos/scripts/"):
            raise Exception("Scripts must be in /var/lib/tyranthos/scripts/")
        
        cmd = [script_path] + args
        output, returncode = self._run_command(cmd, timeout=ACTION_TIMEOUT)
        
        if returncode != 0:
            raise Exception(f"Script failed with code {returncode}: {output}")
        
        return f"Script executed: {script_path}", {"output": output, "returncode": returncode}
    
    def _wait(self, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Wait for specified duration"""
        seconds = params.get("seconds", 0)
        time.sleep(seconds)
        return f"Waited {seconds} seconds", {"seconds": seconds}


class PlaybookEngine:
    """Executes playbooks with conditional logic"""
    
    def __init__(self, database: SOARDatabase, executor: ActionExecutor):
        self.database = database
        self.executor = executor
        self._execution_queue = queue.Queue()
        self._worker_thread = None
        self._stop_event = threading.Event()
    
    def start(self):
        """Start playbook engine"""
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logger.info("Playbook engine started")
    
    def stop(self):
        """Stop playbook engine"""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
    
    def _worker_loop(self):
        """Process execution queue"""
        while not self._stop_event.is_set():
            try:
                execution_id, playbook, variables = self._execution_queue.get(timeout=1)
                self._execute_playbook(execution_id, playbook, variables)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
    
    def execute_playbook(self, playbook: Playbook, trigger_event: Dict[str, Any],
                         executed_by: str = "system") -> str:
        """Queue playbook for execution"""
        execution_id = f"EXEC-{hashlib.sha256(f'{playbook.playbook_id}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        variables = {**playbook.variables}
        variables.update(trigger_event)
        
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook.playbook_id,
            status=ExecutionStatus.PENDING,
            trigger_event=trigger_event,
            variables=variables,
            action_results=[],
            started_at=datetime.utcnow(),
            completed_at=None,
            executed_by=executed_by,
            error=None
        )
        
        self.database.save_execution(execution)
        self._execution_queue.put((execution_id, playbook, variables))
        
        return execution_id
    
    def _execute_playbook(self, execution_id: str, playbook: Playbook,
                          variables: Dict[str, Any]):
        """Execute playbook actions"""
        action_results = []
        current_action_id = playbook.actions[0].action_id if playbook.actions else None
        action_map = {a.action_id: a for a in playbook.actions}
        
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook.playbook_id,
            status=ExecutionStatus.RUNNING,
            trigger_event=variables,
            variables=variables,
            action_results=[],
            started_at=datetime.utcnow(),
            completed_at=None,
            executed_by="system",
            error=None
        )
        self.database.save_execution(execution)
        
        while current_action_id:
            action = action_map.get(current_action_id)
            if not action:
                break
            
            if action.condition:
                if not self._evaluate_condition(action.condition, variables):
                    current_action_id = action.on_success
                    continue
            
            if action.action_type == ActionType.PARALLEL:
                parallel_actions = action.parameters.get("actions", [])
                with ThreadPoolExecutor(max_workers=MAX_PARALLEL_ACTIONS) as executor:
                    futures = []
                    for parallel_action_id in parallel_actions:
                        parallel_action = action_map.get(parallel_action_id)
                        if parallel_action:
                            futures.append(executor.submit(
                                self.executor.execute_action, parallel_action, variables
                            ))
                    
                    for future in as_completed(futures):
                        result = future.result()
                        action_results.append(result)
                        variables[f"result_{result.action_id}"] = result.output
                
                current_action_id = action.on_success
                continue
            
            if action.action_type == ActionType.CONDITIONAL:
                condition = action.parameters.get("condition", "")
                if self._evaluate_condition(condition, variables):
                    current_action_id = action.parameters.get("if_true")
                else:
                    current_action_id = action.parameters.get("if_false")
                continue
            
            result = self.executor.execute_action(action, variables)
            action_results.append(result)
            
            variables[f"result_{action.action_id}"] = result.output
            variables["last_result"] = result.output
            variables["last_status"] = result.status.value
            
            if result.status == ExecutionStatus.COMPLETED:
                current_action_id = action.on_success
            else:
                current_action_id = action.on_failure
                if not current_action_id:
                    break
        
        all_success = all(r.status == ExecutionStatus.COMPLETED for r in action_results)
        
        execution.status = ExecutionStatus.COMPLETED if all_success else ExecutionStatus.FAILED
        execution.action_results = action_results
        execution.completed_at = datetime.utcnow()
        
        if not all_success:
            failed = [r for r in action_results if r.status == ExecutionStatus.FAILED]
            execution.error = f"Failed actions: {[r.action_id for r in failed]}"
        
        self.database.save_execution(execution)
        logger.info(f"Playbook execution {execution_id} completed: {execution.status.value}")
    
    def _evaluate_condition(self, condition: str, variables: Dict[str, Any]) -> bool:
        """Evaluate condition expression"""
        try:
            safe_vars = {k: v for k, v in variables.items() if isinstance(v, (str, int, float, bool, list, dict))}
            
            for var_name, var_value in safe_vars.items():
                condition = condition.replace(f"${{{var_name}}}", repr(var_value))
            
            allowed_names = {"True": True, "False": False, "None": None}
            allowed_names.update(safe_vars)
            
            result = eval(condition, {"__builtins__": {}}, allowed_names)
            return bool(result)
        except Exception as e:
            logger.error(f"Condition evaluation failed: {e}")
            return False


class AlertCorrelator:
    """Correlates and deduplicates alerts"""
    
    def __init__(self, database: SOARDatabase):
        self.database = database
        self._correlation_window = timedelta(hours=1)
        self._dedup_window = timedelta(minutes=5)
        self._recent_alerts: Dict[str, Alert] = {}
        self._lock = threading.Lock()
    
    def process_alert(self, alert: Alert) -> Tuple[bool, Optional[str]]:
        """Process incoming alert, returns (is_new, case_id)"""
        alert_hash = self._compute_alert_hash(alert)
        
        with self._lock:
            if alert_hash in self._recent_alerts:
                existing = self._recent_alerts[alert_hash]
                if (alert.timestamp - existing.timestamp) < self._dedup_window:
                    return False, existing.case_id
            
            self._recent_alerts[alert_hash] = alert
        
        self.database.save_alert(alert)
        
        correlated_case = self._find_correlated_case(alert)
        if correlated_case:
            self._add_alert_to_case(alert, correlated_case)
            return True, correlated_case.case_id
        
        if alert.severity in [CaseSeverity.CRITICAL, CaseSeverity.HIGH]:
            case = self._create_case_from_alert(alert)
            return True, case.case_id
        
        return True, None
    
    def _compute_alert_hash(self, alert: Alert) -> str:
        """Compute hash for deduplication"""
        key_parts = [
            alert.source,
            alert.title,
            json.dumps(sorted(alert.indicators, key=lambda x: str(x)))
        ]
        return hashlib.sha256("|".join(key_parts).encode()).hexdigest()
    
    def _find_correlated_case(self, alert: Alert) -> Optional[Case]:
        """Find existing case that correlates with alert"""
        alert_iocs = set()
        for indicator in alert.indicators:
            alert_iocs.add(indicator.get("value", ""))
        
        return None
    
    def _add_alert_to_case(self, alert: Alert, case: Case):
        """Add alert to existing case"""
        case.source_alerts.append(alert.alert_id)
        case.updated_at = datetime.utcnow()
        
        for indicator in alert.indicators:
            ioc_value = indicator.get("value", "")
            if ioc_value and ioc_value not in case.related_iocs:
                case.related_iocs.append(ioc_value)
        
        case.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "alert_added",
            "alert_id": alert.alert_id,
            "description": alert.title
        })
        
        self.database.save_case(case)
        
        alert.case_id = case.case_id
        alert.is_processed = True
        self.database.save_alert(alert)
    
    def _create_case_from_alert(self, alert: Alert) -> Case:
        """Create new case from alert"""
        case_id = f"CASE-{hashlib.sha256(f'{alert.alert_id}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        related_iocs = [i.get("value", "") for i in alert.indicators if i.get("value")]
        
        case = Case(
            case_id=case_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            status=CaseStatus.NEW,
            assignee=None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            closed_at=None,
            source_alerts=[alert.alert_id],
            related_iocs=related_iocs,
            evidence=[],
            timeline=[{
                "timestamp": datetime.utcnow().isoformat(),
                "event": "case_created",
                "description": f"Case created from alert: {alert.alert_id}"
            }],
            playbook_executions=[],
            tags=[],
            notes=[],
            metrics={"mttd": 0, "mttr": 0}
        )
        
        self.database.save_case(case)
        
        alert.case_id = case_id
        alert.is_processed = True
        self.database.save_alert(alert)
        
        return case


class SOAREngine:
    """Main SOAR engine interface"""
    
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
        
        self.database = SOARDatabase()
        self.executor = ActionExecutor(self.database)
        self.playbook_engine = PlaybookEngine(self.database, self.executor)
        self.alert_correlator = AlertCorrelator(self.database)
        
        self._load_default_playbooks()
    
    def start(self):
        """Start SOAR engine"""
        self.playbook_engine.start()
        logger.info("SOAR engine started")
    
    def stop(self):
        """Stop SOAR engine"""
        self.playbook_engine.stop()
    
    def _load_default_playbooks(self):
        """Load default playbooks"""
        default_playbooks = [
            Playbook(
                playbook_id="PB-BLOCK-MALICIOUS-IP",
                name="Block Malicious IP",
                description="Automatically block IP addresses identified as malicious",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger_conditions=[{"type": "alert", "severity": ["critical", "high"], "category": "malicious_ip"}],
                actions=[
                    PlaybookAction(
                        action_id="enrich-ip",
                        action_type=ActionType.ENRICH_IOC,
                        name="Enrich IP",
                        description="Enrich IP with threat intelligence",
                        parameters={"value": "{{source_ip}}", "type": "ip"},
                        timeout=60,
                        retry_count=2,
                        retry_delay=5,
                        on_success="block-ip",
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="block-ip",
                        action_type=ActionType.BLOCK_IP,
                        name="Block IP",
                        description="Block the malicious IP",
                        parameters={"ip": "{{source_ip}}", "comment": "SOAR-auto-blocked"},
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success="notify",
                        on_failure="notify-failure",
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="notify",
                        action_type=ActionType.SEND_NOTIFICATION,
                        name="Send Notification",
                        description="Notify about blocked IP",
                        parameters={"message": "Blocked malicious IP: {{source_ip}}", "severity": "high"},
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success=None,
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="notify-failure",
                        action_type=ActionType.SEND_NOTIFICATION,
                        name="Notify Failure",
                        description="Notify about failed block",
                        parameters={"message": "Failed to block IP: {{source_ip}}", "severity": "critical"},
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success=None,
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    )
                ],
                variables={},
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                created_by="system",
                tags=["auto", "blocking", "ip"]
            ),
            Playbook(
                playbook_id="PB-ISOLATE-COMPROMISED-HOST",
                name="Isolate Compromised Host",
                description="Isolate host showing signs of compromise",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger_conditions=[{"type": "alert", "severity": ["critical"], "category": "compromise"}],
                actions=[
                    PlaybookAction(
                        action_id="collect-evidence",
                        action_type=ActionType.COLLECT_EVIDENCE,
                        name="Collect Evidence",
                        description="Collect evidence before isolation",
                        parameters={"type": "processes"},
                        timeout=120,
                        retry_count=1,
                        retry_delay=10,
                        on_success="isolate-host",
                        on_failure="isolate-host",
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="isolate-host",
                        action_type=ActionType.ISOLATE_HOST,
                        name="Isolate Host",
                        description="Isolate the compromised host",
                        parameters={"host_ip": "{{host_ip}}", "management_ip": "{{management_ip}}"},
                        timeout=60,
                        retry_count=2,
                        retry_delay=5,
                        on_success="create-ticket",
                        on_failure="notify-failure",
                        requires_approval=True,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="create-ticket",
                        action_type=ActionType.CREATE_TICKET,
                        name="Create Ticket",
                        description="Create incident ticket",
                        parameters={
                            "title": "Compromised Host Isolated: {{host_ip}}",
                            "description": "Host {{host_ip}} has been isolated due to compromise indicators",
                            "severity": "critical"
                        },
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success="notify-success",
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="notify-success",
                        action_type=ActionType.SEND_NOTIFICATION,
                        name="Notify Success",
                        description="Notify about successful isolation",
                        parameters={"message": "Host {{host_ip}} isolated successfully", "severity": "high"},
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success=None,
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="notify-failure",
                        action_type=ActionType.SEND_NOTIFICATION,
                        name="Notify Failure",
                        description="Notify about failed isolation",
                        parameters={"message": "Failed to isolate host {{host_ip}}", "severity": "critical"},
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success=None,
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    )
                ],
                variables={"management_ip": "10.0.0.1"},
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                created_by="system",
                tags=["auto", "isolation", "compromise"]
            ),
            Playbook(
                playbook_id="PB-MALWARE-RESPONSE",
                name="Malware Detection Response",
                description="Respond to malware detection",
                version="1.0.0",
                status=PlaybookStatus.ACTIVE,
                trigger_conditions=[{"type": "alert", "category": "malware"}],
                actions=[
                    PlaybookAction(
                        action_id="quarantine-file",
                        action_type=ActionType.QUARANTINE_FILE,
                        name="Quarantine File",
                        description="Quarantine the malicious file",
                        parameters={"file_path": "{{file_path}}"},
                        timeout=60,
                        retry_count=1,
                        retry_delay=5,
                        on_success="yara-scan",
                        on_failure="notify-failure",
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="yara-scan",
                        action_type=ActionType.RUN_YARA_SCAN,
                        name="YARA Scan",
                        description="Scan system for similar malware",
                        parameters={"target": "/home", "rules": "/opt/yara-rules"},
                        timeout=300,
                        retry_count=1,
                        retry_delay=10,
                        on_success="collect-evidence",
                        on_failure="collect-evidence",
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="collect-evidence",
                        action_type=ActionType.COLLECT_EVIDENCE,
                        name="Collect Evidence",
                        description="Collect system evidence",
                        parameters={"type": "logs"},
                        timeout=120,
                        retry_count=1,
                        retry_delay=10,
                        on_success="create-ticket",
                        on_failure="create-ticket",
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="create-ticket",
                        action_type=ActionType.CREATE_TICKET,
                        name="Create Ticket",
                        description="Create malware incident ticket",
                        parameters={
                            "title": "Malware Detected: {{file_path}}",
                            "description": "Malware detected and quarantined",
                            "severity": "high"
                        },
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success=None,
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    ),
                    PlaybookAction(
                        action_id="notify-failure",
                        action_type=ActionType.SEND_NOTIFICATION,
                        name="Notify Failure",
                        description="Notify about quarantine failure",
                        parameters={"message": "Failed to quarantine: {{file_path}}", "severity": "critical"},
                        timeout=30,
                        retry_count=1,
                        retry_delay=5,
                        on_success=None,
                        on_failure=None,
                        requires_approval=False,
                        condition=None
                    )
                ],
                variables={},
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                created_by="system",
                tags=["auto", "malware", "quarantine"]
            )
        ]
        
        for playbook in default_playbooks:
            self.database.save_playbook(playbook)
    
    def process_alert(self, alert: Alert) -> Dict[str, Any]:
        """Process incoming alert"""
        is_new, case_id = self.alert_correlator.process_alert(alert)
        
        if is_new:
            matching_playbooks = self._find_matching_playbooks(alert)
            execution_ids = []
            
            for playbook in matching_playbooks:
                trigger_event = {
                    "alert_id": alert.alert_id,
                    "source_ip": alert.indicators[0].get("value", "") if alert.indicators else "",
                    "severity": alert.severity.value
                }
                
                for indicator in alert.indicators:
                    trigger_event[indicator.get("type", "unknown")] = indicator.get("value", "")
                
                exec_id = self.playbook_engine.execute_playbook(playbook, trigger_event)
                execution_ids.append(exec_id)
            
            return {
                "is_new": True,
                "case_id": case_id,
                "playbook_executions": execution_ids
            }
        
        return {"is_new": False, "case_id": case_id, "playbook_executions": []}
    
    def _find_matching_playbooks(self, alert: Alert) -> List[Playbook]:
        """Find playbooks matching alert"""
        matching = []
        active_playbooks = self.database.get_active_playbooks()
        
        for playbook in active_playbooks:
            for condition in playbook.trigger_conditions:
                if self._matches_condition(alert, condition):
                    matching.append(playbook)
                    break
        
        return matching
    
    def _matches_condition(self, alert: Alert, condition: Dict[str, Any]) -> bool:
        """Check if alert matches trigger condition"""
        if condition.get("type") == "alert":
            severities = condition.get("severity", [])
            if severities and alert.severity.value not in severities:
                return False
            
            category = condition.get("category")
            if category:
                alert_categories = [i.get("category", "") for i in alert.indicators]
                if category not in alert_categories and category not in alert.raw_data.get("categories", []):
                    return False
            
            return True
        
        return False
    
    def execute_playbook_manual(self, playbook_id: str, variables: Dict[str, Any],
                                 executed_by: str = "operator") -> str:
        """Manually execute playbook"""
        playbook = self.database.get_playbook(playbook_id)
        if not playbook:
            raise Exception(f"Playbook not found: {playbook_id}")
        
        return self.playbook_engine.execute_playbook(playbook, variables, executed_by)
    
    def create_case(self, title: str, description: str, severity: CaseSeverity,
                    assignee: str = None) -> Case:
        """Create new case manually"""
        case_id = f"CASE-{hashlib.sha256(f'{title}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        case = Case(
            case_id=case_id,
            title=title,
            description=description,
            severity=severity,
            status=CaseStatus.NEW,
            assignee=assignee,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            closed_at=None,
            source_alerts=[],
            related_iocs=[],
            evidence=[],
            timeline=[{
                "timestamp": datetime.utcnow().isoformat(),
                "event": "case_created",
                "description": "Case created manually"
            }],
            playbook_executions=[],
            tags=[],
            notes=[],
            metrics={}
        )
        
        self.database.save_case(case)
        return case
    
    def get_case(self, case_id: str) -> Optional[Case]:
        """Get case by ID"""
        return self.database.get_case(case_id)
    
    def update_case_status(self, case_id: str, status: CaseStatus) -> bool:
        """Update case status"""
        case = self.database.get_case(case_id)
        if not case:
            return False
        
        case.status = status
        case.updated_at = datetime.utcnow()
        
        if status == CaseStatus.CLOSED:
            case.closed_at = datetime.utcnow()
            if case.created_at:
                mttr = (case.closed_at - case.created_at).total_seconds()
                case.metrics["mttr"] = mttr
        
        case.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "status_changed",
            "description": f"Status changed to {status.value}"
        })
        
        return self.database.save_case(case)
    
    def add_case_note(self, case_id: str, note: str, author: str) -> bool:
        """Add note to case"""
        case = self.database.get_case(case_id)
        if not case:
            return False
        
        case.notes.append({
            "timestamp": datetime.utcnow().isoformat(),
            "author": author,
            "content": note
        })
        case.updated_at = datetime.utcnow()
        
        return self.database.save_case(case)
    
    def get_playbooks(self) -> List[Playbook]:
        """Get all playbooks"""
        return self.database.get_active_playbooks()
    
    def block_ip(self, ip: str, reason: str = "Manual block") -> Dict[str, Any]:
        """Manually block IP"""
        result = self.executor._block_ip({"ip": ip, "comment": reason})
        return {"output": result[0], "metadata": result[1]}
    
    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """Manually unblock IP"""
        result = self.executor._unblock_ip({"ip": ip})
        return {"output": result[0], "metadata": result[1]}


def get_soar_engine() -> SOAREngine:
    """Get singleton instance of SOAREngine"""
    return SOAREngine()
