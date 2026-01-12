from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List
from enum import Enum

class ThreatSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class ThreatStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"

class IntelType(str, Enum):
    SIGINT = "SIGINT"
    FININT = "FININT"
    OSINT = "OSINT"
    HUMINT = "HUMINT"
    CI = "CI"

class IntelPriority(str, Enum):
    ROUTINE = "routine"
    PRIORITY = "priority"
    IMMEDIATE = "immediate"
    FLASH = "flash"

class NodeType(str, Enum):
    SERVER = "server"
    ENDPOINT = "endpoint"
    FIREWALL = "firewall"
    ROUTER = "router"
    SENSOR = "sensor"

class NodeStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"

class ThreatEventCreate(BaseModel):
    type: str
    source: str
    severity: ThreatSeverity
    description: str
    status: ThreatStatus = ThreatStatus.ACTIVE
    mitre_tactic: Optional[str] = None
    mitre_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_country: Optional[str] = None
    target_country: Optional[str] = None
    source_region: Optional[str] = None
    target_region: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    payload_hash: Optional[str] = None

class ThreatEventUpdate(BaseModel):
    type: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[ThreatSeverity] = None
    description: Optional[str] = None
    status: Optional[ThreatStatus] = None
    mitre_tactic: Optional[str] = None
    mitre_id: Optional[str] = None

class ThreatEventResponse(BaseModel):
    id: int
    threat_id: str
    timestamp: datetime
    type: str
    source: str
    severity: str
    description: str
    status: str
    mitre_tactic: Optional[str]
    mitre_id: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_country: Optional[str]
    target_country: Optional[str]
    source_region: Optional[str]
    target_region: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

class IntelReportCreate(BaseModel):
    type: IntelType
    classification: str
    priority: IntelPriority
    summary: str
    content: Optional[str] = None
    source: Optional[str] = None
    analyst: Optional[str] = None

class IntelReportUpdate(BaseModel):
    type: Optional[IntelType] = None
    classification: Optional[str] = None
    priority: Optional[IntelPriority] = None
    summary: Optional[str] = None
    content: Optional[str] = None

class IntelReportResponse(BaseModel):
    id: int
    report_id: str
    type: str
    classification: str
    priority: str
    summary: str
    content: Optional[str]
    source: Optional[str]
    analyst: Optional[str]
    timestamp: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True

class NetworkNodeCreate(BaseModel):
    name: str
    type: NodeType
    status: NodeStatus = NodeStatus.ONLINE
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    location: Optional[str] = None

class NetworkNodeUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[NodeType] = None
    status: Optional[NodeStatus] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    location: Optional[str] = None
    threats_detected: Optional[int] = None

class NetworkNodeResponse(BaseModel):
    id: int
    node_id: str
    name: str
    type: str
    status: str
    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    os_type: Optional[str]
    os_version: Optional[str]
    location: Optional[str]
    threats_detected: int
    last_seen: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "port"
    ports: Optional[str] = "1-1024"

class ScanResultResponse(BaseModel):
    id: int
    scan_id: str
    target: str
    scan_type: str
    status: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    results: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

class SystemMetricsResponse(BaseModel):
    timestamp: datetime
    events_per_second: int
    total_events: int
    blocked_threats: int
    active_incidents: int
    mttd: float
    mttr: float
    active_sensors: int
    active_nodes: int
    network_latency: float
    cpu_usage: float
    memory_usage: float
    storage_usage: float
    
    class Config:
        from_attributes = True

class DashboardStats(BaseModel):
    total_threats: int
    active_threats: int
    resolved_threats: int
    total_intel_reports: int
    total_nodes: int
    online_nodes: int
    compromised_nodes: int
    total_scans: int
    critical_findings: int

class MitreAttackCoverage(BaseModel):
    tactic: str
    coverage: float
    techniques_covered: int
    total_techniques: int
