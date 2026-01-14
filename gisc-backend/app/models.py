from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text, Enum as SQLEnum
from sqlalchemy.sql import func
from datetime import datetime
import enum
from app.database import Base

class ThreatSeverity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class ThreatStatus(str, enum.Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"

class IntelType(str, enum.Enum):
    SIGINT = "SIGINT"
    FININT = "FININT"
    OSINT = "OSINT"
    HUMINT = "HUMINT"
    CI = "CI"

class IntelPriority(str, enum.Enum):
    ROUTINE = "routine"
    PRIORITY = "priority"
    IMMEDIATE = "immediate"
    FLASH = "flash"

class NodeType(str, enum.Enum):
    SERVER = "server"
    ENDPOINT = "endpoint"
    FIREWALL = "firewall"
    ROUTER = "router"
    SENSOR = "sensor"

class NodeStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"

class ThreatEvent(Base):
    __tablename__ = "threat_events"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(20), unique=True, index=True)
    timestamp = Column(DateTime, default=func.now())
    type = Column(String(100))
    source = Column(String(100))
    severity = Column(String(20))
    description = Column(Text)
    status = Column(String(20), default="active")
    mitre_tactic = Column(String(100))
    mitre_id = Column(String(20))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    source_country = Column(String(50))
    target_country = Column(String(50))
    source_region = Column(String(50))
    target_region = Column(String(50))
    port = Column(Integer)
    protocol = Column(String(20))
    payload_hash = Column(String(64))
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class IntelReport(Base):
    __tablename__ = "intel_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(20), unique=True, index=True)
    type = Column(String(20))
    classification = Column(String(50))
    priority = Column(String(20))
    summary = Column(Text)
    content = Column(Text)
    source = Column(String(200))
    analyst = Column(String(100))
    timestamp = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class NetworkNode(Base):
    __tablename__ = "network_nodes"
    
    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String(20), unique=True, index=True)
    name = Column(String(100))
    type = Column(String(20))
    status = Column(String(20), default="online")
    ip_address = Column(String(45))
    mac_address = Column(String(17))
    hostname = Column(String(255))
    os_type = Column(String(100))
    os_version = Column(String(100))
    location = Column(String(200))
    threats_detected = Column(Integer, default=0)
    last_seen = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(20), unique=True, index=True)
    target = Column(String(255))
    scan_type = Column(String(50))
    status = Column(String(20))
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    results = Column(Text)
    created_at = Column(DateTime, default=func.now())

class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=func.now())
    events_per_second = Column(Integer, default=0)
    total_events = Column(Integer, default=0)
    blocked_threats = Column(Integer, default=0)
    active_incidents = Column(Integer, default=0)
    mttd = Column(Float, default=0.0)
    mttr = Column(Float, default=0.0)
    active_sensors = Column(Integer, default=0)
    active_nodes = Column(Integer, default=0)
    network_latency = Column(Float, default=0.0)
    cpu_usage = Column(Float, default=0.0)
    memory_usage = Column(Float, default=0.0)
    storage_usage = Column(Float, default=0.0)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=func.now())
    action = Column(String(100))
    entity_type = Column(String(50))
    entity_id = Column(String(50))
    user = Column(String(100))
    details = Column(Text)
    ip_address = Column(String(45))
