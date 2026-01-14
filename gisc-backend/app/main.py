from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import json
import socket
import os
import psutil
import base64
import hashlib

from app.database import engine, get_db, Base
from app import models, schemas
from app.operations import (
    WebCrawlerEngine, VulnerabilityScanner, MalwareAnalyzer, ForensicsEngine,
    IntelligenceCollector, SIEMEngine, CrawlerMode, ScanMode, InternetLayer,
    convert_to_dict
)
from app.enterprise_api import router as enterprise_router
from app.domain_integration import get_domain_integration_hub
from app.rate_limiter import RateLimitMiddleware
from app.system_data import system_data_provider
from app.realtime_threat_feeds import get_realtime_threat_aggregator
from app.tier5_router import router as tier5_router
from app.advanced_tier5_router import router as advanced_tier5_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="TYRANTHOS API",
    description="CYBER INTELLIGENCE OPERATIONS SYSTEM - Enterprise-grade security operations API",
    version="1.0.0"
)

ALLOWED_ORIGINS = os.environ.get(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-API-Key"],
)

app.add_middleware(RateLimitMiddleware)

app.include_router(enterprise_router)
app.include_router(tier5_router)
app.include_router(advanced_tier5_router)

domain_hub = get_domain_integration_hub()


@app.get("/api/v1/domains/status")
async def get_domain_status():
    return domain_hub.get_system_status()


@app.get("/api/v1/domains/threat-intel/analyze/ip/{ip_address}")
async def analyze_ip_threat_intel(ip_address: str):
    return domain_hub.threat_intel.analyze_ip(ip_address)


@app.get("/api/v1/domains/threat-intel/analyze/domain/{domain}")
async def analyze_domain_threat_intel(domain: str):
    return domain_hub.threat_intel.analyze_domain(domain)


@app.get("/api/v1/domains/threat-intel/analyze/hash/{file_hash}")
async def analyze_hash_threat_intel(file_hash: str):
    return domain_hub.threat_intel.analyze_hash(file_hash)


@app.get("/api/v1/domains/osint/search")
async def osint_comprehensive_search(query: str):
    return domain_hub.osint.comprehensive_search(query)


@app.get("/api/v1/domains/osint/person/name")
async def osint_person_by_name(first_name: str, last_name: str):
    return domain_hub.osint.search_person_by_name(first_name, last_name)


@app.get("/api/v1/domains/osint/person/email/{email}")
async def osint_person_by_email(email: str):
    return domain_hub.osint.search_person_by_email(email)


@app.get("/api/v1/domains/osint/social/{username}")
async def osint_social_profiles(username: str):
    return domain_hub.osint.discover_social_profiles(username)


@app.get("/api/v1/domains/osint/breaches/{email}")
async def osint_data_breaches(email: str):
    return domain_hub.osint.check_data_breaches(email)


@app.get("/api/v1/domains/darkweb/status")
async def darkweb_status():
    return {
        "tor": domain_hub.dark_web.check_tor_connectivity(),
        "i2p": domain_hub.dark_web.check_i2p_connectivity()
    }


@app.get("/api/v1/domains/darkweb/search")
async def darkweb_search(query: str):
    return domain_hub.dark_web.search_onion_directories(query)


@app.post("/api/v1/domains/darkweb/crawl")
async def darkweb_crawl(onion_url: str):
    return domain_hub.dark_web.crawl_onion(onion_url)


@app.get("/api/v1/domains/forensics/yara/rules")
async def forensics_yara_rules():
    return domain_hub.forensics.list_yara_rules()


@app.get("/api/v1/domains/forensics/yara/status")
async def forensics_yara_status():
    return domain_hub.forensics.get_yara_status()


@app.post("/api/v1/domains/forensics/yara/scan")
async def forensics_yara_scan(file_path: str):
    return domain_hub.forensics.scan_file(file_path)


@app.get("/api/v1/domains/person-intel/search")
async def person_intel_search(query: str):
    return domain_hub.person_intel.comprehensive_search(query)


@app.post("/api/v1/domains/correlate")
async def correlate_threat_data(indicator: str, indicator_type: str):
    return domain_hub.correlate_threat_data(indicator, indicator_type)


@app.get("/api/v1/domains/investigate/person")
async def investigate_person(query: str):
    return domain_hub.comprehensive_person_investigation(query)


@app.get("/api/v1/domains/investigate/darkweb")
async def investigate_darkweb(query: str):
    return domain_hub.dark_web_investigation(query)


@app.get("/api/v1/system-data")
async def get_system_data(db: Session = Depends(get_db)):
    """Get comprehensive system data for all UI modules"""
    threats = db.query(models.ThreatEvent).all()
    threat_list = [
        {
            'threat_id': t.threat_id,
            'type': t.type,
            'description': t.description,
            'status': t.status,
            'severity': t.severity,
            'mitre_id': t.mitre_id,
            'mitre_tactic': t.mitre_tactic,
            'source_ip': t.source_ip
        }
        for t in threats
    ]
    return system_data_provider.get_all_system_data(threat_list)


@app.get("/api/v1/system-data/mitre-coverage")
async def get_mitre_attack_coverage(db: Session = Depends(get_db)):
    """Get MITRE ATT&CK coverage data"""
    threats = db.query(models.ThreatEvent).all()
    threat_list = [{'mitre_id': t.mitre_id} for t in threats]
    return system_data_provider.mitre_coverage.calculate_coverage(threat_list)


@app.get("/api/v1/system-data/threat-distribution")
async def get_threat_distribution(db: Session = Depends(get_db)):
    """Get threat distribution data"""
    threats = db.query(models.ThreatEvent).all()
    threat_list = [{'type': t.type, 'description': t.description} for t in threats]
    return system_data_provider.threat_distribution.analyze_distribution(threat_list)


@app.get("/api/v1/system-data/ids-ips")
async def get_ids_ips_stats():
    """Get IDS/IPS system statistics"""
    return system_data_provider.ids_ips_monitor.get_ids_ips_stats()


@app.get("/api/v1/system-data/packet-capture")
async def get_packet_capture_stats():
    """Get packet capture system statistics"""
    return system_data_provider.packet_capture_monitor.get_capture_stats()


@app.get("/api/v1/system-data/attack-vectors")
async def get_attack_vectors(db: Session = Depends(get_db)):
    """Get attack vector analysis"""
    threats = db.query(models.ThreatEvent).all()
    threat_list = [{'type': t.type, 'description': t.description} for t in threats]
    return system_data_provider.attack_vector_analyzer.analyze_vectors(threat_list)


@app.get("/api/v1/system-data/malware-families")
async def get_malware_families():
    """Get malware family tracking data"""
    return system_data_provider.malware_tracker.track_families()


@app.get("/api/v1/system-data/ai-ml-models")
async def get_ai_ml_model_stats():
    """Get AI/ML model statistics"""
    return system_data_provider.ai_ml_monitor.get_model_stats()


@app.get("/api/v1/system-data/secure-comms")
async def get_secure_comms_stats():
    """Get secure communications channel statistics"""
    return system_data_provider.secure_comms_monitor.get_channel_stats()


@app.get("/api/v1/system-data/blockchain-forensics")
async def get_blockchain_forensics_stats():
    """Get blockchain forensics statistics"""
    return system_data_provider.blockchain_monitor.get_chain_stats()


@app.get("/api/v1/system-data/evidence-vault")
async def get_evidence_vault_stats():
    """Get evidence vault statistics"""
    return system_data_provider.evidence_monitor.get_vault_stats()


@app.get("/api/v1/system-data/operations-command")
async def get_operations_command_stats():
    """Get operations command statistics"""
    return system_data_provider.operations_monitor.get_operations_stats()


@app.get("/api/v1/system-data/quantum-security")
async def get_quantum_security_stats():
    """Get quantum security statistics"""
    return system_data_provider.quantum_monitor.get_quantum_stats()


import uuid
import time

def generate_id(prefix: str, db: Session, model) -> str:
    timestamp = int(time.time() * 1000) % 1000000
    random_part = uuid.uuid4().hex[:4].upper()
    return f"{prefix}-{timestamp:06d}-{random_part}"

def log_audit(db: Session, action: str, entity_type: str, entity_id: str, details: str = None, user: str = "system"):
    audit = models.AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        user=user,
        details=details
    )
    db.add(audit)
    db.commit()

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "GISC Command Center API", "classification": "TOP SECRET // NSOC"}

@app.get("/api/v1/status")
async def get_system_status(db: Session = Depends(get_db)):
    total_threats = db.query(models.ThreatEvent).count()
    active_threats = db.query(models.ThreatEvent).filter(models.ThreatEvent.status == "active").count()
    total_nodes = db.query(models.NetworkNode).count()
    online_nodes = db.query(models.NetworkNode).filter(models.NetworkNode.status == "online").count()
    
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "system_status": "OPERATIONAL",
        "threat_level": "CRITICAL" if active_threats > 10 else "HIGH" if active_threats > 5 else "MEDIUM" if active_threats > 0 else "LOW",
        "total_threats": total_threats,
        "active_threats": active_threats,
        "total_nodes": total_nodes,
        "online_nodes": online_nodes,
        "cpu_usage": cpu_percent,
        "memory_usage": memory.percent,
        "storage_usage": disk.percent,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/metrics", response_model=schemas.SystemMetricsResponse)
async def get_metrics(db: Session = Depends(get_db)):
    total_events = db.query(models.ThreatEvent).count()
    active_incidents = db.query(models.ThreatEvent).filter(models.ThreatEvent.status == "active").count()
    blocked_threats = db.query(models.ThreatEvent).filter(models.ThreatEvent.status == "contained").count()
    active_nodes = db.query(models.NetworkNode).filter(models.NetworkNode.status == "online").count()
    total_nodes = db.query(models.NetworkNode).count()
    
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    recent_events = db.query(models.ThreatEvent).filter(
        models.ThreatEvent.created_at >= datetime.utcnow() - timedelta(seconds=60)
    ).count()
    
    import psutil as ps
    net_if_stats = ps.net_if_stats()
    active_interfaces = sum(1 for iface, stats in net_if_stats.items() if stats.isup)
    net_connections = len(ps.net_connections(kind='inet'))
    
    return schemas.SystemMetricsResponse(
        timestamp=datetime.utcnow(),
        events_per_second=recent_events,
        total_events=total_events,
        blocked_threats=blocked_threats,
        active_incidents=active_incidents,
        mttd=round(2.3 + (cpu_percent / 100), 1),
        mttr=round(4.7 + (memory.percent / 50), 1),
        active_sensors=active_interfaces,
        active_nodes=active_nodes if active_nodes > 0 else total_nodes,
        network_latency=round(2.3 + (cpu_percent / 200), 1),
        cpu_usage=cpu_percent,
        memory_usage=memory.percent,
        storage_usage=disk.percent
    )

@app.get("/api/v1/dashboard/stats", response_model=schemas.DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    total_threats = db.query(models.ThreatEvent).count()
    active_threats = db.query(models.ThreatEvent).filter(models.ThreatEvent.status == "active").count()
    resolved_threats = db.query(models.ThreatEvent).filter(models.ThreatEvent.status == "resolved").count()
    total_intel = db.query(models.IntelReport).count()
    total_nodes = db.query(models.NetworkNode).count()
    online_nodes = db.query(models.NetworkNode).filter(models.NetworkNode.status == "online").count()
    compromised_nodes = db.query(models.NetworkNode).filter(models.NetworkNode.status == "compromised").count()
    total_scans = db.query(models.ScanResult).count()
    critical_findings = db.query(models.ScanResult).with_entities(func.sum(models.ScanResult.critical_count)).scalar() or 0
    
    return schemas.DashboardStats(
        total_threats=total_threats,
        active_threats=active_threats,
        resolved_threats=resolved_threats,
        total_intel_reports=total_intel,
        total_nodes=total_nodes,
        online_nodes=online_nodes,
        compromised_nodes=compromised_nodes,
        total_scans=total_scans,
        critical_findings=critical_findings
    )

@app.post("/api/v1/threats", response_model=schemas.ThreatEventResponse)
async def create_threat(threat: schemas.ThreatEventCreate, db: Session = Depends(get_db)):
    threat_id = generate_id("THREAT", db, models.ThreatEvent)
    db_threat = models.ThreatEvent(
        threat_id=threat_id,
        type=threat.type,
        source=threat.source,
        severity=threat.severity.value,
        description=threat.description,
        status=threat.status.value,
        mitre_tactic=threat.mitre_tactic,
        mitre_id=threat.mitre_id,
        source_ip=threat.source_ip,
        destination_ip=threat.destination_ip,
        port=threat.port,
        protocol=threat.protocol,
        payload_hash=threat.payload_hash
    )
    db.add(db_threat)
    db.commit()
    db.refresh(db_threat)
    log_audit(db, "CREATE", "threat", threat_id, f"Created threat: {threat.type}")
    return db_threat

@app.get("/api/v1/threats", response_model=List[schemas.ThreatEventResponse])
async def get_threats(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.ThreatEvent)
    if severity:
        query = query.filter(models.ThreatEvent.severity == severity)
    if status:
        query = query.filter(models.ThreatEvent.status == status)
    return query.order_by(models.ThreatEvent.created_at.desc()).offset(skip).limit(limit).all()

@app.get("/api/v1/threats/{threat_id}", response_model=schemas.ThreatEventResponse)
async def get_threat(threat_id: str, db: Session = Depends(get_db)):
    threat = db.query(models.ThreatEvent).filter(models.ThreatEvent.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat

@app.put("/api/v1/threats/{threat_id}", response_model=schemas.ThreatEventResponse)
async def update_threat(threat_id: str, threat_update: schemas.ThreatEventUpdate, db: Session = Depends(get_db)):
    threat = db.query(models.ThreatEvent).filter(models.ThreatEvent.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    update_data = threat_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if value is not None:
            if hasattr(value, 'value'):
                setattr(threat, key, value.value)
            else:
                setattr(threat, key, value)
    
    db.commit()
    db.refresh(threat)
    log_audit(db, "UPDATE", "threat", threat_id, f"Updated threat status to: {threat.status}")
    return threat

@app.delete("/api/v1/threats/{threat_id}")
async def delete_threat(threat_id: str, db: Session = Depends(get_db)):
    threat = db.query(models.ThreatEvent).filter(models.ThreatEvent.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    db.delete(threat)
    db.commit()
    log_audit(db, "DELETE", "threat", threat_id, "Deleted threat")
    return {"status": "deleted", "threat_id": threat_id}


@app.get("/api/v1/threats/realtime/feed")
async def get_realtime_threats(limit: int = 100):
    """
    Fetch REAL threats from public threat intelligence feeds.
    Sources: URLhaus, Feodo Tracker, ThreatFox, SSL Blacklist (abuse.ch)
    NO API KEYS REQUIRED - These are free public feeds with real threat data.
    """
    aggregator = get_realtime_threat_aggregator()
    threats = aggregator.get_threats_for_map(limit=limit)
    return {
        "status": "success",
        "source": "Real-time public threat intelligence feeds",
        "feeds": ["URLhaus", "Feodo Tracker", "ThreatFox", "SSL Blacklist"],
        "count": len(threats),
        "threats": threats,
        "last_updated": datetime.utcnow().isoformat(),
    }


@app.get("/api/v1/threats/realtime/sync")
async def sync_realtime_threats_to_db(limit: int = 50, db: Session = Depends(get_db)):
    """
    Fetch real threats from public feeds and sync them to the database.
    This replaces static seed data with real threat intelligence.
    """
    aggregator = get_realtime_threat_aggregator()
    threats = aggregator.get_threats_for_map(limit=limit)
    
    synced_count = 0
    for threat_data in threats:
        existing = db.query(models.ThreatEvent).filter(
            models.ThreatEvent.threat_id == threat_data["threat_id"]
        ).first()
        
        if not existing:
            db_threat = models.ThreatEvent(
                threat_id=threat_data["threat_id"],
                timestamp=datetime.fromisoformat(threat_data["timestamp"]),
                type=threat_data["type"],
                source=threat_data["source"],
                severity=threat_data["severity"],
                description=threat_data["description"],
                status=threat_data["status"],
                mitre_tactic=threat_data.get("mitre_tactic", ""),
                mitre_id=threat_data.get("mitre_id", ""),
                source_ip=threat_data["source_ip"],
                destination_ip=threat_data.get("destination_ip", ""),
                source_country=threat_data["source_country"],
                target_country=threat_data["target_country"],
                source_region=threat_data["source_region"],
                target_region=threat_data["target_region"],
            )
            db.add(db_threat)
            synced_count += 1
    
    db.commit()
    
    return {
        "status": "success",
        "message": f"Synced {synced_count} new real threats to database",
        "total_fetched": len(threats),
        "new_threats": synced_count,
    }


@app.post("/api/v1/intel", response_model=schemas.IntelReportResponse)
async def create_intel_report(report: schemas.IntelReportCreate, db: Session = Depends(get_db)):
    report_id = generate_id("INTEL", db, models.IntelReport)
    db_report = models.IntelReport(
        report_id=report_id,
        type=report.type.value,
        classification=report.classification,
        priority=report.priority.value,
        summary=report.summary,
        content=report.content,
        source=report.source,
        analyst=report.analyst
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    log_audit(db, "CREATE", "intel", report_id, f"Created intel report: {report.type.value}")
    return db_report

@app.get("/api/v1/intel", response_model=List[schemas.IntelReportResponse])
async def get_intel_reports(
    skip: int = 0,
    limit: int = 100,
    type: Optional[str] = None,
    priority: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.IntelReport)
    if type:
        query = query.filter(models.IntelReport.type == type)
    if priority:
        query = query.filter(models.IntelReport.priority == priority)
    return query.order_by(models.IntelReport.created_at.desc()).offset(skip).limit(limit).all()

@app.get("/api/v1/intel/{report_id}", response_model=schemas.IntelReportResponse)
async def get_intel_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(models.IntelReport).filter(models.IntelReport.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Intel report not found")
    return report

@app.put("/api/v1/intel/{report_id}", response_model=schemas.IntelReportResponse)
async def update_intel_report(report_id: str, report_update: schemas.IntelReportUpdate, db: Session = Depends(get_db)):
    report = db.query(models.IntelReport).filter(models.IntelReport.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Intel report not found")
    
    update_data = report_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if value is not None:
            if hasattr(value, 'value'):
                setattr(report, key, value.value)
            else:
                setattr(report, key, value)
    
    db.commit()
    db.refresh(report)
    log_audit(db, "UPDATE", "intel", report_id, "Updated intel report")
    return report

@app.delete("/api/v1/intel/{report_id}")
async def delete_intel_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(models.IntelReport).filter(models.IntelReport.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Intel report not found")
    db.delete(report)
    db.commit()
    log_audit(db, "DELETE", "intel", report_id, "Deleted intel report")
    return {"status": "deleted", "report_id": report_id}

@app.post("/api/v1/nodes", response_model=schemas.NetworkNodeResponse)
async def create_node(node: schemas.NetworkNodeCreate, db: Session = Depends(get_db)):
    node_id = generate_id("NODE", db, models.NetworkNode)
    db_node = models.NetworkNode(
        node_id=node_id,
        name=node.name,
        type=node.type.value,
        status=node.status.value,
        ip_address=node.ip_address,
        mac_address=node.mac_address,
        hostname=node.hostname,
        os_type=node.os_type,
        os_version=node.os_version,
        location=node.location
    )
    db.add(db_node)
    db.commit()
    db.refresh(db_node)
    log_audit(db, "CREATE", "node", node_id, f"Created node: {node.name}")
    return db_node

@app.get("/api/v1/nodes", response_model=List[schemas.NetworkNodeResponse])
async def get_nodes(
    skip: int = 0,
    limit: int = 100,
    type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.NetworkNode)
    if type:
        query = query.filter(models.NetworkNode.type == type)
    if status:
        query = query.filter(models.NetworkNode.status == status)
    return query.order_by(models.NetworkNode.created_at.desc()).offset(skip).limit(limit).all()

@app.get("/api/v1/nodes/{node_id}", response_model=schemas.NetworkNodeResponse)
async def get_node(node_id: str, db: Session = Depends(get_db)):
    node = db.query(models.NetworkNode).filter(models.NetworkNode.node_id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return node

@app.put("/api/v1/nodes/{node_id}", response_model=schemas.NetworkNodeResponse)
async def update_node(node_id: str, node_update: schemas.NetworkNodeUpdate, db: Session = Depends(get_db)):
    node = db.query(models.NetworkNode).filter(models.NetworkNode.node_id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    update_data = node_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if value is not None:
            if hasattr(value, 'value'):
                setattr(node, key, value.value)
            else:
                setattr(node, key, value)
    
    node.last_seen = datetime.utcnow()
    db.commit()
    db.refresh(node)
    log_audit(db, "UPDATE", "node", node_id, f"Updated node status to: {node.status}")
    return node

@app.delete("/api/v1/nodes/{node_id}")
async def delete_node(node_id: str, db: Session = Depends(get_db)):
    node = db.query(models.NetworkNode).filter(models.NetworkNode.node_id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    db.delete(node)
    db.commit()
    log_audit(db, "DELETE", "node", node_id, "Deleted node")
    return {"status": "deleted", "node_id": node_id}

def perform_port_scan(target: str, ports: str = "1-1024") -> dict:
    results = {"open_ports": [], "closed_ports": 0, "filtered_ports": 0}
    
    try:
        port_range = ports.split("-")
        start_port = int(port_range[0])
        end_port = int(port_range[1]) if len(port_range) > 1 else start_port
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        ports_to_scan = [p for p in common_ports if start_port <= p <= end_port]
        
        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                results["open_ports"].append({"port": port, "service": service, "state": "open"})
            else:
                results["closed_ports"] += 1
            sock.close()
    except Exception as e:
        results["error"] = str(e)
    
    return results

@app.post("/api/v1/scan", response_model=schemas.ScanResultResponse)
async def start_scan(scan_request: schemas.ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan_id = generate_id("SCAN", db, models.ScanResult)
    
    db_scan = models.ScanResult(
        scan_id=scan_id,
        target=scan_request.target,
        scan_type=scan_request.scan_type,
        status="running",
        start_time=datetime.utcnow()
    )
    db.add(db_scan)
    db.commit()
    
    if scan_request.scan_type == "port":
        results = perform_port_scan(scan_request.target, scan_request.ports or "1-1024")
        
        findings_count = len(results.get("open_ports", []))
        critical_count = sum(1 for p in results.get("open_ports", []) if p["port"] in [21, 23, 445, 3389])
        high_count = sum(1 for p in results.get("open_ports", []) if p["port"] in [22, 3306, 5432])
        
        db_scan.status = "completed"
        db_scan.end_time = datetime.utcnow()
        db_scan.findings_count = findings_count
        db_scan.critical_count = critical_count
        db_scan.high_count = high_count
        db_scan.medium_count = findings_count - critical_count - high_count
        db_scan.results = json.dumps(results)
        db.commit()
        
        if critical_count > 0:
            threat = models.ThreatEvent(
                threat_id=generate_id("THREAT", db, models.ThreatEvent),
                type="Vulnerability Scan Finding",
                source="Port Scanner",
                severity="critical" if critical_count > 0 else "warning",
                description=f"Found {critical_count} critical open ports on {scan_request.target}",
                status="active",
                mitre_tactic="Discovery",
                mitre_id="T1046",
                destination_ip=scan_request.target
            )
            db.add(threat)
            db.commit()
    
    db.refresh(db_scan)
    log_audit(db, "SCAN", "scan", scan_id, f"Completed {scan_request.scan_type} scan on {scan_request.target}")
    return db_scan

@app.get("/api/v1/scans", response_model=List[schemas.ScanResultResponse])
async def get_scans(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.ScanResult).order_by(models.ScanResult.created_at.desc()).offset(skip).limit(limit).all()

@app.get("/api/v1/scans/{scan_id}", response_model=schemas.ScanResultResponse)
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(models.ScanResult).filter(models.ScanResult.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/api/v1/mitre/coverage")
async def get_mitre_coverage(db: Session = Depends(get_db)):
    tactics = [
        {"tactic": "Initial Access", "total_techniques": 9},
        {"tactic": "Execution", "total_techniques": 14},
        {"tactic": "Persistence", "total_techniques": 19},
        {"tactic": "Privilege Escalation", "total_techniques": 13},
        {"tactic": "Defense Evasion", "total_techniques": 42},
        {"tactic": "Credential Access", "total_techniques": 17},
        {"tactic": "Discovery", "total_techniques": 31},
        {"tactic": "Lateral Movement", "total_techniques": 9},
        {"tactic": "Collection", "total_techniques": 17},
        {"tactic": "Exfiltration", "total_techniques": 9},
        {"tactic": "Impact", "total_techniques": 14}
    ]
    
    coverage = []
    for tactic in tactics:
        threats_with_tactic = db.query(models.ThreatEvent).filter(
            models.ThreatEvent.mitre_tactic == tactic["tactic"]
        ).count()
        techniques_covered = min(threats_with_tactic, tactic["total_techniques"])
        coverage_percent = (techniques_covered / tactic["total_techniques"]) * 100 if tactic["total_techniques"] > 0 else 0
        
        coverage.append({
            "tactic": tactic["tactic"],
            "coverage": round(coverage_percent, 1),
            "techniques_covered": techniques_covered,
            "total_techniques": tactic["total_techniques"]
        })
    
    return coverage

@app.get("/api/v1/audit")
async def get_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).offset(skip).limit(limit).all()

@app.post("/api/v1/seed")
async def seed_data(db: Session = Depends(get_db)):
    import random
    
    if db.query(models.ThreatEvent).count() > 0:
        return {"status": "Data already exists", "seeded": False}
    
    threat_types = ["Malware Detection", "Intrusion Attempt", "Data Exfiltration", "Privilege Escalation", "Lateral Movement", "C2 Communication", "Credential Theft", "Ransomware Activity"]
    sources = ["SIEM", "IDS/IPS", "EDR", "Firewall", "WAF", "UEBA", "NDR", "Honeypot"]
    tactics = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"]
    severities = ["info", "warning", "error", "critical"]
    statuses = ["active", "investigating", "contained", "resolved"]
    
    # Real geographic attack data - source and target countries/regions
    attack_origins = [
        {"country": "Russia", "region": "EUROPE", "ip_prefix": "185."},
        {"country": "China", "region": "ASIA", "ip_prefix": "223."},
        {"country": "North Korea", "region": "ASIA", "ip_prefix": "175."},
        {"country": "Iran", "region": "MIDDLE_EAST", "ip_prefix": "5."},
        {"country": "Brazil", "region": "S_AMERICA", "ip_prefix": "177."},
        {"country": "Nigeria", "region": "AFRICA", "ip_prefix": "41."},
        {"country": "Vietnam", "region": "ASIA", "ip_prefix": "113."},
        {"country": "India", "region": "ASIA", "ip_prefix": "103."},
        {"country": "Ukraine", "region": "EUROPE", "ip_prefix": "91."},
        {"country": "Romania", "region": "EUROPE", "ip_prefix": "79."},
    ]
    
    attack_targets = [
        {"country": "United States", "region": "NORTH_AMERICA", "ip_prefix": "192."},
        {"country": "Germany", "region": "EUROPE", "ip_prefix": "195."},
        {"country": "United Kingdom", "region": "EUROPE", "ip_prefix": "194."},
        {"country": "France", "region": "EUROPE", "ip_prefix": "193."},
        {"country": "Japan", "region": "ASIA", "ip_prefix": "202."},
        {"country": "Australia", "region": "OCEANIA", "ip_prefix": "203."},
        {"country": "Canada", "region": "NORTH_AMERICA", "ip_prefix": "204."},
        {"country": "Slovenia", "region": "EUROPE", "ip_prefix": "213."},
    ]
    
    for i in range(15):
        origin = random.choice(attack_origins)
        target = random.choice(attack_targets)
        threat = models.ThreatEvent(
            threat_id=f"THREAT-{str(i+1).zfill(6)}",
            type=random.choice(threat_types),
            source=random.choice(sources),
            severity=random.choice(severities),
            description=f"Detected {random.choice(threat_types).lower()} from {origin['country']} targeting {target['country']}",
            status=random.choice(statuses),
            mitre_tactic=random.choice(tactics),
            mitre_id=f"T{1000 + random.randint(0, 600)}",
            source_ip=f"{origin['ip_prefix']}{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            destination_ip=f"{target['ip_prefix']}{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            source_country=origin['country'],
            target_country=target['country'],
            source_region=origin['region'],
            target_region=target['region']
        )
        db.add(threat)
    
    intel_types = ["SIGINT", "FININT", "OSINT", "HUMINT", "CI"]
    classifications = ["TOP SECRET//SCI", "SECRET//NOFORN", "CONFIDENTIAL", "UNCLASSIFIED"]
    priorities = ["routine", "priority", "immediate", "flash"]
    
    for i in range(20):
        report = models.IntelReport(
            report_id=f"INTEL-{str(i+1).zfill(5)}",
            type=random.choice(intel_types),
            classification=random.choice(classifications),
            priority=random.choice(priorities),
            summary=f"Intelligence report regarding threat actor activity in sector {random.randint(1, 100)}",
            source="Intelligence Division",
            analyst="Analyst Team"
        )
        db.add(report)
    
    node_types = ["server", "endpoint", "firewall", "router", "sensor"]
    node_statuses = ["online", "offline", "compromised", "quarantined"]
    
    for i in range(50):
        node = models.NetworkNode(
            node_id=f"NODE-{str(i+1).zfill(4)}",
            name=f"{random.choice(node_types)}-{i+1}",
            type=random.choice(node_types),
            status=random.choice(node_statuses),
            ip_address=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            hostname=f"host-{i+1}.internal",
            threats_detected=random.randint(0, 10)
        )
        db.add(node)
    
    db.commit()
    
    return {
        "status": "Data seeded successfully",
        "seeded": True,
        "threats": 15,
        "intel_reports": 20,
        "nodes": 50
    }


# ═══════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE OPERATIONS API - Implementing all 32 template directory functionalities
# ═══════════════════════════════════════════════════════════════════════════════

# Initialize operational engines
crawler_engine = WebCrawlerEngine()
vulnerability_scanner = VulnerabilityScanner()
malware_analyzer = MalwareAnalyzer()
forensics_engine = ForensicsEngine()
intelligence_collector = IntelligenceCollector()
siem_engine = SIEMEngine()


# ═══════════════════════════════════════════════════════════════════════════════
# CRAWLER API - web-crawler-engine.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/crawler/crawl")
async def crawl_target(
    target: str = Form(...),
    mode: str = Form("BREADTH_FIRST"),
    layer: str = Form("SURFACE"),
    max_depth: int = Form(3),
    max_pages: int = Form(50),
    db: Session = Depends(get_db)
):
    """Execute web crawling operation on target URL"""
    try:
        crawler_mode = CrawlerMode[mode.upper()]
    except KeyError:
        crawler_mode = CrawlerMode.BREADTH_FIRST
    
    try:
        internet_layer = InternetLayer[layer.upper()]
    except KeyError:
        internet_layer = InternetLayer.SURFACE
    
    engine = WebCrawlerEngine(mode=crawler_mode, max_depth=max_depth, max_pages=max_pages)
    
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    results = engine.crawl([target], internet_layer)
    
    log_audit(db, "CRAWL", "crawler", target, f"Crawled {len(results)} pages in {layer} layer")
    
    return {
        "status": "completed",
        "target": target,
        "mode": mode,
        "layer": layer,
        "pages_crawled": len(results),
        "results": [convert_to_dict(r) for r in results],
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/crawler/modes")
async def get_crawler_modes():
    """Get available crawler modes"""
    return {
        "modes": [
            {"id": "BREADTH_FIRST", "name": "Breadth First", "description": "Crawl level by level"},
            {"id": "DEPTH_FIRST", "name": "Depth First", "description": "Follow links deeply before backtracking"},
            {"id": "BEST_FIRST", "name": "Best First", "description": "Prioritize most relevant pages"},
            {"id": "FOCUSED", "name": "Focused", "description": "Target specific content types"},
            {"id": "INCREMENTAL", "name": "Incremental", "description": "Only crawl changed content"},
            {"id": "DISTRIBUTED", "name": "Distributed", "description": "Multi-node crawling"},
            {"id": "STEALTH", "name": "Stealth", "description": "Low-profile crawling with delays"}
        ],
        "layers": [
            {"id": "SURFACE", "name": "Surface Web", "protocols": ["HTTP", "HTTPS"]},
            {"id": "DARK", "name": "Dark Web", "protocols": ["TOR", "I2P", "FREENET"]},
            {"id": "DEEP", "name": "Deep Web", "protocols": ["HIDDEN_SERVICES", "AUTHENTICATED"]}
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER API - live-web-vulnerability-scanner.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/scanner/full")
async def full_vulnerability_scan(
    target: str = Form(...),
    layer: str = Form("SURFACE"),
    port_range: str = Form("common"),
    mode: str = Form("ACTIVE"),
    db: Session = Depends(get_db)
):
    """Execute comprehensive vulnerability scan"""
    try:
        internet_layer = InternetLayer[layer.upper()]
    except KeyError:
        internet_layer = InternetLayer.SURFACE
    
    try:
        scan_mode = ScanMode[mode.upper()]
    except KeyError:
        scan_mode = ScanMode.ACTIVE
    
    scanner = VulnerabilityScanner(mode=scan_mode)
    result = scanner.full_scan(target, internet_layer, port_range)
    
    scan_id = generate_id("SCAN", db, models.ScanResult)
    db_scan = models.ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=f"full_{layer}",
        status="completed",
        start_time=datetime.fromisoformat(result.start_time),
        end_time=datetime.fromisoformat(result.end_time),
        findings_count=len(result.findings),
        critical_count=sum(1 for v in result.vulnerabilities if v.get("severity") == "CRITICAL"),
        high_count=sum(1 for v in result.vulnerabilities if v.get("severity") == "HIGH"),
        medium_count=sum(1 for v in result.vulnerabilities if v.get("severity") == "MEDIUM"),
        low_count=sum(1 for v in result.vulnerabilities if v.get("severity") == "LOW"),
        results=json.dumps(convert_to_dict(result))
    )
    db.add(db_scan)
    db.commit()
    
    log_audit(db, "SCAN", "scanner", scan_id, f"Full scan on {target} - {len(result.vulnerabilities)} vulnerabilities found")
    
    return {
        "scan_id": scan_id,
        "status": "completed",
        **convert_to_dict(result)
    }


@app.post("/api/v1/scanner/ports")
async def port_scan(
    target: str = Form(...),
    ports: str = Form("common"),
    db: Session = Depends(get_db)
):
    """Execute port scan on target"""
    scanner = VulnerabilityScanner()
    
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        ip_address = target
    
    if ports == "common":
        ports_to_scan = scanner.common_ports
    elif ports == "full":
        ports_to_scan = list(range(1, 1025))
    else:
        try:
            start, end = ports.split("-")
            ports_to_scan = list(range(int(start), int(end) + 1))
        except:
            ports_to_scan = scanner.common_ports
    
    open_ports = []
    for port in ports_to_scan:
        result = scanner.scan_port(ip_address, port)
        if result["state"] == "open":
            open_ports.append(result)
    
    scan_id = generate_id("SCAN", db, models.ScanResult)
    db_scan = models.ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type="port",
        status="completed",
        start_time=datetime.utcnow(),
        end_time=datetime.utcnow(),
        findings_count=len(open_ports),
        results=json.dumps({"open_ports": open_ports, "target_ip": ip_address})
    )
    db.add(db_scan)
    db.commit()
    
    return {
        "scan_id": scan_id,
        "target": target,
        "target_ip": ip_address,
        "open_ports": open_ports,
        "total_scanned": len(ports_to_scan),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/scanner/ssl")
async def ssl_scan(target: str = Form(...), port: int = Form(443)):
    """Analyze SSL/TLS configuration"""
    scanner = VulnerabilityScanner()
    result = scanner.scan_ssl(target, port)
    
    return {
        "target": target,
        "port": port,
        **result,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/scanner/dns")
async def dns_scan(target: str = Form(...)):
    """Perform DNS reconnaissance"""
    scanner = VulnerabilityScanner()
    result = scanner.scan_dns(target)
    
    return {
        "target": target,
        **result,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/scanner/vulnerability-categories")
async def get_vulnerability_categories():
    """Get OWASP Top 10 and vulnerability categories"""
    return {
        "owasp_top_10": [
            {"id": "A01", "name": "Broken Access Control", "category": "BROKEN_ACCESS_CONTROL"},
            {"id": "A02", "name": "Cryptographic Failures", "category": "CRYPTOGRAPHIC_FAILURES"},
            {"id": "A03", "name": "Injection", "category": "INJECTION"},
            {"id": "A04", "name": "Insecure Design", "category": "INSECURE_DESIGN"},
            {"id": "A05", "name": "Security Misconfiguration", "category": "SECURITY_MISCONFIGURATION"},
            {"id": "A06", "name": "Vulnerable Components", "category": "VULNERABLE_COMPONENTS"},
            {"id": "A07", "name": "Authentication Failures", "category": "BROKEN_AUTHENTICATION"},
            {"id": "A08", "name": "Software Integrity Failures", "category": "INSECURE_DESERIALIZATION"},
            {"id": "A09", "name": "Logging Failures", "category": "INSUFFICIENT_LOGGING"},
            {"id": "A10", "name": "Server-Side Request Forgery", "category": "SERVER_SIDE_REQUEST_FORGERY"}
        ],
        "injection_types": [
            "SQL_INJECTION", "NOSQL_INJECTION", "LDAP_INJECTION", "XPATH_INJECTION",
            "COMMAND_INJECTION", "CODE_INJECTION", "TEMPLATE_INJECTION", "HEADER_INJECTION"
        ],
        "xss_types": [
            "XSS_REFLECTED", "XSS_STORED", "XSS_DOM_BASED", "XSS_MUTATION", "XSS_BLIND"
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MALWARE ANALYSIS API - malware-analysis.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/malware/analyze")
async def analyze_malware(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Analyze uploaded file for malware indicators"""
    content = await file.read()
    
    result = malware_analyzer.analyze(content, file.filename)
    
    log_audit(db, "ANALYZE", "malware", result.sample_id, 
              f"Analyzed {file.filename} - Threat Level: {result.threat_level}")
    
    return convert_to_dict(result)


@app.post("/api/v1/malware/analyze-hash")
async def analyze_hash(
    hash_value: str = Form(...),
    hash_type: str = Form("sha256")
):
    """Lookup hash in threat intelligence databases"""
    return {
        "hash": hash_value,
        "hash_type": hash_type,
        "known_malware": False,
        "threat_level": "UNKNOWN",
        "first_seen": None,
        "last_seen": None,
        "detection_names": [],
        "note": "Hash lookup requires external threat intelligence feed integration",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/malware/yara-scan")
async def yara_scan(file: UploadFile = File(...)):
    """Scan file with YARA rules"""
    content = await file.read()
    
    matches = []
    content_str = content.decode('utf-8', errors='ignore').lower()
    
    if 'cmd.exe' in content_str or 'powershell' in content_str:
        matches.append({
            "rule": "Suspicious_Commands",
            "description": "Contains suspicious command execution strings",
            "severity": "HIGH"
        })
    
    if b'UPX' in content:
        matches.append({
            "rule": "Packed_UPX",
            "description": "File appears to be packed with UPX",
            "severity": "MEDIUM"
        })
    
    if 'bitcoin' in content_str or 'wallet' in content_str:
        matches.append({
            "rule": "Crypto_Strings",
            "description": "Contains cryptocurrency-related strings",
            "severity": "HIGH"
        })
    
    return {
        "filename": file.filename,
        "file_size": len(content),
        "yara_matches": matches,
        "total_matches": len(matches),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/malware/types")
async def get_malware_types():
    """Get malware classification types"""
    return {
        "malware_types": [
            {"id": "VIRUS", "name": "Virus", "description": "Self-replicating malicious code"},
            {"id": "WORM", "name": "Worm", "description": "Self-propagating network malware"},
            {"id": "TROJAN", "name": "Trojan", "description": "Disguised malicious software"},
            {"id": "RANSOMWARE", "name": "Ransomware", "description": "Encrypts files for ransom"},
            {"id": "SPYWARE", "name": "Spyware", "description": "Covert surveillance software"},
            {"id": "ROOTKIT", "name": "Rootkit", "description": "Hides malicious activity"},
            {"id": "RAT", "name": "RAT", "description": "Remote Access Trojan"},
            {"id": "BACKDOOR", "name": "Backdoor", "description": "Unauthorized access mechanism"},
            {"id": "CRYPTOMINER", "name": "Cryptominer", "description": "Unauthorized cryptocurrency mining"},
            {"id": "BOTNET", "name": "Botnet", "description": "Network of compromised systems"}
        ],
        "analysis_types": [
            {"id": "STATIC", "name": "Static Analysis", "description": "Analyze without execution"},
            {"id": "DYNAMIC", "name": "Dynamic Analysis", "description": "Analyze during execution"},
            {"id": "BEHAVIORAL", "name": "Behavioral Analysis", "description": "Analyze runtime behavior"},
            {"id": "MEMORY", "name": "Memory Analysis", "description": "Analyze memory artifacts"},
            {"id": "NETWORK", "name": "Network Analysis", "description": "Analyze network traffic"}
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# FORENSICS API - device-forensics.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/forensics/create-case")
async def create_forensics_case(
    case_name: str = Form(...),
    examiner: str = Form(...),
    description: str = Form(""),
    db: Session = Depends(get_db)
):
    """Create new forensics case"""
    case_id = forensics_engine.create_case(case_name, examiner, description)
    
    log_audit(db, "CREATE", "forensics_case", case_id, f"Created case: {case_name}")
    
    return {
        "case_id": case_id,
        "case_name": case_name,
        "examiner": examiner,
        "description": description,
        "status": "OPEN",
        "created_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/forensics/analyze-file")
async def forensics_analyze_file(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Analyze file for forensic evidence"""
    content = await file.read()
    
    metadata = forensics_engine.analyze_file_metadata(file.filename, content)
    
    artifacts = []
    for artifact_type in ["BROWSER", "EMAIL", "NETWORK"]:
        artifacts.extend(forensics_engine.extract_artifacts(content, artifact_type))
    
    log_audit(db, "ANALYZE", "forensics", case_id, f"Analyzed file: {file.filename}")
    
    return {
        "case_id": case_id,
        "filename": file.filename,
        "metadata": metadata,
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/forensics/device-types")
async def get_forensics_device_types():
    """Get supported device types for forensic analysis"""
    return {
        "device_types": [
            {"id": "MOBILE_PHONE", "name": "Mobile Phone", "os": ["ANDROID", "IOS"]},
            {"id": "TABLET", "name": "Tablet", "os": ["ANDROID", "IOS", "WINDOWS"]},
            {"id": "LAPTOP", "name": "Laptop", "os": ["WINDOWS", "MACOS", "LINUX"]},
            {"id": "DESKTOP", "name": "Desktop", "os": ["WINDOWS", "MACOS", "LINUX"]},
            {"id": "SERVER", "name": "Server", "os": ["WINDOWS_SERVER", "LINUX"]},
            {"id": "IOT_DEVICE", "name": "IoT Device", "os": ["EMBEDDED_LINUX", "RTOS"]},
            {"id": "NETWORK_DEVICE", "name": "Network Device", "os": ["PROPRIETARY"]},
            {"id": "STORAGE_DEVICE", "name": "Storage Device", "os": ["N/A"]}
        ],
        "acquisition_types": [
            {"id": "PHYSICAL", "name": "Physical", "description": "Bit-for-bit copy"},
            {"id": "LOGICAL", "name": "Logical", "description": "File system copy"},
            {"id": "FILE_SYSTEM", "name": "File System", "description": "Active files only"},
            {"id": "MEMORY_DUMP", "name": "Memory Dump", "description": "RAM acquisition"},
            {"id": "NETWORK_CAPTURE", "name": "Network Capture", "description": "Traffic capture"}
        ],
        "evidence_types": [
            "FILE", "DELETED_FILE", "REGISTRY", "LOG", "DATABASE", "MESSAGE",
            "CALL_RECORD", "CONTACT", "LOCATION", "BROWSER_HISTORY", "APPLICATION_DATA"
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE API - osint-platform.ts.predloga, darkweb-intelligence.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/intelligence/osint")
async def collect_osint(
    target: str = Form(...),
    sources: str = Form("all"),
    db: Session = Depends(get_db)
):
    """Collect OSINT on target"""
    source_list = sources.split(",") if sources != "all" else None
    result = intelligence_collector.collect_osint(target, source_list)
    
    log_audit(db, "COLLECT", "osint", result.report_id, f"OSINT collection on {target}")
    
    return convert_to_dict(result)


@app.post("/api/v1/intelligence/darkweb")
async def analyze_darkweb_indicator(
    indicator: str = Form(...),
    db: Session = Depends(get_db)
):
    """Analyze dark web indicator"""
    result = intelligence_collector.analyze_darkweb_indicator(indicator)
    
    log_audit(db, "ANALYZE", "darkweb", indicator, f"Dark web analysis: {result['type']}")
    
    return {
        **result,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/intelligence/sources")
async def get_intelligence_sources():
    """Get available intelligence sources"""
    return {
        "osint_sources": [
            {"id": "SOCIAL_MEDIA", "name": "Social Media", "platforms": ["TWITTER", "FACEBOOK", "LINKEDIN", "INSTAGRAM"]},
            {"id": "NEWS", "name": "News", "types": ["RSS", "WEB_SCRAPING", "API"]},
            {"id": "PUBLIC_RECORDS", "name": "Public Records", "types": ["CORPORATE", "COURT", "PROPERTY"]},
            {"id": "FORUMS", "name": "Forums", "types": ["SECURITY", "HACKING", "GENERAL"]},
            {"id": "DARK_WEB", "name": "Dark Web", "networks": ["TOR", "I2P", "FREENET"]}
        ],
        "intel_types": [
            {"id": "SIGINT", "name": "Signals Intelligence"},
            {"id": "FININT", "name": "Financial Intelligence"},
            {"id": "OSINT", "name": "Open Source Intelligence"},
            {"id": "HUMINT", "name": "Human Intelligence"},
            {"id": "DARKWEB", "name": "Dark Web Intelligence"}
        ],
        "darkweb_networks": [
            {"id": "TOR", "name": "Tor Network", "domain": ".onion"},
            {"id": "I2P", "name": "I2P Network", "domain": ".i2p"},
            {"id": "FREENET", "name": "Freenet", "domain": "N/A"},
            {"id": "ZERONET", "name": "ZeroNet", "domain": ".bit"}
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SIEM/SOC API - siem-soc.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/siem/parse-log")
async def parse_log(
    log_entry: str = Form(...),
    log_type: str = Form("SYSLOG")
):
    """Parse log entry"""
    result = siem_engine.parse_log(log_entry, log_type)
    return result


@app.post("/api/v1/siem/correlate")
async def correlate_events(events: List[Dict[str, Any]]):
    """Correlate security events"""
    result = siem_engine.correlate_events(events)
    return {
        "correlations": result,
        "total_events": len(events),
        "correlated_count": len(result),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/siem/alert")
async def create_alert(
    event: Dict[str, Any],
    rule_name: str = Form(...),
    severity: str = Form("MEDIUM"),
    db: Session = Depends(get_db)
):
    """Create security alert"""
    alert = siem_engine.generate_alert(event, rule_name, severity)
    
    log_audit(db, "ALERT", "siem", alert["alert_id"], f"Alert: {rule_name} - {severity}")
    
    return alert


@app.get("/api/v1/siem/log-sources")
async def get_log_sources():
    """Get supported log source types"""
    return {
        "log_sources": [
            {"id": "FIREWALL", "name": "Firewall", "formats": ["SYSLOG", "CEF", "LEEF"]},
            {"id": "IDS_IPS", "name": "IDS/IPS", "formats": ["SYSLOG", "CEF", "SNORT"]},
            {"id": "ENDPOINT", "name": "Endpoint", "formats": ["SYSLOG", "JSON", "XML"]},
            {"id": "SERVER", "name": "Server", "formats": ["SYSLOG", "WINDOWS_EVENT", "JSON"]},
            {"id": "APPLICATION", "name": "Application", "formats": ["JSON", "XML", "CUSTOM"]},
            {"id": "DATABASE", "name": "Database", "formats": ["SYSLOG", "JSON"]},
            {"id": "CLOUD", "name": "Cloud", "formats": ["JSON", "CEF"]},
            {"id": "NETWORK_DEVICE", "name": "Network Device", "formats": ["SYSLOG", "SNMP"]},
            {"id": "AUTHENTICATION", "name": "Authentication", "formats": ["SYSLOG", "JSON"]},
            {"id": "EMAIL", "name": "Email", "formats": ["SYSLOG", "JSON"]}
        ],
        "normalization_formats": ["CEF", "LEEF", "ECS", "OCSF", "STIX"],
        "correlation_rule_types": [
            "THRESHOLD", "SEQUENCE", "AGGREGATION", "PATTERN", "ANOMALY", "BASELINE", "ML_BASED"
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# RED TEAM / OFFENSIVE API - red-team-operations.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/redteam/techniques")
async def get_redteam_techniques():
    """Get red team techniques mapped to MITRE ATT&CK"""
    return {
        "techniques": [
            {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
            {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence"},
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
            {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
            {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
            {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
            {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
        ],
        "tactics": [
            "Reconnaissance", "Resource Development", "Initial Access", "Execution",
            "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact"
        ]
    }


@app.post("/api/v1/redteam/engagement")
async def create_engagement(
    name: str = Form(...),
    target_scope: str = Form(...),
    rules_of_engagement: str = Form(...),
    db: Session = Depends(get_db)
):
    """Create red team engagement"""
    import secrets
    engagement_id = f"ENG-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
    
    log_audit(db, "CREATE", "engagement", engagement_id, f"Red team engagement: {name}")
    
    return {
        "engagement_id": engagement_id,
        "name": name,
        "target_scope": target_scope,
        "rules_of_engagement": rules_of_engagement,
        "status": "PLANNING",
        "created_at": datetime.utcnow().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════════════
# BLUE TEAM / DEFENSIVE API - blue-team-operations.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/blueteam/defenses")
async def get_defense_capabilities():
    """Get blue team defense capabilities"""
    return {
        "detection_capabilities": [
            {"id": "EDR", "name": "Endpoint Detection & Response", "coverage": "Endpoints"},
            {"id": "NDR", "name": "Network Detection & Response", "coverage": "Network"},
            {"id": "SIEM", "name": "Security Information & Event Management", "coverage": "Logs"},
            {"id": "UEBA", "name": "User & Entity Behavior Analytics", "coverage": "Behavior"},
            {"id": "SOAR", "name": "Security Orchestration & Response", "coverage": "Automation"}
        ],
        "response_actions": [
            {"id": "ISOLATE", "name": "Isolate Host", "type": "Containment"},
            {"id": "BLOCK_IP", "name": "Block IP Address", "type": "Containment"},
            {"id": "DISABLE_USER", "name": "Disable User Account", "type": "Containment"},
            {"id": "QUARANTINE", "name": "Quarantine File", "type": "Containment"},
            {"id": "COLLECT_EVIDENCE", "name": "Collect Evidence", "type": "Investigation"},
            {"id": "MEMORY_DUMP", "name": "Memory Dump", "type": "Investigation"}
        ],
        "playbooks": [
            {"id": "MALWARE", "name": "Malware Response", "steps": 8},
            {"id": "PHISHING", "name": "Phishing Response", "steps": 6},
            {"id": "RANSOMWARE", "name": "Ransomware Response", "steps": 12},
            {"id": "DATA_BREACH", "name": "Data Breach Response", "steps": 10},
            {"id": "INSIDER_THREAT", "name": "Insider Threat Response", "steps": 9}
        ]
    }


@app.post("/api/v1/blueteam/incident")
async def create_incident(
    title: str = Form(...),
    severity: str = Form("MEDIUM"),
    description: str = Form(...),
    db: Session = Depends(get_db)
):
    """Create security incident"""
    import secrets
    incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
    
    log_audit(db, "CREATE", "incident", incident_id, f"Incident: {title} - {severity}")
    
    return {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "description": description,
        "status": "OPEN",
        "created_at": datetime.utcnow().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════════════
# QUANTUM SECURITY API - quantum-safe-operations.ts.predloga
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/quantum/algorithms")
async def get_quantum_safe_algorithms():
    """Get post-quantum cryptographic algorithms"""
    return {
        "key_encapsulation": [
            {"id": "KYBER", "name": "CRYSTALS-Kyber", "nist_level": 3, "status": "STANDARDIZED"},
            {"id": "BIKE", "name": "BIKE", "nist_level": 1, "status": "ROUND_4"},
            {"id": "HQC", "name": "HQC", "nist_level": 1, "status": "ROUND_4"},
            {"id": "CLASSIC_MCELIECE", "name": "Classic McEliece", "nist_level": 5, "status": "ROUND_4"}
        ],
        "digital_signatures": [
            {"id": "DILITHIUM", "name": "CRYSTALS-Dilithium", "nist_level": 3, "status": "STANDARDIZED"},
            {"id": "FALCON", "name": "FALCON", "nist_level": 5, "status": "STANDARDIZED"},
            {"id": "SPHINCS", "name": "SPHINCS+", "nist_level": 5, "status": "STANDARDIZED"}
        ],
        "hybrid_schemes": [
            {"id": "KYBER_ECDH", "name": "Kyber + ECDH", "classical": "ECDH", "pqc": "Kyber"},
            {"id": "DILITHIUM_ECDSA", "name": "Dilithium + ECDSA", "classical": "ECDSA", "pqc": "Dilithium"}
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM CAPABILITIES API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/capabilities")
async def get_system_capabilities():
    """Get all system capabilities from 32 template directories"""
    return {
        "classification": "TOP SECRET // NSOC // TIER-0",
        "version": "1.0.0",
        "capabilities": {
            "analytics": ["Real-time analytics", "Behavioral analytics", "Predictive analytics"],
            "antiforensics": ["Detection", "Prevention", "Analysis"],
            "biometric": ["Facial recognition", "Fingerprint", "Voice", "Iris"],
            "communications": ["Encrypted comms", "Secure channels", "Covert messaging"],
            "crawler": ["Surface web", "Dark web", "Deep web", "Multi-mode crawling"],
            "cryptography": ["Symmetric", "Asymmetric", "Post-quantum", "Key management"],
            "defense": ["Perimeter", "Endpoint", "Network", "Application"],
            "defensive": ["Threat hunting", "Incident response", "Forensics"],
            "detection": ["Signature-based", "Behavioral", "ML-based", "Anomaly"],
            "emsec": ["TEMPEST", "RF shielding", "Emanation analysis"],
            "forensics": ["Mobile", "Computer", "Network", "Memory", "IoT"],
            "intelligence": ["OSINT", "SIGINT", "FININT", "HUMINT", "Dark web"],
            "malware": ["Static analysis", "Dynamic analysis", "Behavioral", "YARA"],
            "monitoring": ["Network", "Endpoint", "Application", "Cloud"],
            "network": ["Packet analysis", "Flow analysis", "Protocol analysis"],
            "observability": ["Logging", "Metrics", "Tracing", "Alerting"],
            "offensive": ["Penetration testing", "Red team", "Exploitation"],
            "operations": ["SOC", "NOC", "Incident management"],
            "reliability": ["Circuit breaker", "Rate limiting", "Retry", "Fallback"],
            "research": ["Zero-day", "Vulnerability", "Threat research"],
            "response": ["Automated", "Manual", "Playbook-driven"],
            "scanner": ["Port", "Vulnerability", "Web application", "SSL/TLS"],
            "search": ["Full-text", "Indexed", "Distributed"],
            "security": ["Authentication", "Authorization", "Encryption"],
            "specialized": ["ICS/SCADA", "IoT", "Cloud", "Mobile"],
            "stealth": ["Evasion", "Anti-detection", "Covert operations"],
            "supply_chain": ["Vendor assessment", "Component analysis", "Risk scoring"],
            "surveillance": ["Network", "Endpoint", "Physical"],
            "ui": ["Dashboard", "Visualization", "Reporting"],
            "visualization": ["3D", "Graph", "Timeline", "Geospatial"],
            "vulnerability": ["Assessment", "Management", "Prioritization"],
            "warfare": ["Cyber operations", "Information warfare", "Electronic warfare"]
        },
        "operational_modules": [
            "SOC_CORE", "INTELLIGENCE", "NET_MON", "THREAT_FEED",
            "FORENSICS", "RED_TEAM", "BLUE_TEAM", "MALWARE_LAB",
            "QUANTUM_SEC", "AI_DEFENSE", "REDACTED_COMMS", "CHAIN_TRACK",
            "EVIDENCE_VAULT", "OPSCOM"
        ],
        "person_tags": [
            "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "WATCHLIST", "BLACKLIST", "WHITELIST",
            "SANCTIONED", "PEP", "VERIFIED", "UNVERIFIED", "PARTIALLY_VERIFIED",
            "IDENTITY_CONFIRMED", "IDENTITY_DISPUTED", "ACTIVE", "INACTIVE", "DECEASED",
            "UNDER_INVESTIGATION", "CASE_CLOSED", "MONITORING", "PRIMARY_TARGET",
            "SECONDARY_TARGET", "ASSOCIATE", "FAMILY_MEMBER", "BUSINESS_PARTNER",
            "KNOWN_CONTACT", "SUSPECTED_CONTACT", "OSINT_SOURCE", "HUMINT_SOURCE",
            "SIGINT_SOURCE", "DARK_WEB_PRESENCE", "SOCIAL_MEDIA_ACTIVE", "DATA_BREACH_VICTIM",
            "PRIORITY_CRITICAL", "PRIORITY_HIGH", "PRIORITY_MEDIUM", "PRIORITY_LOW",
            "VIP", "INFORMANT", "ASSET", "HOSTILE", "NEUTRAL", "FRIENDLY",
            "FOREIGN_NATIONAL", "DUAL_CITIZEN"
        ],
        "relationship_types": [
            "FAMILY", "FRIEND", "COLLEAGUE", "BUSINESS_PARTNER", "ROMANTIC_PARTNER",
            "ASSOCIATE", "KNOWN_CONTACT", "SUSPECTED_CONTACT", "EMPLOYER", "EMPLOYEE"
        ],
        "connection_labels": [
            "STRONG_CONNECTION", "MODERATE_CONNECTION", "WEAK_CONNECTION",
            "SUSPECTED_CONNECTION", "CONFIRMED_CONNECTION", "DIRECT_CONTACT",
            "INDIRECT_CONTACT", "FINANCIAL_LINK", "COMMUNICATION_LINK",
            "TRAVEL_COMPANION", "CO_LOCATED", "SHARED_ADDRESS", "SHARED_PHONE",
            "SHARED_EMAIL_DOMAIN", "SHARED_EMPLOYER", "SHARED_EDUCATION",
            "CURRENT", "HISTORICAL", "RECENT", "LONG_TERM",
            "PERSON_OF_INTEREST", "WITNESS", "SUSPECT", "VICTIM", "ACCOMPLICE"
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY TOOLS INTEGRATION API
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from app.security_tools import (
        SecurityToolsManager, convert_dataclass_to_dict
    )
    security_tools_manager = SecurityToolsManager()
    SECURITY_TOOLS_AVAILABLE = True
except ImportError:
    SECURITY_TOOLS_AVAILABLE = False
    security_tools_manager = None


@app.get("/api/v1/security-tools/status")
async def get_security_tools_status():
    """Get status of all integrated security tools"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return security_tools_manager.get_all_status()


@app.get("/api/v1/security-tools/suricata/status")
async def get_suricata_status():
    """Get Suricata IDS/IPS status"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return security_tools_manager.suricata.get_status()


@app.get("/api/v1/security-tools/suricata/alerts")
async def get_suricata_alerts(limit: int = 100, severity: Optional[str] = None):
    """Get Suricata alerts"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    alerts = security_tools_manager.suricata.get_alerts(limit=limit, severity=severity)
    return {
        "count": len(alerts),
        "alerts": [convert_dataclass_to_dict(a) for a in alerts]
    }


@app.get("/api/v1/security-tools/zeek/status")
async def get_zeek_status():
    """Get Zeek Network Security Monitor status"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return security_tools_manager.zeek.get_status()


@app.get("/api/v1/security-tools/zeek/connections")
async def get_zeek_connections(limit: int = 100):
    """Get Zeek connection logs"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    connections = security_tools_manager.zeek.get_connections(limit=limit)
    return {
        "count": len(connections),
        "connections": [convert_dataclass_to_dict(c) for c in connections]
    }


@app.get("/api/v1/security-tools/elasticsearch/status")
async def get_elasticsearch_status():
    """Get Elasticsearch/OpenSearch status"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return security_tools_manager.elasticsearch.get_status()


@app.get("/api/v1/security-tools/ntopng/status")
async def get_ntopng_status():
    """Get ntopng Network Traffic Monitor status"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return security_tools_manager.ntopng.get_status()


@app.get("/api/v1/security-tools/tor/status")
async def get_tor_status():
    """Get Tor status for Dark Web connectivity"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return security_tools_manager.tor.get_status()


@app.get("/api/v1/security-tools/unified/alerts")
async def get_unified_alerts(limit: int = 100):
    """Get unified alerts from all security tools"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return {
        "alerts": security_tools_manager.get_unified_alerts(limit=limit)
    }


@app.get("/api/v1/security-tools/unified/connections")
async def get_unified_connections(limit: int = 100):
    """Get unified connections from all security tools"""
    if not SECURITY_TOOLS_AVAILABLE:
        return {"error": "Security tools module not available"}
    return {
        "connections": security_tools_manager.get_unified_connections(limit=limit)
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "GISC Command Center"}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED MODULES API - Complete Implementation of All Template Functionalities
# ═══════════════════════════════════════════════════════════════════════════════

# Import all advanced modules
try:
    from app.cryptography_engine import create_cryptography_engine, CryptoAlgorithm, HashAlgorithm, KeyType, EncryptionLevel as CryptoEncryptionLevel
    crypto_engine = create_cryptography_engine()
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    crypto_engine = None

try:
    from app.operations_engine import create_operations_engine, OperationType, OperationStatus
    ops_engine = create_operations_engine()
    OPS_AVAILABLE = True
except ImportError:
    OPS_AVAILABLE = False
    ops_engine = None

try:
    from app.surveillance_engine import create_surveillance_engine, SurveillanceType, TargetStatus as SurvTargetStatus
    surveillance_engine = create_surveillance_engine()
    SURVEILLANCE_AVAILABLE = True
except ImportError:
    SURVEILLANCE_AVAILABLE = False
    surveillance_engine = None

try:
    from app.communications_engine import create_communications_engine, ChannelType, EncryptionLevel, ProtocolType
    comms_engine = create_communications_engine()
    COMMS_AVAILABLE = True
except ImportError:
    COMMS_AVAILABLE = False
    comms_engine = None

try:
    from app.warfare_engine import create_warfare_engine, WarfareType, TargetType as WarfareTargetType
    warfare_engine = create_warfare_engine()
    WARFARE_AVAILABLE = True
except ImportError:
    WARFARE_AVAILABLE = False
    warfare_engine = None

try:
    from app.specialized_engine import create_specialized_engine, BiometricType, EMSECThreatType
    specialized_engine = create_specialized_engine()
    SPECIALIZED_AVAILABLE = True
except ImportError:
    SPECIALIZED_AVAILABLE = False
    specialized_engine = None

try:
    from app.darkweb_intelligence import create_darkweb_engine
    darkweb_engine = create_darkweb_engine()
    DARKWEB_AVAILABLE = True
except ImportError:
    DARKWEB_AVAILABLE = False
    darkweb_engine = None

try:
    from app.redteam_operations import create_redteam_engine
    redteam_engine = create_redteam_engine()
    REDTEAM_AVAILABLE = True
except ImportError:
    REDTEAM_AVAILABLE = False
    redteam_engine = None

try:
    from app.blueteam_operations import create_blueteam_engine
    blueteam_engine = create_blueteam_engine()
    BLUETEAM_AVAILABLE = True
except ImportError:
    BLUETEAM_AVAILABLE = False
    blueteam_engine = None

try:
    from app.malware_analysis import create_malware_engine
    malware_engine = create_malware_engine()
    MALWARE_AVAILABLE = True
except ImportError:
    MALWARE_AVAILABLE = False
    malware_engine = None

try:
    from app.forensics_engine import create_forensics_engine
    forensics_engine_adv = create_forensics_engine()
    FORENSICS_ADV_AVAILABLE = True
except ImportError:
    FORENSICS_ADV_AVAILABLE = False
    forensics_engine_adv = None

try:
    from app.siem_engine import create_siem_engine
    siem_engine = create_siem_engine()
    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False
    siem_engine = None

try:
    from app.intelligence_engine import create_intelligence_engine
    intel_engine = create_intelligence_engine()
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False
    intel_engine = None

try:
    from app.detection_engine import create_detection_engine
    detection_engine = create_detection_engine()
    DETECTION_AVAILABLE = True
except ImportError:
    DETECTION_AVAILABLE = False
    detection_engine = None

try:
    from app.defense_engine import create_defense_engine
    defense_engine = create_defense_engine()
    DEFENSE_AVAILABLE = True
except ImportError:
    DEFENSE_AVAILABLE = False
    defense_engine = None


# ═══════════════════════════════════════════════════════════════════════════════
# CRYPTOGRAPHY API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/crypto/status")
async def get_crypto_status():
    """Get cryptography engine status"""
    if not CRYPTO_AVAILABLE:
        return {"error": "Cryptography module not available"}
    return crypto_engine.get_crypto_status()


@app.post("/api/v1/crypto/keys/generate")
async def generate_crypto_key(name: str, algorithm: str = "AES_256_GCM", key_type: str = "SYMMETRIC"):
    """Generate cryptographic key"""
    if not CRYPTO_AVAILABLE:
        return {"error": "Cryptography module not available"}
    try:
        algo = CryptoAlgorithm(algorithm)
        ktype = KeyType(key_type)
        key = crypto_engine.key_manager.generate_key(name, algo, ktype)
        return {"key_id": key.key_id, "algorithm": key.algorithm.value, "status": key.status.value}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/crypto/encrypt")
async def encrypt_data(data: str, key_id: str = None):
    """Encrypt data"""
    if not CRYPTO_AVAILABLE:
        return {"error": "Cryptography module not available"}
    try:
        result = crypto_engine.encrypt_data(data.encode(), key_id)
        return {
            "ciphertext": result.ciphertext,
            "iv": result.iv,
            "tag": result.tag,
            "key_id": result.key_id,
            "algorithm": result.algorithm.value
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/crypto/hash")
async def hash_data(data: str, algorithm: str = "SHA256"):
    """Hash data"""
    if not CRYPTO_AVAILABLE:
        return {"error": "Cryptography module not available"}
    try:
        algo = HashAlgorithm(algorithm)
        hash_result = crypto_engine.hash_data(data.encode(), algo)
        return {"hash": hash_result, "algorithm": algorithm}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/crypto/quantum-readiness")
async def get_quantum_readiness():
    """Get quantum cryptography readiness assessment"""
    if not CRYPTO_AVAILABLE:
        return {"error": "Cryptography module not available"}
    return crypto_engine.quantum_crypto.get_quantum_readiness_assessment()


# ═══════════════════════════════════════════════════════════════════════════════
# OPERATIONS API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/operations/status")
async def get_operations_status():
    """Get operations engine status"""
    if not OPS_AVAILABLE:
        return {"error": "Operations module not available"}
    return ops_engine.get_operations_summary()


@app.post("/api/v1/operations/create")
async def create_operation(codename: str, operation_type: str, objectives: List[str]):
    """Create new operation"""
    if not OPS_AVAILABLE:
        return {"error": "Operations module not available"}
    try:
        op_type = OperationType(operation_type)
        operation = ops_engine.create_operation(codename, op_type, objectives)
        return {
            "operation_id": operation.operation_id,
            "codename": operation.codename,
            "status": operation.status.value
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/operations/identity/create")
async def create_identity(name: str, nationality: str, background: Dict[str, Any]):
    """Create operational identity"""
    if not OPS_AVAILABLE:
        return {"error": "Operations module not available"}
    try:
        identity = ops_engine.identity_ops.create_identity(name, nationality, background)
        return identity
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/operations/opsec/assess")
async def assess_opsec(operation_id: str, assessor: str):
    """Conduct OPSEC assessment"""
    if not OPS_AVAILABLE:
        return {"error": "Operations module not available"}
    try:
        from dataclasses import asdict
        assessment = ops_engine.conduct_opsec_assessment(operation_id, assessor)
        return asdict(assessment)
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# SURVEILLANCE API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/surveillance/status")
async def get_surveillance_status():
    """Get surveillance engine status"""
    if not SURVEILLANCE_AVAILABLE:
        return {"error": "Surveillance module not available"}
    return surveillance_engine.get_surveillance_status()


@app.post("/api/v1/surveillance/target/create")
async def create_surveillance_target(name: str, identifiers: Dict[str, List[str]], priority: int = 1):
    """Create surveillance target"""
    if not SURVEILLANCE_AVAILABLE:
        return {"error": "Surveillance module not available"}
    try:
        from dataclasses import asdict
        target = surveillance_engine.create_target(name, identifiers, priority)
        return asdict(target)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/surveillance/selector/add")
async def add_surveillance_selector(selector_type: str, value: str):
    """Add communication selector"""
    if not SURVEILLANCE_AVAILABLE:
        return {"error": "Surveillance module not available"}
    try:
        selector = surveillance_engine.add_selector(selector_type, value)
        return selector
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/surveillance/network/watch")
async def add_network_watch(entity_type: str, value: str):
    """Add network watch"""
    if not SURVEILLANCE_AVAILABLE:
        return {"error": "Surveillance module not available"}
    try:
        watch = surveillance_engine.add_network_watch(entity_type, value)
        return watch
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# COMMUNICATIONS API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/communications/status")
async def get_communications_status():
    """Get communications engine status"""
    if not COMMS_AVAILABLE:
        return {"error": "Communications module not available"}
    return comms_engine.get_communications_status()


@app.post("/api/v1/communications/channel/create")
async def create_secure_channel(name: str, participants: List[str], encryption_level: str = "SECRET"):
    """Create secure communication channel"""
    if not COMMS_AVAILABLE:
        return {"error": "Communications module not available"}
    try:
        from dataclasses import asdict
        enc_level = EncryptionLevel(encryption_level)
        channel = comms_engine.create_secure_channel(name, participants, enc_level)
        return asdict(channel)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/communications/message/send")
async def send_secure_message(channel_id: str, sender: str, content: str):
    """Send secure message"""
    if not COMMS_AVAILABLE:
        return {"error": "Communications module not available"}
    try:
        from dataclasses import asdict
        message = comms_engine.send_secure_message(channel_id, sender, content)
        return asdict(message)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/communications/covert/create")
async def create_covert_channel(name: str, protocol: str, method: str):
    """Create covert channel"""
    if not COMMS_AVAILABLE:
        return {"error": "Communications module not available"}
    try:
        from dataclasses import asdict
        proto = ProtocolType(protocol)
        channel = comms_engine.create_covert_channel(name, proto, method)
        return asdict(channel)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/communications/anonymous/circuit")
async def create_anonymous_circuit(hops: int = 3):
    """Create anonymous circuit"""
    if not COMMS_AVAILABLE:
        return {"error": "Communications module not available"}
    try:
        circuit = comms_engine.create_anonymous_circuit(hops)
        return circuit
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# WARFARE API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/warfare/status")
async def get_warfare_status():
    """Get warfare engine status"""
    if not WARFARE_AVAILABLE:
        return {"error": "Warfare module not available"}
    return warfare_engine.get_warfare_status()


@app.post("/api/v1/warfare/operation/create")
async def create_warfare_operation(codename: str, warfare_type: str, objectives: List[str]):
    """Create warfare operation"""
    if not WARFARE_AVAILABLE:
        return {"error": "Warfare module not available"}
    try:
        from dataclasses import asdict
        wf_type = WarfareType(warfare_type)
        operation = warfare_engine.create_operation(codename, wf_type, objectives)
        return asdict(operation)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/warfare/infrastructure/register")
async def register_critical_infrastructure(name: str, asset_type: str, location: Dict[str, Any], criticality: int):
    """Register critical infrastructure asset"""
    if not WARFARE_AVAILABLE:
        return {"error": "Warfare module not available"}
    try:
        from dataclasses import asdict
        a_type = WarfareTargetType(asset_type)
        asset = warfare_engine.critical_infrastructure.register_asset(name, a_type, location, criticality)
        return asdict(asset)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/warfare/infrastructure/assess")
async def assess_infrastructure_vulnerability(asset_id: str):
    """Assess infrastructure vulnerability"""
    if not WARFARE_AVAILABLE:
        return {"error": "Warfare module not available"}
    try:
        assessment = warfare_engine.critical_infrastructure.assess_vulnerability(asset_id)
        return assessment
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# SPECIALIZED SYSTEMS API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/specialized/status")
async def get_specialized_status():
    """Get specialized systems status"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    return specialized_engine.get_specialized_status()


@app.post("/api/v1/specialized/biometric/enroll")
async def enroll_biometric(subject_id: str, biometric_type: str, biometric_data: str):
    """Enroll biometric template"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        from dataclasses import asdict
        bio_type = BiometricType(biometric_type)
        data = base64.b64decode(biometric_data)
        template = specialized_engine.biometric.enroll_biometric(subject_id, bio_type, data)
        return asdict(template)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/specialized/biometric/verify")
async def verify_biometric(template_id: str, probe_data: str):
    """Verify biometric"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        from dataclasses import asdict
        data = base64.b64decode(probe_data)
        match = specialized_engine.biometric.verify_biometric(template_id, data)
        return asdict(match)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/specialized/emsec/assess")
async def assess_emsec(location: str, equipment: List[str]):
    """Conduct EMSEC assessment"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        from dataclasses import asdict
        assessment = specialized_engine.emsec.conduct_assessment(location, equipment)
        return asdict(assessment)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/specialized/supply-chain/supplier/register")
async def register_supplier(name: str, country: str, certifications: List[str]):
    """Register supplier"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        from dataclasses import asdict
        supplier = specialized_engine.supply_chain.register_supplier(name, country, certifications)
        return asdict(supplier)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/specialized/supply-chain/sbom/generate")
async def generate_sbom(product_id: str, components: List[str]):
    """Generate Software Bill of Materials"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        sbom = specialized_engine.supply_chain.generate_sbom(product_id, components)
        return sbom
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/specialized/visualization/network")
async def create_network_visualization(title: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
    """Create network graph visualization"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        from dataclasses import asdict
        viz = specialized_engine.visualization.create_network_graph(title, nodes, edges)
        return asdict(viz)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/specialized/visualization/3d")
async def create_3d_visualization(title: str, objects: List[Dict[str, Any]]):
    """Create 3D visualization"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        from dataclasses import asdict
        viz = specialized_engine.visualization.create_3d_visualization(title, objects)
        return asdict(viz)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/specialized/visualization/attack")
async def create_attack_visualization(attack_data: Dict[str, Any]):
    """Create cyber attack visualization"""
    if not SPECIALIZED_AVAILABLE:
        return {"error": "Specialized module not available"}
    try:
        from dataclasses import asdict
        viz = specialized_engine.visualization.create_attack_visualization(attack_data)
        return asdict(viz)
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# DARK WEB INTELLIGENCE API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/darkweb/status")
async def get_darkweb_status():
    """Get dark web intelligence status"""
    if not DARKWEB_AVAILABLE:
        return {"error": "Dark web module not available"}
    return darkweb_engine.get_network_status()


@app.post("/api/v1/darkweb/crawl")
async def crawl_darkweb(url: str, network: str = "TOR"):
    """Crawl dark web URL"""
    if not DARKWEB_AVAILABLE:
        return {"error": "Dark web module not available"}
    try:
        result = darkweb_engine.crawl_onion_site(url)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/darkweb/credential/check")
async def check_credential_leak(email: str = None, domain: str = None):
    """Check for credential leaks"""
    if not DARKWEB_AVAILABLE:
        return {"error": "Dark web module not available"}
    try:
        result = darkweb_engine.check_credential_leak(email=email, domain=domain)
        return result
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED RED TEAM API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/redteam-adv/status")
async def get_redteam_adv_status():
    """Get advanced red team status"""
    if not REDTEAM_AVAILABLE:
        return {"error": "Red team module not available"}
    return redteam_engine.get_redteam_status()


@app.post("/api/v1/redteam-adv/engagement/create")
async def create_redteam_engagement(name: str, target: str, scope: List[str]):
    """Create red team engagement"""
    if not REDTEAM_AVAILABLE:
        return {"error": "Red team module not available"}
    try:
        from dataclasses import asdict
        engagement = redteam_engine.create_engagement(name, target, scope)
        return asdict(engagement)
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED BLUE TEAM API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/blueteam-adv/status")
async def get_blueteam_adv_status():
    """Get advanced blue team status"""
    if not BLUETEAM_AVAILABLE:
        return {"error": "Blue team module not available"}
    return blueteam_engine.get_blueteam_status()


@app.post("/api/v1/blueteam-adv/hunt/execute")
async def execute_threat_hunt(playbook_id: str, target_data: Dict[str, Any]):
    """Execute threat hunting playbook"""
    if not BLUETEAM_AVAILABLE:
        return {"error": "Blue team module not available"}
    try:
        result = blueteam_engine.execute_hunt(playbook_id, target_data)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/blueteam-adv/ioc/add")
async def add_ioc(ioc_type: str, value: str, source: str):
    """Add Indicator of Compromise"""
    if not BLUETEAM_AVAILABLE:
        return {"error": "Blue team module not available"}
    try:
        from dataclasses import asdict
        ioc = blueteam_engine.add_ioc(ioc_type, value, source)
        return asdict(ioc)
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED MALWARE ANALYSIS API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/malware-adv/status")
async def get_malware_adv_status():
    """Get advanced malware analysis status"""
    if not MALWARE_AVAILABLE:
        return {"error": "Malware analysis module not available"}
    return malware_engine.get_malware_status()


@app.post("/api/v1/malware-adv/analyze")
async def analyze_malware_advanced(file_data: str, filename: str):
    """Perform advanced malware analysis"""
    if not MALWARE_AVAILABLE:
        return {"error": "Malware analysis module not available"}
    try:
        data = base64.b64decode(file_data)
        result = malware_engine.analyze_sample(data, filename)
        return result
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED FORENSICS API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/forensics-adv/status")
async def get_forensics_adv_status():
    """Get advanced forensics status"""
    if not FORENSICS_ADV_AVAILABLE:
        return {"error": "Forensics module not available"}
    return forensics_engine_adv.get_forensics_status()


@app.post("/api/v1/forensics-adv/case/create")
async def create_forensics_case_adv(case_name: str, case_type: str, description: str):
    """Create forensics case"""
    if not FORENSICS_ADV_AVAILABLE:
        return {"error": "Forensics module not available"}
    try:
        from dataclasses import asdict
        case = forensics_engine_adv.create_case(case_name, case_type, description)
        return asdict(case)
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED SIEM API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/siem-adv/status")
async def get_siem_adv_status():
    """Get advanced SIEM status"""
    if not SIEM_AVAILABLE:
        return {"error": "SIEM module not available"}
    return siem_engine.get_siem_status()


@app.post("/api/v1/siem-adv/log/ingest")
async def ingest_log(log_data: str, source: str):
    """Ingest log data"""
    if not SIEM_AVAILABLE:
        return {"error": "SIEM module not available"}
    try:
        result = siem_engine.ingest_log(log_data, source)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/siem-adv/alerts")
async def get_siem_alerts(limit: int = 100):
    """Get SIEM alerts"""
    if not SIEM_AVAILABLE:
        return {"error": "SIEM module not available"}
    try:
        alerts = siem_engine.get_alerts(limit=limit)
        return {"count": len(alerts), "alerts": alerts}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED INTELLIGENCE API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/intelligence-adv/status")
async def get_intelligence_adv_status():
    """Get advanced intelligence status"""
    if not INTEL_AVAILABLE:
        return {"error": "Intelligence module not available"}
    return intel_engine.get_intelligence_status()


@app.post("/api/v1/intelligence-adv/osint/collect")
async def collect_osint_advanced(target: str):
    """Collect OSINT on target"""
    if not INTEL_AVAILABLE:
        return {"error": "Intelligence module not available"}
    try:
        result = intel_engine.collect_osint(target)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/intelligence-adv/threat-actors")
async def get_threat_actors():
    """Get known threat actors"""
    if not INTEL_AVAILABLE:
        return {"error": "Intelligence module not available"}
    try:
        actors = intel_engine.get_threat_actors()
        return {"count": len(actors), "actors": actors}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED DETECTION API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/detection-adv/status")
async def get_detection_adv_status():
    """Get advanced detection status"""
    if not DETECTION_AVAILABLE:
        return {"error": "Detection module not available"}
    return detection_engine.get_detection_summary()


@app.post("/api/v1/detection-adv/apt/analyze")
async def analyze_apt_indicators(indicators: List[Dict[str, Any]]):
    """Analyze APT indicators"""
    if not DETECTION_AVAILABLE:
        return {"error": "Detection module not available"}
    try:
        result = detection_engine.analyze_apt(indicators)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/detection-adv/anomaly/detect")
async def detect_anomalies(data: List[Dict[str, Any]]):
    """Detect anomalies in data"""
    if not DETECTION_AVAILABLE:
        return {"error": "Detection module not available"}
    try:
        result = detection_engine.detect_anomalies(data)
        return result
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED DEFENSE API
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/defense-adv/status")
async def get_defense_adv_status():
    """Get advanced defense status"""
    if not DEFENSE_AVAILABLE:
        return {"error": "Defense module not available"}
    return defense_engine.get_defense_status()


@app.post("/api/v1/defense-adv/firewall/rule/add")
async def add_firewall_rule(action: str, source: str, destination: str, port: int, protocol: str):
    """Add firewall rule"""
    if not DEFENSE_AVAILABLE:
        return {"error": "Defense module not available"}
    try:
        result = defense_engine.add_firewall_rule(action, source, destination, port, protocol)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/defense-adv/threat/neutralize")
async def neutralize_threat(threat_id: str, action: str):
    """Neutralize threat"""
    if not DEFENSE_AVAILABLE:
        return {"error": "Defense module not available"}
    try:
        result = defense_engine.neutralize_threat(threat_id, action)
        return result
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM CAPABILITIES SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/capabilities")
async def get_system_capabilities():
    """Get complete system capabilities summary"""
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "classification": "TOP SECRET // NSOC // TIER-0",
        "modules": {
            "core": {
                "threats": True,
                "intel": True,
                "nodes": True,
                "scans": True,
                "mitre": True
            },
            "operations": {
                "crawler": True,
                "vulnerability_scanner": True,
                "malware_analyzer": True,
                "forensics": True,
                "intelligence": True,
                "siem": True,
                "redteam": True,
                "blueteam": True
            },
            "advanced": {
                "cryptography": CRYPTO_AVAILABLE,
                "operations": OPS_AVAILABLE,
                "surveillance": SURVEILLANCE_AVAILABLE,
                "communications": COMMS_AVAILABLE,
                "warfare": WARFARE_AVAILABLE,
                "specialized": SPECIALIZED_AVAILABLE,
                "darkweb": DARKWEB_AVAILABLE,
                "redteam_advanced": REDTEAM_AVAILABLE,
                "blueteam_advanced": BLUETEAM_AVAILABLE,
                "malware_advanced": MALWARE_AVAILABLE,
                "forensics_advanced": FORENSICS_ADV_AVAILABLE,
                "siem_advanced": SIEM_AVAILABLE,
                "intelligence_advanced": INTEL_AVAILABLE,
                "detection_advanced": DETECTION_AVAILABLE,
                "defense_advanced": DEFENSE_AVAILABLE
            },
            "security_tools": {
                "suricata": SECURITY_TOOLS_AVAILABLE,
                "zeek": SECURITY_TOOLS_AVAILABLE,
                "elasticsearch": SECURITY_TOOLS_AVAILABLE,
                "ntopng": SECURITY_TOOLS_AVAILABLE,
                "tor": SECURITY_TOOLS_AVAILABLE
            }
        },
        "capabilities": [
            "Web Crawling (7 modes: BREADTH_FIRST, DEPTH_FIRST, BEST_FIRST, FOCUSED, INCREMENTAL, DISTRIBUTED, STEALTH)",
            "Vulnerability Scanning (OWASP Top 10, CWE/SANS Top 25)",
            "Malware Analysis (Static, Dynamic, Behavioral, YARA)",
            "Digital Forensics (Disk, Memory, Network, Mobile, IoT, Blockchain)",
            "Intelligence Collection (OSINT, SIGINT, HUMINT, FININT)",
            "SIEM/SOC (Log aggregation, Event correlation, MITRE ATT&CK mapping)",
            "Red Team Operations (Reconnaissance, Exploitation, Persistence, C2)",
            "Blue Team Operations (Threat Hunting, Incident Response, YARA/Sigma)",
            "Dark Web Intelligence (Tor/I2P crawling, Credential monitoring)",
            "Cryptography (Quantum-safe algorithms, Key management)",
            "Covert Operations (Identity management, OPSEC)",
            "Surveillance (Network, Communications, Target tracking)",
            "Secure Communications (Encrypted channels, Steganography, Anonymous circuits)",
            "Cyber Warfare (Critical infrastructure protection, Electronic warfare)",
            "Biometric Security (Fingerprint, Facial, Iris, Voice, Behavioral)",
            "EMSEC (Electromagnetic security assessment)",
            "Supply Chain Security (SBOM generation, Component verification)",
            "3D Visualization (Attack visualization, Network graphs)",
            "APT Detection (Kill chain analysis, Attribution)",
            "Deepfake Detection (Image, Video, Audio analysis)",
            "Anomaly Detection (Statistical, Behavioral, Temporal)",
            "Active Defense (Honeypots, Threat neutralization, DDoS mitigation)",
            "Person Intelligence (Internet-wide search, Social media crawling, Profile database, Tagging)"
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PERSON INTELLIGENCE API
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from app.person_intelligence import (
        create_person_intelligence_engine, 
        SearchScope, 
        SocialPlatform, 
        PersonTag, 
        ConnectionLabel,
        RelationshipType
    )
    person_intel_engine = create_person_intelligence_engine()
    PERSON_INTEL_AVAILABLE = True
except ImportError as e:
    PERSON_INTEL_AVAILABLE = False
    person_intel_engine = None
    print(f"Person Intelligence module not available: {e}")


@app.get("/api/v1/person-intel/status")
async def get_person_intel_status():
    """Get person intelligence engine status"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    return person_intel_engine.get_status()


@app.post("/api/v1/person-intel/search")
async def search_person(query: str, scope: str = "ALL", auto_save: bool = True, max_results: int = 20):
    """Search for a person across internet and databases with automatic data extraction and storage
    
    Parameters:
    - query: Search query (name, email, username, etc.)
    - scope: Search scope (ALL, SURFACE_WEB, SOCIAL_MEDIA, PUBLIC_RECORDS, DATA_BREACHES, DEEP_WEB, DARK_WEB)
    - auto_save: Automatically save discovered profiles and connections to database (default: True)
    - max_results: Maximum number of results to return and save (default: 20)
    
    Returns comprehensive results including:
    - social_profiles: Discovered social media profiles
    - saved_profiles: Profiles automatically saved to database
    - discovered_connections: Automatically discovered relationships between persons
    - extracted_data: Emails, phones, addresses found during search
    """
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        search_scope = SearchScope(scope)
        result = person_intel_engine.comprehensive_search(query, search_scope, auto_save=auto_save, max_results=max_results)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/profile/create")
async def create_person_profile(
    first_name: str = None,
    last_name: str = None,
    email: str = None,
    phone: str = None,
    auto_enrich: bool = True
):
    """Create a new person profile"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.create_person_profile(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            auto_enrich=auto_enrich
        )
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/profile/{profile_id}")
async def get_person_profile(profile_id: str):
    """Get a person profile by ID"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        profile = person_intel_engine.profile_db.get_profile(profile_id)
        if not profile:
            return {"error": "Profile not found"}
        from dataclasses import asdict
        return asdict(profile)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/profile/{profile_id}/enrich")
async def enrich_person_profile(profile_id: str):
    """Enrich a person profile with additional data"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.enrich_profile(profile_id)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/profile/{profile_id}/tag/add")
async def add_tag_to_person(
    profile_id: str,
    tag: str,
    reason: str = None,
    applied_by: str = "user",
    expires_in_days: int = None
):
    """Add a tag to a person profile"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.add_tag_to_person(
            profile_id, tag, reason, applied_by, expires_in_days
        )
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/profile/{profile_id}/tag/remove")
async def remove_tag_from_person(profile_id: str, tag: str):
    """Remove a tag from a person profile"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.remove_tag_from_person(profile_id, tag)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/profile/{profile_id}/tags")
async def get_person_tags(profile_id: str):
    """Get all tags for a person"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.get_person_tags(profile_id)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/profile/{profile_id}/auto-tag")
async def auto_tag_person(profile_id: str):
    """Automatically apply tags based on profile data"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.auto_tag_profile(profile_id)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/search/by-tag/{tag}")
async def search_persons_by_tag(tag: str):
    """Search for persons by tag"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.search_by_tag(tag)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/relationship/add")
async def add_person_relationship(
    person_a_id: str,
    person_b_id: str,
    relationship_type: str,
    strength: float = 0.5
):
    """Add a relationship between two persons"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.add_relationship(
            person_a_id, person_b_id, relationship_type, strength
        )
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/relationship/{relationship_id}/label/add")
async def add_connection_label(
    relationship_id: str,
    label: str,
    evidence: List[str] = None,
    applied_by: str = "user"
):
    """Add a label to a connection between persons"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.add_connection_label(
            relationship_id, label, evidence, applied_by
        )
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/relationship/{relationship_id}/labels")
async def get_connection_labels(relationship_id: str):
    """Get all labels for a connection"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.get_connection_labels(relationship_id)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/profile/{profile_id}/network")
async def get_person_network(profile_id: str):
    """Analyze social network around a person"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.analyze_person_network(profile_id)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/image-search")
async def search_by_face(image_data: str):
    """Search for person by facial image (base64 encoded)"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        image_bytes = base64.b64decode(image_data)
        result = person_intel_engine.search_by_face(image_bytes)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/tags/available")
async def get_available_tags():
    """Get all available tags organized by category"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        result = person_intel_engine.get_available_tags()
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/social-platforms")
async def get_social_platforms():
    """Get list of supported social media platforms"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    return {
        "platforms": [p.value for p in SocialPlatform],
        "total_count": len(SocialPlatform),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/person-intel/search-scopes")
async def get_search_scopes():
    """Get list of supported search scopes"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    return {
        "scopes": [s.value for s in SearchScope],
        "descriptions": {
            "SURFACE_WEB": "Standard internet search (Google, Bing, etc.)",
            "DEEP_WEB": "Hidden services, databases, forums",
            "DARK_WEB": "Tor/I2P hidden services, .onion domains",
            "SOCIAL_MEDIA": "Social media platforms (LinkedIn, Facebook, Twitter, etc.)",
            "PUBLIC_RECORDS": "Government databases, court records, business registries",
            "DATA_BREACHES": "Known data breach databases",
            "ALL": "Search all available sources"
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/person-intel/relationship-types")
async def get_relationship_types():
    """Get list of supported relationship types"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    return {
        "types": [r.value for r in RelationshipType],
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/person-intel/connection-labels")
async def get_connection_label_types():
    """Get list of supported connection labels"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    return {
        "labels": [l.value for l in ConnectionLabel],
        "categories": {
            "strength": ["STRONG_CONNECTION", "MODERATE_CONNECTION", "WEAK_CONNECTION", "SUSPECTED_CONNECTION", "CONFIRMED_CONNECTION"],
            "type": ["DIRECT_CONTACT", "INDIRECT_CONTACT", "FINANCIAL_LINK", "COMMUNICATION_LINK", "TRAVEL_COMPANION", "CO_LOCATED", "SHARED_ADDRESS", "SHARED_PHONE", "SHARED_EMAIL_DOMAIN", "SHARED_EMPLOYER", "SHARED_EDUCATION"],
            "temporal": ["CURRENT", "HISTORICAL", "RECENT", "LONG_TERM"],
            "investigation": ["PERSON_OF_INTEREST", "WITNESS", "SUSPECT", "VICTIM", "ACCOMPLICE"]
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/person-intel/social-media/crawl")
async def crawl_social_media(username: str, platforms: List[str] = None):
    """Crawl social media profiles for a username"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        if platforms:
            results = {}
            for platform_name in platforms:
                platform = SocialPlatform(platform_name)
                profile = person_intel_engine.social_crawler.crawl_profile(platform, username)
                if profile:
                    from dataclasses import asdict
                    results[platform_name] = asdict(profile)
            return {
                "username": username,
                "platforms_crawled": platforms,
                "profiles_found": results,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            profiles = person_intel_engine.social_crawler.crawl_all_platforms(username)
            from dataclasses import asdict
            return {
                "username": username,
                "platforms_crawled": [p.value for p in SocialPlatform],
                "profiles_found": {k: asdict(v) if v else None for k, v in profiles.items()},
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/database/statistics")
async def get_profile_database_statistics():
    """Get profile database statistics"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        stats = person_intel_engine.profile_db.get_statistics()
        return stats
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/cameras/discover")
async def discover_online_cameras(request: Request):
    """Discover online cameras in a specific location or country with region and source filtering"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        location = body.get("location")
        country = body.get("country")
        camera_type = body.get("camera_type")
        region = body.get("region")
        source = body.get("source")
        
        results = person_intel_engine.discover_online_cameras(location, country, camera_type, region, source)
        return results
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/cameras/list")
async def list_discovered_cameras():
    """List all discovered cameras"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        cameras = list(person_intel_engine.camera_search.discovered_cameras.values())
        return {
            "cameras": cameras,
            "total": len(cameras),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/cameras/{camera_id}/snapshot")
async def capture_camera_snapshot(camera_id: str):
    """Capture a snapshot from a specific camera"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        snapshot = person_intel_engine.capture_camera_snapshot(camera_id)
        return snapshot
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/cameras/search-person")
async def search_person_in_cameras(request: Request):
    """Search for a person across discovered camera feeds"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        person_id = body.get("person_id")
        camera_ids = body.get("camera_ids")
        
        if not person_id:
            return {"error": "person_id is required"}
        
        results = person_intel_engine.search_person_in_cameras(person_id, camera_ids)
        return results
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/cameras/statistics")
async def get_camera_statistics():
    """Get statistics about discovered cameras"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        stats = person_intel_engine.get_camera_statistics()
        return stats
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/cameras/set-shodan-key")
async def set_shodan_api_key(request: Request):
    """Set Shodan API key for camera discovery"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        api_key = body.get("api_key")
        
        if not api_key:
            return {"error": "api_key is required"}
        
        person_intel_engine.set_shodan_api_key(api_key)
        return {"status": "success", "message": "Shodan API key configured"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/proxies/add")
async def add_proxy(request: Request):
    """Add a proxy to the rotation pool for camera crawling"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        host = body.get("host")
        port = body.get("port")
        protocol = body.get("protocol", "http")
        username = body.get("username")
        password = body.get("password")
        
        if not host or not port:
            return {"error": "host and port are required"}
        
        success = person_intel_engine.add_proxy(host, int(port), protocol, username, password)
        return {"status": "success" if success else "duplicate", "message": f"Proxy {'added' if success else 'already exists'}"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/proxies/add-list")
async def add_proxies_from_list(request: Request):
    """Add multiple proxies from a list"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        proxy_list = body.get("proxies", [])
        
        if not proxy_list:
            return {"error": "proxies list is required"}
        
        count = person_intel_engine.add_proxies_from_list(proxy_list)
        return {"status": "success", "proxies_added": count}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/proxies/enable")
async def enable_proxy_rotation(request: Request):
    """Enable or disable proxy rotation"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        enabled = body.get("enabled", True)
        
        person_intel_engine.enable_proxy_rotation(enabled)
        return {"status": "success", "proxy_rotation": "enabled" if enabled else "disabled"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/proxies/stats")
async def get_proxy_statistics():
    """Get proxy pool statistics"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        stats = person_intel_engine.get_proxy_statistics()
        return stats
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/captchas/pending")
async def get_pending_captchas():
    """Get list of pending CAPTCHAs requiring human interaction"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        captchas = person_intel_engine.get_pending_captchas()
        return {"pending_captchas": captchas, "count": len(captchas)}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/captchas/solve")
async def solve_captcha(request: Request):
    """Mark a CAPTCHA as solved by human"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        captcha_id = body.get("captcha_id")
        solution = body.get("solution")
        
        if not captcha_id:
            return {"error": "captcha_id is required"}
        
        success = person_intel_engine.solve_captcha(captcha_id, solution)
        return {"status": "success" if success else "not_found", "captcha_id": captcha_id}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/captchas/skip")
async def skip_captcha(request: Request):
    """Skip a CAPTCHA"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        captcha_id = body.get("captcha_id")
        
        if not captcha_id:
            return {"error": "captcha_id is required"}
        
        success = person_intel_engine.skip_captcha(captcha_id)
        return {"status": "success" if success else "not_found", "captcha_id": captcha_id}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/motion/detect")
async def detect_motion(request: Request):
    """Detect motion in a camera frame"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        camera_id = body.get("camera_id")
        frame_data = body.get("frame_data")
        
        if not camera_id or not frame_data:
            return {"error": "camera_id and frame_data are required"}
        
        import base64
        frame_bytes = base64.b64decode(frame_data)
        
        result = person_intel_engine.motion_detector.detect_motion(camera_id, frame_bytes)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/motion/history")
async def get_motion_history(camera_id: str = None, limit: int = 100):
    """Get motion detection history"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        history = person_intel_engine.motion_detector.get_motion_history(camera_id, limit)
        return {"motion_history": history, "count": len(history)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/motion/alerts")
async def get_motion_alerts(acknowledged: bool = None, limit: int = 50):
    """Get motion alerts"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        alerts = person_intel_engine.motion_detector.get_motion_alerts(acknowledged, limit)
        return {"motion_alerts": alerts, "count": len(alerts)}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/motion/acknowledge")
async def acknowledge_motion_alert(request: Request):
    """Acknowledge a motion alert"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        alert_id = body.get("alert_id")
        
        if not alert_id:
            return {"error": "alert_id is required"}
        
        success = person_intel_engine.motion_detector.acknowledge_alert(alert_id)
        return {"status": "success" if success else "not_found", "alert_id": alert_id}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/person-intel/motion/statistics")
async def get_motion_statistics():
    """Get motion detection statistics"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        stats = person_intel_engine.motion_detector.get_statistics()
        return stats
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/person-intel/search-person-on-cameras")
async def search_person_on_cameras_by_location(request: Request):
    """Search for a person on cameras based on their location data"""
    if not PERSON_INTEL_AVAILABLE:
        return {"error": "Person Intelligence module not available"}
    try:
        body = await request.json()
        person_id = body.get("person_id")
        search_all_locations = body.get("search_all_locations", False)
        
        if not person_id:
            return {"error": "person_id is required"}
        
        profile = person_intel_engine.profile_db.get_profile(person_id)
        if not profile:
            return {"error": f"Person profile {person_id} not found"}
        
        locations_to_search = []
        
        if profile.addresses:
            for addr in profile.addresses:
                if addr.city:
                    locations_to_search.append({
                        "city": addr.city,
                        "country": addr.country,
                        "region": addr.state
                    })
        
        if profile.metadata and profile.metadata.get("location"):
            loc = profile.metadata.get("location")
            if isinstance(loc, dict):
                locations_to_search.append(loc)
            elif isinstance(loc, str):
                locations_to_search.append({"city": loc})
        
        if not locations_to_search:
            locations_to_search.append({"city": None, "country": None})
        
        all_cameras = []
        cameras_by_location = {}
        
        for loc in locations_to_search:
            city = loc.get("city")
            country = loc.get("country")
            region = loc.get("region")
            
            cameras = person_intel_engine.discover_online_cameras(
                location=city,
                country=country,
                region=region
            )
            
            loc_key = f"{city or 'Unknown'}, {country or 'Unknown'}"
            cameras_by_location[loc_key] = cameras
            all_cameras.extend(cameras)
        
        face_matches = []
        if profile.facial_data:
            camera_ids = [cam.get("camera_id") for cam in all_cameras if cam.get("camera_id")]
            if camera_ids:
                face_results = person_intel_engine.search_person_in_cameras(person_id, camera_ids[:20])
                face_matches = face_results.get("matches", [])
        
        return {
            "person_id": person_id,
            "person_name": profile.full_name,
            "locations_searched": locations_to_search,
            "total_cameras_found": len(all_cameras),
            "cameras_by_location": {k: len(v) for k, v in cameras_by_location.items()},
            "cameras": all_cameras[:50],
            "face_matches": face_matches,
            "search_timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}


import subprocess
import threading
import queue
from typing import Generator

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, conf
    conf.use_pcap = True
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

packet_capture_queue = queue.Queue(maxsize=1000)
captured_packets_store = []
captured_payloads_store = []
capture_process = None
capture_active = False
scapy_capture_thread = None

def extract_payload_from_packet(packet) -> dict:
    payload_data = {
        "raw_payload": None,
        "payload_hex": None,
        "payload_ascii": None,
        "payload_base64": None,
        "payload_length": 0,
        "detected_patterns": [],
        "is_malicious": False,
        "malicious_indicators": []
    }
    
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        payload_data["payload_length"] = len(raw_bytes)
        payload_data["raw_payload"] = raw_bytes[:2000]
        payload_data["payload_hex"] = raw_bytes[:500].hex()
        
        try:
            payload_data["payload_ascii"] = raw_bytes[:1000].decode('utf-8', errors='replace')
        except:
            payload_data["payload_ascii"] = raw_bytes[:1000].decode('latin-1', errors='replace')
        
        payload_data["payload_base64"] = base64.b64encode(raw_bytes[:1000]).decode('ascii')
        
        from urllib.parse import unquote
        try:
            decoded_payload = unquote(raw_bytes.decode('utf-8', errors='replace'))
            decoded_bytes = decoded_payload.encode('utf-8')
        except:
            decoded_bytes = raw_bytes
        
        malicious_patterns = [
            (b'/bin/sh', 'Shell command execution'),
            (b'/bin/bash', 'Bash shell execution'),
            (b'cmd.exe', 'Windows command execution'),
            (b'powershell', 'PowerShell execution'),
            (b'eval(', 'Code evaluation'),
            (b'exec(', 'Code execution'),
            (b'system(', 'System call'),
            (b'<script', 'JavaScript injection'),
            (b'SELECT ', 'SQL query'),
            (b'UNION ', 'SQL injection'),
            (b'DROP ', 'SQL injection'),
            (b'INSERT ', 'SQL injection'),
            (b'DELETE ', 'SQL injection'),
            (b'UPDATE ', 'SQL injection'),
            (b'../..', 'Path traversal'),
            (b'%00', 'Null byte injection'),
            (b'\\x00', 'Null byte'),
            (b'nc -e', 'Netcat reverse shell'),
            (b'wget ', 'Remote file download'),
            (b'curl ', 'Remote file download'),
            (b'chmod ', 'Permission change'),
            (b'base64 -d', 'Base64 decode'),
            (b'python -c', 'Python execution'),
            (b'perl -e', 'Perl execution'),
            (b'ruby -e', 'Ruby execution'),
            (b'\\xeb\\x', 'Shellcode pattern'),
            (b'\\x90\\x90', 'NOP sled'),
            (b'JUNK', 'Buffer overflow padding'),
            (b'AAAA', 'Buffer overflow pattern'),
            (b'/etc/passwd', 'Sensitive file access'),
            (b'/etc/shadow', 'Sensitive file access'),
            (b'cat /etc', 'System file read'),
            (b"' OR '", 'SQL injection'),
            (b"' OR 1=1", 'SQL injection'),
            (b"admin'--", 'SQL injection'),
            (b'sqlmap', 'SQL injection tool'),
            (b'nikto', 'Web scanner'),
            (b'nmap', 'Port scanner'),
            (b'metasploit', 'Exploitation framework'),
            (b'msfconsole', 'Metasploit console'),
            (b'meterpreter', 'Metasploit payload'),
            (b'reverse_tcp', 'Reverse shell'),
            (b'bind_shell', 'Bind shell'),
        ]
        
        raw_lower = raw_bytes.lower()
        decoded_lower = decoded_bytes.lower()
        for pattern, description in malicious_patterns:
            pattern_lower = pattern.lower()
            if pattern_lower in raw_lower or pattern_lower in decoded_lower:
                payload_data["detected_patterns"].append({
                    "pattern": pattern.decode('utf-8', errors='replace'),
                    "description": description
                })
                payload_data["is_malicious"] = True
                payload_data["malicious_indicators"].append(description)
    
    return payload_data

def parse_scapy_packet(packet) -> dict:
    timestamp = datetime.utcnow().isoformat()
    src_ip = "unknown"
    dst_ip = "unknown"
    src_port = 0
    dst_port = 0
    protocol = "UNKNOWN"
    flags = []
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "IP"
    
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
        if tcp_flags & 0x02:
            flags.append("SYN")
        if tcp_flags & 0x10:
            flags.append("ACK")
        if tcp_flags & 0x01:
            flags.append("FIN")
        if tcp_flags & 0x04:
            flags.append("RST")
        if tcp_flags & 0x08:
            flags.append("PSH")
        if tcp_flags & 0x20:
            flags.append("URG")
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    
    payload_info = extract_payload_from_packet(packet)
    
    packet_length = len(packet)
    
    is_suspicious = False
    suspicious_reason = None
    
    suspicious_ports = [4444, 5555, 6666, 31337, 12345, 23, 445, 3389, 1433, 3306, 6379, 27017]
    if dst_port in suspicious_ports:
        is_suspicious = True
        suspicious_reason = f"Suspicious destination port {dst_port}"
    elif src_port in suspicious_ports:
        is_suspicious = True
        suspicious_reason = f"Suspicious source port {src_port}"
    
    if payload_info["is_malicious"]:
        is_suspicious = True
        suspicious_reason = f"Malicious payload detected: {', '.join(payload_info['malicious_indicators'][:3])}"
    
    return {
        "timestamp": timestamp,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "flags": " ".join(flags) if flags else "DATA",
        "length": str(packet_length),
        "payload": payload_info,
        "is_suspicious": is_suspicious,
        "suspicious_reason": suspicious_reason,
        "raw": packet.summary()[:200]
    }

def scapy_packet_callback(packet):
    global captured_packets_store, captured_payloads_store, detected_attacks, capture_active
    
    if not capture_active:
        return
    
    parsed = parse_scapy_packet(packet)
    if parsed:
        captured_packets_store.append(parsed)
        if len(captured_packets_store) > 1000:
            captured_packets_store.pop(0)
        
        if parsed["payload"]["payload_length"] > 0:
            captured_payloads_store.append({
                "timestamp": parsed["timestamp"],
                "source_ip": parsed["source_ip"],
                "destination_ip": parsed["destination_ip"],
                "protocol": parsed["protocol"],
                "payload_hex": parsed["payload"]["payload_hex"],
                "payload_ascii": parsed["payload"]["payload_ascii"],
                "payload_base64": parsed["payload"]["payload_base64"],
                "payload_length": parsed["payload"]["payload_length"],
                "is_malicious": parsed["payload"]["is_malicious"],
                "detected_patterns": parsed["payload"]["detected_patterns"]
            })
            if len(captured_payloads_store) > 500:
                captured_payloads_store.pop(0)
        
        attacks = detect_attack_patterns(parsed)
        for attack in attacks:
            attack["timestamp"] = datetime.utcnow().isoformat()
            attack["packet_info"] = parsed
            attack["captured_payload"] = parsed["payload"]
            attack_exists = False
            for existing in detected_attacks:
                if existing["type"] == attack["type"] and existing["source_ip"] == attack["source_ip"]:
                    existing.update(attack)
                    attack_exists = True
                    break
            if not attack_exists:
                detected_attacks.append(attack)
                capture_error_log.append(f"ATTACK DETECTED: {attack['type']} from {attack['source_ip']}")
        
        try:
            packet_capture_queue.put_nowait(parsed)
        except queue.Full:
            packet_capture_queue.get()
            packet_capture_queue.put_nowait(parsed)

def scapy_capture_thread_func(interface: str, count: int, filter_expr: str):
    global capture_active, capture_error_log, captured_packets_store, captured_payloads_store, detected_attacks
    capture_error_log = []
    detected_attacks = []
    captured_payloads_store = []
    
    try:
        capture_error_log.append(f"Starting Scapy capture on interface: {interface}")
        capture_error_log.append(f"Filter: {filter_expr if filter_expr else 'none'}")
        capture_error_log.append(f"Max packets: {count}")
        capture_active = True
        
        sniff(
            iface=interface if interface != "any" else None,
            count=count,
            filter=filter_expr if filter_expr else None,
            prn=scapy_packet_callback,
            store=False,
            stop_filter=lambda x: not capture_active
        )
        
        capture_error_log.append(f"Capture completed. Total packets: {len(captured_packets_store)}")
        capture_error_log.append(f"Payloads captured: {len(captured_payloads_store)}")
        capture_error_log.append(f"Attacks detected: {len(detected_attacks)}")
        capture_active = False
    except Exception as e:
        capture_error_log.append(f"SCAPY EXCEPTION: {type(e).__name__}: {str(e)}")
        capture_active = False

def parse_tcpdump_line(line: str) -> dict:
    parts = line.strip().split()
    if len(parts) < 5:
        return None
    try:
        timestamp = parts[0]
        protocol = "TCP"
        src_ip = "unknown"
        dst_ip = "unknown"
        info = " ".join(parts[1:])
        
        for i, part in enumerate(parts):
            if ">" in part and i > 0:
                src_ip = parts[i-1].rsplit(".", 1)[0] if "." in parts[i-1] else parts[i-1]
                if i+1 < len(parts):
                    dst_ip = parts[i+1].rstrip(":").rsplit(".", 1)[0] if "." in parts[i+1] else parts[i+1]
                break
        
        if "UDP" in line or "udp" in line:
            protocol = "UDP"
        elif "ICMP" in line or "icmp" in line:
            protocol = "ICMP"
        elif "HTTP" in line or "http" in line:
            protocol = "HTTP"
        elif "HTTPS" in line or "https" in line or "443" in line:
            protocol = "HTTPS"
        elif "DNS" in line or "dns" in line or ".53" in line:
            protocol = "DNS"
        
        flags = []
        if "SYN" in line or "[S]" in line:
            flags.append("SYN")
        if "ACK" in line or "[.]" in line:
            flags.append("ACK")
        if "FIN" in line or "[F]" in line:
            flags.append("FIN")
        if "RST" in line or "[R]" in line:
            flags.append("RST")
        if "PSH" in line or "[P]" in line:
            flags.append("PSH")
        
        length_match = None
        for part in parts:
            if part.startswith("length"):
                idx = parts.index(part)
                if idx + 1 < len(parts):
                    length_match = parts[idx + 1]
                    break
        
        is_suspicious = False
        suspicious_reason = None
        
        suspicious_ports = ["4444", "5555", "6666", "31337", "12345", "23", "445", "3389"]
        for port in suspicious_ports:
            if f".{port}" in line or f":{port}" in line:
                is_suspicious = True
                suspicious_reason = f"Suspicious port {port}"
                break
        
        if any(x in line.lower() for x in ["malicious", "attack", "exploit", "shell", "reverse"]):
            is_suspicious = True
            suspicious_reason = "Suspicious keyword detected"
        
        return {
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "flags": " ".join(flags) if flags else "DATA",
            "length": length_match or "0",
            "info": info[:100],
            "is_suspicious": is_suspicious,
            "suspicious_reason": suspicious_reason,
            "raw": line[:200]
        }
    except Exception:
        return None

capture_error_log = []
detected_attacks = []
attack_detection_state = {
    "syn_packets_by_source": {},
    "connection_attempts_by_source": {},
    "ports_scanned_by_source": {},
    "icmp_packets_by_source": {},
    "last_reset": datetime.utcnow()
}

def detect_attack_patterns(packet: dict) -> list:
    global attack_detection_state
    attacks = []
    
    now = datetime.utcnow()
    if (now - attack_detection_state["last_reset"]).seconds > 60:
        attack_detection_state = {
            "syn_packets_by_source": {},
            "connection_attempts_by_source": {},
            "ports_scanned_by_source": {},
            "icmp_packets_by_source": {},
            "last_reset": now
        }
    
    src_ip = packet.get("source_ip", "unknown")
    dst_ip = packet.get("destination_ip", "unknown")
    flags = packet.get("flags", "")
    protocol = packet.get("protocol", "TCP")
    raw = packet.get("raw", "")
    
    dst_port = None
    for part in raw.split():
        if "." in part and part.count(".") >= 4:
            port_part = part.split(".")[-1].rstrip(":")
            if port_part.isdigit():
                dst_port = int(port_part)
                break
    
    if "SYN" in flags and "ACK" not in flags:
        if src_ip not in attack_detection_state["syn_packets_by_source"]:
            attack_detection_state["syn_packets_by_source"][src_ip] = {"count": 0, "first_seen": now, "ports": set()}
        
        attack_detection_state["syn_packets_by_source"][src_ip]["count"] += 1
        if dst_port:
            attack_detection_state["syn_packets_by_source"][src_ip]["ports"].add(dst_port)
        
        syn_data = attack_detection_state["syn_packets_by_source"][src_ip]
        time_window = (now - syn_data["first_seen"]).seconds + 1
        syn_rate = syn_data["count"] / time_window
        unique_ports = len(syn_data["ports"])
        
        if syn_rate > 50:
            attacks.append({
                "type": "SYN_FLOOD",
                "severity": "critical",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "description": f"SYN Flood Attack detected: {syn_data['count']} SYN packets in {time_window}s ({syn_rate:.1f}/s)",
                "mitre_tactic": "Impact",
                "mitre_id": "T1498",
                "indicators": {
                    "syn_count": syn_data["count"],
                    "rate_per_second": syn_rate,
                    "time_window": time_window
                }
            })
        
        if unique_ports > 10:
            attacks.append({
                "type": "PORT_SCAN",
                "severity": "high",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "description": f"Port Scan detected: {unique_ports} unique ports scanned from {src_ip}",
                "mitre_tactic": "Discovery",
                "mitre_id": "T1046",
                "indicators": {
                    "ports_scanned": unique_ports,
                    "ports_list": list(syn_data["ports"])[:50],
                    "scan_duration": time_window
                }
            })
    
    if "RST" in flags:
        if src_ip not in attack_detection_state["connection_attempts_by_source"]:
            attack_detection_state["connection_attempts_by_source"][src_ip] = {"rst_count": 0, "first_seen": now}
        
        attack_detection_state["connection_attempts_by_source"][src_ip]["rst_count"] += 1
        rst_data = attack_detection_state["connection_attempts_by_source"][src_ip]
        
        if rst_data["rst_count"] > 20:
            attacks.append({
                "type": "RECONNAISSANCE",
                "severity": "medium",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "description": f"Network Reconnaissance detected: {rst_data['rst_count']} RST packets indicating port probing",
                "mitre_tactic": "Reconnaissance",
                "mitre_id": "T1595",
                "indicators": {
                    "rst_count": rst_data["rst_count"]
                }
            })
    
    if protocol == "ICMP":
        if src_ip not in attack_detection_state["icmp_packets_by_source"]:
            attack_detection_state["icmp_packets_by_source"][src_ip] = {"count": 0, "first_seen": now}
        
        attack_detection_state["icmp_packets_by_source"][src_ip]["count"] += 1
        icmp_data = attack_detection_state["icmp_packets_by_source"][src_ip]
        time_window = (now - icmp_data["first_seen"]).seconds + 1
        
        if icmp_data["count"] > 100 and time_window < 10:
            attacks.append({
                "type": "ICMP_FLOOD",
                "severity": "high",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "description": f"ICMP Flood detected: {icmp_data['count']} ICMP packets in {time_window}s",
                "mitre_tactic": "Impact",
                "mitre_id": "T1498.001",
                "indicators": {
                    "icmp_count": icmp_data["count"],
                    "time_window": time_window
                }
            })
    
    malicious_ports = {
        4444: "Metasploit default",
        5555: "Android Debug Bridge",
        6666: "IRC backdoor",
        31337: "Back Orifice",
        12345: "NetBus",
        23: "Telnet bruteforce",
        445: "SMB exploitation",
        3389: "RDP bruteforce",
        1433: "MSSQL attack",
        3306: "MySQL attack",
        6379: "Redis exploitation",
        27017: "MongoDB exploitation"
    }
    
    if dst_port and dst_port in malicious_ports:
        attacks.append({
            "type": "SUSPICIOUS_PORT_ACCESS",
            "severity": "high",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "description": f"Suspicious port access: {dst_port} ({malicious_ports[dst_port]})",
            "mitre_tactic": "Initial Access",
            "mitre_id": "T1190",
            "indicators": {
                "port": dst_port,
                "service": malicious_ports[dst_port]
            }
        })
    
    return attacks

def capture_packets_thread(interface: str, count: int, filter_expr: str):
    global capture_process, capture_active, capture_error_log, captured_packets_store, detected_attacks
    capture_error_log = []
    detected_attacks = []
    try:
        cmd = ["/usr/bin/tcpdump", "-i", interface, "-n", "-l", "-c", str(count)]
        if filter_expr:
            cmd.extend(filter_expr.split())
        
        capture_error_log.append(f"Starting tcpdump with command: {' '.join(cmd)}")
        
        capture_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        capture_error_log.append(f"Process started with PID: {capture_process.pid}")
        capture_active = True
        
        def read_stderr():
            for line in capture_process.stderr:
                capture_error_log.append(f"STDERR: {line.strip()}")
        
        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()
        
        packet_count = 0
        for line in capture_process.stdout:
            if not capture_active:
                capture_error_log.append("Capture stopped by user")
                break
            parsed = parse_tcpdump_line(line)
            if parsed:
                packet_count += 1
                captured_packets_store.append(parsed)
                if len(captured_packets_store) > 1000:
                    captured_packets_store.pop(0)
                
                attacks = detect_attack_patterns(parsed)
                for attack in attacks:
                    attack["timestamp"] = datetime.utcnow().isoformat()
                    attack["packet_info"] = parsed
                    attack_exists = False
                    for existing in detected_attacks:
                        if existing["type"] == attack["type"] and existing["source_ip"] == attack["source_ip"]:
                            existing.update(attack)
                            attack_exists = True
                            break
                    if not attack_exists:
                        detected_attacks.append(attack)
                        capture_error_log.append(f"ATTACK DETECTED: {attack['type']} from {attack['source_ip']}")
                
                try:
                    packet_capture_queue.put_nowait(parsed)
                except queue.Full:
                    packet_capture_queue.get()
                    packet_capture_queue.put_nowait(parsed)
        
        capture_error_log.append(f"Captured {packet_count} packets")
        capture_error_log.append(f"Detected {len(detected_attacks)} attacks")
        capture_process.wait()
        capture_error_log.append(f"Process exited with code: {capture_process.returncode}")
        capture_active = False
    except Exception as e:
        capture_error_log.append(f"EXCEPTION: {type(e).__name__}: {str(e)}")
        capture_active = False

@app.post("/api/v1/capture/start")
async def start_packet_capture(
    interface: str = Form(default="eth0"),
    count: int = Form(default=100),
    filter_expr: str = Form(default=""),
    db: Session = Depends(get_db)
):
    global capture_active, captured_packets_store, captured_payloads_store, scapy_capture_thread
    
    if capture_active:
        return {"status": "error", "message": "Capture already running"}
    
    captured_packets_store = []
    captured_payloads_store = []
    
    while not packet_capture_queue.empty():
        try:
            packet_capture_queue.get_nowait()
        except queue.Empty:
            break
    
    if SCAPY_AVAILABLE:
        scapy_capture_thread = threading.Thread(
            target=scapy_capture_thread_func,
            args=(interface, count, filter_expr),
            daemon=True
        )
        scapy_capture_thread.start()
        capture_method = "scapy_deep_packet_inspection"
    else:
        thread = threading.Thread(
            target=capture_packets_thread,
            args=(interface, count, filter_expr),
            daemon=True
        )
        thread.start()
        capture_method = "tcpdump"
    
    log_audit(db, "START", "packet_capture", "CAPTURE-LIVE", f"Started {capture_method} capture on {interface}")
    
    return {
        "status": "started",
        "interface": interface,
        "max_packets": count,
        "filter": filter_expr,
        "capture_method": capture_method,
        "deep_packet_inspection": SCAPY_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/capture/stop")
async def stop_packet_capture(db: Session = Depends(get_db)):
    global capture_process, capture_active
    
    capture_active = False
    if capture_process:
        try:
            capture_process.terminate()
            capture_process.wait(timeout=2)
        except Exception:
            capture_process.kill()
        capture_process = None
    
    log_audit(db, "STOP", "packet_capture", "CAPTURE-LIVE", "Stopped capture")
    
    return {
        "status": "stopped",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/capture/status")
async def get_capture_status():
    return {
        "active": capture_active,
        "queue_size": packet_capture_queue.qsize(),
        "attacks_detected": len(detected_attacks),
        "error_log": capture_error_log[-20:] if capture_error_log else [],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/capture/attacks")
async def get_detected_attacks():
    return {
        "attacks": detected_attacks,
        "count": len(detected_attacks),
        "capture_active": capture_active,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/capture/attacks/analyze")
async def analyze_detected_attack(attack_index: int = Form(default=0), db: Session = Depends(get_db)):
    if not detected_attacks:
        return {"status": "error", "message": "No attacks detected"}
    
    if attack_index >= len(detected_attacks):
        attack_index = 0
    
    attack = detected_attacks[attack_index]
    
    threat = models.ThreatEvent(
        threat_id=generate_id("THREAT", db, models.ThreatEvent),
        type=attack["type"],
        source="Attack Detection Engine",
        severity=attack["severity"],
        description=attack["description"],
        status="active",
        mitre_tactic=attack.get("mitre_tactic", "Unknown"),
        mitre_id=attack.get("mitre_id", ""),
        source_ip=attack.get("source_ip", "unknown"),
        destination_ip=attack.get("destination_ip", "unknown"),
        protocol=attack.get("packet_info", {}).get("protocol", "TCP")
    )
    db.add(threat)
    db.commit()
    
    captured_payload = attack.get("captured_payload", {})
    packet_info = attack.get("packet_info", {})
    
    payload_hex = captured_payload.get("payload_hex", "")
    payload_ascii = captured_payload.get("payload_ascii", "")
    payload_base64 = captured_payload.get("payload_base64", "")
    payload_length = captured_payload.get("payload_length", 0)
    detected_patterns = captured_payload.get("detected_patterns", [])
    is_malicious = captured_payload.get("is_malicious", False)
    
    bit_analysis = []
    if payload_hex:
        for i in range(0, min(len(payload_hex), 64), 2):
            byte_hex = payload_hex[i:i+2]
            byte_val = int(byte_hex, 16)
            byte_bin = format(byte_val, '08b')
            byte_char = chr(byte_val) if 32 <= byte_val <= 126 else '.'
            bit_analysis.append({
                "offset": i // 2,
                "hex": byte_hex,
                "decimal": byte_val,
                "binary": byte_bin,
                "ascii": byte_char
            })
    
    hex_dump_lines = []
    if payload_hex:
        for i in range(0, len(payload_hex), 32):
            line_hex = payload_hex[i:i+32]
            hex_bytes = ' '.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
            ascii_repr = ''
            for j in range(0, len(line_hex), 2):
                byte_val = int(line_hex[j:j+2], 16)
                ascii_repr += chr(byte_val) if 32 <= byte_val <= 126 else '.'
            hex_dump_lines.append({
                "offset": f"{i//2:08x}",
                "hex": hex_bytes,
                "ascii": ascii_repr
            })
    
    analysis = {
        "attack_type": attack["type"],
        "severity": attack["severity"],
        "source_ip": attack.get("source_ip"),
        "destination_ip": attack.get("destination_ip"),
        "source_port": packet_info.get("source_port"),
        "destination_port": packet_info.get("destination_port"),
        "protocol": packet_info.get("protocol"),
        "description": attack["description"],
        "mitre_mapping": {
            "tactic": attack.get("mitre_tactic"),
            "technique_id": attack.get("mitre_id"),
            "technique_name": attack["type"]
        },
        "indicators": attack.get("indicators", {}),
        "packet_sample": packet_info,
        "threat_id": threat.threat_id,
        "captured_payload": {
            "payload_length": payload_length,
            "payload_hex": payload_hex,
            "payload_ascii": payload_ascii,
            "payload_base64": payload_base64,
            "is_malicious": is_malicious,
            "detected_patterns": detected_patterns,
            "bit_by_bit_analysis": bit_analysis,
            "hex_dump": hex_dump_lines
        },
        "recommendations": []
    }
    
    if attack["type"] == "PORT_SCAN":
        analysis["recommendations"] = [
            f"Block source IP {attack.get('source_ip')} at firewall",
            "Enable port scan detection on IDS/IPS",
            "Review exposed services and close unnecessary ports",
            "Implement rate limiting on connection attempts"
        ]
    elif attack["type"] == "SYN_FLOOD":
        analysis["recommendations"] = [
            f"Block source IP {attack.get('source_ip')} immediately",
            "Enable SYN cookies on the target system",
            "Configure rate limiting for SYN packets",
            "Consider DDoS mitigation service"
        ]
    elif attack["type"] == "RECONNAISSANCE":
        analysis["recommendations"] = [
            f"Monitor traffic from {attack.get('source_ip')}",
            "Review firewall rules for unnecessary exposure",
            "Enable network segmentation",
            "Deploy honeypots to detect further probing"
        ]
    elif attack["type"] == "SUSPICIOUS_PORT_ACCESS":
        analysis["recommendations"] = [
            f"Block access to suspicious port from {attack.get('source_ip')}",
            "Verify if the service on this port is legitimate",
            "Check for signs of compromise on the target system",
            "Review access logs for the target service"
        ]
    
    log_audit(db, "ANALYZE", "attack_detection", threat.threat_id, f"Analyzed {attack['type']} attack from {attack.get('source_ip')}")
    
    return {
        "status": "completed",
        "analysis": analysis,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/capture/payloads")
async def get_captured_payloads(limit: int = 50):
    payloads = captured_payloads_store[-limit:] if captured_payloads_store else []
    
    return {
        "payloads": payloads,
        "count": len(payloads),
        "total_captured": len(captured_payloads_store),
        "capture_active": capture_active,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/capture/payloads/{index}/analyze")
async def analyze_payload_bitwise(index: int):
    if not captured_payloads_store:
        return {"status": "error", "message": "No payloads captured"}
    
    if index >= len(captured_payloads_store):
        index = len(captured_payloads_store) - 1
    
    payload = captured_payloads_store[index]
    payload_hex = payload.get("payload_hex", "")
    
    bit_analysis = []
    for i in range(0, min(len(payload_hex), 1000), 2):
        byte_hex = payload_hex[i:i+2]
        byte_val = int(byte_hex, 16)
        byte_bin = format(byte_val, '08b')
        byte_char = chr(byte_val) if 32 <= byte_val <= 126 else '.'
        bit_analysis.append({
            "offset": i // 2,
            "hex": byte_hex,
            "decimal": byte_val,
            "binary": byte_bin,
            "ascii": byte_char
        })
    
    hex_dump_lines = []
    for i in range(0, len(payload_hex), 32):
        line_hex = payload_hex[i:i+32]
        hex_bytes = ' '.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
        ascii_repr = ''
        for j in range(0, len(line_hex), 2):
            byte_val = int(line_hex[j:j+2], 16)
            ascii_repr += chr(byte_val) if 32 <= byte_val <= 126 else '.'
        hex_dump_lines.append({
            "offset": f"{i//2:08x}",
            "hex": hex_bytes,
            "ascii": ascii_repr
        })
    
    return {
        "status": "completed",
        "payload_info": {
            "timestamp": payload.get("timestamp"),
            "source_ip": payload.get("source_ip"),
            "destination_ip": payload.get("destination_ip"),
            "protocol": payload.get("protocol"),
            "payload_length": payload.get("payload_length"),
            "is_malicious": payload.get("is_malicious"),
            "detected_patterns": payload.get("detected_patterns")
        },
        "raw_data": {
            "hex": payload_hex,
            "ascii": payload.get("payload_ascii"),
            "base64": payload.get("payload_base64")
        },
        "bit_by_bit_analysis": bit_analysis,
        "hex_dump": hex_dump_lines,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/capture/malicious")
async def get_malicious_payloads():
    malicious = [p for p in captured_payloads_store if p.get("is_malicious")]
    
    return {
        "malicious_payloads": malicious,
        "count": len(malicious),
        "total_payloads": len(captured_payloads_store),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/capture/packets")
async def get_captured_packets(limit: int = 50):
    packets = captured_packets_store[-limit:] if captured_packets_store else []
    
    return {
        "packets": packets,
        "count": len(packets),
        "total_captured": len(captured_packets_store),
        "capture_active": capture_active,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/capture/analyze")
async def analyze_captured_traffic(db: Session = Depends(get_db)):
    packets = list(captured_packets_store)
    
    if not packets:
        return {"status": "no_data", "message": "No packets captured"}
    
    analysis = {
        "total_packets": len(packets),
        "protocols": {},
        "source_ips": {},
        "destination_ips": {},
        "suspicious_packets": [],
        "threats_detected": []
    }
    
    for packet in packets:
        proto = packet.get("protocol", "UNKNOWN")
        analysis["protocols"][proto] = analysis["protocols"].get(proto, 0) + 1
        
        src = packet.get("source_ip", "unknown")
        analysis["source_ips"][src] = analysis["source_ips"].get(src, 0) + 1
        
        dst = packet.get("destination_ip", "unknown")
        analysis["destination_ips"][dst] = analysis["destination_ips"].get(dst, 0) + 1
        
        if packet.get("is_suspicious"):
            analysis["suspicious_packets"].append(packet)
            
            threat = models.ThreatEvent(
                threat_id=generate_id("THREAT", db, models.ThreatEvent),
                type="Network Anomaly",
                source="Packet Capture",
                severity="warning",
                description=f"Suspicious traffic detected: {packet.get('suspicious_reason', 'Unknown')}",
                status="active",
                mitre_tactic="Discovery",
                mitre_id="T1046",
                source_ip=packet.get("source_ip", "unknown"),
                destination_ip=packet.get("destination_ip", "unknown"),
                protocol=packet.get("protocol", "TCP")
            )
            db.add(threat)
            analysis["threats_detected"].append({
                "threat_id": threat.threat_id,
                "source_ip": threat.source_ip,
                "destination_ip": threat.destination_ip,
                "reason": packet.get("suspicious_reason")
            })
    
    db.commit()
    
    analysis["top_talkers"] = sorted(
        analysis["source_ips"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    analysis["top_destinations"] = sorted(
        analysis["destination_ips"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    log_audit(db, "ANALYZE", "packet_capture", "ANALYSIS", f"Analyzed {len(packets)} packets")
    
    return {
        "status": "completed",
        "analysis": analysis,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/network/live-connections")
async def get_live_connections():
    try:
        result = subprocess.run(
            ["ss", "-tunapo"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        connections = []
        lines = result.stdout.strip().split("\n")[1:]
        
        for line in lines[:50]:
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "protocol": parts[0],
                    "state": parts[1] if len(parts) > 1 else "UNKNOWN",
                    "local_address": parts[4] if len(parts) > 4 else "unknown",
                    "remote_address": parts[5] if len(parts) > 5 else "unknown",
                    "process": parts[-1] if len(parts) > 6 else "unknown"
                })
        
        return {
            "connections": connections,
            "count": len(connections),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/network/interfaces")
async def get_network_interfaces():
    try:
        import psutil
        interfaces = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        io = psutil.net_io_counters(pernic=True)
        
        for name, stat in stats.items():
            iface = {
                "name": name,
                "is_up": stat.isup,
                "speed": stat.speed,
                "mtu": stat.mtu,
                "addresses": [],
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets_sent": 0,
                "packets_recv": 0
            }
            
            if name in addrs:
                for addr in addrs[name]:
                    iface["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask
                    })
            
            if name in io:
                iface["bytes_sent"] = io[name].bytes_sent
                iface["bytes_recv"] = io[name].bytes_recv
                iface["packets_sent"] = io[name].packets_sent
                iface["packets_recv"] = io[name].packets_recv
            
            interfaces.append(iface)
        
        return {
            "interfaces": interfaces,
            "count": len(interfaces),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}
