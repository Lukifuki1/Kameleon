"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - TIER 5 API ROUTER
Enterprise-grade API endpoints for Tier 5 Security Operations Center

This module provides API endpoints for:
- Local Threat Intelligence (100% opensource, no external APIs)
- SOAR Engine (Security Orchestration, Automation and Response)
- Threat Hunting (Advanced hypothesis-driven hunting)
- Compliance Engine (NIST 800-53, ISO 27001, SOC 2)
- Distributed Tasks (Celery/Redis task queue)
- Real-time Streaming (WebSocket)
- High Availability Infrastructure
- Multi-tenancy with RBAC

Classification: TOP SECRET // NSOC // TIER-0
"""

from fastapi import APIRouter, HTTPException, Depends, Query, WebSocket, BackgroundTasks
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/tier5", tags=["Tier 5 Operations"])


class IOCAnalysisRequest(BaseModel):
    indicator: str
    indicator_type: Optional[str] = None


class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    variables: Dict[str, Any] = Field(default_factory=dict)


class AlertRequest(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    source: str
    indicators: List[str] = Field(default_factory=list)


class HuntCampaignRequest(BaseModel):
    name: str
    description: str
    hypotheses: List[Dict[str, Any]]
    priority: str = "medium"


class ComplianceAssessmentRequest(BaseModel):
    framework: str
    scope: Optional[List[str]] = None


class TenantCreateRequest(BaseModel):
    name: str
    display_name: str
    settings: Dict[str, Any] = Field(default_factory=dict)


class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    roles: List[str] = Field(default_factory=list)


class RoleCreateRequest(BaseModel):
    name: str
    permissions: List[str]
    description: str = ""


class TaskSubmitRequest(BaseModel):
    task_name: str
    args: List[Any] = Field(default_factory=list)
    kwargs: Dict[str, Any] = Field(default_factory=dict)
    priority: str = "medium"


@router.get("/status")
async def get_tier5_status():
    """Get Tier 5 system status"""
    from app.local_threat_intel import get_local_threat_intel
    from app.soar_engine import get_soar_engine
    from app.threat_hunting import get_threat_hunting_engine
    from app.compliance_engine import get_compliance_engine
    from app.ha_infrastructure import get_ha_infrastructure
    from app.multi_tenant import get_multi_tenant_engine
    
    threat_intel = get_local_threat_intel()
    soar = get_soar_engine()
    hunting = get_threat_hunting_engine()
    compliance = get_compliance_engine()
    ha = get_ha_infrastructure()
    tenants = get_multi_tenant_engine()
    
    return {
        "status": "OPERATIONAL",
        "classification": "TOP SECRET // NSOC // TIER-5",
        "components": {
            "threat_intelligence": {
                "status": "active",
                "ioc_count": threat_intel.database.get_statistics().get("total_iocs", 0),
                "feeds_configured": len(threat_intel.ingester.FREE_FEEDS)
            },
            "soar": {
                "status": "active",
                "playbooks": len(soar.get_playbooks()),
                "active_cases": 0
            },
            "threat_hunting": {
                "status": "active",
                "active_campaigns": 0
            },
            "compliance": {
                "status": "active",
                "frameworks": ["NIST_800_53", "ISO_27001", "SOC_2", "CIS", "GDPR", "PCI_DSS", "HIPAA"]
            },
            "high_availability": ha.get_health_status(),
            "multi_tenancy": {
                "status": "active"
            }
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/threat-intel/feeds")
async def get_threat_feeds():
    """Get configured threat intelligence feeds"""
    from app.local_threat_intel import get_local_threat_intel
    threat_intel = get_local_threat_intel()
    
    return {
        "feeds": [
            {
                "name": config.name,
                "url": config.url,
                "feed_type": config.feed_type,
                "update_interval": config.update_interval,
                "enabled": config.enabled
            }
            for config in threat_intel.feed_configs
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/threat-intel/feeds/update")
async def update_threat_feeds(background_tasks: BackgroundTasks):
    """Trigger threat feed update"""
    from app.local_threat_intel import get_local_threat_intel
    threat_intel = get_local_threat_intel()
    
    def update_feeds():
        threat_intel.update_feeds()
    
    background_tasks.add_task(update_feeds)
    
    return {
        "status": "update_started",
        "message": "Threat feed update initiated in background",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/threat-intel/analyze")
async def analyze_ioc(request: IOCAnalysisRequest):
    """Analyze indicator of compromise"""
    from app.local_threat_intel import get_local_threat_intel
    threat_intel = get_local_threat_intel()
    
    if request.indicator_type == "ip":
        report = threat_intel.analyze_ip(request.indicator)
    elif request.indicator_type == "domain":
        report = threat_intel.analyze_domain(request.indicator)
    elif request.indicator_type == "url":
        report = threat_intel.analyze_url(request.indicator)
    elif request.indicator_type == "hash":
        report = threat_intel.analyze_hash(request.indicator)
    else:
        report = threat_intel.analyze_text(request.indicator)
    
    return {
        "report_id": report.report_id,
        "indicator": report.indicator,
        "indicator_type": report.indicator_type.value,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level.value,
        "matches": [
            {
                "ioc_id": m.ioc_id,
                "ioc_type": m.ioc_type.value,
                "threat_category": m.threat_category.value,
                "severity": m.severity.value,
                "confidence": m.confidence,
                "source": m.source
            }
            for m in report.matches
        ],
        "mitre_techniques": report.mitre_techniques,
        "recommendations": report.recommendations,
        "timestamp": report.timestamp.isoformat()
    }


@router.get("/threat-intel/iocs")
async def get_iocs(
    ioc_type: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = Query(default=100, le=1000)
):
    """Get stored IOCs"""
    from app.local_threat_intel import get_local_threat_intel, IOCType, ThreatCategory
    threat_intel = get_local_threat_intel()
    
    ioc_type_enum = None
    if ioc_type:
        try:
            ioc_type_enum = IOCType(ioc_type)
        except ValueError:
            pass
    
    category_enum = None
    if category:
        try:
            category_enum = ThreatCategory(category)
        except ValueError:
            pass
    
    iocs = threat_intel.database.search_iocs(
        query=None,
        ioc_type=ioc_type_enum,
        category=category_enum,
        severity=None,
        limit=limit
    )
    
    return {
        "count": len(iocs),
        "iocs": [
            {
                "ioc_id": ioc.ioc_id,
                "ioc_type": ioc.ioc_type.value,
                "value": ioc.value,
                "category": ioc.category.value,
                "severity": ioc.severity.value,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "first_seen": ioc.first_seen.isoformat(),
                "last_seen": ioc.last_seen.isoformat()
            }
            for ioc in iocs
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/soar/playbooks")
async def get_playbooks():
    """Get all SOAR playbooks"""
    from app.soar_engine import get_soar_engine
    soar = get_soar_engine()
    
    playbooks = soar.get_playbooks()
    
    return {
        "count": len(playbooks),
        "playbooks": [
            {
                "playbook_id": p.playbook_id,
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "trigger_conditions": p.trigger_conditions,
                "status": p.status.value,
                "actions_count": len(p.actions),
                "tags": p.tags,
                "created_at": p.created_at.isoformat(),
                "updated_at": p.updated_at.isoformat()
            }
            for p in playbooks
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/soar/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str):
    """Get specific playbook"""
    from app.soar_engine import get_soar_engine
    soar = get_soar_engine()
    
    playbook = soar.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    return {
        "playbook_id": playbook.playbook_id,
        "name": playbook.name,
        "description": playbook.description,
        "trigger_type": playbook.trigger_type,
        "trigger_conditions": playbook.trigger_conditions,
        "status": playbook.status.value,
        "actions": [
            {
                "action_id": a.action_id,
                "action_type": a.action_type.value,
                "name": a.name,
                "parameters": a.parameters,
                "condition": a.condition,
                "on_success": a.on_success,
                "on_failure": a.on_failure
            }
            for a in playbook.actions
        ],
        "created_at": playbook.created_at.isoformat(),
        "updated_at": playbook.updated_at.isoformat()
    }


@router.post("/soar/playbooks/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, request: PlaybookExecuteRequest):
    """Execute playbook manually"""
    from app.soar_engine import get_soar_engine
    soar = get_soar_engine()
    
    execution_id = soar.execute_playbook_manual(playbook_id, request.variables)
    
    return {
        "execution_id": execution_id,
        "playbook_id": playbook_id,
        "status": "started",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/soar/executions")
async def get_executions(limit: int = Query(default=50, le=200)):
    """Get playbook executions"""
    from app.soar_engine import get_soar_engine
    soar = get_soar_engine()
    
    executions = soar.list_executions(limit)
    
    return {
        "count": len(executions),
        "executions": [
            {
                "execution_id": e.execution_id,
                "playbook_id": e.playbook_id,
                "status": e.status.value,
                "started_at": e.started_at.isoformat(),
                "completed_at": e.completed_at.isoformat() if e.completed_at else None,
                "actions_completed": len([r for r in e.action_results if r.success]),
                "actions_failed": len([r for r in e.action_results if not r.success])
            }
            for e in executions
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/soar/alerts")
async def process_alert(request: AlertRequest):
    """Process security alert through SOAR"""
    from app.soar_engine import get_soar_engine, Alert, CaseSeverity
    import hashlib
    
    soar = get_soar_engine()
    
    alert = Alert(
        alert_id=f"ALERT-{hashlib.sha256(f'{request.title}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:8].upper()}",
        title=request.title,
        description=request.description,
        severity=CaseSeverity(request.severity),
        source=request.source,
        timestamp=datetime.utcnow(),
        indicators=request.indicators,
        raw_data=request.dict(),
        is_processed=False,
        case_id=None,
        playbook_executions=[]
    )
    
    result = soar.process_alert(alert)
    
    return {
        "alert_id": alert.alert_id,
        "is_new": result["is_new"],
        "case_id": result["case_id"],
        "playbook_executions": result["playbook_executions"],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/soar/cases")
async def get_cases(status: Optional[str] = None, limit: int = Query(default=50, le=200)):
    """Get SOAR cases"""
    from app.soar_engine import get_soar_engine, CaseStatus
    soar = get_soar_engine()
    
    status_enum = CaseStatus(status) if status else None
    cases = soar.list_cases(status_enum, limit)
    
    return {
        "count": len(cases),
        "cases": [
            {
                "case_id": c.case_id,
                "title": c.title,
                "description": c.description,
                "severity": c.severity.value,
                "status": c.status.value,
                "assignee": c.assignee,
                "alert_count": len(c.alerts),
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat()
            }
            for c in cases
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/hunting/campaigns")
async def get_hunt_campaigns(status: Optional[str] = None):
    """Get threat hunting campaigns"""
    from app.threat_hunting import get_threat_hunting_engine, HuntStatus
    hunting = get_threat_hunting_engine()
    
    status_enum = HuntStatus(status) if status else None
    campaigns = hunting.list_campaigns(status_enum)
    
    return {
        "count": len(campaigns),
        "campaigns": [
            {
                "campaign_id": c.campaign_id,
                "name": c.name,
                "description": c.description,
                "status": c.status.value,
                "priority": c.priority.value,
                "hypothesis_count": len(c.hypotheses),
                "finding_count": len(c.findings),
                "created_at": c.created_at.isoformat()
            }
            for c in campaigns
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/hunting/campaigns")
async def create_hunt_campaign(request: HuntCampaignRequest):
    """Create new threat hunting campaign"""
    from app.threat_hunting import get_threat_hunting_engine, HuntHypothesis, HuntPriority
    hunting = get_threat_hunting_engine()
    
    hypotheses = []
    for h in request.hypotheses:
        hypotheses.append(HuntHypothesis(
            hypothesis_id=h.get("hypothesis_id", ""),
            description=h.get("description", ""),
            mitre_techniques=h.get("mitre_techniques", []),
            data_sources=h.get("data_sources", []),
            queries=[]
        ))
    
    campaign = hunting.create_campaign(
        name=request.name,
        description=request.description,
        hypotheses=hypotheses,
        priority=HuntPriority(request.priority)
    )
    
    return {
        "campaign_id": campaign.campaign_id,
        "name": campaign.name,
        "status": campaign.status.value,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/hunting/techniques/{technique_id}")
async def hunt_technique(technique_id: str):
    """Hunt for specific MITRE ATT&CK technique"""
    from app.threat_hunting import get_threat_hunting_engine
    hunting = get_threat_hunting_engine()
    
    results = hunting.hunt_for_technique(technique_id)
    
    return {
        "technique_id": technique_id,
        "hits": len(results),
        "results": results[:100],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/hunting/anomalies")
async def get_anomalies(limit: int = Query(default=50, le=200)):
    """Get detected anomalies"""
    from app.threat_hunting import get_threat_hunting_engine
    hunting = get_threat_hunting_engine()
    
    anomalies = hunting.get_anomalies(limit)
    
    return {
        "count": len(anomalies),
        "anomalies": [
            {
                "anomaly_id": a.anomaly_id,
                "entity_type": a.entity_type,
                "entity_id": a.entity_id,
                "metric_name": a.metric_name,
                "observed_value": a.observed_value,
                "expected_min": a.expected_range[0],
                "expected_max": a.expected_range[1],
                "deviation_score": a.deviation_score,
                "detected_at": a.detected_at.isoformat(),
                "context": a.context
            }
            for a in anomalies
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/compliance/frameworks")
async def get_compliance_frameworks():
    """Get available compliance frameworks"""
    from app.compliance_engine import get_compliance_engine, ComplianceFramework
    compliance = get_compliance_engine()
    
    return {
        "frameworks": [
            {
                "id": fw.value,
                "name": fw.name,
                "controls_count": len(compliance.get_controls_by_framework(fw))
            }
            for fw in ComplianceFramework
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/compliance/controls")
async def get_compliance_controls(framework: str):
    """Get compliance controls for framework"""
    from app.compliance_engine import get_compliance_engine, ComplianceFramework
    compliance = get_compliance_engine()
    
    fw = ComplianceFramework(framework)
    controls = compliance.get_controls_by_framework(fw)
    
    return {
        "framework": framework,
        "count": len(controls),
        "controls": [
            {
                "control_id": c.control_id,
                "framework": c.framework.value,
                "name": c.name,
                "description": c.description,
                "category": c.category,
                "priority": c.priority.value,
                "automated_check": c.automated_check
            }
            for c in controls
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/compliance/assess")
async def run_compliance_assessment(request: ComplianceAssessmentRequest):
    """Run compliance assessment"""
    from app.compliance_engine import get_compliance_engine, ComplianceFramework
    compliance = get_compliance_engine()
    
    fw = ComplianceFramework(request.framework)
    report = compliance.generate_report(fw)
    
    return {
        "report_id": report.report_id,
        "framework": report.framework.value,
        "overall_score": report.overall_score,
        "compliant_controls": report.compliant_controls,
        "non_compliant_controls": report.non_compliant_controls,
        "not_assessed_controls": report.not_assessed_controls,
        "critical_findings": report.critical_findings,
        "generated_at": report.generated_at.isoformat()
    }


@router.get("/compliance/summary")
async def get_compliance_summary():
    """Get compliance summary across all frameworks"""
    from app.compliance_engine import get_compliance_engine
    compliance = get_compliance_engine()
    
    summary = compliance.get_compliance_summary()
    
    return {
        "summary": summary,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/tasks/status")
async def get_task_queue_status():
    """Get distributed task queue status"""
    from app.distributed_tasks import get_task_manager
    task_manager = get_task_manager()
    
    return {
        "queue_stats": task_manager.get_queue_stats(),
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/tasks/submit")
async def submit_task(request: TaskSubmitRequest):
    """Submit task to distributed queue"""
    from app.distributed_tasks import get_task_manager, TaskPriority
    task_manager = get_task_manager()
    
    task_id = task_manager.submit_task(
        task_name=request.task_name,
        args=request.args,
        kwargs=request.kwargs,
        priority=TaskPriority(request.priority)
    )
    
    return {
        "task_id": task_id,
        "status": "submitted",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Get task status"""
    from app.distributed_tasks import get_task_manager
    task_manager = get_task_manager()
    
    status = task_manager.get_task_status(task_id)
    if not status:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return status


@router.get("/ha/health")
async def get_ha_health():
    """Get high availability health status"""
    from app.ha_infrastructure import get_ha_infrastructure
    ha = get_ha_infrastructure()
    
    return ha.get_health_status()


@router.get("/ha/services")
async def get_registered_services():
    """Get registered services"""
    from app.ha_infrastructure import get_ha_infrastructure
    ha = get_ha_infrastructure()
    
    return {
        "node_id": ha.leader_election._leader_id,
        "role": ha.leader_election.get_role().value,
        "is_leader": ha.is_leader(),
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/tenants")
async def get_tenants():
    """Get all tenants"""
    from app.multi_tenant import get_multi_tenant_engine, DEFAULT_TENANT_ID
    engine = get_multi_tenant_engine()
    
    default_tenant = engine.get_tenant(DEFAULT_TENANT_ID)
    
    return {
        "tenants": [
            {
                "tenant_id": default_tenant.tenant_id,
                "name": default_tenant.name,
                "display_name": default_tenant.display_name,
                "status": default_tenant.status.value,
                "created_at": default_tenant.created_at.isoformat()
            }
        ] if default_tenant else [],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/tenants")
async def create_tenant(request: TenantCreateRequest):
    """Create new tenant"""
    from app.multi_tenant import get_multi_tenant_engine
    engine = get_multi_tenant_engine()
    
    tenant = engine.create_tenant(
        name=request.name,
        display_name=request.display_name,
        settings=request.settings
    )
    
    return {
        "tenant_id": tenant.tenant_id,
        "name": tenant.name,
        "display_name": tenant.display_name,
        "status": tenant.status.value,
        "created_at": tenant.created_at.isoformat()
    }


@router.get("/tenants/{tenant_id}")
async def get_tenant(tenant_id: str):
    """Get tenant details"""
    from app.multi_tenant import get_multi_tenant_engine
    engine = get_multi_tenant_engine()
    
    tenant = engine.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    stats = engine.get_tenant_stats(tenant_id)
    
    return {
        "tenant_id": tenant.tenant_id,
        "name": tenant.name,
        "display_name": tenant.display_name,
        "status": tenant.status.value,
        "settings": tenant.settings,
        "quotas": tenant.quotas,
        "stats": stats,
        "created_at": tenant.created_at.isoformat(),
        "updated_at": tenant.updated_at.isoformat()
    }


@router.post("/tenants/{tenant_id}/users")
async def create_user(tenant_id: str, request: UserCreateRequest):
    """Create user in tenant"""
    from app.multi_tenant import get_multi_tenant_engine
    engine = get_multi_tenant_engine()
    
    user = engine.create_user(
        tenant_id=tenant_id,
        username=request.username,
        email=request.email,
        password=request.password,
        roles=request.roles
    )
    
    return {
        "user_id": user.user_id,
        "username": user.username,
        "email": user.email,
        "status": user.status.value,
        "roles": user.roles,
        "created_at": user.created_at.isoformat()
    }


@router.get("/tenants/{tenant_id}/users")
async def get_tenant_users(tenant_id: str):
    """Get users in tenant"""
    from app.multi_tenant import get_multi_tenant_engine
    engine = get_multi_tenant_engine()
    
    users = engine.database.get_users_by_tenant(tenant_id)
    
    return {
        "count": len(users),
        "users": [
            {
                "user_id": u.user_id,
                "username": u.username,
                "email": u.email,
                "status": u.status.value,
                "roles": u.roles,
                "last_login": u.last_login.isoformat() if u.last_login else None,
                "created_at": u.created_at.isoformat()
            }
            for u in users
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/tenants/{tenant_id}/roles")
async def get_tenant_roles(tenant_id: str):
    """Get roles in tenant"""
    from app.multi_tenant import get_multi_tenant_engine
    engine = get_multi_tenant_engine()
    
    roles = engine.database.get_roles_by_tenant(tenant_id)
    
    return {
        "count": len(roles),
        "roles": [
            {
                "role_id": r.role_id,
                "name": r.name,
                "role_type": r.role_type.value,
                "permissions": [p.value for p in r.permissions],
                "is_system": r.is_system,
                "created_at": r.created_at.isoformat()
            }
            for r in roles
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/tenants/{tenant_id}/roles")
async def create_role(tenant_id: str, request: RoleCreateRequest):
    """Create custom role in tenant"""
    from app.multi_tenant import get_multi_tenant_engine, Permission
    engine = get_multi_tenant_engine()
    
    permissions = [Permission(p) for p in request.permissions]
    
    role = engine.create_role(
        tenant_id=tenant_id,
        name=request.name,
        permissions=permissions,
        description=request.description
    )
    
    return {
        "role_id": role.role_id,
        "name": role.name,
        "permissions": [p.value for p in role.permissions],
        "created_at": role.created_at.isoformat()
    }


@router.get("/tenants/{tenant_id}/audit")
async def get_tenant_audit_logs(
    tenant_id: str,
    limit: int = Query(default=100, le=500)
):
    """Get audit logs for tenant"""
    from app.multi_tenant import get_multi_tenant_engine
    engine = get_multi_tenant_engine()
    
    logs = engine.get_audit_logs(tenant_id, limit)
    
    return {
        "count": len(logs),
        "logs": [
            {
                "log_id": l.log_id,
                "action": l.action,
                "resource_type": l.resource_type,
                "resource_id": l.resource_id,
                "user_id": l.user_id,
                "success": l.success,
                "timestamp": l.timestamp.isoformat()
            }
            for l in logs
        ],
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/streaming/stats")
async def get_streaming_stats():
    """Get real-time streaming statistics"""
    from app.realtime_streaming import get_streaming_engine
    engine = get_streaming_engine()
    
    return engine.get_stats()


@router.get("/streaming/events")
async def get_recent_events(
    count: int = Query(default=100, le=500),
    channel: Optional[str] = None
):
    """Get recent streaming events"""
    from app.realtime_streaming import get_streaming_engine
    engine = get_streaming_engine()
    
    events = engine.get_recent_events(count, channel)
    
    return {
        "count": len(events),
        "events": events,
        "timestamp": datetime.utcnow().isoformat()
    }
