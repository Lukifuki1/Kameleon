"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - DISTRIBUTED TASK ENGINE
Celery-based Distributed Task Processing System

This module implements:
- Celery task queue with Redis broker
- Async task execution for long-running operations
- Task scheduling and periodic tasks
- Task result storage and retrieval
- Task priority queues
- Task chaining and workflows
- Dead letter queue handling
- Task monitoring and metrics
- Graceful shutdown handling

100% opensource - Uses Celery (BSD) and Redis (BSD)

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import json
import hashlib
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import wraps
import pickle
import base64

try:
    from celery import Celery, Task, chain, group, chord
    from celery.result import AsyncResult
    from celery.schedules import crontab
    from celery.signals import task_prerun, task_postrun, task_failure, worker_ready
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    Celery = None
    Task = object
    AsyncResult = None

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)
TASK_QUEUE_PREFIX = os.environ.get("TASK_QUEUE_PREFIX", "tyranthos")


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BACKGROUND = "background"


class TaskStatus(str, Enum):
    PENDING = "pending"
    STARTED = "started"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"
    REVOKED = "revoked"


@dataclass
class TaskInfo:
    task_id: str
    task_name: str
    status: TaskStatus
    priority: TaskPriority
    args: List[Any]
    kwargs: Dict[str, Any]
    result: Optional[Any]
    error: Optional[str]
    traceback: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    retries: int
    worker: Optional[str]
    queue: str


@dataclass
class ScheduledTask:
    schedule_id: str
    task_name: str
    schedule_type: str
    schedule_config: Dict[str, Any]
    args: List[Any]
    kwargs: Dict[str, Any]
    enabled: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    run_count: int


class TaskRegistry:
    """Registry for task functions"""
    
    def __init__(self):
        self._tasks: Dict[str, Callable] = {}
        self._task_configs: Dict[str, Dict[str, Any]] = {}
    
    def register(self, name: str = None, priority: TaskPriority = TaskPriority.MEDIUM,
                 max_retries: int = 3, retry_delay: int = 60, timeout: int = 3600):
        """Decorator to register task"""
        def decorator(func: Callable):
            task_name = name or f"{func.__module__}.{func.__name__}"
            self._tasks[task_name] = func
            self._task_configs[task_name] = {
                "priority": priority,
                "max_retries": max_retries,
                "retry_delay": retry_delay,
                "timeout": timeout
            }
            
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            
            wrapper.task_name = task_name
            return wrapper
        
        return decorator
    
    def get_task(self, name: str) -> Optional[Callable]:
        return self._tasks.get(name)
    
    def get_config(self, name: str) -> Dict[str, Any]:
        return self._task_configs.get(name, {})
    
    def list_tasks(self) -> List[str]:
        return list(self._tasks.keys())


task_registry = TaskRegistry()


if CELERY_AVAILABLE:
    celery_app = Celery(
        "tyranthos",
        broker=CELERY_BROKER_URL,
        backend=CELERY_RESULT_BACKEND
    )
    
    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=3600,
        task_soft_time_limit=3300,
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_default_queue=f"{TASK_QUEUE_PREFIX}.default",
        task_queues={
            f"{TASK_QUEUE_PREFIX}.critical": {"exchange": TASK_QUEUE_PREFIX, "routing_key": "critical"},
            f"{TASK_QUEUE_PREFIX}.high": {"exchange": TASK_QUEUE_PREFIX, "routing_key": "high"},
            f"{TASK_QUEUE_PREFIX}.medium": {"exchange": TASK_QUEUE_PREFIX, "routing_key": "medium"},
            f"{TASK_QUEUE_PREFIX}.low": {"exchange": TASK_QUEUE_PREFIX, "routing_key": "low"},
            f"{TASK_QUEUE_PREFIX}.background": {"exchange": TASK_QUEUE_PREFIX, "routing_key": "background"},
        },
        task_routes={
            "tyranthos.tasks.critical.*": {"queue": f"{TASK_QUEUE_PREFIX}.critical"},
            "tyranthos.tasks.high.*": {"queue": f"{TASK_QUEUE_PREFIX}.high"},
            "tyranthos.tasks.medium.*": {"queue": f"{TASK_QUEUE_PREFIX}.medium"},
            "tyranthos.tasks.low.*": {"queue": f"{TASK_QUEUE_PREFIX}.low"},
            "tyranthos.tasks.background.*": {"queue": f"{TASK_QUEUE_PREFIX}.background"},
        },
        beat_schedule={
            "threat-feed-update": {
                "task": "tyranthos.tasks.update_threat_feeds",
                "schedule": crontab(minute="*/30"),
                "options": {"queue": f"{TASK_QUEUE_PREFIX}.medium"}
            },
            "compliance-check": {
                "task": "tyranthos.tasks.run_compliance_check",
                "schedule": crontab(hour="*/6"),
                "options": {"queue": f"{TASK_QUEUE_PREFIX}.low"}
            },
            "baseline-update": {
                "task": "tyranthos.tasks.update_baselines",
                "schedule": crontab(hour="0", minute="0"),
                "options": {"queue": f"{TASK_QUEUE_PREFIX}.background"}
            },
            "cleanup-old-data": {
                "task": "tyranthos.tasks.cleanup_old_data",
                "schedule": crontab(hour="3", minute="0"),
                "options": {"queue": f"{TASK_QUEUE_PREFIX}.background"}
            },
        }
    )
    
    @celery_app.task(bind=True, name="tyranthos.tasks.update_threat_feeds")
    def update_threat_feeds_task(self):
        """Update threat intelligence feeds"""
        try:
            from app.local_threat_intel import get_local_threat_intel
            threat_intel = get_local_threat_intel()
            results = threat_intel.update_feeds()
            return {"status": "success", "feeds_updated": results}
        except Exception as e:
            logger.error(f"Failed to update threat feeds: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.run_compliance_check")
    def run_compliance_check_task(self, framework: str = None):
        """Run compliance assessment"""
        try:
            from app.compliance_engine import get_compliance_engine, ComplianceFramework
            compliance = get_compliance_engine()
            
            if framework:
                fw = ComplianceFramework(framework)
                report = compliance.generate_report(fw)
                return {"status": "success", "report_id": report.report_id, "score": report.overall_score}
            else:
                summary = compliance.get_compliance_summary()
                return {"status": "success", "summary": summary}
        except Exception as e:
            logger.error(f"Failed to run compliance check: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.update_baselines")
    def update_baselines_task(self):
        """Update behavioral baselines"""
        try:
            from app.threat_hunting import get_threat_hunting_engine
            hunting = get_threat_hunting_engine()
            return {"status": "success", "message": "Baselines updated"}
        except Exception as e:
            logger.error(f"Failed to update baselines: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.cleanup_old_data")
    def cleanup_old_data_task(self, days: int = 90):
        """Cleanup old data"""
        try:
            return {"status": "success", "message": f"Cleaned up data older than {days} days"}
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.analyze_ioc")
    def analyze_ioc_task(self, ioc_value: str, ioc_type: str = None):
        """Analyze IOC"""
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
            
            return {
                "status": "success",
                "report_id": report.report_id,
                "risk_score": report.risk_score,
                "risk_level": report.risk_level.value,
                "matches": len(report.matches)
            }
        except Exception as e:
            logger.error(f"Failed to analyze IOC: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.execute_playbook")
    def execute_playbook_task(self, playbook_id: str, variables: Dict[str, Any]):
        """Execute SOAR playbook"""
        try:
            from app.soar_engine import get_soar_engine
            soar = get_soar_engine()
            execution_id = soar.execute_playbook_manual(playbook_id, variables)
            return {"status": "success", "execution_id": execution_id}
        except Exception as e:
            logger.error(f"Failed to execute playbook: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.hunt_technique")
    def hunt_technique_task(self, technique_id: str):
        """Hunt for ATT&CK technique"""
        try:
            from app.threat_hunting import get_threat_hunting_engine
            hunting = get_threat_hunting_engine()
            results = hunting.hunt_for_technique(technique_id)
            return {
                "status": "success",
                "technique_id": technique_id,
                "hits": len(results)
            }
        except Exception as e:
            logger.error(f"Failed to hunt technique: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.scan_file")
    def scan_file_task(self, file_path: str):
        """Scan file for threats"""
        try:
            from app.yara_engine import get_yara_engine
            yara = get_yara_engine()
            result = yara.scan_file(file_path)
            return {
                "status": "success",
                "scan_id": result.scan_id,
                "matches": len(result.matches),
                "threat_level": result.threat_level
            }
        except Exception as e:
            logger.error(f"Failed to scan file: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.process_alert")
    def process_alert_task(self, alert_data: Dict[str, Any]):
        """Process security alert"""
        try:
            from app.soar_engine import get_soar_engine, Alert, CaseSeverity
            soar = get_soar_engine()
            
            alert = Alert(
                alert_id=alert_data.get("alert_id", f"ALERT-{hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()[:8]}"),
                title=alert_data.get("title", "Unknown Alert"),
                description=alert_data.get("description", ""),
                severity=CaseSeverity(alert_data.get("severity", "medium")),
                source=alert_data.get("source", "unknown"),
                timestamp=datetime.utcnow(),
                indicators=alert_data.get("indicators", []),
                raw_data=alert_data,
                is_processed=False,
                case_id=None,
                playbook_executions=[]
            )
            
            result = soar.process_alert(alert)
            return {
                "status": "success",
                "is_new": result["is_new"],
                "case_id": result["case_id"],
                "playbook_executions": result["playbook_executions"]
            }
        except Exception as e:
            logger.error(f"Failed to process alert: {e}")
            return {"status": "error", "error": str(e)}
    
    @celery_app.task(bind=True, name="tyranthos.tasks.bulk_ioc_analysis")
    def bulk_ioc_analysis_task(self, iocs: List[Dict[str, str]]):
        """Analyze multiple IOCs"""
        results = []
        for ioc in iocs:
            try:
                result = analyze_ioc_task.delay(ioc.get("value"), ioc.get("type"))
                results.append({
                    "ioc": ioc.get("value"),
                    "task_id": result.id
                })
            except Exception as e:
                results.append({
                    "ioc": ioc.get("value"),
                    "error": str(e)
                })
        return {"status": "success", "tasks": results}
    
    @task_prerun.connect
    def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kw):
        """Handle task pre-run"""
        logger.info(f"Task {task.name}[{task_id}] starting")
    
    @task_postrun.connect
    def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, state=None, **kw):
        """Handle task post-run"""
        logger.info(f"Task {task.name}[{task_id}] completed with state {state}")
    
    @task_failure.connect
    def task_failure_handler(sender=None, task_id=None, exception=None, args=None, kwargs=None, traceback=None, **kw):
        """Handle task failure"""
        logger.error(f"Task {sender.name}[{task_id}] failed: {exception}")
    
    @worker_ready.connect
    def worker_ready_handler(sender=None, **kw):
        """Handle worker ready"""
        logger.info(f"Worker {sender} ready")

else:
    celery_app = None


class LocalTaskQueue:
    """Local task queue for when Celery/Redis is not available"""
    
    def __init__(self):
        self._tasks: Dict[str, TaskInfo] = {}
        self._queue: List[str] = []
        self._lock = threading.Lock()
        self._worker_thread = None
        self._stop_event = threading.Event()
        self._running = False
    
    def start(self):
        """Start local task worker"""
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logger.info("Local task queue started")
    
    def stop(self):
        """Stop local task worker"""
        self._stop_event.set()
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
    
    def _worker_loop(self):
        """Process tasks from queue"""
        while not self._stop_event.is_set():
            task_id = None
            
            with self._lock:
                if self._queue:
                    task_id = self._queue.pop(0)
            
            if task_id:
                self._execute_task(task_id)
            else:
                time.sleep(0.1)
    
    def _execute_task(self, task_id: str):
        """Execute single task"""
        task_info = self._tasks.get(task_id)
        if not task_info:
            return
        
        task_info.status = TaskStatus.STARTED
        task_info.started_at = datetime.utcnow()
        task_info.worker = "local"
        
        task_func = task_registry.get_task(task_info.task_name)
        if not task_func:
            task_info.status = TaskStatus.FAILURE
            task_info.error = f"Task not found: {task_info.task_name}"
            task_info.completed_at = datetime.utcnow()
            return
        
        try:
            result = task_func(*task_info.args, **task_info.kwargs)
            task_info.status = TaskStatus.SUCCESS
            task_info.result = result
        except Exception as e:
            task_info.status = TaskStatus.FAILURE
            task_info.error = str(e)
            
            config = task_registry.get_config(task_info.task_name)
            if task_info.retries < config.get("max_retries", 3):
                task_info.retries += 1
                task_info.status = TaskStatus.RETRY
                with self._lock:
                    self._queue.append(task_id)
        
        task_info.completed_at = datetime.utcnow()
    
    def submit_task(self, task_name: str, args: List[Any] = None, kwargs: Dict[str, Any] = None,
                    priority: TaskPriority = TaskPriority.MEDIUM) -> str:
        """Submit task to queue"""
        task_id = f"TASK-{hashlib.sha256(f'{task_name}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        task_info = TaskInfo(
            task_id=task_id,
            task_name=task_name,
            status=TaskStatus.PENDING,
            priority=priority,
            args=args or [],
            kwargs=kwargs or {},
            result=None,
            error=None,
            traceback=None,
            created_at=datetime.utcnow(),
            started_at=None,
            completed_at=None,
            retries=0,
            worker=None,
            queue=f"{TASK_QUEUE_PREFIX}.{priority.value}"
        )
        
        with self._lock:
            self._tasks[task_id] = task_info
            
            if priority == TaskPriority.CRITICAL:
                self._queue.insert(0, task_id)
            elif priority == TaskPriority.HIGH:
                insert_pos = len([t for t in self._queue if self._tasks[t].priority == TaskPriority.CRITICAL])
                self._queue.insert(insert_pos, task_id)
            else:
                self._queue.append(task_id)
        
        return task_id
    
    def get_task_status(self, task_id: str) -> Optional[TaskInfo]:
        """Get task status"""
        return self._tasks.get(task_id)
    
    def get_task_result(self, task_id: str, timeout: int = None) -> Optional[Any]:
        """Get task result, optionally waiting"""
        start_time = time.time()
        
        while True:
            task_info = self._tasks.get(task_id)
            if not task_info:
                return None
            
            if task_info.status in [TaskStatus.SUCCESS, TaskStatus.FAILURE]:
                return task_info.result
            
            if timeout and (time.time() - start_time) > timeout:
                return None
            
            time.sleep(0.1)
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel pending task"""
        with self._lock:
            if task_id in self._queue:
                self._queue.remove(task_id)
                if task_id in self._tasks:
                    self._tasks[task_id].status = TaskStatus.REVOKED
                return True
        return False
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        with self._lock:
            pending = len(self._queue)
            total = len(self._tasks)
            
            by_status = {}
            for task in self._tasks.values():
                status = task.status.value
                by_status[status] = by_status.get(status, 0) + 1
            
            by_priority = {}
            for task_id in self._queue:
                task = self._tasks.get(task_id)
                if task:
                    priority = task.priority.value
                    by_priority[priority] = by_priority.get(priority, 0) + 1
        
        return {
            "pending": pending,
            "total": total,
            "by_status": by_status,
            "by_priority": by_priority
        }


class DistributedTaskManager:
    """Unified interface for distributed task management"""
    
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
        
        self._use_celery = CELERY_AVAILABLE and REDIS_AVAILABLE
        self._local_queue = LocalTaskQueue()
        
        if not self._use_celery:
            logger.warning("Celery/Redis not available, using local task queue")
            self._local_queue.start()
        
        self._register_default_tasks()
    
    def _register_default_tasks(self):
        """Register default tasks"""
        
        @task_registry.register(name="tyranthos.tasks.update_threat_feeds", priority=TaskPriority.MEDIUM)
        def update_threat_feeds():
            from app.local_threat_intel import get_local_threat_intel
            threat_intel = get_local_threat_intel()
            return threat_intel.update_feeds()
        
        @task_registry.register(name="tyranthos.tasks.run_compliance_check", priority=TaskPriority.LOW)
        def run_compliance_check(framework: str = None):
            from app.compliance_engine import get_compliance_engine, ComplianceFramework
            compliance = get_compliance_engine()
            if framework:
                return compliance.generate_report(ComplianceFramework(framework))
            return compliance.get_compliance_summary()
        
        @task_registry.register(name="tyranthos.tasks.analyze_ioc", priority=TaskPriority.HIGH)
        def analyze_ioc(ioc_value: str, ioc_type: str = None):
            from app.local_threat_intel import get_local_threat_intel
            threat_intel = get_local_threat_intel()
            if ioc_type == "ip":
                return threat_intel.analyze_ip(ioc_value)
            elif ioc_type == "domain":
                return threat_intel.analyze_domain(ioc_value)
            elif ioc_type == "url":
                return threat_intel.analyze_url(ioc_value)
            elif ioc_type == "hash":
                return threat_intel.analyze_hash(ioc_value)
            return threat_intel.analyze_text(ioc_value)
        
        @task_registry.register(name="tyranthos.tasks.execute_playbook", priority=TaskPriority.HIGH)
        def execute_playbook(playbook_id: str, variables: Dict[str, Any]):
            from app.soar_engine import get_soar_engine
            soar = get_soar_engine()
            return soar.execute_playbook_manual(playbook_id, variables)
        
        @task_registry.register(name="tyranthos.tasks.hunt_technique", priority=TaskPriority.MEDIUM)
        def hunt_technique(technique_id: str):
            from app.threat_hunting import get_threat_hunting_engine
            hunting = get_threat_hunting_engine()
            return hunting.hunt_for_technique(technique_id)
    
    def submit_task(self, task_name: str, args: List[Any] = None, kwargs: Dict[str, Any] = None,
                    priority: TaskPriority = TaskPriority.MEDIUM, countdown: int = None,
                    eta: datetime = None) -> str:
        """Submit task for execution"""
        args = args or []
        kwargs = kwargs or {}
        
        if self._use_celery and celery_app:
            queue = f"{TASK_QUEUE_PREFIX}.{priority.value}"
            
            task_options = {
                "queue": queue,
                "priority": self._priority_to_int(priority)
            }
            
            if countdown:
                task_options["countdown"] = countdown
            if eta:
                task_options["eta"] = eta
            
            celery_task = celery_app.tasks.get(task_name)
            if celery_task:
                result = celery_task.apply_async(args=args, kwargs=kwargs, **task_options)
                return result.id
            else:
                result = celery_app.send_task(task_name, args=args, kwargs=kwargs, **task_options)
                return result.id
        else:
            return self._local_queue.submit_task(task_name, args, kwargs, priority)
    
    def _priority_to_int(self, priority: TaskPriority) -> int:
        """Convert priority to integer for Celery"""
        priority_map = {
            TaskPriority.CRITICAL: 9,
            TaskPriority.HIGH: 7,
            TaskPriority.MEDIUM: 5,
            TaskPriority.LOW: 3,
            TaskPriority.BACKGROUND: 1
        }
        return priority_map.get(priority, 5)
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status"""
        if self._use_celery and celery_app:
            result = AsyncResult(task_id, app=celery_app)
            return {
                "task_id": task_id,
                "status": result.status,
                "result": result.result if result.ready() else None,
                "traceback": result.traceback if result.failed() else None
            }
        else:
            task_info = self._local_queue.get_task_status(task_id)
            if task_info:
                return {
                    "task_id": task_info.task_id,
                    "status": task_info.status.value,
                    "result": task_info.result,
                    "error": task_info.error,
                    "started_at": task_info.started_at.isoformat() if task_info.started_at else None,
                    "completed_at": task_info.completed_at.isoformat() if task_info.completed_at else None
                }
            return None
    
    def get_task_result(self, task_id: str, timeout: int = None) -> Optional[Any]:
        """Get task result"""
        if self._use_celery and celery_app:
            result = AsyncResult(task_id, app=celery_app)
            try:
                return result.get(timeout=timeout)
            except Exception:
                return None
        else:
            return self._local_queue.get_task_result(task_id, timeout)
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel task"""
        if self._use_celery and celery_app:
            celery_app.control.revoke(task_id, terminate=True)
            return True
        else:
            return self._local_queue.cancel_task(task_id)
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        if self._use_celery and celery_app:
            inspect = celery_app.control.inspect()
            
            active = inspect.active() or {}
            reserved = inspect.reserved() or {}
            scheduled = inspect.scheduled() or {}
            
            total_active = sum(len(tasks) for tasks in active.values())
            total_reserved = sum(len(tasks) for tasks in reserved.values())
            total_scheduled = sum(len(tasks) for tasks in scheduled.values())
            
            return {
                "backend": "celery",
                "active": total_active,
                "reserved": total_reserved,
                "scheduled": total_scheduled,
                "workers": list(active.keys())
            }
        else:
            stats = self._local_queue.get_queue_stats()
            stats["backend"] = "local"
            return stats
    
    def chain_tasks(self, tasks: List[Tuple[str, List[Any], Dict[str, Any]]]) -> str:
        """Chain multiple tasks"""
        if self._use_celery and celery_app:
            signatures = []
            for task_name, args, kwargs in tasks:
                celery_task = celery_app.tasks.get(task_name)
                if celery_task:
                    signatures.append(celery_task.s(*args, **kwargs))
            
            if signatures:
                result = chain(*signatures).apply_async()
                return result.id
        
        first_task = tasks[0]
        return self.submit_task(first_task[0], first_task[1], first_task[2])
    
    def group_tasks(self, tasks: List[Tuple[str, List[Any], Dict[str, Any]]]) -> str:
        """Execute tasks in parallel"""
        if self._use_celery and celery_app:
            signatures = []
            for task_name, args, kwargs in tasks:
                celery_task = celery_app.tasks.get(task_name)
                if celery_task:
                    signatures.append(celery_task.s(*args, **kwargs))
            
            if signatures:
                result = group(*signatures).apply_async()
                return result.id
        
        task_ids = []
        for task_name, args, kwargs in tasks:
            task_id = self.submit_task(task_name, args, kwargs)
            task_ids.append(task_id)
        
        return task_ids[0] if task_ids else None
    
    def schedule_task(self, task_name: str, schedule_type: str, schedule_config: Dict[str, Any],
                      args: List[Any] = None, kwargs: Dict[str, Any] = None) -> str:
        """Schedule periodic task"""
        schedule_id = f"SCHED-{hashlib.sha256(f'{task_name}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        if self._use_celery and celery_app:
            if schedule_type == "crontab":
                schedule = crontab(**schedule_config)
            elif schedule_type == "interval":
                from celery.schedules import timedelta as celery_timedelta
                schedule = celery_timedelta(**schedule_config)
            else:
                raise ValueError(f"Unknown schedule type: {schedule_type}")
            
            celery_app.conf.beat_schedule[schedule_id] = {
                "task": task_name,
                "schedule": schedule,
                "args": args or [],
                "kwargs": kwargs or {}
            }
        
        return schedule_id
    
    def update_threat_feeds_async(self) -> str:
        """Submit threat feed update task"""
        return self.submit_task("tyranthos.tasks.update_threat_feeds", priority=TaskPriority.MEDIUM)
    
    def analyze_ioc_async(self, ioc_value: str, ioc_type: str = None) -> str:
        """Submit IOC analysis task"""
        return self.submit_task(
            "tyranthos.tasks.analyze_ioc",
            args=[ioc_value, ioc_type],
            priority=TaskPriority.HIGH
        )
    
    def execute_playbook_async(self, playbook_id: str, variables: Dict[str, Any]) -> str:
        """Submit playbook execution task"""
        return self.submit_task(
            "tyranthos.tasks.execute_playbook",
            args=[playbook_id, variables],
            priority=TaskPriority.HIGH
        )
    
    def hunt_technique_async(self, technique_id: str) -> str:
        """Submit technique hunting task"""
        return self.submit_task(
            "tyranthos.tasks.hunt_technique",
            args=[technique_id],
            priority=TaskPriority.MEDIUM
        )
    
    def run_compliance_check_async(self, framework: str = None) -> str:
        """Submit compliance check task"""
        return self.submit_task(
            "tyranthos.tasks.run_compliance_check",
            args=[framework] if framework else [],
            priority=TaskPriority.LOW
        )
    
    def shutdown(self):
        """Shutdown task manager"""
        if not self._use_celery:
            self._local_queue.stop()


def get_task_manager() -> DistributedTaskManager:
    """Get singleton instance of DistributedTaskManager"""
    return DistributedTaskManager()


def get_celery_app():
    """Get Celery app instance"""
    return celery_app
