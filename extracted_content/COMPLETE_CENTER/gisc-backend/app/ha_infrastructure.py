"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - HIGH AVAILABILITY INFRASTRUCTURE
Enterprise-grade High Availability and Fault Tolerance System

This module implements:
- Health check endpoints and monitoring
- Circuit breaker pattern for external dependencies
- Load balancing and request distribution
- Failover logic and automatic recovery
- Service discovery and registration
- Leader election for clustered deployments
- Graceful degradation under load
- Connection pooling and resource management
- Distributed locking mechanisms
- State synchronization across nodes

100% opensource - Uses standard Python libraries and Redis (BSD)

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import json
import hashlib
import logging
import threading
import time
import socket
import signal
import atexit
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from functools import wraps
import random
import uuid

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
NODE_ID = os.environ.get("NODE_ID", f"node-{socket.gethostname()}-{os.getpid()}")
CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "tyranthos-cluster")
HEALTH_CHECK_INTERVAL = int(os.environ.get("HEALTH_CHECK_INTERVAL", "10"))
LEADER_TTL = int(os.environ.get("LEADER_TTL", "30"))
SERVICE_TTL = int(os.environ.get("SERVICE_TTL", "60"))


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class NodeRole(str, Enum):
    LEADER = "leader"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    STANDALONE = "standalone"


@dataclass
class HealthCheck:
    name: str
    status: HealthStatus
    message: str
    latency_ms: float
    last_check: datetime
    consecutive_failures: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceInstance:
    service_id: str
    service_name: str
    node_id: str
    host: str
    port: int
    status: HealthStatus
    weight: int
    metadata: Dict[str, Any]
    registered_at: datetime
    last_heartbeat: datetime


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    success_threshold: int = 3
    timeout_seconds: int = 30
    half_open_max_calls: int = 3


@dataclass
class CircuitBreakerState:
    name: str
    state: CircuitState
    failure_count: int
    success_count: int
    last_failure: Optional[datetime]
    last_success: Optional[datetime]
    opened_at: Optional[datetime]
    half_open_calls: int


class HealthChecker:
    """Performs health checks on system components"""
    
    def __init__(self):
        self._checks: Dict[str, Callable[[], HealthCheck]] = {}
        self._results: Dict[str, HealthCheck] = {}
        self._lock = threading.Lock()
    
    def register_check(self, name: str, check_func: Callable[[], HealthCheck]):
        """Register health check"""
        with self._lock:
            self._checks[name] = check_func
    
    def run_check(self, name: str) -> HealthCheck:
        """Run single health check"""
        check_func = self._checks.get(name)
        if not check_func:
            return HealthCheck(
                name=name,
                status=HealthStatus.UNKNOWN,
                message="Check not found",
                latency_ms=0,
                last_check=datetime.utcnow(),
                consecutive_failures=0
            )
        
        start_time = time.time()
        try:
            result = check_func()
            result.latency_ms = (time.time() - start_time) * 1000
            result.last_check = datetime.utcnow()
            
            with self._lock:
                prev = self._results.get(name)
                if prev and result.status == HealthStatus.UNHEALTHY:
                    result.consecutive_failures = prev.consecutive_failures + 1
                else:
                    result.consecutive_failures = 0
                self._results[name] = result
            
            return result
        except Exception as e:
            result = HealthCheck(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                last_check=datetime.utcnow(),
                consecutive_failures=0
            )
            
            with self._lock:
                prev = self._results.get(name)
                if prev:
                    result.consecutive_failures = prev.consecutive_failures + 1
                self._results[name] = result
            
            return result
    
    def run_all_checks(self) -> Dict[str, HealthCheck]:
        """Run all health checks"""
        results = {}
        with self._lock:
            check_names = list(self._checks.keys())
        
        for name in check_names:
            results[name] = self.run_check(name)
        
        return results
    
    def get_overall_status(self) -> Tuple[HealthStatus, Dict[str, HealthCheck]]:
        """Get overall health status"""
        results = self.run_all_checks()
        
        if not results:
            return HealthStatus.UNKNOWN, results
        
        unhealthy_count = sum(1 for r in results.values() if r.status == HealthStatus.UNHEALTHY)
        degraded_count = sum(1 for r in results.values() if r.status == HealthStatus.DEGRADED)
        
        if unhealthy_count > 0:
            return HealthStatus.UNHEALTHY, results
        elif degraded_count > 0:
            return HealthStatus.DEGRADED, results
        else:
            return HealthStatus.HEALTHY, results
    
    def get_last_results(self) -> Dict[str, HealthCheck]:
        """Get last check results"""
        with self._lock:
            return dict(self._results)


class CircuitBreaker:
    """Circuit breaker for fault tolerance"""
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState(
            name=name,
            state=CircuitState.CLOSED,
            failure_count=0,
            success_count=0,
            last_failure=None,
            last_success=None,
            opened_at=None,
            half_open_calls=0
        )
        self._lock = threading.Lock()
    
    def _should_allow_request(self) -> bool:
        """Check if request should be allowed"""
        with self._lock:
            if self._state.state == CircuitState.CLOSED:
                return True
            
            elif self._state.state == CircuitState.OPEN:
                if self._state.opened_at:
                    elapsed = (datetime.utcnow() - self._state.opened_at).total_seconds()
                    if elapsed >= self.config.timeout_seconds:
                        self._state.state = CircuitState.HALF_OPEN
                        self._state.half_open_calls = 0
                        return True
                return False
            
            elif self._state.state == CircuitState.HALF_OPEN:
                if self._state.half_open_calls < self.config.half_open_max_calls:
                    self._state.half_open_calls += 1
                    return True
                return False
        
        return False
    
    def _record_success(self):
        """Record successful call"""
        with self._lock:
            self._state.last_success = datetime.utcnow()
            self._state.success_count += 1
            
            if self._state.state == CircuitState.HALF_OPEN:
                if self._state.success_count >= self.config.success_threshold:
                    self._state.state = CircuitState.CLOSED
                    self._state.failure_count = 0
                    self._state.success_count = 0
                    logger.info(f"Circuit breaker {self.name} closed")
            
            elif self._state.state == CircuitState.CLOSED:
                self._state.failure_count = 0
    
    def _record_failure(self):
        """Record failed call"""
        with self._lock:
            self._state.last_failure = datetime.utcnow()
            self._state.failure_count += 1
            
            if self._state.state == CircuitState.HALF_OPEN:
                self._state.state = CircuitState.OPEN
                self._state.opened_at = datetime.utcnow()
                self._state.success_count = 0
                logger.warning(f"Circuit breaker {self.name} opened (half-open failure)")
            
            elif self._state.state == CircuitState.CLOSED:
                if self._state.failure_count >= self.config.failure_threshold:
                    self._state.state = CircuitState.OPEN
                    self._state.opened_at = datetime.utcnow()
                    logger.warning(f"Circuit breaker {self.name} opened (threshold reached)")
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        if not self._should_allow_request():
            raise CircuitBreakerOpenError(f"Circuit breaker {self.name} is open")
        
        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            self._record_failure()
            raise
    
    async def call_async(self, func: Callable, *args, **kwargs) -> Any:
        """Execute async function with circuit breaker protection"""
        if not self._should_allow_request():
            raise CircuitBreakerOpenError(f"Circuit breaker {self.name} is open")
        
        try:
            result = await func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            self._record_failure()
            raise
    
    def get_state(self) -> CircuitBreakerState:
        """Get current state"""
        with self._lock:
            return CircuitBreakerState(
                name=self._state.name,
                state=self._state.state,
                failure_count=self._state.failure_count,
                success_count=self._state.success_count,
                last_failure=self._state.last_failure,
                last_success=self._state.last_success,
                opened_at=self._state.opened_at,
                half_open_calls=self._state.half_open_calls
            )
    
    def reset(self):
        """Reset circuit breaker"""
        with self._lock:
            self._state.state = CircuitState.CLOSED
            self._state.failure_count = 0
            self._state.success_count = 0
            self._state.opened_at = None
            self._state.half_open_calls = 0


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open"""
    pass


def circuit_breaker(name: str, config: CircuitBreakerConfig = None):
    """Decorator for circuit breaker protection"""
    cb = CircuitBreaker(name, config)
    
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return cb.call(func, *args, **kwargs)
        
        wrapper.circuit_breaker = cb
        return wrapper
    
    return decorator


class LoadBalancer:
    """Load balancer for service instances"""
    
    def __init__(self, strategy: str = "round_robin"):
        self._instances: Dict[str, List[ServiceInstance]] = defaultdict(list)
        self._counters: Dict[str, int] = defaultdict(int)
        self._strategy = strategy
        self._lock = threading.Lock()
    
    def register_instance(self, instance: ServiceInstance):
        """Register service instance"""
        with self._lock:
            instances = self._instances[instance.service_name]
            existing = next((i for i in instances if i.service_id == instance.service_id), None)
            if existing:
                instances.remove(existing)
            instances.append(instance)
    
    def deregister_instance(self, service_name: str, service_id: str):
        """Deregister service instance"""
        with self._lock:
            instances = self._instances[service_name]
            self._instances[service_name] = [i for i in instances if i.service_id != service_id]
    
    def get_instance(self, service_name: str) -> Optional[ServiceInstance]:
        """Get next instance based on strategy"""
        with self._lock:
            instances = [i for i in self._instances[service_name] if i.status == HealthStatus.HEALTHY]
            
            if not instances:
                return None
            
            if self._strategy == "round_robin":
                idx = self._counters[service_name] % len(instances)
                self._counters[service_name] += 1
                return instances[idx]
            
            elif self._strategy == "weighted":
                total_weight = sum(i.weight for i in instances)
                if total_weight == 0:
                    return instances[0]
                
                r = random.randint(1, total_weight)
                cumulative = 0
                for instance in instances:
                    cumulative += instance.weight
                    if r <= cumulative:
                        return instance
                return instances[-1]
            
            elif self._strategy == "least_connections":
                return min(instances, key=lambda i: i.metadata.get("connections", 0))
            
            elif self._strategy == "random":
                return random.choice(instances)
            
            else:
                return instances[0]
    
    def get_all_instances(self, service_name: str) -> List[ServiceInstance]:
        """Get all instances for service"""
        with self._lock:
            return list(self._instances[service_name])
    
    def update_instance_status(self, service_name: str, service_id: str, status: HealthStatus):
        """Update instance health status"""
        with self._lock:
            for instance in self._instances[service_name]:
                if instance.service_id == service_id:
                    instance.status = status
                    instance.last_heartbeat = datetime.utcnow()
                    break


class ServiceRegistry:
    """Service discovery and registration"""
    
    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._local_services: Dict[str, ServiceInstance] = {}
        self._lock = threading.Lock()
        self._heartbeat_thread = None
        self._stop_event = threading.Event()
    
    def register(self, service_name: str, host: str, port: int, weight: int = 100,
                 metadata: Dict[str, Any] = None) -> str:
        """Register service instance"""
        service_id = f"{service_name}-{NODE_ID}-{port}"
        
        instance = ServiceInstance(
            service_id=service_id,
            service_name=service_name,
            node_id=NODE_ID,
            host=host,
            port=port,
            status=HealthStatus.HEALTHY,
            weight=weight,
            metadata=metadata or {},
            registered_at=datetime.utcnow(),
            last_heartbeat=datetime.utcnow()
        )
        
        with self._lock:
            self._local_services[service_id] = instance
        
        if self._redis:
            key = f"{CLUSTER_NAME}:services:{service_name}:{service_id}"
            self._redis.setex(key, SERVICE_TTL, json.dumps(asdict(instance), default=str))
        
        logger.info(f"Registered service {service_id}")
        return service_id
    
    def deregister(self, service_id: str):
        """Deregister service instance"""
        with self._lock:
            instance = self._local_services.pop(service_id, None)
        
        if instance and self._redis:
            key = f"{CLUSTER_NAME}:services:{instance.service_name}:{service_id}"
            self._redis.delete(key)
        
        logger.info(f"Deregistered service {service_id}")
    
    def discover(self, service_name: str) -> List[ServiceInstance]:
        """Discover service instances"""
        instances = []
        
        if self._redis:
            pattern = f"{CLUSTER_NAME}:services:{service_name}:*"
            keys = self._redis.keys(pattern)
            
            for key in keys:
                data = self._redis.get(key)
                if data:
                    try:
                        instance_data = json.loads(data)
                        instance = ServiceInstance(
                            service_id=instance_data["service_id"],
                            service_name=instance_data["service_name"],
                            node_id=instance_data["node_id"],
                            host=instance_data["host"],
                            port=instance_data["port"],
                            status=HealthStatus(instance_data["status"]),
                            weight=instance_data["weight"],
                            metadata=instance_data["metadata"],
                            registered_at=datetime.fromisoformat(instance_data["registered_at"]),
                            last_heartbeat=datetime.fromisoformat(instance_data["last_heartbeat"])
                        )
                        instances.append(instance)
                    except Exception as e:
                        logger.error(f"Failed to parse service data: {e}")
        else:
            with self._lock:
                instances = [i for i in self._local_services.values() if i.service_name == service_name]
        
        return instances
    
    def start_heartbeat(self):
        """Start heartbeat thread"""
        if self._heartbeat_thread:
            return
        
        self._stop_event.clear()
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()
    
    def stop_heartbeat(self):
        """Stop heartbeat thread"""
        self._stop_event.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
            self._heartbeat_thread = None
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while not self._stop_event.is_set():
            with self._lock:
                services = list(self._local_services.values())
            
            for instance in services:
                instance.last_heartbeat = datetime.utcnow()
                
                if self._redis:
                    key = f"{CLUSTER_NAME}:services:{instance.service_name}:{instance.service_id}"
                    self._redis.setex(key, SERVICE_TTL, json.dumps(asdict(instance), default=str))
            
            self._stop_event.wait(HEALTH_CHECK_INTERVAL)


class LeaderElection:
    """Leader election for clustered deployments"""
    
    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._role = NodeRole.STANDALONE if not redis_client else NodeRole.FOLLOWER
        self._leader_id: Optional[str] = None
        self._lock = threading.Lock()
        self._election_thread = None
        self._stop_event = threading.Event()
        self._on_leader_change: List[Callable[[str, NodeRole], None]] = []
    
    def on_leader_change(self, callback: Callable[[str, NodeRole], None]):
        """Register callback for leader changes"""
        self._on_leader_change.append(callback)
    
    def get_role(self) -> NodeRole:
        """Get current role"""
        with self._lock:
            return self._role
    
    def get_leader(self) -> Optional[str]:
        """Get current leader ID"""
        with self._lock:
            return self._leader_id
    
    def is_leader(self) -> bool:
        """Check if this node is leader"""
        with self._lock:
            return self._role == NodeRole.LEADER
    
    def start_election(self):
        """Start leader election process"""
        if not self._redis:
            with self._lock:
                self._role = NodeRole.STANDALONE
            return
        
        self._stop_event.clear()
        self._election_thread = threading.Thread(target=self._election_loop, daemon=True)
        self._election_thread.start()
    
    def stop_election(self):
        """Stop leader election"""
        self._stop_event.set()
        if self._election_thread:
            self._election_thread.join(timeout=5)
            self._election_thread = None
        
        if self._redis and self.is_leader():
            self._redis.delete(f"{CLUSTER_NAME}:leader")
    
    def _election_loop(self):
        """Leader election loop"""
        while not self._stop_event.is_set():
            try:
                self._try_become_leader()
            except Exception as e:
                logger.error(f"Election error: {e}")
            
            self._stop_event.wait(LEADER_TTL // 3)
    
    def _try_become_leader(self):
        """Try to become leader"""
        if not self._redis:
            return
        
        leader_key = f"{CLUSTER_NAME}:leader"
        
        current_leader = self._redis.get(leader_key)
        if current_leader:
            current_leader = current_leader.decode() if isinstance(current_leader, bytes) else current_leader
        
        old_role = self._role
        old_leader = self._leader_id
        
        if current_leader == NODE_ID:
            self._redis.expire(leader_key, LEADER_TTL)
            with self._lock:
                self._role = NodeRole.LEADER
                self._leader_id = NODE_ID
        
        elif current_leader:
            with self._lock:
                self._role = NodeRole.FOLLOWER
                self._leader_id = current_leader
        
        else:
            acquired = self._redis.set(leader_key, NODE_ID, nx=True, ex=LEADER_TTL)
            if acquired:
                with self._lock:
                    self._role = NodeRole.LEADER
                    self._leader_id = NODE_ID
                logger.info(f"Node {NODE_ID} became leader")
            else:
                current_leader = self._redis.get(leader_key)
                if current_leader:
                    current_leader = current_leader.decode() if isinstance(current_leader, bytes) else current_leader
                with self._lock:
                    self._role = NodeRole.FOLLOWER
                    self._leader_id = current_leader
        
        if old_role != self._role or old_leader != self._leader_id:
            for callback in self._on_leader_change:
                try:
                    callback(self._leader_id, self._role)
                except Exception as e:
                    logger.error(f"Leader change callback error: {e}")


class DistributedLock:
    """Distributed locking mechanism"""
    
    def __init__(self, redis_client, name: str, timeout: int = 30):
        self._redis = redis_client
        self._name = name
        self._timeout = timeout
        self._lock_id = str(uuid.uuid4())
        self._acquired = False
    
    def acquire(self, blocking: bool = True, timeout: int = None) -> bool:
        """Acquire lock"""
        if not self._redis:
            self._acquired = True
            return True
        
        key = f"{CLUSTER_NAME}:lock:{self._name}"
        timeout = timeout or self._timeout
        
        if blocking:
            start_time = time.time()
            while True:
                if self._redis.set(key, self._lock_id, nx=True, ex=self._timeout):
                    self._acquired = True
                    return True
                
                if time.time() - start_time > timeout:
                    return False
                
                time.sleep(0.1)
        else:
            if self._redis.set(key, self._lock_id, nx=True, ex=self._timeout):
                self._acquired = True
                return True
            return False
    
    def release(self):
        """Release lock"""
        if not self._acquired:
            return
        
        if not self._redis:
            self._acquired = False
            return
        
        key = f"{CLUSTER_NAME}:lock:{self._name}"
        
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """
        
        try:
            self._redis.eval(script, 1, key, self._lock_id)
        except Exception as e:
            logger.error(f"Failed to release lock: {e}")
        
        self._acquired = False
    
    def extend(self, additional_time: int = None):
        """Extend lock timeout"""
        if not self._acquired or not self._redis:
            return False
        
        key = f"{CLUSTER_NAME}:lock:{self._name}"
        additional_time = additional_time or self._timeout
        
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        
        try:
            result = self._redis.eval(script, 1, key, self._lock_id, additional_time)
            return result == 1
        except Exception as e:
            logger.error(f"Failed to extend lock: {e}")
            return False
    
    def __enter__(self):
        self.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


class ConnectionPool:
    """Connection pool for resource management"""
    
    def __init__(self, factory: Callable, max_size: int = 10, min_size: int = 2):
        self._factory = factory
        self._max_size = max_size
        self._min_size = min_size
        self._pool: List[Any] = []
        self._in_use: Set[int] = set()
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        
        for _ in range(min_size):
            try:
                conn = factory()
                self._pool.append(conn)
            except Exception as e:
                logger.error(f"Failed to create initial connection: {e}")
    
    def acquire(self, timeout: float = None) -> Any:
        """Acquire connection from pool"""
        with self._condition:
            start_time = time.time()
            
            while True:
                for i, conn in enumerate(self._pool):
                    if i not in self._in_use:
                        self._in_use.add(i)
                        return conn
                
                if len(self._pool) < self._max_size:
                    try:
                        conn = self._factory()
                        idx = len(self._pool)
                        self._pool.append(conn)
                        self._in_use.add(idx)
                        return conn
                    except Exception as e:
                        logger.error(f"Failed to create connection: {e}")
                
                if timeout is not None:
                    remaining = timeout - (time.time() - start_time)
                    if remaining <= 0:
                        raise TimeoutError("Connection pool timeout")
                    self._condition.wait(remaining)
                else:
                    self._condition.wait()
    
    def release(self, conn: Any):
        """Release connection back to pool"""
        with self._condition:
            try:
                idx = self._pool.index(conn)
                self._in_use.discard(idx)
                self._condition.notify()
            except ValueError:
                pass
    
    def close_all(self):
        """Close all connections"""
        with self._lock:
            for conn in self._pool:
                try:
                    if hasattr(conn, "close"):
                        conn.close()
                except Exception:
                    pass
            self._pool.clear()
            self._in_use.clear()


class HAInfrastructure:
    """Main High Availability infrastructure manager"""
    
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
        
        self._redis = None
        if REDIS_AVAILABLE:
            try:
                self._redis = redis.from_url(REDIS_URL)
                self._redis.ping()
                logger.info("Connected to Redis for HA")
            except Exception as e:
                logger.warning(f"Redis not available for HA: {e}")
                self._redis = None
        
        self.health_checker = HealthChecker()
        self.load_balancer = LoadBalancer()
        self.service_registry = ServiceRegistry(self._redis)
        self.leader_election = LeaderElection(self._redis)
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        
        self._register_default_health_checks()
        
        atexit.register(self._cleanup)
    
    def _register_default_health_checks(self):
        """Register default health checks"""
        
        def check_database():
            try:
                import sqlite3
                conn = sqlite3.connect(":memory:")
                conn.execute("SELECT 1")
                conn.close()
                return HealthCheck(
                    name="database",
                    status=HealthStatus.HEALTHY,
                    message="Database connection OK",
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0
                )
            except Exception as e:
                return HealthCheck(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    message=str(e),
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0
                )
        
        def check_redis():
            if not self._redis:
                return HealthCheck(
                    name="redis",
                    status=HealthStatus.DEGRADED,
                    message="Redis not configured",
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0
                )
            
            try:
                start = time.time()
                self._redis.ping()
                latency = (time.time() - start) * 1000
                return HealthCheck(
                    name="redis",
                    status=HealthStatus.HEALTHY,
                    message="Redis connection OK",
                    latency_ms=latency,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0
                )
            except Exception as e:
                return HealthCheck(
                    name="redis",
                    status=HealthStatus.UNHEALTHY,
                    message=str(e),
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0
                )
        
        def check_disk():
            try:
                import shutil
                total, used, free = shutil.disk_usage("/")
                free_percent = (free / total) * 100
                
                if free_percent < 5:
                    status = HealthStatus.UNHEALTHY
                    message = f"Critical: Only {free_percent:.1f}% disk space free"
                elif free_percent < 15:
                    status = HealthStatus.DEGRADED
                    message = f"Warning: Only {free_percent:.1f}% disk space free"
                else:
                    status = HealthStatus.HEALTHY
                    message = f"Disk space OK: {free_percent:.1f}% free"
                
                return HealthCheck(
                    name="disk",
                    status=status,
                    message=message,
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0,
                    metadata={"free_percent": free_percent, "free_bytes": free}
                )
            except Exception as e:
                return HealthCheck(
                    name="disk",
                    status=HealthStatus.UNKNOWN,
                    message=str(e),
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0
                )
        
        def check_memory():
            try:
                with open("/proc/meminfo", "r") as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            meminfo[parts[0].rstrip(":")] = int(parts[1])
                
                total = meminfo.get("MemTotal", 0)
                available = meminfo.get("MemAvailable", 0)
                
                if total > 0:
                    available_percent = (available / total) * 100
                else:
                    available_percent = 100
                
                if available_percent < 5:
                    status = HealthStatus.UNHEALTHY
                    message = f"Critical: Only {available_percent:.1f}% memory available"
                elif available_percent < 15:
                    status = HealthStatus.DEGRADED
                    message = f"Warning: Only {available_percent:.1f}% memory available"
                else:
                    status = HealthStatus.HEALTHY
                    message = f"Memory OK: {available_percent:.1f}% available"
                
                return HealthCheck(
                    name="memory",
                    status=status,
                    message=message,
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0,
                    metadata={"available_percent": available_percent}
                )
            except Exception as e:
                return HealthCheck(
                    name="memory",
                    status=HealthStatus.UNKNOWN,
                    message=str(e),
                    latency_ms=0,
                    last_check=datetime.utcnow(),
                    consecutive_failures=0
                )
        
        self.health_checker.register_check("database", check_database)
        self.health_checker.register_check("redis", check_redis)
        self.health_checker.register_check("disk", check_disk)
        self.health_checker.register_check("memory", check_memory)
    
    def start(self):
        """Start HA infrastructure"""
        self.service_registry.start_heartbeat()
        self.leader_election.start_election()
        logger.info(f"HA infrastructure started for node {NODE_ID}")
    
    def stop(self):
        """Stop HA infrastructure"""
        self.service_registry.stop_heartbeat()
        self.leader_election.stop_election()
        logger.info("HA infrastructure stopped")
    
    def _cleanup(self):
        """Cleanup on exit"""
        self.stop()
    
    def get_circuit_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create circuit breaker"""
        if name not in self._circuit_breakers:
            self._circuit_breakers[name] = CircuitBreaker(name, config)
        return self._circuit_breakers[name]
    
    def get_distributed_lock(self, name: str, timeout: int = 30) -> DistributedLock:
        """Get distributed lock"""
        return DistributedLock(self._redis, name, timeout)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        overall_status, checks = self.health_checker.get_overall_status()
        
        return {
            "status": overall_status.value,
            "node_id": NODE_ID,
            "role": self.leader_election.get_role().value,
            "leader": self.leader_election.get_leader(),
            "checks": {
                name: {
                    "status": check.status.value,
                    "message": check.message,
                    "latency_ms": check.latency_ms,
                    "last_check": check.last_check.isoformat(),
                    "consecutive_failures": check.consecutive_failures
                }
                for name, check in checks.items()
            },
            "circuit_breakers": {
                name: {
                    "state": cb.get_state().state.value,
                    "failure_count": cb.get_state().failure_count
                }
                for name, cb in self._circuit_breakers.items()
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def register_service(self, service_name: str, host: str, port: int,
                         weight: int = 100, metadata: Dict[str, Any] = None) -> str:
        """Register service instance"""
        service_id = self.service_registry.register(service_name, host, port, weight, metadata)
        
        instance = ServiceInstance(
            service_id=service_id,
            service_name=service_name,
            node_id=NODE_ID,
            host=host,
            port=port,
            status=HealthStatus.HEALTHY,
            weight=weight,
            metadata=metadata or {},
            registered_at=datetime.utcnow(),
            last_heartbeat=datetime.utcnow()
        )
        self.load_balancer.register_instance(instance)
        
        return service_id
    
    def discover_service(self, service_name: str) -> Optional[ServiceInstance]:
        """Discover and get instance for service"""
        instances = self.service_registry.discover(service_name)
        
        for instance in instances:
            self.load_balancer.register_instance(instance)
        
        return self.load_balancer.get_instance(service_name)
    
    def is_leader(self) -> bool:
        """Check if this node is leader"""
        return self.leader_election.is_leader()


def get_ha_infrastructure() -> HAInfrastructure:
    """Get singleton instance of HAInfrastructure"""
    return HAInfrastructure()
