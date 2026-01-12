"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - MULTI-TENANCY ENGINE
Enterprise Multi-tenant Architecture with RBAC

This module implements:
- Organization management and isolation
- Role-Based Access Control (RBAC)
- Permission management and enforcement
- Tenant provisioning and lifecycle
- Data isolation and partitioning
- Cross-tenant administration
- Audit logging for tenant operations
- Resource quotas and limits
- API key management per tenant
- Tenant-specific configuration

100% opensource - Uses SQLite for data storage

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import json
import hashlib
import logging
import threading
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import wraps
from contextlib import contextmanager
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


TENANT_DB_PATH = os.environ.get("TENANT_DB_PATH", "/tmp/tyranthos/tenants.db")
DEFAULT_TENANT_ID = os.environ.get("DEFAULT_TENANT_ID", "default")
API_KEY_LENGTH = 64
API_KEY_PREFIX = "tyr_"


class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"
    DELETED = "deleted"


class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING = "pending"


class Permission(str, Enum):
    READ_THREATS = "read:threats"
    WRITE_THREATS = "write:threats"
    DELETE_THREATS = "delete:threats"
    
    READ_ALERTS = "read:alerts"
    WRITE_ALERTS = "write:alerts"
    DELETE_ALERTS = "delete:alerts"
    ACKNOWLEDGE_ALERTS = "acknowledge:alerts"
    
    READ_INCIDENTS = "read:incidents"
    WRITE_INCIDENTS = "write:incidents"
    DELETE_INCIDENTS = "delete:incidents"
    MANAGE_INCIDENTS = "manage:incidents"
    
    READ_PLAYBOOKS = "read:playbooks"
    WRITE_PLAYBOOKS = "write:playbooks"
    DELETE_PLAYBOOKS = "delete:playbooks"
    EXECUTE_PLAYBOOKS = "execute:playbooks"
    
    READ_COMPLIANCE = "read:compliance"
    WRITE_COMPLIANCE = "write:compliance"
    RUN_ASSESSMENTS = "run:assessments"
    
    READ_HUNTING = "read:hunting"
    WRITE_HUNTING = "write:hunting"
    EXECUTE_HUNTS = "execute:hunts"
    
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"
    DELETE_USERS = "delete:users"
    MANAGE_ROLES = "manage:roles"
    
    READ_CONFIG = "read:config"
    WRITE_CONFIG = "write:config"
    
    READ_AUDIT = "read:audit"
    
    ADMIN_TENANT = "admin:tenant"
    ADMIN_SYSTEM = "admin:system"
    
    READ_NETWORK = "read:network"
    WRITE_NETWORK = "write:network"
    BLOCK_IP = "block:ip"
    
    READ_FORENSICS = "read:forensics"
    WRITE_FORENSICS = "write:forensics"
    COLLECT_EVIDENCE = "collect:evidence"


class RoleType(str, Enum):
    SYSTEM_ADMIN = "system_admin"
    TENANT_ADMIN = "tenant_admin"
    SECURITY_ANALYST = "security_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    THREAT_HUNTER = "threat_hunter"
    COMPLIANCE_OFFICER = "compliance_officer"
    SOC_MANAGER = "soc_manager"
    READ_ONLY = "read_only"
    CUSTOM = "custom"


ROLE_PERMISSIONS = {
    RoleType.SYSTEM_ADMIN: list(Permission),
    
    RoleType.TENANT_ADMIN: [
        Permission.READ_THREATS, Permission.WRITE_THREATS, Permission.DELETE_THREATS,
        Permission.READ_ALERTS, Permission.WRITE_ALERTS, Permission.DELETE_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
        Permission.READ_INCIDENTS, Permission.WRITE_INCIDENTS, Permission.DELETE_INCIDENTS, Permission.MANAGE_INCIDENTS,
        Permission.READ_PLAYBOOKS, Permission.WRITE_PLAYBOOKS, Permission.DELETE_PLAYBOOKS, Permission.EXECUTE_PLAYBOOKS,
        Permission.READ_COMPLIANCE, Permission.WRITE_COMPLIANCE, Permission.RUN_ASSESSMENTS,
        Permission.READ_HUNTING, Permission.WRITE_HUNTING, Permission.EXECUTE_HUNTS,
        Permission.READ_USERS, Permission.WRITE_USERS, Permission.DELETE_USERS, Permission.MANAGE_ROLES,
        Permission.READ_CONFIG, Permission.WRITE_CONFIG,
        Permission.READ_AUDIT,
        Permission.ADMIN_TENANT,
        Permission.READ_NETWORK, Permission.WRITE_NETWORK, Permission.BLOCK_IP,
        Permission.READ_FORENSICS, Permission.WRITE_FORENSICS, Permission.COLLECT_EVIDENCE,
    ],
    
    RoleType.SOC_MANAGER: [
        Permission.READ_THREATS, Permission.WRITE_THREATS,
        Permission.READ_ALERTS, Permission.WRITE_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
        Permission.READ_INCIDENTS, Permission.WRITE_INCIDENTS, Permission.MANAGE_INCIDENTS,
        Permission.READ_PLAYBOOKS, Permission.EXECUTE_PLAYBOOKS,
        Permission.READ_COMPLIANCE, Permission.RUN_ASSESSMENTS,
        Permission.READ_HUNTING, Permission.EXECUTE_HUNTS,
        Permission.READ_USERS,
        Permission.READ_CONFIG,
        Permission.READ_AUDIT,
        Permission.READ_NETWORK, Permission.BLOCK_IP,
        Permission.READ_FORENSICS,
    ],
    
    RoleType.SECURITY_ANALYST: [
        Permission.READ_THREATS, Permission.WRITE_THREATS,
        Permission.READ_ALERTS, Permission.WRITE_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
        Permission.READ_INCIDENTS, Permission.WRITE_INCIDENTS,
        Permission.READ_PLAYBOOKS,
        Permission.READ_COMPLIANCE,
        Permission.READ_HUNTING,
        Permission.READ_NETWORK,
        Permission.READ_FORENSICS,
    ],
    
    RoleType.INCIDENT_RESPONDER: [
        Permission.READ_THREATS,
        Permission.READ_ALERTS, Permission.ACKNOWLEDGE_ALERTS,
        Permission.READ_INCIDENTS, Permission.WRITE_INCIDENTS, Permission.MANAGE_INCIDENTS,
        Permission.READ_PLAYBOOKS, Permission.EXECUTE_PLAYBOOKS,
        Permission.READ_NETWORK, Permission.BLOCK_IP,
        Permission.READ_FORENSICS, Permission.WRITE_FORENSICS, Permission.COLLECT_EVIDENCE,
    ],
    
    RoleType.THREAT_HUNTER: [
        Permission.READ_THREATS, Permission.WRITE_THREATS,
        Permission.READ_ALERTS,
        Permission.READ_INCIDENTS,
        Permission.READ_HUNTING, Permission.WRITE_HUNTING, Permission.EXECUTE_HUNTS,
        Permission.READ_NETWORK,
        Permission.READ_FORENSICS,
    ],
    
    RoleType.COMPLIANCE_OFFICER: [
        Permission.READ_THREATS,
        Permission.READ_ALERTS,
        Permission.READ_INCIDENTS,
        Permission.READ_COMPLIANCE, Permission.WRITE_COMPLIANCE, Permission.RUN_ASSESSMENTS,
        Permission.READ_AUDIT,
        Permission.READ_CONFIG,
    ],
    
    RoleType.READ_ONLY: [
        Permission.READ_THREATS,
        Permission.READ_ALERTS,
        Permission.READ_INCIDENTS,
        Permission.READ_PLAYBOOKS,
        Permission.READ_COMPLIANCE,
        Permission.READ_HUNTING,
        Permission.READ_NETWORK,
        Permission.READ_FORENSICS,
    ],
}


@dataclass
class Tenant:
    tenant_id: str
    name: str
    display_name: str
    status: TenantStatus
    created_at: datetime
    updated_at: datetime
    settings: Dict[str, Any]
    quotas: Dict[str, int]
    metadata: Dict[str, Any]
    parent_tenant_id: Optional[str] = None


@dataclass
class Role:
    role_id: str
    tenant_id: str
    name: str
    role_type: RoleType
    permissions: List[Permission]
    description: str
    created_at: datetime
    updated_at: datetime
    is_system: bool = False


@dataclass
class User:
    user_id: str
    tenant_id: str
    username: str
    email: str
    password_hash: str
    status: UserStatus
    roles: List[str]
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]
    mfa_enabled: bool
    metadata: Dict[str, Any]


@dataclass
class APIKey:
    key_id: str
    tenant_id: str
    user_id: Optional[str]
    name: str
    key_hash: str
    key_prefix: str
    permissions: List[Permission]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    is_active: bool


@dataclass
class AuditLog:
    log_id: str
    tenant_id: str
    user_id: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime
    success: bool


class TenantDatabase:
    """SQLite database for tenant management"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or TENANT_DB_PATH
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
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    display_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    settings TEXT,
                    quotas TEXT,
                    metadata TEXT,
                    parent_tenant_id TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    role_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role_type TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_system INTEGER DEFAULT 0,
                    UNIQUE(tenant_id, name)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    roles TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT,
                    mfa_enabled INTEGER DEFAULT 0,
                    metadata TEXT,
                    UNIQUE(tenant_id, username),
                    UNIQUE(tenant_id, email)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TEXT NOT NULL,
                    success INTEGER NOT NULL
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
            
            conn.commit()
    
    def save_tenant(self, tenant: Tenant) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO tenants
                        (tenant_id, name, display_name, status, created_at, updated_at,
                         settings, quotas, metadata, parent_tenant_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        tenant.tenant_id,
                        tenant.name,
                        tenant.display_name,
                        tenant.status.value,
                        tenant.created_at.isoformat(),
                        tenant.updated_at.isoformat(),
                        json.dumps(tenant.settings),
                        json.dumps(tenant.quotas),
                        json.dumps(tenant.metadata),
                        tenant.parent_tenant_id
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save tenant: {e}")
                return False
    
    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_tenant(row)
        except Exception as e:
            logger.error(f"Failed to get tenant: {e}")
        return None
    
    def get_tenant_by_name(self, name: str) -> Optional[Tenant]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM tenants WHERE name = ?", (name,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_tenant(row)
        except Exception as e:
            logger.error(f"Failed to get tenant by name: {e}")
        return None
    
    def _row_to_tenant(self, row: sqlite3.Row) -> Tenant:
        return Tenant(
            tenant_id=row["tenant_id"],
            name=row["name"],
            display_name=row["display_name"],
            status=TenantStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            settings=json.loads(row["settings"]) if row["settings"] else {},
            quotas=json.loads(row["quotas"]) if row["quotas"] else {},
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            parent_tenant_id=row["parent_tenant_id"]
        )
    
    def save_role(self, role: Role) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO roles
                        (role_id, tenant_id, name, role_type, permissions, description,
                         created_at, updated_at, is_system)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        role.role_id,
                        role.tenant_id,
                        role.name,
                        role.role_type.value,
                        json.dumps([p.value for p in role.permissions]),
                        role.description,
                        role.created_at.isoformat(),
                        role.updated_at.isoformat(),
                        1 if role.is_system else 0
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save role: {e}")
                return False
    
    def get_role(self, role_id: str) -> Optional[Role]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM roles WHERE role_id = ?", (role_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_role(row)
        except Exception as e:
            logger.error(f"Failed to get role: {e}")
        return None
    
    def get_roles_by_tenant(self, tenant_id: str) -> List[Role]:
        roles = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM roles WHERE tenant_id = ?", (tenant_id,))
                for row in cursor.fetchall():
                    roles.append(self._row_to_role(row))
        except Exception as e:
            logger.error(f"Failed to get roles: {e}")
        return roles
    
    def _row_to_role(self, row: sqlite3.Row) -> Role:
        return Role(
            role_id=row["role_id"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            role_type=RoleType(row["role_type"]),
            permissions=[Permission(p) for p in json.loads(row["permissions"])],
            description=row["description"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            is_system=bool(row["is_system"])
        )
    
    def save_user(self, user: User) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO users
                        (user_id, tenant_id, username, email, password_hash, status,
                         roles, created_at, updated_at, last_login, mfa_enabled, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        user.user_id,
                        user.tenant_id,
                        user.username,
                        user.email,
                        user.password_hash,
                        user.status.value,
                        json.dumps(user.roles),
                        user.created_at.isoformat(),
                        user.updated_at.isoformat(),
                        user.last_login.isoformat() if user.last_login else None,
                        1 if user.mfa_enabled else 0,
                        json.dumps(user.metadata)
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save user: {e}")
                return False
    
    def get_user(self, user_id: str) -> Optional[User]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_user(row)
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
        return None
    
    def get_user_by_username(self, tenant_id: str, username: str) -> Optional[User]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM users WHERE tenant_id = ? AND username = ?",
                    (tenant_id, username)
                )
                row = cursor.fetchone()
                if row:
                    return self._row_to_user(row)
        except Exception as e:
            logger.error(f"Failed to get user by username: {e}")
        return None
    
    def get_users_by_tenant(self, tenant_id: str) -> List[User]:
        users = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE tenant_id = ?", (tenant_id,))
                for row in cursor.fetchall():
                    users.append(self._row_to_user(row))
        except Exception as e:
            logger.error(f"Failed to get users: {e}")
        return users
    
    def _row_to_user(self, row: sqlite3.Row) -> User:
        return User(
            user_id=row["user_id"],
            tenant_id=row["tenant_id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            status=UserStatus(row["status"]),
            roles=json.loads(row["roles"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
            mfa_enabled=bool(row["mfa_enabled"]),
            metadata=json.loads(row["metadata"]) if row["metadata"] else {}
        )
    
    def save_api_key(self, api_key: APIKey) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO api_keys
                        (key_id, tenant_id, user_id, name, key_hash, key_prefix,
                         permissions, created_at, expires_at, last_used, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        api_key.key_id,
                        api_key.tenant_id,
                        api_key.user_id,
                        api_key.name,
                        api_key.key_hash,
                        api_key.key_prefix,
                        json.dumps([p.value for p in api_key.permissions]),
                        api_key.created_at.isoformat(),
                        api_key.expires_at.isoformat() if api_key.expires_at else None,
                        api_key.last_used.isoformat() if api_key.last_used else None,
                        1 if api_key.is_active else 0
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save API key: {e}")
                return False
    
    def get_api_key_by_hash(self, key_hash: str) -> Optional[APIKey]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_api_key(row)
        except Exception as e:
            logger.error(f"Failed to get API key: {e}")
        return None
    
    def _row_to_api_key(self, row: sqlite3.Row) -> APIKey:
        return APIKey(
            key_id=row["key_id"],
            tenant_id=row["tenant_id"],
            user_id=row["user_id"],
            name=row["name"],
            key_hash=row["key_hash"],
            key_prefix=row["key_prefix"],
            permissions=[Permission(p) for p in json.loads(row["permissions"])],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            last_used=datetime.fromisoformat(row["last_used"]) if row["last_used"] else None,
            is_active=bool(row["is_active"])
        )
    
    def save_audit_log(self, audit_log: AuditLog) -> bool:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO audit_logs
                        (log_id, tenant_id, user_id, action, resource_type, resource_id,
                         details, ip_address, user_agent, timestamp, success)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        audit_log.log_id,
                        audit_log.tenant_id,
                        audit_log.user_id,
                        audit_log.action,
                        audit_log.resource_type,
                        audit_log.resource_id,
                        json.dumps(audit_log.details),
                        audit_log.ip_address,
                        audit_log.user_agent,
                        audit_log.timestamp.isoformat(),
                        1 if audit_log.success else 0
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to save audit log: {e}")
                return False
    
    def get_audit_logs(self, tenant_id: str, limit: int = 100,
                       start_time: datetime = None, end_time: datetime = None) -> List[AuditLog]:
        logs = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM audit_logs WHERE tenant_id = ?"
                params = [tenant_id]
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time.isoformat())
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time.isoformat())
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                for row in cursor.fetchall():
                    logs.append(AuditLog(
                        log_id=row["log_id"],
                        tenant_id=row["tenant_id"],
                        user_id=row["user_id"],
                        action=row["action"],
                        resource_type=row["resource_type"],
                        resource_id=row["resource_id"],
                        details=json.loads(row["details"]) if row["details"] else {},
                        ip_address=row["ip_address"],
                        user_agent=row["user_agent"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        success=bool(row["success"])
                    ))
        except Exception as e:
            logger.error(f"Failed to get audit logs: {e}")
        return logs


class PasswordHasher:
    """Password hashing utility"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(32)
        hash_input = f"{salt}{password}".encode()
        password_hash = hashlib.sha256(hash_input).hexdigest()
        return f"{salt}:{password_hash}"
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, hash_value = stored_hash.split(":")
            hash_input = f"{salt}{password}".encode()
            computed_hash = hashlib.sha256(hash_input).hexdigest()
            return secrets.compare_digest(computed_hash, hash_value)
        except Exception:
            return False


class TenantContext:
    """Thread-local tenant context"""
    
    _local = threading.local()
    
    @classmethod
    def set_tenant(cls, tenant_id: str):
        """Set current tenant"""
        cls._local.tenant_id = tenant_id
    
    @classmethod
    def get_tenant(cls) -> Optional[str]:
        """Get current tenant"""
        return getattr(cls._local, "tenant_id", None)
    
    @classmethod
    def set_user(cls, user_id: str):
        """Set current user"""
        cls._local.user_id = user_id
    
    @classmethod
    def get_user(cls) -> Optional[str]:
        """Get current user"""
        return getattr(cls._local, "user_id", None)
    
    @classmethod
    def set_permissions(cls, permissions: Set[Permission]):
        """Set current permissions"""
        cls._local.permissions = permissions
    
    @classmethod
    def get_permissions(cls) -> Set[Permission]:
        """Get current permissions"""
        return getattr(cls._local, "permissions", set())
    
    @classmethod
    def clear(cls):
        """Clear context"""
        cls._local.tenant_id = None
        cls._local.user_id = None
        cls._local.permissions = set()


@contextmanager
def tenant_context(tenant_id: str, user_id: str = None, permissions: Set[Permission] = None):
    """Context manager for tenant operations"""
    TenantContext.set_tenant(tenant_id)
    if user_id:
        TenantContext.set_user(user_id)
    if permissions:
        TenantContext.set_permissions(permissions)
    try:
        yield
    finally:
        TenantContext.clear()


def require_permission(*required_permissions: Permission):
    """Decorator to require permissions"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_permissions = TenantContext.get_permissions()
            
            for perm in required_permissions:
                if perm not in current_permissions:
                    raise PermissionDeniedError(f"Missing permission: {perm.value}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_tenant():
    """Decorator to require tenant context"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tenant_id = TenantContext.get_tenant()
            if not tenant_id:
                raise TenantRequiredError("Tenant context required")
            return func(*args, **kwargs)
        return wrapper
    return decorator


class PermissionDeniedError(Exception):
    """Raised when permission is denied"""
    pass


class TenantRequiredError(Exception):
    """Raised when tenant context is required"""
    pass


class MultiTenantEngine:
    """Main multi-tenant management engine"""
    
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
        
        self.database = TenantDatabase()
        self._ensure_default_tenant()
    
    def _ensure_default_tenant(self):
        """Ensure default tenant exists"""
        tenant = self.database.get_tenant(DEFAULT_TENANT_ID)
        if not tenant:
            tenant = Tenant(
                tenant_id=DEFAULT_TENANT_ID,
                name="default",
                display_name="Default Organization",
                status=TenantStatus.ACTIVE,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                settings={},
                quotas={
                    "max_users": 100,
                    "max_api_keys": 50,
                    "max_alerts_per_day": 10000,
                    "max_incidents": 1000,
                    "max_playbooks": 100
                },
                metadata={}
            )
            self.database.save_tenant(tenant)
            
            for role_type in RoleType:
                if role_type != RoleType.CUSTOM:
                    self._create_system_role(DEFAULT_TENANT_ID, role_type)
            
            logger.info(f"Created default tenant: {DEFAULT_TENANT_ID}")
    
    def _create_system_role(self, tenant_id: str, role_type: RoleType) -> Role:
        """Create system role for tenant"""
        role = Role(
            role_id=f"ROLE-{tenant_id}-{role_type.value}",
            tenant_id=tenant_id,
            name=role_type.value,
            role_type=role_type,
            permissions=ROLE_PERMISSIONS.get(role_type, []),
            description=f"System role: {role_type.value}",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            is_system=True
        )
        self.database.save_role(role)
        return role
    
    def create_tenant(self, name: str, display_name: str, settings: Dict[str, Any] = None,
                      quotas: Dict[str, int] = None, parent_tenant_id: str = None) -> Tenant:
        """Create new tenant"""
        tenant_id = f"TENANT-{hashlib.sha256(f'{name}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        default_quotas = {
            "max_users": 50,
            "max_api_keys": 25,
            "max_alerts_per_day": 5000,
            "max_incidents": 500,
            "max_playbooks": 50
        }
        
        if quotas:
            default_quotas.update(quotas)
        
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            display_name=display_name,
            status=TenantStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            settings=settings or {},
            quotas=default_quotas,
            metadata={},
            parent_tenant_id=parent_tenant_id
        )
        
        self.database.save_tenant(tenant)
        
        for role_type in RoleType:
            if role_type != RoleType.CUSTOM:
                self._create_system_role(tenant_id, role_type)
        
        self._audit_log(tenant_id, None, "tenant.created", "tenant", tenant_id, {"name": name})
        
        logger.info(f"Created tenant: {tenant_id} ({name})")
        return tenant
    
    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        return self.database.get_tenant(tenant_id)
    
    def update_tenant(self, tenant_id: str, updates: Dict[str, Any]) -> Optional[Tenant]:
        """Update tenant"""
        tenant = self.database.get_tenant(tenant_id)
        if not tenant:
            return None
        
        if "display_name" in updates:
            tenant.display_name = updates["display_name"]
        if "status" in updates:
            tenant.status = TenantStatus(updates["status"])
        if "settings" in updates:
            tenant.settings.update(updates["settings"])
        if "quotas" in updates:
            tenant.quotas.update(updates["quotas"])
        
        tenant.updated_at = datetime.utcnow()
        self.database.save_tenant(tenant)
        
        self._audit_log(tenant_id, None, "tenant.updated", "tenant", tenant_id, updates)
        
        return tenant
    
    def create_user(self, tenant_id: str, username: str, email: str, password: str,
                    roles: List[str] = None, metadata: Dict[str, Any] = None) -> User:
        """Create new user"""
        user_id = f"USER-{hashlib.sha256(f'{tenant_id}{username}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        password_hash = PasswordHasher.hash_password(password)
        
        if not roles:
            roles = [f"ROLE-{tenant_id}-{RoleType.READ_ONLY.value}"]
        
        user = User(
            user_id=user_id,
            tenant_id=tenant_id,
            username=username,
            email=email,
            password_hash=password_hash,
            status=UserStatus.ACTIVE,
            roles=roles,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_login=None,
            mfa_enabled=False,
            metadata=metadata or {}
        )
        
        self.database.save_user(user)
        
        self._audit_log(tenant_id, None, "user.created", "user", user_id, {"username": username})
        
        logger.info(f"Created user: {user_id} ({username}) in tenant {tenant_id}")
        return user
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.database.get_user(user_id)
    
    def authenticate_user(self, tenant_id: str, username: str, password: str) -> Optional[User]:
        """Authenticate user"""
        user = self.database.get_user_by_username(tenant_id, username)
        
        if not user:
            return None
        
        if user.status != UserStatus.ACTIVE:
            return None
        
        if not PasswordHasher.verify_password(password, user.password_hash):
            self._audit_log(tenant_id, user.user_id, "auth.failed", "user", user.user_id, {"reason": "invalid_password"})
            return None
        
        user.last_login = datetime.utcnow()
        self.database.save_user(user)
        
        self._audit_log(tenant_id, user.user_id, "auth.success", "user", user.user_id, {})
        
        return user
    
    def get_user_permissions(self, user: User) -> Set[Permission]:
        """Get all permissions for user"""
        permissions = set()
        
        for role_id in user.roles:
            role = self.database.get_role(role_id)
            if role:
                permissions.update(role.permissions)
        
        return permissions
    
    def check_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has permission"""
        permissions = self.get_user_permissions(user)
        return permission in permissions
    
    def create_role(self, tenant_id: str, name: str, permissions: List[Permission],
                    description: str = "") -> Role:
        """Create custom role"""
        role_id = f"ROLE-{tenant_id}-{hashlib.sha256(f'{name}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:8]}"
        
        role = Role(
            role_id=role_id,
            tenant_id=tenant_id,
            name=name,
            role_type=RoleType.CUSTOM,
            permissions=permissions,
            description=description,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            is_system=False
        )
        
        self.database.save_role(role)
        
        self._audit_log(tenant_id, None, "role.created", "role", role_id, {"name": name})
        
        return role
    
    def create_api_key(self, tenant_id: str, name: str, permissions: List[Permission],
                       user_id: str = None, expires_in_days: int = None) -> Tuple[str, APIKey]:
        """Create API key"""
        key_id = f"KEY-{hashlib.sha256(f'{tenant_id}{name}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        raw_key = f"{API_KEY_PREFIX}{secrets.token_hex(API_KEY_LENGTH // 2)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:12]
        
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        api_key = APIKey(
            key_id=key_id,
            tenant_id=tenant_id,
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            permissions=permissions,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            last_used=None,
            is_active=True
        )
        
        self.database.save_api_key(api_key)
        
        self._audit_log(tenant_id, user_id, "api_key.created", "api_key", key_id, {"name": name})
        
        return raw_key, api_key
    
    def validate_api_key(self, raw_key: str) -> Optional[Tuple[APIKey, Tenant]]:
        """Validate API key and return key info with tenant"""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = self.database.get_api_key_by_hash(key_hash)
        
        if not api_key:
            return None
        
        if not api_key.is_active:
            return None
        
        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
            return None
        
        tenant = self.database.get_tenant(api_key.tenant_id)
        if not tenant or tenant.status != TenantStatus.ACTIVE:
            return None
        
        api_key.last_used = datetime.utcnow()
        self.database.save_api_key(api_key)
        
        return api_key, tenant
    
    def _audit_log(self, tenant_id: str, user_id: Optional[str], action: str,
                   resource_type: str, resource_id: str, details: Dict[str, Any],
                   ip_address: str = None, user_agent: str = None, success: bool = True):
        """Create audit log entry"""
        log = AuditLog(
            log_id=f"AUDIT-{hashlib.sha256(f'{tenant_id}{action}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}",
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow(),
            success=success
        )
        self.database.save_audit_log(log)
    
    def get_audit_logs(self, tenant_id: str, limit: int = 100,
                       start_time: datetime = None, end_time: datetime = None) -> List[AuditLog]:
        """Get audit logs for tenant"""
        return self.database.get_audit_logs(tenant_id, limit, start_time, end_time)
    
    def get_tenant_stats(self, tenant_id: str) -> Dict[str, Any]:
        """Get tenant statistics"""
        users = self.database.get_users_by_tenant(tenant_id)
        roles = self.database.get_roles_by_tenant(tenant_id)
        tenant = self.database.get_tenant(tenant_id)
        
        return {
            "tenant_id": tenant_id,
            "status": tenant.status.value if tenant else "unknown",
            "user_count": len(users),
            "role_count": len(roles),
            "quotas": tenant.quotas if tenant else {},
            "created_at": tenant.created_at.isoformat() if tenant else None
        }


def get_multi_tenant_engine() -> MultiTenantEngine:
    """Get singleton instance of MultiTenantEngine"""
    return MultiTenantEngine()
