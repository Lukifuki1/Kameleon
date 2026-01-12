"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - AUTHENTICATION & AUTHORIZATION MODULE
Enterprise-grade JWT/OAuth2 authentication with Role-Based Access Control (RBAC)

This module implements:
- JWT token generation and validation
- OAuth2 password flow authentication
- Role-Based Access Control (RBAC)
- Multi-Factor Authentication (MFA) with TOTP
- Session management
- API key management
- Password hashing with Argon2/bcrypt

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set
from enum import Enum
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, ForeignKey, Table
from sqlalchemy.orm import relationship

import pyotp

from app.database import Base, get_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
MFA_ISSUER = os.environ.get("MFA_ISSUER", "TYRANTHOS-TIER0")


class Permission(str, Enum):
    READ_THREATS = "read:threats"
    WRITE_THREATS = "write:threats"
    DELETE_THREATS = "delete:threats"
    READ_INTEL = "read:intel"
    WRITE_INTEL = "write:intel"
    DELETE_INTEL = "delete:intel"
    READ_NODES = "read:nodes"
    WRITE_NODES = "write:nodes"
    DELETE_NODES = "delete:nodes"
    READ_SCANS = "read:scans"
    WRITE_SCANS = "write:scans"
    READ_FORENSICS = "read:forensics"
    WRITE_FORENSICS = "write:forensics"
    READ_OSINT = "read:osint"
    WRITE_OSINT = "write:osint"
    READ_DARKWEB = "read:darkweb"
    WRITE_DARKWEB = "write:darkweb"
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"
    DELETE_USERS = "delete:users"
    ADMIN_SYSTEM = "admin:system"
    ADMIN_AUDIT = "admin:audit"
    ADMIN_CONFIG = "admin:config"
    ENTERPRISE_FULL = "enterprise:full"


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.VIEWER: {
        Permission.READ_THREATS,
        Permission.READ_INTEL,
        Permission.READ_NODES,
        Permission.READ_SCANS,
    },
    Role.ANALYST: {
        Permission.READ_THREATS,
        Permission.WRITE_THREATS,
        Permission.READ_INTEL,
        Permission.WRITE_INTEL,
        Permission.READ_NODES,
        Permission.READ_SCANS,
        Permission.WRITE_SCANS,
        Permission.READ_FORENSICS,
        Permission.READ_OSINT,
    },
    Role.OPERATOR: {
        Permission.READ_THREATS,
        Permission.WRITE_THREATS,
        Permission.DELETE_THREATS,
        Permission.READ_INTEL,
        Permission.WRITE_INTEL,
        Permission.DELETE_INTEL,
        Permission.READ_NODES,
        Permission.WRITE_NODES,
        Permission.READ_SCANS,
        Permission.WRITE_SCANS,
        Permission.READ_FORENSICS,
        Permission.WRITE_FORENSICS,
        Permission.READ_OSINT,
        Permission.WRITE_OSINT,
        Permission.READ_DARKWEB,
    },
    Role.ADMIN: {
        Permission.READ_THREATS,
        Permission.WRITE_THREATS,
        Permission.DELETE_THREATS,
        Permission.READ_INTEL,
        Permission.WRITE_INTEL,
        Permission.DELETE_INTEL,
        Permission.READ_NODES,
        Permission.WRITE_NODES,
        Permission.DELETE_NODES,
        Permission.READ_SCANS,
        Permission.WRITE_SCANS,
        Permission.READ_FORENSICS,
        Permission.WRITE_FORENSICS,
        Permission.READ_OSINT,
        Permission.WRITE_OSINT,
        Permission.READ_DARKWEB,
        Permission.WRITE_DARKWEB,
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.ADMIN_AUDIT,
    },
    Role.SUPER_ADMIN: {p for p in Permission},
}


user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)


class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(64), unique=True, index=True, nullable=False)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(256), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(256))
    department = Column(String(128))
    clearance_level = Column(String(32), default="UNCLASSIFIED")
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(64))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    last_login = Column(DateTime)
    last_password_change = Column(DateTime)
    password_expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(64))
    
    roles = relationship("RoleModel", secondary=user_roles, back_populates="users")
    api_keys = relationship("APIKeyModel", back_populates="user")
    sessions = relationship("SessionModel", back_populates="user")


class RoleModel(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(256))
    permissions = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    users = relationship("UserModel", secondary=user_roles, back_populates="roles")


class APIKeyModel(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    key_id = Column(String(64), unique=True, index=True, nullable=False)
    key_hash = Column(String(256), nullable=False)
    name = Column(String(128), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    permissions = Column(Text)
    rate_limit = Column(Integer, default=1000)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)
    last_used = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("UserModel", back_populates="api_keys")


class SessionModel(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    refresh_token_hash = Column(String(256))
    ip_address = Column(String(64))
    user_agent = Column(String(512))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    last_activity = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("UserModel", back_populates="sessions")


class AuditLogModel(Base):
    __tablename__ = "auth_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    event_type = Column(String(64), nullable=False)
    user_id = Column(String(64))
    username = Column(String(64))
    ip_address = Column(String(64))
    user_agent = Column(String(512))
    resource = Column(String(256))
    action = Column(String(64))
    status = Column(String(32))
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: str


class TokenData(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    session_id: Optional[str] = None


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=12)
    full_name: Optional[str] = None
    department: Optional[str] = None
    clearance_level: str = "UNCLASSIFIED"
    roles: List[str] = [Role.VIEWER.value]


class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    department: Optional[str]
    clearance_level: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    roles: List[str]
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    backup_codes: List[str]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def validate_password_strength(password: str) -> bool:
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    return has_upper and has_lower and has_digit and has_special


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[TokenData]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
        return TokenData(
            user_id=user_id,
            username=payload.get("username"),
            roles=payload.get("roles", []),
            permissions=payload.get("permissions", []),
            session_id=payload.get("session_id")
        )
    except JWTError:
        return None


def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def get_mfa_provisioning_uri(secret: str, username: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=MFA_ISSUER)


def verify_mfa_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_backup_codes(count: int = 10) -> List[str]:
    return [secrets.token_hex(4).upper() for _ in range(count)]


def generate_api_key() -> tuple:
    key = f"tyranthos_{secrets.token_hex(32)}"
    key_id = f"key_{secrets.token_hex(8)}"
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key_id, key, key_hash


class AuthService:
    def __init__(self, db: Session):
        self.db = db
    
    def get_user_by_username(self, username: str) -> Optional[UserModel]:
        return self.db.query(UserModel).filter(UserModel.username == username).first()
    
    def get_user_by_email(self, email: str) -> Optional[UserModel]:
        return self.db.query(UserModel).filter(UserModel.email == email).first()
    
    def get_user_by_id(self, user_id: str) -> Optional[UserModel]:
        return self.db.query(UserModel).filter(UserModel.user_id == user_id).first()
    
    def authenticate_user(self, username: str, password: str) -> Optional[UserModel]:
        user = self.get_user_by_username(username)
        if not user:
            user = self.get_user_by_email(username)
        
        if not user:
            return None
        
        if user.locked_until and user.locked_until > datetime.utcnow():
            return None
        
        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            self.db.commit()
            return None
        
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        return user
    
    def create_user(self, user_data: UserCreate, created_by: str = "system") -> UserModel:
        if not validate_password_strength(user_data.password):
            raise ValueError("Password does not meet security requirements")
        
        if self.get_user_by_username(user_data.username):
            raise ValueError("Username already exists")
        
        if self.get_user_by_email(user_data.email):
            raise ValueError("Email already exists")
        
        user = UserModel(
            user_id=f"user_{secrets.token_hex(16)}",
            username=user_data.username,
            email=user_data.email,
            hashed_password=get_password_hash(user_data.password),
            full_name=user_data.full_name,
            department=user_data.department,
            clearance_level=user_data.clearance_level,
            created_by=created_by,
            last_password_change=datetime.utcnow(),
            password_expires_at=datetime.utcnow() + timedelta(days=90)
        )
        
        for role_name in user_data.roles:
            role = self.db.query(RoleModel).filter(RoleModel.name == role_name).first()
            if role:
                user.roles.append(role)
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        return user
    
    def get_user_permissions(self, user: UserModel) -> Set[str]:
        permissions = set()
        for role in user.roles:
            role_enum = Role(role.name)
            role_perms = ROLE_PERMISSIONS.get(role_enum, set())
            permissions.update(p.value for p in role_perms)
        return permissions
    
    def create_session(self, user: UserModel, request: Request) -> SessionModel:
        session = SessionModel(
            session_id=f"sess_{secrets.token_hex(16)}",
            user_id=user.id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:512],
            expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session
    
    def invalidate_session(self, session_id: str):
        session = self.db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
        if session:
            session.is_active = False
            self.db.commit()
    
    def create_tokens(self, user: UserModel, session: SessionModel) -> Token:
        permissions = list(self.get_user_permissions(user))
        roles = [r.name for r in user.roles]
        
        token_data = {
            "sub": user.user_id,
            "username": user.username,
            "roles": roles,
            "permissions": permissions,
            "session_id": session.session_id,
            "clearance": user.clearance_level
        }
        
        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token({"sub": user.user_id, "session_id": session.session_id})
        
        session.refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        self.db.commit()
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            scope=" ".join(permissions)
        )
    
    def verify_api_key(self, api_key: str) -> Optional[UserModel]:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        api_key_record = self.db.query(APIKeyModel).filter(
            APIKeyModel.key_hash == key_hash,
            APIKeyModel.is_active == True
        ).first()
        
        if not api_key_record:
            return None
        
        if api_key_record.expires_at and api_key_record.expires_at < datetime.utcnow():
            return None
        
        api_key_record.last_used = datetime.utcnow()
        self.db.commit()
        
        return api_key_record.user
    
    def log_auth_event(self, event_type: str, user_id: str = None, username: str = None,
                       request: Request = None, status: str = "success", details: str = None):
        event = AuditLogModel(
            event_id=f"auth_{secrets.token_hex(8)}",
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent", "")[:512] if request else None,
            status=status,
            details=details
        )
        self.db.add(event)
        self.db.commit()


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_header),
    db: Session = Depends(get_db)
) -> UserModel:
    auth_service = AuthService(db)
    
    if api_key:
        user = auth_service.verify_api_key(api_key)
        if user:
            return user
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = decode_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = auth_service.get_user_by_id(token_data.user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


async def get_current_active_user(
    current_user: UserModel = Depends(get_current_user)
) -> UserModel:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_permissions(*required_permissions: Permission):
    async def permission_checker(
        current_user: UserModel = Depends(get_current_active_user),
        db: Session = Depends(get_db)
    ) -> UserModel:
        auth_service = AuthService(db)
        user_permissions = auth_service.get_user_permissions(current_user)
        
        for perm in required_permissions:
            if perm.value not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {perm.value} required"
                )
        
        return current_user
    
    return permission_checker


def require_roles(*required_roles: Role):
    async def role_checker(
        current_user: UserModel = Depends(get_current_active_user)
    ) -> UserModel:
        user_roles = {r.name for r in current_user.roles}
        required_role_names = {r.value for r in required_roles}
        
        if not user_roles.intersection(required_role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {', '.join(required_role_names)}"
            )
        
        return current_user
    
    return role_checker


def require_clearance(min_clearance: str):
    clearance_levels = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET", "TOP_SECRET_SCI"]
    
    async def clearance_checker(
        current_user: UserModel = Depends(get_current_active_user)
    ) -> UserModel:
        user_level = clearance_levels.index(current_user.clearance_level) if current_user.clearance_level in clearance_levels else 0
        required_level = clearance_levels.index(min_clearance) if min_clearance in clearance_levels else 0
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient clearance level: {min_clearance} required"
            )
        
        return current_user
    
    return clearance_checker


def initialize_default_roles(db: Session):
    for role in Role:
        existing = db.query(RoleModel).filter(RoleModel.name == role.value).first()
        if not existing:
            permissions = ROLE_PERMISSIONS.get(role, set())
            role_model = RoleModel(
                name=role.value,
                description=f"{role.value.replace('_', ' ').title()} role",
                permissions=",".join(p.value for p in permissions)
            )
            db.add(role_model)
    db.commit()


def create_default_admin(db: Session):
    auth_service = AuthService(db)
    
    existing = auth_service.get_user_by_username("admin")
    if existing:
        return existing
    
    admin_password = os.environ.get("ADMIN_PASSWORD", secrets.token_urlsafe(16))
    
    admin_user = UserModel(
        user_id=f"user_{secrets.token_hex(16)}",
        username="admin",
        email="admin@tyranthos.local",
        hashed_password=get_password_hash(admin_password),
        full_name="System Administrator",
        department="Security Operations",
        clearance_level="TOP_SECRET_SCI",
        is_active=True,
        is_verified=True,
        created_by="system",
        last_password_change=datetime.utcnow(),
        password_expires_at=datetime.utcnow() + timedelta(days=90)
    )
    
    super_admin_role = db.query(RoleModel).filter(RoleModel.name == Role.SUPER_ADMIN.value).first()
    if super_admin_role:
        admin_user.roles.append(super_admin_role)
    
    db.add(admin_user)
    db.commit()
    
    logger.info(f"Default admin user created. Password: {admin_password}")
    
    return admin_user
