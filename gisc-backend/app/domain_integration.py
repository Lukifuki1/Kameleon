"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - DOMAIN INTEGRATION
Enterprise-grade integration layer connecting all TIER-0 modules

This module provides:
- Unified API for all security domains
- Cross-domain data correlation
- Centralized threat intelligence aggregation
- Authentication and authorization integration
- Rate limiting and encryption integration

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DomainType(str, Enum):
    OSINT = "OSINT"
    HUMINT = "HUMINT"
    SIGINT = "SIGINT"
    THREAT_INTEL = "THREAT_INTEL"
    FORENSICS = "FORENSICS"
    MALWARE_ANALYSIS = "MALWARE_ANALYSIS"
    DARK_WEB = "DARK_WEB"
    NETWORK_SECURITY = "NETWORK_SECURITY"


@dataclass
class DomainStatus:
    domain: DomainType
    available: bool
    status: str
    last_check: str
    capabilities: List[str]
    error: Optional[str] = None


class ThreatIntelligenceIntegration:
    def __init__(self):
        self._client = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.threat_intelligence import get_threat_intelligence_aggregator
            self._client = get_threat_intelligence_aggregator()
            self._available = True
            logger.info("Threat Intelligence integration initialized")
        except ImportError as e:
            logger.warning(f"Threat Intelligence module not available: {e}")
            self._available = False
    
    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Threat Intelligence module not available"}
        return self._client.analyze_ip(ip_address)
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Threat Intelligence module not available"}
        return self._client.analyze_domain(domain)
    
    def analyze_hash(self, file_hash: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Threat Intelligence module not available"}
        return self._client.analyze_hash(file_hash)
    
    def analyze_email(self, email: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Threat Intelligence module not available"}
        return self._client.analyze_email(email)
    
    def get_status(self) -> DomainStatus:
        return DomainStatus(
            domain=DomainType.THREAT_INTEL,
            available=self._available,
            status="operational" if self._available else "unavailable",
            last_check=datetime.utcnow().isoformat(),
            capabilities=["ip_analysis", "domain_analysis", "hash_analysis", "email_analysis"] if self._available else []
        )


class OSINTIntegration:
    def __init__(self):
        self._person_search = None
        self._social_discovery = None
        self._breach_checker = None
        self._aggregator = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.osint_engine import (
                get_person_search_engine,
                get_social_discovery_engine,
                get_breach_checker,
                get_osint_aggregator
            )
            self._person_search = get_person_search_engine()
            self._social_discovery = get_social_discovery_engine()
            self._breach_checker = get_breach_checker()
            self._aggregator = get_osint_aggregator()
            self._available = True
            logger.info("OSINT integration initialized")
        except ImportError as e:
            logger.warning(f"OSINT module not available: {e}")
            self._available = False
    
    def search_person_by_name(self, first_name: str, last_name: str) -> List[Dict[str, Any]]:
        if not self._available:
            return [{"error": "OSINT module not available"}]
        results = self._person_search.search_by_name(first_name, last_name)
        return [asdict(r) for r in results]
    
    def search_person_by_email(self, email: str) -> List[Dict[str, Any]]:
        if not self._available:
            return [{"error": "OSINT module not available"}]
        results = self._person_search.search_by_email(email)
        return [asdict(r) for r in results]
    
    def search_person_by_phone(self, phone: str) -> List[Dict[str, Any]]:
        if not self._available:
            return [{"error": "OSINT module not available"}]
        results = self._person_search.search_by_phone(phone)
        return [asdict(r) for r in results]
    
    def discover_social_profiles(self, username: str) -> List[Dict[str, Any]]:
        if not self._available:
            return [{"error": "OSINT module not available"}]
        results = self._social_discovery.discover_profiles(username)
        return [asdict(r) for r in results]
    
    def check_data_breaches(self, email: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "OSINT module not available"}
        result = self._breach_checker.check_email(email)
        return asdict(result)
    
    def comprehensive_search(self, query: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "OSINT module not available"}
        result = self._aggregator.comprehensive_search(query)
        return asdict(result)
    
    def get_status(self) -> DomainStatus:
        return DomainStatus(
            domain=DomainType.OSINT,
            available=self._available,
            status="operational" if self._available else "unavailable",
            last_check=datetime.utcnow().isoformat(),
            capabilities=[
                "person_search", "social_discovery", "breach_checking", "comprehensive_search"
            ] if self._available else []
        )


class DarkWebIntegration:
    def __init__(self):
        self._connector = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.darkweb_connector import get_darkweb_connector
            self._connector = get_darkweb_connector()
            self._available = True
            logger.info("Dark Web integration initialized")
        except ImportError as e:
            logger.warning(f"Dark Web module not available: {e}")
            self._available = False
    
    def check_tor_connectivity(self) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Dark Web module not available"}
        return self._connector.check_tor_connectivity()
    
    def check_i2p_connectivity(self) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Dark Web module not available"}
        return self._connector.check_i2p_connectivity()
    
    def crawl_onion(self, onion_url: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Dark Web module not available"}
        result = self._connector.crawl_onion(onion_url)
        return asdict(result) if hasattr(result, '__dataclass_fields__') else result
    
    def search_onion_directories(self, query: str) -> List[Dict[str, Any]]:
        if not self._available:
            return [{"error": "Dark Web module not available"}]
        return self._connector.search_onion_directories(query)
    
    def new_tor_identity(self) -> bool:
        if not self._available:
            return False
        return self._connector.new_tor_identity()
    
    def get_status(self) -> DomainStatus:
        return DomainStatus(
            domain=DomainType.DARK_WEB,
            available=self._available,
            status="operational" if self._available else "unavailable",
            last_check=datetime.utcnow().isoformat(),
            capabilities=[
                "tor_connectivity", "i2p_connectivity", "onion_crawling", "directory_search"
            ] if self._available else []
        )


class ForensicsIntegration:
    def __init__(self):
        self._yara_engine = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.yara_engine import get_yara_engine
            self._yara_engine = get_yara_engine()
            self._available = True
            logger.info("Forensics integration initialized")
        except ImportError as e:
            logger.warning(f"Forensics module not available: {e}")
            self._available = False
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Forensics module not available"}
        result = self._yara_engine.scan_file(file_path)
        return asdict(result)
    
    def scan_data(self, data: bytes, identifier: str = "memory") -> Dict[str, Any]:
        if not self._available:
            return {"error": "Forensics module not available"}
        result = self._yara_engine.scan_data(data, identifier)
        return asdict(result)
    
    def list_yara_rules(self) -> List[Dict[str, Any]]:
        if not self._available:
            return [{"error": "Forensics module not available"}]
        rules = self._yara_engine.list_rules()
        return [asdict(r) for r in rules]
    
    def add_yara_rule(self, name: str, source: str, **kwargs) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Forensics module not available"}
        rule = self._yara_engine.add_rule(name, source, **kwargs)
        return asdict(rule)
    
    def get_yara_status(self) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Forensics module not available"}
        return self._yara_engine.get_status()
    
    def get_status(self) -> DomainStatus:
        return DomainStatus(
            domain=DomainType.FORENSICS,
            available=self._available,
            status="operational" if self._available else "unavailable",
            last_check=datetime.utcnow().isoformat(),
            capabilities=[
                "yara_scanning", "file_analysis", "memory_analysis", "rule_management"
            ] if self._available else []
        )


class PersonIntelligenceIntegration:
    def __init__(self):
        self._engine = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.person_intelligence import create_person_intelligence_engine
            self._engine = create_person_intelligence_engine()
            self._available = True
            logger.info("Person Intelligence integration initialized")
        except ImportError as e:
            logger.warning(f"Person Intelligence module not available: {e}")
            self._available = False
    
    def comprehensive_search(self, query: str, scopes: List[str] = None) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Person Intelligence module not available"}
        from app.person_intelligence import SearchScope
        scope_enums = [SearchScope(s) for s in scopes] if scopes else None
        return self._engine.comprehensive_search(query, scope_enums)
    
    def create_profile(self, first_name: str, last_name: str, **kwargs) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Person Intelligence module not available"}
        profile = self._engine.create_person_profile(first_name, last_name, **kwargs)
        return asdict(profile)
    
    def search_by_face(self, image_data: bytes, threshold: float = 0.6) -> List[Dict[str, Any]]:
        if not self._available:
            return [{"error": "Person Intelligence module not available"}]
        return self._engine.search_by_face(image_data, threshold)
    
    def analyze_network(self, person_id: str, depth: int = 2) -> Dict[str, Any]:
        if not self._available:
            return {"error": "Person Intelligence module not available"}
        return self._engine.analyze_person_network(person_id, depth)
    
    def get_status(self) -> DomainStatus:
        if not self._available:
            return DomainStatus(
                domain=DomainType.HUMINT,
                available=False,
                status="unavailable",
                last_check=datetime.utcnow().isoformat(),
                capabilities=[]
            )
        status = self._engine.get_status()
        return DomainStatus(
            domain=DomainType.HUMINT,
            available=True,
            status="operational",
            last_check=datetime.utcnow().isoformat(),
            capabilities=[
                "person_search", "profile_management", "facial_recognition",
                "network_analysis", "social_media_discovery"
            ]
        )


class AuthenticationIntegration:
    def __init__(self):
        self._auth_service = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.auth import get_auth_service
            self._auth_service = get_auth_service()
            self._available = True
            logger.info("Authentication integration initialized")
        except ImportError as e:
            logger.warning(f"Authentication module not available: {e}")
            self._available = False
    
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        if not self._available:
            return None
        return self._auth_service.authenticate(username, password)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        if not self._available:
            return None
        return self._auth_service.verify_token(token)
    
    def check_permission(self, user_id: str, permission: str) -> bool:
        if not self._available:
            return False
        return self._auth_service.check_permission(user_id, permission)
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "available": self._available,
            "status": "operational" if self._available else "unavailable"
        }


class EncryptionIntegration:
    def __init__(self):
        self._encryption_service = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.encryption import get_encryption_service
            self._encryption_service = get_encryption_service()
            self._available = True
            logger.info("Encryption integration initialized")
        except ImportError as e:
            logger.warning(f"Encryption module not available: {e}")
            self._available = False
    
    def encrypt(self, data: bytes) -> Optional[bytes]:
        if not self._available:
            return None
        return self._encryption_service.encrypt(data)
    
    def decrypt(self, encrypted_data: bytes) -> Optional[bytes]:
        if not self._available:
            return None
        return self._encryption_service.decrypt(encrypted_data)
    
    def encrypt_string(self, plaintext: str) -> Optional[str]:
        if not self._available:
            return None
        return self._encryption_service.encrypt_string(plaintext)
    
    def decrypt_string(self, ciphertext: str) -> Optional[str]:
        if not self._available:
            return None
        return self._encryption_service.decrypt_string(ciphertext)
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "available": self._available,
            "status": "operational" if self._available else "unavailable"
        }


class RateLimiterIntegration:
    def __init__(self):
        self._rate_limiter = None
        self._available = False
        self._initialize()
    
    def _initialize(self):
        try:
            from app.rate_limiter import get_rate_limiter
            self._rate_limiter = get_rate_limiter()
            self._available = True
            logger.info("Rate Limiter integration initialized")
        except ImportError as e:
            logger.warning(f"Rate Limiter module not available: {e}")
            self._available = False
    
    def check_rate_limit(self, identifier: str, tier: str = "free") -> Dict[str, Any]:
        if not self._available:
            return {"allowed": True, "reason": "Rate limiting not available"}
        return self._rate_limiter.check_rate_limit(identifier, tier)
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "available": self._available,
            "status": "operational" if self._available else "unavailable"
        }


class DomainIntegrationHub:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.threat_intel = ThreatIntelligenceIntegration()
        self.osint = OSINTIntegration()
        self.dark_web = DarkWebIntegration()
        self.forensics = ForensicsIntegration()
        self.person_intel = PersonIntelligenceIntegration()
        self.auth = AuthenticationIntegration()
        self.encryption = EncryptionIntegration()
        self.rate_limiter = RateLimiterIntegration()
        
        logger.info("Domain Integration Hub initialized")
    
    def get_all_domain_statuses(self) -> Dict[str, DomainStatus]:
        return {
            "threat_intel": self.threat_intel.get_status(),
            "osint": self.osint.get_status(),
            "dark_web": self.dark_web.get_status(),
            "forensics": self.forensics.get_status(),
            "person_intel": self.person_intel.get_status(),
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        domain_statuses = self.get_all_domain_statuses()
        
        available_count = sum(1 for s in domain_statuses.values() if s.available)
        total_count = len(domain_statuses)
        
        return {
            "system_status": "OPERATIONAL" if available_count == total_count else "DEGRADED" if available_count > 0 else "OFFLINE",
            "domains_available": available_count,
            "domains_total": total_count,
            "domain_statuses": {k: asdict(v) for k, v in domain_statuses.items()},
            "auth_status": self.auth.get_status(),
            "encryption_status": self.encryption.get_status(),
            "rate_limiter_status": self.rate_limiter.get_status(),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def correlate_threat_data(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        results = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "correlations": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if indicator_type == "ip":
            results["correlations"]["threat_intel"] = self.threat_intel.analyze_ip(indicator)
        elif indicator_type == "domain":
            results["correlations"]["threat_intel"] = self.threat_intel.analyze_domain(indicator)
        elif indicator_type == "hash":
            results["correlations"]["threat_intel"] = self.threat_intel.analyze_hash(indicator)
        elif indicator_type == "email":
            results["correlations"]["threat_intel"] = self.threat_intel.analyze_email(indicator)
            results["correlations"]["osint"] = self.osint.check_data_breaches(indicator)
        
        return results
    
    def comprehensive_person_investigation(self, query: str) -> Dict[str, Any]:
        results = {
            "query": query,
            "osint_results": self.osint.comprehensive_search(query),
            "person_intel_results": self.person_intel.comprehensive_search(query),
            "timestamp": datetime.utcnow().isoformat()
        }
        return results
    
    def dark_web_investigation(self, query: str) -> Dict[str, Any]:
        results = {
            "query": query,
            "tor_status": self.dark_web.check_tor_connectivity(),
            "i2p_status": self.dark_web.check_i2p_connectivity(),
            "directory_results": self.dark_web.search_onion_directories(query),
            "timestamp": datetime.utcnow().isoformat()
        }
        return results
    
    def forensic_analysis(self, file_path: str = None, data: bytes = None) -> Dict[str, Any]:
        results = {
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if file_path:
            results["yara_scan"] = self.forensics.scan_file(file_path)
        elif data:
            results["yara_scan"] = self.forensics.scan_data(data)
        
        return results


def get_domain_integration_hub() -> DomainIntegrationHub:
    return DomainIntegrationHub()
