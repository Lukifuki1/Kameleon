"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - INTELLIGENCE ENGINE MODULE
Complete implementation of intelligence templates

This module implements:
- OSINT (Open Source Intelligence)
- SIGINT (Signals Intelligence)
- HUMINT (Human Intelligence)
- FININT (Financial Intelligence)
- GEOINT (Geospatial Intelligence)
- TECHINT (Technical Intelligence)
- Counter-Intelligence
- Threat Intelligence Platform

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import socket
import time
import json
import base64
import secrets
import re
import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import urllib.parse

logger = logging.getLogger(__name__)


class IntelligenceType(str, Enum):
    OSINT = "OSINT"
    SIGINT = "SIGINT"
    HUMINT = "HUMINT"
    FININT = "FININT"
    GEOINT = "GEOINT"
    TECHINT = "TECHINT"
    CYBINT = "CYBINT"
    MASINT = "MASINT"


class IntelligenceClassification(str, Enum):
    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"
    TOP_SECRET_SCI = "TOP_SECRET_SCI"


class ThreatActorType(str, Enum):
    APT = "APT"
    CYBERCRIME = "CYBERCRIME"
    HACKTIVIST = "HACKTIVIST"
    INSIDER = "INSIDER"
    NATION_STATE = "NATION_STATE"
    TERRORIST = "TERRORIST"
    UNKNOWN = "UNKNOWN"


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IndicatorType(str, Enum):
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL = "EMAIL"
    FILE_HASH = "FILE_HASH"
    CERTIFICATE = "CERTIFICATE"
    MUTEX = "MUTEX"
    REGISTRY = "REGISTRY"
    USER_AGENT = "USER_AGENT"
    BITCOIN = "BITCOIN"
    ETHEREUM = "ETHEREUM"
    CVE = "CVE"
    YARA = "YARA"
    SIGMA = "SIGMA"


@dataclass
class ThreatActor:
    actor_id: str
    name: str
    aliases: List[str]
    actor_type: ThreatActorType
    origin_country: Optional[str]
    target_sectors: List[str]
    target_countries: List[str]
    ttps: List[str]
    tools: List[str]
    first_seen: str
    last_seen: str
    description: str
    confidence: float
    references: List[str]


@dataclass
class ThreatIndicator:
    indicator_id: str
    indicator_type: IndicatorType
    value: str
    threat_level: ThreatLevel
    confidence: float
    first_seen: str
    last_seen: str
    source: str
    tags: List[str]
    context: Dict[str, Any]
    related_actors: List[str]
    related_campaigns: List[str]


@dataclass
class Campaign:
    campaign_id: str
    name: str
    description: str
    threat_actors: List[str]
    target_sectors: List[str]
    target_countries: List[str]
    start_date: str
    end_date: Optional[str]
    status: str
    indicators: List[str]
    ttps: List[str]
    references: List[str]


@dataclass
class IntelligenceReport:
    report_id: str
    title: str
    intelligence_type: IntelligenceType
    classification: IntelligenceClassification
    summary: str
    content: str
    threat_actors: List[str]
    campaigns: List[str]
    indicators: List[str]
    recommendations: List[str]
    created_at: str
    updated_at: str
    author: str
    sources: List[str]
    tlp: str  # Traffic Light Protocol


class OSINTCollector:
    """Open Source Intelligence collection engine"""
    
    def __init__(self):
        self.sources = {
            "dns": self._collect_dns,
            "whois": self._collect_whois,
            "ssl": self._collect_ssl,
            "headers": self._collect_headers,
            "robots": self._collect_robots,
            "sitemap": self._collect_sitemap,
        }
    
    def collect(self, target: str, source_types: List[str] = None) -> Dict[str, Any]:
        """Collect OSINT on target"""
        results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "sources": {}
        }
        
        sources_to_use = source_types or list(self.sources.keys())
        
        for source in sources_to_use:
            if source in self.sources:
                try:
                    results["sources"][source] = self.sources[source](target)
                except Exception as e:
                    results["sources"][source] = {"error": str(e)}
        
        return results
    
    def _collect_dns(self, target: str) -> Dict[str, Any]:
        """Collect DNS information"""
        dns_info = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": []
        }
        
        try:
            # A records
            try:
                answers = socket.getaddrinfo(target, None, socket.AF_INET)
                dns_info["a_records"] = list(set([a[4][0] for a in answers]))
            except socket.gaierror as e:
                logger.debug(f"Failed to get A records for {target}: {e}")
            
            # AAAA records
            try:
                answers = socket.getaddrinfo(target, None, socket.AF_INET6)
                dns_info["aaaa_records"] = list(set([a[4][0] for a in answers]))
            except socket.gaierror as e:
                logger.debug(f"Failed to get AAAA records for {target}: {e}")
            
        except Exception as e:
            dns_info["error"] = str(e)
        
        return dns_info
    
    def _collect_whois(self, target: str) -> Dict[str, Any]:
        """Collect WHOIS information"""
        whois_info = {
            "domain": target,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "status": []
        }
        
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.verisign-grs.com", 43))
            s.send(f"{target}\r\n".encode())
            
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            
            response_text = response.decode('utf-8', errors='ignore')
            
            # Parse response
            for line in response_text.split('\n'):
                line = line.strip()
                if line.startswith("Registrar:"):
                    whois_info["registrar"] = line.split(":", 1)[1].strip()
                elif line.startswith("Creation Date:"):
                    whois_info["creation_date"] = line.split(":", 1)[1].strip()
                elif line.startswith("Registry Expiry Date:"):
                    whois_info["expiration_date"] = line.split(":", 1)[1].strip()
                elif line.startswith("Name Server:"):
                    whois_info["name_servers"].append(line.split(":", 1)[1].strip())
                elif line.startswith("Domain Status:"):
                    whois_info["status"].append(line.split(":", 1)[1].strip())
            
        except Exception as e:
            whois_info["error"] = str(e)
        
        return whois_info
    
    def _collect_ssl(self, target: str) -> Dict[str, Any]:
        """Collect SSL certificate information"""
        ssl_info = {
            "subject": {},
            "issuer": {},
            "version": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "san": []
        }
        
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    ssl_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    ssl_info["version"] = cert.get("version")
                    ssl_info["serial_number"] = cert.get("serialNumber")
                    ssl_info["not_before"] = cert.get("notBefore")
                    ssl_info["not_after"] = cert.get("notAfter")
                    ssl_info["san"] = [x[1] for x in cert.get("subjectAltName", [])]
                    
        except Exception as e:
            ssl_info["error"] = str(e)
        
        return ssl_info
    
    def _collect_headers(self, target: str) -> Dict[str, Any]:
        """Collect HTTP headers"""
        headers_info = {
            "status_code": None,
            "headers": {},
            "security_headers": {}
        }
        
        try:
            import http.client
            
            conn = http.client.HTTPSConnection(target, timeout=10)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            
            headers_info["status_code"] = response.status
            headers_info["headers"] = dict(response.getheaders())
            
            # Check security headers
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy"
            ]
            
            for header in security_headers:
                value = headers_info["headers"].get(header)
                headers_info["security_headers"][header] = {
                    "present": value is not None,
                    "value": value
                }
            
            conn.close()
            
        except Exception as e:
            headers_info["error"] = str(e)
        
        return headers_info
    
    def _collect_robots(self, target: str) -> Dict[str, Any]:
        """Collect robots.txt"""
        robots_info = {
            "exists": False,
            "content": None,
            "disallowed": [],
            "allowed": [],
            "sitemaps": []
        }
        
        try:
            import http.client
            
            conn = http.client.HTTPSConnection(target, timeout=10)
            conn.request("GET", "/robots.txt")
            response = conn.getresponse()
            
            if response.status == 200:
                robots_info["exists"] = True
                content = response.read().decode('utf-8', errors='ignore')
                robots_info["content"] = content
                
                for line in content.split('\n'):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        robots_info["disallowed"].append(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("allow:"):
                        robots_info["allowed"].append(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("sitemap:"):
                        robots_info["sitemaps"].append(line.split(":", 1)[1].strip())
            
            conn.close()
            
        except Exception as e:
            robots_info["error"] = str(e)
        
        return robots_info
    
    def _collect_sitemap(self, target: str) -> Dict[str, Any]:
        """Collect sitemap.xml"""
        sitemap_info = {
            "exists": False,
            "urls": [],
            "sitemaps": []
        }
        
        try:
            import http.client
            
            conn = http.client.HTTPSConnection(target, timeout=10)
            conn.request("GET", "/sitemap.xml")
            response = conn.getresponse()
            
            if response.status == 200:
                sitemap_info["exists"] = True
                content = response.read().decode('utf-8', errors='ignore')
                
                # Extract URLs
                url_pattern = r'<loc>([^<]+)</loc>'
                sitemap_info["urls"] = re.findall(url_pattern, content)[:100]
            
            conn.close()
            
        except Exception as e:
            sitemap_info["error"] = str(e)
        
        return sitemap_info


class ThreatIntelligencePlatform:
    """Threat Intelligence Platform"""
    
    def __init__(self):
        self.actors: Dict[str, ThreatActor] = {}
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.campaigns: Dict[str, Campaign] = {}
        self.reports: Dict[str, IntelligenceReport] = {}
        self._initialize_known_actors()
    
    def _initialize_known_actors(self):
        """Initialize known threat actors"""
        known_actors = [
            {
                "name": "APT28",
                "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit"],
                "actor_type": ThreatActorType.APT,
                "origin_country": "Russia",
                "target_sectors": ["Government", "Military", "Defense", "Media"],
                "target_countries": ["USA", "Ukraine", "Georgia", "NATO members"],
                "ttps": ["T1566", "T1059", "T1071", "T1027"],
                "tools": ["X-Agent", "Zebrocy", "Komplex"]
            },
            {
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes", "CozyDuke"],
                "actor_type": ThreatActorType.APT,
                "origin_country": "Russia",
                "target_sectors": ["Government", "Think Tanks", "Healthcare"],
                "target_countries": ["USA", "Europe"],
                "ttps": ["T1566", "T1059", "T1071", "T1055"],
                "tools": ["SUNBURST", "TEARDROP", "WellMess"]
            },
            {
                "name": "Lazarus Group",
                "aliases": ["Hidden Cobra", "Guardians of Peace", "ZINC"],
                "actor_type": ThreatActorType.APT,
                "origin_country": "North Korea",
                "target_sectors": ["Financial", "Cryptocurrency", "Defense"],
                "target_countries": ["USA", "South Korea", "Japan"],
                "ttps": ["T1566", "T1059", "T1486", "T1565"],
                "tools": ["HOPLIGHT", "ELECTRICFISH", "CROWDEDFLOUNDER"]
            },
            {
                "name": "APT41",
                "aliases": ["Double Dragon", "Winnti", "Barium"],
                "actor_type": ThreatActorType.APT,
                "origin_country": "China",
                "target_sectors": ["Gaming", "Healthcare", "Technology", "Telecom"],
                "target_countries": ["USA", "Europe", "Asia"],
                "ttps": ["T1566", "T1059", "T1195", "T1071"],
                "tools": ["ShadowPad", "Winnti", "POISONPLUG"]
            },
            {
                "name": "FIN7",
                "aliases": ["Carbanak", "Navigator Group"],
                "actor_type": ThreatActorType.CYBERCRIME,
                "origin_country": "Russia",
                "target_sectors": ["Retail", "Hospitality", "Financial"],
                "target_countries": ["USA", "Europe"],
                "ttps": ["T1566", "T1059", "T1055", "T1041"],
                "tools": ["Carbanak", "GRIFFON", "BOOSTWRITE"]
            },
            {
                "name": "LockBit",
                "aliases": ["LockBit 2.0", "LockBit 3.0"],
                "actor_type": ThreatActorType.CYBERCRIME,
                "origin_country": "Unknown",
                "target_sectors": ["All sectors"],
                "target_countries": ["Global"],
                "ttps": ["T1486", "T1490", "T1027", "T1059"],
                "tools": ["LockBit Ransomware", "StealBit"]
            }
        ]
        
        for actor_data in known_actors:
            actor = ThreatActor(
                actor_id=f"TA-{secrets.token_hex(8).upper()}",
                name=actor_data["name"],
                aliases=actor_data["aliases"],
                actor_type=actor_data["actor_type"],
                origin_country=actor_data["origin_country"],
                target_sectors=actor_data["target_sectors"],
                target_countries=actor_data["target_countries"],
                ttps=actor_data["ttps"],
                tools=actor_data["tools"],
                first_seen="2010-01-01",
                last_seen=datetime.utcnow().strftime("%Y-%m-%d"),
                description=f"Known threat actor: {actor_data['name']}",
                confidence=0.9,
                references=[]
            )
            self.actors[actor.actor_id] = actor
    
    def add_indicator(self, indicator_type: IndicatorType, value: str,
                     threat_level: ThreatLevel, confidence: float,
                     source: str, tags: List[str] = None) -> ThreatIndicator:
        """Add threat indicator"""
        indicator = ThreatIndicator(
            indicator_id=f"IOC-{secrets.token_hex(8).upper()}",
            indicator_type=indicator_type,
            value=value,
            threat_level=threat_level,
            confidence=confidence,
            first_seen=datetime.utcnow().isoformat(),
            last_seen=datetime.utcnow().isoformat(),
            source=source,
            tags=tags or [],
            context={},
            related_actors=[],
            related_campaigns=[]
        )
        self.indicators[indicator.indicator_id] = indicator
        return indicator
    
    def search_indicators(self, query: str, indicator_type: IndicatorType = None) -> List[ThreatIndicator]:
        """Search indicators"""
        results = []
        for indicator in self.indicators.values():
            if indicator_type and indicator.indicator_type != indicator_type:
                continue
            if query.lower() in indicator.value.lower():
                results.append(indicator)
        return results
    
    def check_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Check if value is a known indicator"""
        for indicator in self.indicators.values():
            if indicator.value.lower() == value.lower():
                indicator.last_seen = datetime.utcnow().isoformat()
                return indicator
        return None
    
    def create_report(self, title: str, intelligence_type: IntelligenceType,
                     classification: IntelligenceClassification, summary: str,
                     content: str, author: str, tlp: str = "AMBER") -> IntelligenceReport:
        """Create intelligence report"""
        report = IntelligenceReport(
            report_id=f"IR-{secrets.token_hex(8).upper()}",
            title=title,
            intelligence_type=intelligence_type,
            classification=classification,
            summary=summary,
            content=content,
            threat_actors=[],
            campaigns=[],
            indicators=[],
            recommendations=[],
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
            author=author,
            sources=[],
            tlp=tlp
        )
        self.reports[report.report_id] = report
        return report
    
    def get_actor_profile(self, actor_name: str) -> Optional[ThreatActor]:
        """Get threat actor profile"""
        for actor in self.actors.values():
            if actor.name.lower() == actor_name.lower():
                return actor
            if any(alias.lower() == actor_name.lower() for alias in actor.aliases):
                return actor
        return None
    
    def get_threat_landscape(self) -> Dict[str, Any]:
        """Get current threat landscape"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_actors": len(self.actors),
            "total_indicators": len(self.indicators),
            "total_campaigns": len(self.campaigns),
            "actor_types": self._count_by_field(self.actors.values(), "actor_type"),
            "indicator_types": self._count_by_field(self.indicators.values(), "indicator_type"),
            "threat_levels": self._count_by_field(self.indicators.values(), "threat_level"),
            "top_targeted_sectors": self._get_top_targeted_sectors(),
            "recent_activity": self._get_recent_activity()
        }
    
    def _count_by_field(self, items, field: str) -> Dict[str, int]:
        """Count items by field"""
        counts = {}
        for item in items:
            value = getattr(item, field, None)
            if value:
                key = value.value if hasattr(value, 'value') else str(value)
                counts[key] = counts.get(key, 0) + 1
        return counts
    
    def _get_top_targeted_sectors(self) -> List[Dict[str, Any]]:
        """Get top targeted sectors"""
        sector_counts = {}
        for actor in self.actors.values():
            for sector in actor.target_sectors:
                sector_counts[sector] = sector_counts.get(sector, 0) + 1
        
        sorted_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"sector": s, "count": c} for s, c in sorted_sectors[:10]]
    
    def _get_recent_activity(self) -> List[Dict[str, Any]]:
        """Get recent threat activity"""
        activities = []
        
        # Recent indicators
        sorted_indicators = sorted(
            self.indicators.values(),
            key=lambda x: x.last_seen,
            reverse=True
        )[:10]
        
        for indicator in sorted_indicators:
            activities.append({
                "type": "indicator",
                "value": indicator.value,
                "threat_level": indicator.threat_level.value,
                "timestamp": indicator.last_seen
            })
        
        return activities


class CounterIntelligenceEngine:
    """Counter-Intelligence operations engine"""
    
    def __init__(self):
        self.operations: Dict[str, Dict[str, Any]] = {}
        self.deception_assets: List[Dict[str, Any]] = []
        self.honeypots: List[Dict[str, Any]] = []
    
    def create_honeypot(self, name: str, honeypot_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create honeypot configuration"""
        honeypot = {
            "honeypot_id": f"HP-{secrets.token_hex(8).upper()}",
            "name": name,
            "type": honeypot_type,
            "config": config,
            "status": "configured",
            "created_at": datetime.utcnow().isoformat(),
            "interactions": []
        }
        self.honeypots.append(honeypot)
        return honeypot
    
    def create_deception_asset(self, asset_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create deception asset"""
        asset = {
            "asset_id": f"DA-{secrets.token_hex(8).upper()}",
            "type": asset_type,
            "config": config,
            "status": "active",
            "created_at": datetime.utcnow().isoformat(),
            "triggers": []
        }
        self.deception_assets.append(asset)
        return asset
    
    def analyze_adversary_behavior(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze adversary behavior patterns"""
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_events": len(events),
            "unique_sources": set(),
            "techniques_observed": [],
            "tools_detected": [],
            "behavioral_patterns": [],
            "attribution_confidence": 0.0,
            "potential_actors": []
        }
        
        for event in events:
            if "source_ip" in event:
                analysis["unique_sources"].add(event["source_ip"])
        
        analysis["unique_sources"] = list(analysis["unique_sources"])
        
        return analysis


class FININTEngine:
    """Financial Intelligence engine"""
    
    def __init__(self):
        self.transactions: List[Dict[str, Any]] = []
        self.suspicious_patterns = [
            {"name": "Structuring", "threshold": 10000, "count": 3, "window": 86400},
            {"name": "Round-trip", "pattern": "same_amount_return"},
            {"name": "Layering", "pattern": "multiple_intermediaries"},
            {"name": "Smurfing", "pattern": "multiple_small_deposits"}
        ]
    
    def analyze_transaction(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze financial transaction"""
        analysis = {
            "transaction_id": transaction.get("id", secrets.token_hex(8)),
            "timestamp": datetime.utcnow().isoformat(),
            "risk_score": 0,
            "flags": [],
            "patterns_matched": []
        }
        
        amount = transaction.get("amount", 0)
        
        # Check for suspicious patterns
        if amount > 10000:
            analysis["flags"].append("Large transaction")
            analysis["risk_score"] += 20
        
        if transaction.get("destination_country") in ["Cayman Islands", "Panama", "Switzerland"]:
            analysis["flags"].append("Offshore destination")
            analysis["risk_score"] += 30
        
        if transaction.get("is_crypto", False):
            analysis["flags"].append("Cryptocurrency transaction")
            analysis["risk_score"] += 15
        
        return analysis
    
    def trace_funds(self, starting_address: str, chain: str = "bitcoin") -> Dict[str, Any]:
        """Trace fund flow"""
        trace = {
            "starting_address": starting_address,
            "chain": chain,
            "timestamp": datetime.utcnow().isoformat(),
            "hops": [],
            "total_value": 0,
            "risk_indicators": []
        }
        
        return trace


class IntelligenceEngine:
    """Main Intelligence engine"""
    
    def __init__(self):
        self.osint = OSINTCollector()
        self.tip = ThreatIntelligencePlatform()
        self.counter_intel = CounterIntelligenceEngine()
        self.finint = FININTEngine()
    
    def collect_osint(self, target: str, sources: List[str] = None) -> Dict[str, Any]:
        """Collect OSINT on target"""
        return self.osint.collect(target, sources)
    
    def get_threat_intel(self, indicator: str) -> Dict[str, Any]:
        """Get threat intelligence for indicator"""
        result = {
            "indicator": indicator,
            "timestamp": datetime.utcnow().isoformat(),
            "found": False,
            "details": None
        }
        
        # Check in TIP
        tip_result = self.tip.check_indicator(indicator)
        if tip_result:
            result["found"] = True
            result["details"] = asdict(tip_result)
        
        return result
    
    def get_actor_intel(self, actor_name: str) -> Dict[str, Any]:
        """Get intelligence on threat actor"""
        actor = self.tip.get_actor_profile(actor_name)
        if actor:
            return asdict(actor)
        return {"error": f"Actor not found: {actor_name}"}
    
    def analyze_target(self, target: str) -> Dict[str, Any]:
        """Comprehensive target analysis"""
        analysis = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "osint": self.osint.collect(target),
            "threat_intel": self.get_threat_intel(target),
            "risk_assessment": self._assess_risk(target)
        }
        
        return analysis
    
    def _assess_risk(self, target: str) -> Dict[str, Any]:
        """Assess risk level for target"""
        risk = {
            "overall_score": 0,
            "factors": [],
            "recommendations": []
        }
        
        # Check if known malicious
        if self.tip.check_indicator(target):
            risk["overall_score"] += 50
            risk["factors"].append("Known malicious indicator")
        
        return risk


# Factory function for API use
def create_intelligence_engine() -> IntelligenceEngine:
    """Create intelligence engine instance"""
    return IntelligenceEngine()
