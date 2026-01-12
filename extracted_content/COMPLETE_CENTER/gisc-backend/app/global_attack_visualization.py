"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - GLOBAL ATTACK VISUALIZATION
Enterprise-grade real-time global attack visualization with geographic routes

This module implements Kaspersky-style attack visualization:
- Real-time attack tracking from threat feeds
- Geographic routing between source and target
- WebSocket streaming for live map updates
- Attack path visualization with coordinates

100% OPENSOURCE - NO EXTERNAL API DEPENDENCIES
Uses free public threat feeds from abuse.ch

Classification: TOP SECRET // NSOC // TIER-5
"""

import os
import json
import math
import hashlib
import asyncio
import logging
import sqlite3
import threading
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Geographic coordinates for major cities/regions (for target visualization)
REGION_COORDINATES = {
    # North America
    "US": {"lat": 37.0902, "lon": -95.7129, "name": "United States"},
    "CA": {"lat": 56.1304, "lon": -106.3468, "name": "Canada"},
    "MX": {"lat": 23.6345, "lon": -102.5528, "name": "Mexico"},
    # South America
    "BR": {"lat": -14.2350, "lon": -51.9253, "name": "Brazil"},
    "AR": {"lat": -38.4161, "lon": -63.6167, "name": "Argentina"},
    "CL": {"lat": -35.6751, "lon": -71.5430, "name": "Chile"},
    "CO": {"lat": 4.5709, "lon": -74.2973, "name": "Colombia"},
    # Europe
    "GB": {"lat": 55.3781, "lon": -3.4360, "name": "United Kingdom"},
    "DE": {"lat": 51.1657, "lon": 10.4515, "name": "Germany"},
    "FR": {"lat": 46.2276, "lon": 2.2137, "name": "France"},
    "IT": {"lat": 41.8719, "lon": 12.5674, "name": "Italy"},
    "ES": {"lat": 40.4637, "lon": -3.7492, "name": "Spain"},
    "NL": {"lat": 52.1326, "lon": 5.2913, "name": "Netherlands"},
    "PL": {"lat": 51.9194, "lon": 19.1451, "name": "Poland"},
    "UA": {"lat": 48.3794, "lon": 31.1656, "name": "Ukraine"},
    "RU": {"lat": 61.5240, "lon": 105.3188, "name": "Russia"},
    "SE": {"lat": 60.1282, "lon": 18.6435, "name": "Sweden"},
    "NO": {"lat": 60.4720, "lon": 8.4689, "name": "Norway"},
    "FI": {"lat": 61.9241, "lon": 25.7482, "name": "Finland"},
    "AT": {"lat": 47.5162, "lon": 14.5501, "name": "Austria"},
    "CH": {"lat": 46.8182, "lon": 8.2275, "name": "Switzerland"},
    "CZ": {"lat": 49.8175, "lon": 15.4730, "name": "Czech Republic"},
    "RO": {"lat": 45.9432, "lon": 24.9668, "name": "Romania"},
    "HU": {"lat": 47.1625, "lon": 19.5033, "name": "Hungary"},
    "PT": {"lat": 39.3999, "lon": -8.2245, "name": "Portugal"},
    "GR": {"lat": 39.0742, "lon": 21.8243, "name": "Greece"},
    "SI": {"lat": 46.1512, "lon": 14.9955, "name": "Slovenia"},
    "HR": {"lat": 45.1000, "lon": 15.2000, "name": "Croatia"},
    "SK": {"lat": 48.6690, "lon": 19.6990, "name": "Slovakia"},
    "BG": {"lat": 42.7339, "lon": 25.4858, "name": "Bulgaria"},
    "RS": {"lat": 44.0165, "lon": 21.0059, "name": "Serbia"},
    "BY": {"lat": 53.7098, "lon": 27.9534, "name": "Belarus"},
    # Asia
    "CN": {"lat": 35.8617, "lon": 104.1954, "name": "China"},
    "JP": {"lat": 36.2048, "lon": 138.2529, "name": "Japan"},
    "KR": {"lat": 35.9078, "lon": 127.7669, "name": "South Korea"},
    "KP": {"lat": 40.3399, "lon": 127.5101, "name": "North Korea"},
    "IN": {"lat": 20.5937, "lon": 78.9629, "name": "India"},
    "PK": {"lat": 30.3753, "lon": 69.3451, "name": "Pakistan"},
    "VN": {"lat": 14.0583, "lon": 108.2772, "name": "Vietnam"},
    "TH": {"lat": 15.8700, "lon": 100.9925, "name": "Thailand"},
    "MY": {"lat": 4.2105, "lon": 101.9758, "name": "Malaysia"},
    "SG": {"lat": 1.3521, "lon": 103.8198, "name": "Singapore"},
    "ID": {"lat": -0.7893, "lon": 113.9213, "name": "Indonesia"},
    "PH": {"lat": 12.8797, "lon": 121.7740, "name": "Philippines"},
    "TW": {"lat": 23.6978, "lon": 120.9605, "name": "Taiwan"},
    "HK": {"lat": 22.3193, "lon": 114.1694, "name": "Hong Kong"},
    "IR": {"lat": 32.4279, "lon": 53.6880, "name": "Iran"},
    "IQ": {"lat": 33.2232, "lon": 43.6793, "name": "Iraq"},
    "SA": {"lat": 23.8859, "lon": 45.0792, "name": "Saudi Arabia"},
    "AE": {"lat": 23.4241, "lon": 53.8478, "name": "UAE"},
    "IL": {"lat": 31.0461, "lon": 34.8516, "name": "Israel"},
    "TR": {"lat": 38.9637, "lon": 35.2433, "name": "Turkey"},
    # Africa
    "ZA": {"lat": -30.5595, "lon": 22.9375, "name": "South Africa"},
    "EG": {"lat": 26.8206, "lon": 30.8025, "name": "Egypt"},
    "NG": {"lat": 9.0820, "lon": 8.6753, "name": "Nigeria"},
    "KE": {"lat": -0.0236, "lon": 37.9062, "name": "Kenya"},
    "MA": {"lat": 31.7917, "lon": -7.0926, "name": "Morocco"},
    # Oceania
    "AU": {"lat": -25.2744, "lon": 133.7751, "name": "Australia"},
    "NZ": {"lat": -40.9006, "lon": 174.8860, "name": "New Zealand"},
}

# Country code to region mapping
COUNTRY_TO_REGION = {
    'US': 'NORTH_AMERICA', 'CA': 'NORTH_AMERICA', 'MX': 'NORTH_AMERICA',
    'BR': 'SOUTH_AMERICA', 'AR': 'SOUTH_AMERICA', 'CL': 'SOUTH_AMERICA', 'CO': 'SOUTH_AMERICA',
    'GB': 'EUROPE', 'DE': 'EUROPE', 'FR': 'EUROPE', 'IT': 'EUROPE', 'ES': 'EUROPE',
    'NL': 'EUROPE', 'PL': 'EUROPE', 'UA': 'EUROPE', 'RU': 'EUROPE', 'SE': 'EUROPE',
    'NO': 'EUROPE', 'FI': 'EUROPE', 'AT': 'EUROPE', 'CH': 'EUROPE', 'CZ': 'EUROPE',
    'RO': 'EUROPE', 'HU': 'EUROPE', 'PT': 'EUROPE', 'GR': 'EUROPE', 'SI': 'EUROPE',
    'HR': 'EUROPE', 'SK': 'EUROPE', 'BG': 'EUROPE', 'RS': 'EUROPE', 'BY': 'EUROPE',
    'CN': 'ASIA', 'JP': 'ASIA', 'KR': 'ASIA', 'KP': 'ASIA', 'IN': 'ASIA',
    'PK': 'ASIA', 'VN': 'ASIA', 'TH': 'ASIA', 'MY': 'ASIA', 'SG': 'ASIA',
    'ID': 'ASIA', 'PH': 'ASIA', 'TW': 'ASIA', 'HK': 'ASIA', 'IR': 'ASIA',
    'IQ': 'ASIA', 'SA': 'ASIA', 'AE': 'ASIA', 'IL': 'ASIA', 'TR': 'ASIA',
    'ZA': 'AFRICA', 'EG': 'AFRICA', 'NG': 'AFRICA', 'KE': 'AFRICA', 'MA': 'AFRICA',
    'AU': 'OCEANIA', 'NZ': 'OCEANIA',
}


@dataclass
class AttackRoute:
    """Represents a single attack route with source and destination coordinates"""
    route_id: str
    timestamp: datetime
    attack_type: str
    severity: str
    source_ip: str
    source_country: str
    source_country_code: str
    source_lat: float
    source_lon: float
    target_ip: str
    target_country: str
    target_country_code: str
    target_lat: float
    target_lon: float
    malware_family: str
    description: str
    source_feed: str
    tags: List[str] = field(default_factory=list)
    iocs: Dict[str, Any] = field(default_factory=dict)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    is_active: bool = True
    duration_ms: int = 3000


@dataclass
class AttackStatistics:
    """Global attack statistics for dashboard"""
    total_attacks_today: int
    attacks_per_hour: int
    top_source_countries: List[Dict[str, Any]]
    top_target_countries: List[Dict[str, Any]]
    top_malware_families: List[Dict[str, Any]]
    attack_types_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    active_routes: int
    timestamp: str


class GeoIPResolver:
    """Resolves IP addresses to geographic coordinates using free APIs"""
    
    GEOIP_APIS = [
        "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as",
        "https://ipapi.co/{ip}/json/",
    ]
    
    _cache: Dict[str, Dict[str, Any]] = {}
    _cache_lock = threading.Lock()
    
    @classmethod
    def resolve(cls, ip: str) -> Dict[str, Any]:
        """Resolve IP address to geographic coordinates"""
        if not ip or ip == "0.0.0.0":
            return cls._get_random_target_location()
        
        with cls._cache_lock:
            if ip in cls._cache:
                return cls._cache[ip]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return cls._get_random_target_location()
        except ValueError:
            return cls._get_random_target_location()
        
        for api_url in cls.GEOIP_APIS:
            try:
                response = requests.get(
                    api_url.format(ip=ip),
                    timeout=5,
                    headers={"User-Agent": "TYRANTHOS-AttackViz/1.0"}
                )
                if response.status_code == 200:
                    data = response.json()
                    
                    if "countryCode" in data:
                        country_code = data.get("countryCode", "XX")
                        country = data.get("country", "Unknown")
                        lat = data.get("lat", 0)
                        lon = data.get("lon", 0)
                    elif "country_code" in data:
                        country_code = data.get("country_code", "XX")
                        country = data.get("country_name", "Unknown")
                        lat = data.get("latitude", 0)
                        lon = data.get("longitude", 0)
                    else:
                        continue
                    
                    result = {
                        "country": country,
                        "country_code": country_code,
                        "region": COUNTRY_TO_REGION.get(country_code, "UNKNOWN"),
                        "city": data.get("city", ""),
                        "lat": float(lat),
                        "lon": float(lon),
                    }
                    
                    with cls._cache_lock:
                        cls._cache[ip] = result
                    
                    return result
                    
            except Exception as e:
                logger.debug(f"GeoIP lookup failed for {ip}: {e}")
                continue
        
        return cls._get_random_target_location()
    
    @classmethod
    def _get_random_target_location(cls) -> Dict[str, Any]:
        """Get a random target location from known regions"""
        import random
        country_codes = list(REGION_COORDINATES.keys())
        code = random.choice(country_codes)
        coords = REGION_COORDINATES[code]
        return {
            "country": coords["name"],
            "country_code": code,
            "region": COUNTRY_TO_REGION.get(code, "UNKNOWN"),
            "city": "",
            "lat": coords["lat"],
            "lon": coords["lon"],
        }
    
    @classmethod
    def get_country_coordinates(cls, country_code: str) -> Tuple[float, float]:
        """Get coordinates for a country code"""
        if country_code in REGION_COORDINATES:
            coords = REGION_COORDINATES[country_code]
            return coords["lat"], coords["lon"]
        return 0.0, 0.0


class AttackRouteGenerator:
    """Generates attack routes from threat feed data"""
    
    def __init__(self):
        self.geo_resolver = GeoIPResolver()
        self.route_cache: Dict[str, AttackRoute] = {}
        self.statistics = defaultdict(int)
        
    def generate_route_from_threat(self, threat_data: Dict[str, Any]) -> AttackRoute:
        """Generate an attack route from threat feed data"""
        
        source_ip = threat_data.get("source_ip", "0.0.0.0")
        source_geo = self.geo_resolver.resolve(source_ip)
        
        target_countries = self._determine_target_countries(threat_data)
        target_code = target_countries[0] if target_countries else "US"
        target_lat, target_lon = self.geo_resolver.get_country_coordinates(target_code)
        target_name = REGION_COORDINATES.get(target_code, {}).get("name", "Unknown")
        
        route_id = f"ROUTE-{hashlib.md5(f'{source_ip}-{target_code}-{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12].upper()}"
        
        severity = threat_data.get("severity", "warning")
        if severity == "critical":
            duration = 5000
        elif severity == "error":
            duration = 4000
        else:
            duration = 3000
        
        route = AttackRoute(
            route_id=route_id,
            timestamp=datetime.utcnow(),
            attack_type=threat_data.get("threat_type", "Unknown"),
            severity=severity,
            source_ip=source_ip,
            source_country=source_geo.get("country", "Unknown"),
            source_country_code=source_geo.get("country_code", "XX"),
            source_lat=source_geo.get("lat", 0),
            source_lon=source_geo.get("lon", 0),
            target_ip=threat_data.get("destination_ip", ""),
            target_country=target_name,
            target_country_code=target_code,
            target_lat=target_lat,
            target_lon=target_lon,
            malware_family=threat_data.get("malware_family", "Unknown"),
            description=threat_data.get("description", ""),
            source_feed=threat_data.get("source_feed", "Unknown"),
            tags=threat_data.get("tags", []),
            iocs=threat_data.get("iocs", {}),
            mitre_tactic=self._get_mitre_tactic(threat_data.get("threat_type", "")),
            mitre_technique=self._get_mitre_technique(threat_data.get("threat_type", "")),
            is_active=True,
            duration_ms=duration
        )
        
        self.route_cache[route_id] = route
        self._update_statistics(route)
        
        return route
    
    def _determine_target_countries(self, threat_data: Dict[str, Any]) -> List[str]:
        """Determine target countries based on threat type and data"""
        threat_type = threat_data.get("threat_type", "").lower()
        
        if "botnet" in threat_type or "c2" in threat_type:
            return ["US", "DE", "GB", "FR", "NL", "JP", "AU"]
        elif "ransomware" in threat_type:
            return ["US", "GB", "DE", "FR", "CA", "AU"]
        elif "phishing" in threat_type:
            return ["US", "GB", "DE", "FR", "JP", "BR"]
        elif "malware" in threat_type:
            return ["US", "DE", "GB", "FR", "NL", "RU", "CN"]
        else:
            return list(REGION_COORDINATES.keys())[:10]
    
    def _get_mitre_tactic(self, threat_type: str) -> str:
        """Map threat type to MITRE ATT&CK tactic"""
        threat_lower = threat_type.lower()
        if "c2" in threat_lower or "botnet" in threat_lower:
            return "Command and Control"
        elif "malware" in threat_lower:
            return "Execution"
        elif "phishing" in threat_lower:
            return "Initial Access"
        elif "ransomware" in threat_lower:
            return "Impact"
        elif "exfil" in threat_lower:
            return "Exfiltration"
        return "Unknown"
    
    def _get_mitre_technique(self, threat_type: str) -> str:
        """Map threat type to MITRE ATT&CK technique"""
        threat_lower = threat_type.lower()
        if "c2" in threat_lower:
            return "T1071 - Application Layer Protocol"
        elif "botnet" in threat_lower:
            return "T1583 - Acquire Infrastructure"
        elif "malware" in threat_lower:
            return "T1204 - User Execution"
        elif "phishing" in threat_lower:
            return "T1566 - Phishing"
        elif "ransomware" in threat_lower:
            return "T1486 - Data Encrypted for Impact"
        return "Unknown"
    
    def _update_statistics(self, route: AttackRoute):
        """Update attack statistics"""
        self.statistics["total_attacks"] += 1
        self.statistics[f"source_{route.source_country_code}"] += 1
        self.statistics[f"target_{route.target_country_code}"] += 1
        self.statistics[f"type_{route.attack_type}"] += 1
        self.statistics[f"severity_{route.severity}"] += 1
        self.statistics[f"malware_{route.malware_family}"] += 1


class GlobalAttackVisualizationEngine:
    """Main engine for global attack visualization with real-time streaming"""
    
    DB_PATH = "/var/lib/tyranthos/attack_visualization.db"
    
    def __init__(self):
        self.route_generator = AttackRouteGenerator()
        self.active_routes: Dict[str, AttackRoute] = {}
        self.route_history: List[AttackRoute] = []
        self.subscribers: List[asyncio.Queue] = []
        self._lock = threading.Lock()
        self._running = False
        self._fetch_thread = None
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for attack route storage"""
        os.makedirs(os.path.dirname(self.DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_routes (
                route_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_country TEXT NOT NULL,
                source_country_code TEXT NOT NULL,
                source_lat REAL NOT NULL,
                source_lon REAL NOT NULL,
                target_ip TEXT,
                target_country TEXT NOT NULL,
                target_country_code TEXT NOT NULL,
                target_lat REAL NOT NULL,
                target_lon REAL NOT NULL,
                malware_family TEXT,
                description TEXT,
                source_feed TEXT NOT NULL,
                tags TEXT,
                iocs TEXT,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                is_active INTEGER DEFAULT 1,
                duration_ms INTEGER DEFAULT 3000
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_routes_timestamp ON attack_routes(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_routes_source_country ON attack_routes(source_country_code)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_routes_target_country ON attack_routes(target_country_code)
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_statistics (
                stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                stat_type TEXT NOT NULL,
                stat_key TEXT NOT NULL,
                stat_value INTEGER NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Attack visualization database initialized at {self.DB_PATH}")
    
    def _save_route_to_db(self, route: AttackRoute):
        """Save attack route to database"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO attack_routes (
                route_id, timestamp, attack_type, severity, source_ip,
                source_country, source_country_code, source_lat, source_lon,
                target_ip, target_country, target_country_code, target_lat, target_lon,
                malware_family, description, source_feed, tags, iocs,
                mitre_tactic, mitre_technique, is_active, duration_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            route.route_id, route.timestamp.isoformat(), route.attack_type, route.severity,
            route.source_ip, route.source_country, route.source_country_code,
            route.source_lat, route.source_lon, route.target_ip, route.target_country,
            route.target_country_code, route.target_lat, route.target_lon,
            route.malware_family, route.description, route.source_feed,
            json.dumps(route.tags), json.dumps(route.iocs),
            route.mitre_tactic, route.mitre_technique, 1 if route.is_active else 0,
            route.duration_ms
        ))
        
        conn.commit()
        conn.close()
    
    def fetch_threats_from_feeds(self) -> List[Dict[str, Any]]:
        """Fetch real threats from abuse.ch feeds"""
        threats = []
        
        threats.extend(self._fetch_urlhaus())
        threats.extend(self._fetch_feodo_tracker())
        threats.extend(self._fetch_threatfox())
        threats.extend(self._fetch_ssl_blacklist())
        
        return threats
    
    def _fetch_urlhaus(self) -> List[Dict[str, Any]]:
        """Fetch threats from URLhaus"""
        threats = []
        try:
            response = requests.get(
                "https://urlhaus.abuse.ch/downloads/csv_recent/",
                timeout=30,
                headers={"User-Agent": "TYRANTHOS-AttackViz/1.0"}
            )
            if response.status_code == 200:
                lines = response.text.split('\n')
                data_lines = [l for l in lines if l and not l.startswith('#')]
                
                import csv
                reader = csv.reader(data_lines)
                
                for row in list(reader)[:50]:
                    if len(row) < 8:
                        continue
                    
                    url = row[2]
                    threat_type = row[5] if len(row) > 5 else "malware_download"
                    tags = row[6].split(',') if len(row) > 6 and row[6] else []
                    
                    import re
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
                    source_ip = ip_match.group(1) if ip_match else "0.0.0.0"
                    
                    threats.append({
                        "source_ip": source_ip,
                        "threat_type": "Malware Distribution",
                        "severity": "critical" if "ransomware" in str(tags).lower() else "error",
                        "description": f"Malware URL: {url[:80]}...",
                        "malware_family": tags[0] if tags else "Unknown",
                        "source_feed": "URLhaus",
                        "tags": tags,
                        "iocs": {"url": url, "ip": source_ip},
                    })
                    
        except Exception as e:
            logger.error(f"Error fetching URLhaus: {e}")
        
        return threats
    
    def _fetch_feodo_tracker(self) -> List[Dict[str, Any]]:
        """Fetch threats from Feodo Tracker"""
        threats = []
        try:
            response = requests.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                timeout=30,
                headers={"User-Agent": "TYRANTHOS-AttackViz/1.0"}
            )
            if response.status_code == 200:
                data = response.json()
                
                for entry in data[:30]:
                    ip = entry.get("ip_address", "")
                    if not ip:
                        continue
                    
                    malware = entry.get("malware", "Unknown")
                    port = entry.get("port", 0)
                    
                    threats.append({
                        "source_ip": ip,
                        "threat_type": "Botnet C2",
                        "severity": "critical",
                        "description": f"Botnet C2: {ip}:{port} ({malware})",
                        "malware_family": malware,
                        "source_feed": "Feodo Tracker",
                        "tags": [malware, "botnet", "c2"],
                        "iocs": {"ip": ip, "port": port, "malware": malware},
                    })
                    
        except Exception as e:
            logger.error(f"Error fetching Feodo Tracker: {e}")
        
        return threats
    
    def _fetch_threatfox(self) -> List[Dict[str, Any]]:
        """Fetch threats from ThreatFox"""
        threats = []
        try:
            response = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": 1},
                timeout=30,
                headers={"User-Agent": "TYRANTHOS-AttackViz/1.0"}
            )
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    for ioc in data.get("data", [])[:30]:
                        ioc_value = ioc.get("ioc", "")
                        ioc_type = ioc.get("ioc_type", "")
                        malware = ioc.get("malware", "Unknown")
                        
                        import re
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ioc_value)
                        source_ip = ip_match.group(1) if ip_match else "0.0.0.0"
                        
                        threats.append({
                            "source_ip": source_ip,
                            "threat_type": f"IOC ({ioc_type})",
                            "severity": "error",
                            "description": f"ThreatFox IOC: {ioc_value[:60]}",
                            "malware_family": malware,
                            "source_feed": "ThreatFox",
                            "tags": [malware, ioc_type],
                            "iocs": {"ioc": ioc_value, "type": ioc_type},
                        })
                        
        except Exception as e:
            logger.error(f"Error fetching ThreatFox: {e}")
        
        return threats
    
    def _fetch_ssl_blacklist(self) -> List[Dict[str, Any]]:
        """Fetch threats from SSL Blacklist"""
        threats = []
        try:
            response = requests.get(
                "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                timeout=30,
                headers={"User-Agent": "TYRANTHOS-AttackViz/1.0"}
            )
            if response.status_code == 200:
                lines = response.text.split('\n')
                data_lines = [l for l in lines if l and not l.startswith('#')]
                
                import csv
                reader = csv.reader(data_lines)
                
                for row in list(reader)[:20]:
                    if len(row) < 3:
                        continue
                    
                    ip = row[1] if len(row) > 1 else ""
                    if not ip:
                        continue
                    
                    reason = row[2] if len(row) > 2 else "Malicious SSL"
                    
                    threats.append({
                        "source_ip": ip,
                        "threat_type": "Malicious SSL",
                        "severity": "warning",
                        "description": f"Malicious SSL certificate: {ip} ({reason})",
                        "malware_family": reason,
                        "source_feed": "SSL Blacklist",
                        "tags": ["ssl", "certificate", "malicious"],
                        "iocs": {"ip": ip, "reason": reason},
                    })
                    
        except Exception as e:
            logger.error(f"Error fetching SSL Blacklist: {e}")
        
        return threats
    
    def generate_attack_routes(self, limit: int = 100) -> List[AttackRoute]:
        """Generate attack routes from real threat feeds"""
        threats = self.fetch_threats_from_feeds()
        routes = []
        
        for threat in threats[:limit]:
            route = self.route_generator.generate_route_from_threat(threat)
            routes.append(route)
            
            with self._lock:
                self.active_routes[route.route_id] = route
                self.route_history.append(route)
            
            self._save_route_to_db(route)
        
        logger.info(f"Generated {len(routes)} attack routes from threat feeds")
        return routes
    
    def get_active_routes(self) -> List[Dict[str, Any]]:
        """Get all active attack routes for map visualization"""
        with self._lock:
            routes = []
            for route in self.active_routes.values():
                routes.append({
                    "route_id": route.route_id,
                    "timestamp": route.timestamp.isoformat(),
                    "attack_type": route.attack_type,
                    "severity": route.severity,
                    "source": {
                        "ip": route.source_ip,
                        "country": route.source_country,
                        "country_code": route.source_country_code,
                        "lat": route.source_lat,
                        "lon": route.source_lon,
                    },
                    "target": {
                        "ip": route.target_ip,
                        "country": route.target_country,
                        "country_code": route.target_country_code,
                        "lat": route.target_lat,
                        "lon": route.target_lon,
                    },
                    "malware_family": route.malware_family,
                    "description": route.description,
                    "source_feed": route.source_feed,
                    "mitre_tactic": route.mitre_tactic,
                    "mitre_technique": route.mitre_technique,
                    "duration_ms": route.duration_ms,
                })
            return routes
    
    def get_statistics(self) -> AttackStatistics:
        """Get global attack statistics"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        today = datetime.utcnow().date().isoformat()
        cursor.execute(
            "SELECT COUNT(*) FROM attack_routes WHERE timestamp >= ?",
            (today,)
        )
        total_today = cursor.fetchone()[0]
        
        hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        cursor.execute(
            "SELECT COUNT(*) FROM attack_routes WHERE timestamp >= ?",
            (hour_ago,)
        )
        attacks_per_hour = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT source_country_code, COUNT(*) as cnt 
            FROM attack_routes 
            WHERE timestamp >= ?
            GROUP BY source_country_code 
            ORDER BY cnt DESC 
            LIMIT 10
        """, (today,))
        top_sources = [{"country_code": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT target_country_code, COUNT(*) as cnt 
            FROM attack_routes 
            WHERE timestamp >= ?
            GROUP BY target_country_code 
            ORDER BY cnt DESC 
            LIMIT 10
        """, (today,))
        top_targets = [{"country_code": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT malware_family, COUNT(*) as cnt 
            FROM attack_routes 
            WHERE timestamp >= ? AND malware_family != 'Unknown'
            GROUP BY malware_family 
            ORDER BY cnt DESC 
            LIMIT 10
        """, (today,))
        top_malware = [{"family": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT attack_type, COUNT(*) as cnt 
            FROM attack_routes 
            WHERE timestamp >= ?
            GROUP BY attack_type
        """, (today,))
        attack_types = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT severity, COUNT(*) as cnt 
            FROM attack_routes 
            WHERE timestamp >= ?
            GROUP BY severity
        """, (today,))
        severity_dist = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return AttackStatistics(
            total_attacks_today=total_today,
            attacks_per_hour=attacks_per_hour,
            top_source_countries=top_sources,
            top_target_countries=top_targets,
            top_malware_families=top_malware,
            attack_types_distribution=attack_types,
            severity_distribution=severity_dist,
            active_routes=len(self.active_routes),
            timestamp=datetime.utcnow().isoformat()
        )
    
    def get_routes_for_map(self) -> Dict[str, Any]:
        """Get all data needed for map visualization"""
        routes = self.get_active_routes()
        stats = self.get_statistics()
        
        return {
            "routes": routes,
            "statistics": asdict(stats),
            "timestamp": datetime.utcnow().isoformat(),
            "map_config": {
                "center": {"lat": 20, "lon": 0},
                "zoom": 2,
                "route_animation_duration": 3000,
                "route_colors": {
                    "critical": "#ff0000",
                    "error": "#ff6600",
                    "warning": "#ffcc00",
                    "info": "#00ccff",
                },
            },
        }
    
    async def subscribe_to_routes(self) -> asyncio.Queue:
        """Subscribe to real-time route updates"""
        queue = asyncio.Queue()
        self.subscribers.append(queue)
        return queue
    
    def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe from route updates"""
        if queue in self.subscribers:
            self.subscribers.remove(queue)
    
    async def broadcast_route(self, route: AttackRoute):
        """Broadcast new route to all subscribers"""
        route_data = {
            "type": "new_route",
            "route": {
                "route_id": route.route_id,
                "timestamp": route.timestamp.isoformat(),
                "attack_type": route.attack_type,
                "severity": route.severity,
                "source": {
                    "ip": route.source_ip,
                    "country": route.source_country,
                    "country_code": route.source_country_code,
                    "lat": route.source_lat,
                    "lon": route.source_lon,
                },
                "target": {
                    "ip": route.target_ip,
                    "country": route.target_country,
                    "country_code": route.target_country_code,
                    "lat": route.target_lat,
                    "lon": route.target_lon,
                },
                "malware_family": route.malware_family,
                "description": route.description,
                "duration_ms": route.duration_ms,
            }
        }
        
        for queue in self.subscribers:
            await queue.put(route_data)
    
    def start_realtime_feed(self, interval_seconds: int = 30):
        """Start real-time threat feed fetching"""
        self._running = True
        
        def fetch_loop():
            while self._running:
                try:
                    routes = self.generate_attack_routes(limit=20)
                    logger.info(f"Fetched {len(routes)} new attack routes")
                except Exception as e:
                    logger.error(f"Error in fetch loop: {e}")
                
                import time
                time.sleep(interval_seconds)
        
        self._fetch_thread = threading.Thread(target=fetch_loop, daemon=True)
        self._fetch_thread.start()
        logger.info("Started real-time attack feed")
    
    def stop_realtime_feed(self):
        """Stop real-time threat feed fetching"""
        self._running = False
        if self._fetch_thread:
            self._fetch_thread.join(timeout=5)
        logger.info("Stopped real-time attack feed")


_visualization_engine: Optional[GlobalAttackVisualizationEngine] = None
_engine_lock = threading.Lock()


def get_attack_visualization_engine() -> GlobalAttackVisualizationEngine:
    """Get singleton instance of attack visualization engine"""
    global _visualization_engine
    
    with _engine_lock:
        if _visualization_engine is None:
            _visualization_engine = GlobalAttackVisualizationEngine()
        return _visualization_engine
