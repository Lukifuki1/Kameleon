"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - LOCAL THREAT INTELLIGENCE
Enterprise-grade local threat intelligence without external API dependencies

This module implements:
- Local IOC database management (IP, domain, hash, URL)
- Threat feed ingestion from free public sources (abuse.ch CSV/JSON)
- IOC correlation and enrichment
- Threat scoring and classification
- MITRE ATT&CK mapping
- Blocklist management
- Threat timeline analysis

All data is stored locally - NO external API calls required
Free feeds used: URLhaus, Feodo Tracker, ThreatFox, SSL Blacklist (all from abuse.ch)

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import csv
import json
import hashlib
import ipaddress
import re
import logging
import threading
import time
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict
import urllib.request
import urllib.error
import gzip
import io

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


LOCAL_INTEL_DB_PATH = os.environ.get("LOCAL_INTEL_DB_PATH", "/var/lib/tyranthos/threat_intel.db")
FEED_CACHE_DIR = os.environ.get("FEED_CACHE_DIR", "/var/lib/tyranthos/feeds")
FEED_UPDATE_INTERVAL = int(os.environ.get("FEED_UPDATE_INTERVAL", "3600"))


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY = "registry"
    MUTEX = "mutex"
    CERTIFICATE = "certificate"
    JA3 = "ja3"
    JA3S = "ja3s"
    SSDEEP = "ssdeep"
    IMPHASH = "imphash"


class ThreatCategory(str, Enum):
    MALWARE = "malware"
    BOTNET = "botnet"
    C2 = "c2"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    EXPLOIT = "exploit"
    APT = "apt"
    SPAM = "spam"
    SCANNER = "scanner"
    BRUTEFORCE = "bruteforce"
    CRYPTOMINER = "cryptominer"
    RAT = "rat"
    STEALER = "stealer"
    LOADER = "loader"
    DROPPER = "dropper"
    BACKDOOR = "backdoor"
    ROOTKIT = "rootkit"
    WORM = "worm"
    TROJAN = "trojan"
    UNKNOWN = "unknown"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MITRETactic(str, Enum):
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class IOCRecord:
    ioc_id: str
    ioc_type: IOCType
    value: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float
    first_seen: datetime
    last_seen: datetime
    source: str
    tags: List[str]
    mitre_tactics: List[MITRETactic]
    mitre_techniques: List[str]
    description: str
    metadata: Dict[str, Any]
    is_active: bool
    hit_count: int


@dataclass
class ThreatFeedConfig:
    feed_id: str
    name: str
    url: str
    feed_type: str
    update_interval: int
    enabled: bool
    last_update: Optional[datetime]
    parser: str


@dataclass
class IOCMatch:
    ioc_record: IOCRecord
    matched_value: str
    match_type: str
    context: Dict[str, Any]
    matched_at: datetime


@dataclass
class ThreatReport:
    report_id: str
    query: str
    query_type: str
    matches: List[IOCMatch]
    risk_score: float
    risk_level: ThreatSeverity
    mitre_coverage: List[Dict[str, Any]]
    recommendations: List[str]
    generated_at: datetime


class LocalThreatDatabase:
    """SQLite-based local threat intelligence database"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or LOCAL_INTEL_DB_PATH
        self._ensure_directory()
        self._init_database()
        self._lock = threading.Lock()
    
    def _ensure_directory(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_id TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    value_hash TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tags TEXT,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT,
                    description TEXT,
                    metadata TEXT,
                    is_active INTEGER DEFAULT 1,
                    hit_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_value_hash ON iocs(value_hash)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_category ON iocs(category)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_is_active ON iocs(is_active)
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feed_status (
                    feed_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    feed_type TEXT NOT NULL,
                    update_interval INTEGER NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    last_update TEXT,
                    last_success TEXT,
                    last_error TEXT,
                    ioc_count INTEGER DEFAULT 0,
                    parser TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ioc_hits (
                    hit_id TEXT PRIMARY KEY,
                    ioc_id TEXT NOT NULL,
                    matched_value TEXT NOT NULL,
                    match_context TEXT,
                    source_system TEXT,
                    hit_timestamp TEXT NOT NULL,
                    FOREIGN KEY (ioc_id) REFERENCES iocs(ioc_id)
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hits_ioc_id ON ioc_hits(ioc_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hits_timestamp ON ioc_hits(hit_timestamp)
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocklists (
                    blocklist_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    list_type TEXT NOT NULL,
                    entries TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1
                )
            """)
            
            conn.commit()
    
    def _hash_value(self, value: str) -> str:
        """Create hash of IOC value for fast lookup"""
        return hashlib.sha256(value.lower().encode()).hexdigest()
    
    def add_ioc(self, ioc: IOCRecord) -> bool:
        """Add or update IOC in database"""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    value_hash = self._hash_value(ioc.value)
                    now = datetime.utcnow().isoformat()
                    
                    cursor.execute("""
                        INSERT INTO iocs (
                            ioc_id, ioc_type, value, value_hash, category, severity,
                            confidence, first_seen, last_seen, source, tags,
                            mitre_tactics, mitre_techniques, description, metadata,
                            is_active, hit_count, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(ioc_id) DO UPDATE SET
                            last_seen = excluded.last_seen,
                            confidence = MAX(iocs.confidence, excluded.confidence),
                            updated_at = excluded.updated_at
                    """, (
                        ioc.ioc_id,
                        ioc.ioc_type.value,
                        ioc.value,
                        value_hash,
                        ioc.category.value,
                        ioc.severity.value,
                        ioc.confidence,
                        ioc.first_seen.isoformat(),
                        ioc.last_seen.isoformat(),
                        ioc.source,
                        json.dumps(ioc.tags),
                        json.dumps([t.value for t in ioc.mitre_tactics]),
                        json.dumps(ioc.mitre_techniques),
                        ioc.description,
                        json.dumps(ioc.metadata),
                        1 if ioc.is_active else 0,
                        ioc.hit_count,
                        now,
                        now
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to add IOC: {e}")
                return False
    
    def add_iocs_batch(self, iocs: List[IOCRecord]) -> int:
        """Add multiple IOCs in batch"""
        added = 0
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    now = datetime.utcnow().isoformat()
                    
                    for ioc in iocs:
                        try:
                            value_hash = self._hash_value(ioc.value)
                            cursor.execute("""
                                INSERT INTO iocs (
                                    ioc_id, ioc_type, value, value_hash, category, severity,
                                    confidence, first_seen, last_seen, source, tags,
                                    mitre_tactics, mitre_techniques, description, metadata,
                                    is_active, hit_count, created_at, updated_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(ioc_id) DO UPDATE SET
                                    last_seen = excluded.last_seen,
                                    confidence = MAX(iocs.confidence, excluded.confidence),
                                    updated_at = excluded.updated_at
                            """, (
                                ioc.ioc_id,
                                ioc.ioc_type.value,
                                ioc.value,
                                value_hash,
                                ioc.category.value,
                                ioc.severity.value,
                                ioc.confidence,
                                ioc.first_seen.isoformat(),
                                ioc.last_seen.isoformat(),
                                ioc.source,
                                json.dumps(ioc.tags),
                                json.dumps([t.value for t in ioc.mitre_tactics]),
                                json.dumps(ioc.mitre_techniques),
                                ioc.description,
                                json.dumps(ioc.metadata),
                                1 if ioc.is_active else 0,
                                ioc.hit_count,
                                now,
                                now
                            ))
                            added += 1
                        except Exception as e:
                            logger.debug(f"Failed to add IOC {ioc.ioc_id}: {e}")
                    
                    conn.commit()
            except Exception as e:
                logger.error(f"Batch insert failed: {e}")
        
        return added
    
    def lookup_ioc(self, value: str, ioc_type: IOCType = None) -> List[IOCRecord]:
        """Lookup IOC by value"""
        results = []
        value_hash = self._hash_value(value)
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if ioc_type:
                    cursor.execute("""
                        SELECT * FROM iocs 
                        WHERE value_hash = ? AND ioc_type = ? AND is_active = 1
                    """, (value_hash, ioc_type.value))
                else:
                    cursor.execute("""
                        SELECT * FROM iocs 
                        WHERE value_hash = ? AND is_active = 1
                    """, (value_hash,))
                
                for row in cursor.fetchall():
                    results.append(self._row_to_ioc(row))
        except Exception as e:
            logger.error(f"IOC lookup failed: {e}")
        
        return results
    
    def search_iocs(self, query: str = None, ioc_type: IOCType = None,
                    category: ThreatCategory = None, severity: ThreatSeverity = None,
                    limit: int = 100, offset: int = 0) -> List[IOCRecord]:
        """Search IOCs with filters"""
        results = []
        conditions = ["is_active = 1"]
        params = []
        
        if query:
            conditions.append("(value LIKE ? OR description LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%"])
        
        if ioc_type:
            conditions.append("ioc_type = ?")
            params.append(ioc_type.value)
        
        if category:
            conditions.append("category = ?")
            params.append(category.value)
        
        if severity:
            conditions.append("severity = ?")
            params.append(severity.value)
        
        where_clause = " AND ".join(conditions)
        params.extend([limit, offset])
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"""
                    SELECT * FROM iocs 
                    WHERE {where_clause}
                    ORDER BY last_seen DESC
                    LIMIT ? OFFSET ?
                """, params)
                
                for row in cursor.fetchall():
                    results.append(self._row_to_ioc(row))
        except Exception as e:
            logger.error(f"IOC search failed: {e}")
        
        return results
    
    def _row_to_ioc(self, row: sqlite3.Row) -> IOCRecord:
        """Convert database row to IOCRecord"""
        return IOCRecord(
            ioc_id=row["ioc_id"],
            ioc_type=IOCType(row["ioc_type"]),
            value=row["value"],
            category=ThreatCategory(row["category"]),
            severity=ThreatSeverity(row["severity"]),
            confidence=row["confidence"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            source=row["source"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            mitre_tactics=[MITRETactic(t) for t in json.loads(row["mitre_tactics"])] if row["mitre_tactics"] else [],
            mitre_techniques=json.loads(row["mitre_techniques"]) if row["mitre_techniques"] else [],
            description=row["description"] or "",
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            is_active=bool(row["is_active"]),
            hit_count=row["hit_count"]
        )
    
    def record_hit(self, ioc_id: str, matched_value: str, context: Dict[str, Any] = None,
                   source_system: str = None) -> bool:
        """Record IOC hit"""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    hit_id = f"HIT-{hashlib.sha256(f'{ioc_id}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:16].upper()}"
                    
                    cursor.execute("""
                        INSERT INTO ioc_hits (hit_id, ioc_id, matched_value, match_context, source_system, hit_timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        hit_id,
                        ioc_id,
                        matched_value,
                        json.dumps(context) if context else None,
                        source_system,
                        datetime.utcnow().isoformat()
                    ))
                    
                    cursor.execute("""
                        UPDATE iocs SET hit_count = hit_count + 1, last_seen = ? WHERE ioc_id = ?
                    """, (datetime.utcnow().isoformat(), ioc_id))
                    
                    conn.commit()
                    return True
            except Exception as e:
                logger.error(f"Failed to record hit: {e}")
                return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {
            "total_iocs": 0,
            "active_iocs": 0,
            "by_type": {},
            "by_category": {},
            "by_severity": {},
            "total_hits": 0,
            "recent_hits_24h": 0
        }
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM iocs")
                stats["total_iocs"] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM iocs WHERE is_active = 1")
                stats["active_iocs"] = cursor.fetchone()[0]
                
                cursor.execute("SELECT ioc_type, COUNT(*) FROM iocs WHERE is_active = 1 GROUP BY ioc_type")
                stats["by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                cursor.execute("SELECT category, COUNT(*) FROM iocs WHERE is_active = 1 GROUP BY category")
                stats["by_category"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                cursor.execute("SELECT severity, COUNT(*) FROM iocs WHERE is_active = 1 GROUP BY severity")
                stats["by_severity"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                cursor.execute("SELECT COUNT(*) FROM ioc_hits")
                stats["total_hits"] = cursor.fetchone()[0]
                
                yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
                cursor.execute("SELECT COUNT(*) FROM ioc_hits WHERE hit_timestamp > ?", (yesterday,))
                stats["recent_hits_24h"] = cursor.fetchone()[0]
                
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats


class ThreatFeedIngester:
    """Ingests threat feeds from free public sources"""
    
    FREE_FEEDS = [
        ThreatFeedConfig(
            feed_id="urlhaus-recent",
            name="URLhaus Recent URLs",
            url="https://urlhaus.abuse.ch/downloads/csv_recent/",
            feed_type="csv",
            update_interval=3600,
            enabled=True,
            last_update=None,
            parser="urlhaus_csv"
        ),
        ThreatFeedConfig(
            feed_id="urlhaus-online",
            name="URLhaus Online URLs",
            url="https://urlhaus.abuse.ch/downloads/csv_online/",
            feed_type="csv",
            update_interval=3600,
            enabled=True,
            last_update=None,
            parser="urlhaus_csv"
        ),
        ThreatFeedConfig(
            feed_id="feodo-ipblocklist",
            name="Feodo Tracker IP Blocklist",
            url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            feed_type="json",
            update_interval=3600,
            enabled=True,
            last_update=None,
            parser="feodo_json"
        ),
        ThreatFeedConfig(
            feed_id="threatfox-recent",
            name="ThreatFox Recent IOCs",
            url="https://threatfox.abuse.ch/export/json/recent/",
            feed_type="json",
            update_interval=3600,
            enabled=True,
            last_update=None,
            parser="threatfox_json"
        ),
        ThreatFeedConfig(
            feed_id="sslbl-recent",
            name="SSL Blacklist Recent",
            url="https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
            feed_type="csv",
            update_interval=3600,
            enabled=True,
            last_update=None,
            parser="sslbl_csv"
        ),
        ThreatFeedConfig(
            feed_id="emergingthreats-compromised",
            name="Emerging Threats Compromised IPs",
            url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            feed_type="txt",
            update_interval=86400,
            enabled=True,
            last_update=None,
            parser="ip_list"
        ),
        ThreatFeedConfig(
            feed_id="cinsscore-badguys",
            name="CI Army Bad Guys",
            url="https://cinsscore.com/list/ci-badguys.txt",
            feed_type="txt",
            update_interval=86400,
            enabled=True,
            last_update=None,
            parser="ip_list"
        ),
        ThreatFeedConfig(
            feed_id="blocklist-de-all",
            name="Blocklist.de All",
            url="https://lists.blocklist.de/lists/all.txt",
            feed_type="txt",
            update_interval=86400,
            enabled=True,
            last_update=None,
            parser="ip_list"
        ),
    ]
    
    def __init__(self, database: LocalThreatDatabase, cache_dir: str = None):
        self.database = database
        self.cache_dir = cache_dir or FEED_CACHE_DIR
        self._ensure_cache_dir()
        self._lock = threading.Lock()
    
    def _ensure_cache_dir(self):
        """Ensure cache directory exists"""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
    
    def _download_feed(self, url: str, feed_id: str) -> Optional[bytes]:
        """Download feed content"""
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "TYRANTHOS-ThreatIntel/1.0",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate"
                }
            )
            
            with urllib.request.urlopen(request, timeout=60) as response:
                content = response.read()
                
                if response.info().get("Content-Encoding") == "gzip":
                    content = gzip.decompress(content)
                
                cache_path = os.path.join(self.cache_dir, f"{feed_id}.cache")
                with open(cache_path, "wb") as f:
                    f.write(content)
                
                return content
                
        except Exception as e:
            logger.error(f"Failed to download feed {feed_id}: {e}")
            
            cache_path = os.path.join(self.cache_dir, f"{feed_id}.cache")
            if os.path.exists(cache_path):
                with open(cache_path, "rb") as f:
                    return f.read()
            
            return None
    
    def _parse_urlhaus_csv(self, content: bytes, source: str) -> List[IOCRecord]:
        """Parse URLhaus CSV format"""
        iocs = []
        try:
            text = content.decode("utf-8", errors="ignore")
            lines = [l for l in text.split("\n") if l and not l.startswith("#")]
            
            reader = csv.reader(lines)
            for row in reader:
                if len(row) < 8:
                    continue
                
                try:
                    url_id = row[0]
                    date_added = row[1]
                    url = row[2]
                    url_status = row[3]
                    threat_type = row[5] if len(row) > 5 else "malware"
                    tags = row[6].split(",") if len(row) > 6 and row[6] else []
                    
                    try:
                        first_seen = datetime.strptime(date_added, "%Y-%m-%d %H:%M:%S")
                    except:
                        first_seen = datetime.utcnow()
                    
                    severity = ThreatSeverity.CRITICAL if url_status == "online" else ThreatSeverity.HIGH
                    category = self._map_threat_category(threat_type, tags)
                    
                    ioc = IOCRecord(
                        ioc_id=f"URLHAUS-{url_id}",
                        ioc_type=IOCType.URL,
                        value=url,
                        category=category,
                        severity=severity,
                        confidence=0.9 if url_status == "online" else 0.7,
                        first_seen=first_seen,
                        last_seen=datetime.utcnow(),
                        source=source,
                        tags=tags,
                        mitre_tactics=[MITRETactic.INITIAL_ACCESS, MITRETactic.EXECUTION],
                        mitre_techniques=["T1566", "T1204"],
                        description=f"Malware distribution URL: {threat_type}",
                        metadata={"url_status": url_status, "threat_type": threat_type},
                        is_active=url_status == "online",
                        hit_count=0
                    )
                    iocs.append(ioc)
                    
                    ip = self._extract_ip_from_url(url)
                    if ip:
                        ip_ioc = IOCRecord(
                            ioc_id=f"URLHAUS-IP-{hashlib.md5(ip.encode()).hexdigest()[:8].upper()}",
                            ioc_type=IOCType.IPV4,
                            value=ip,
                            category=category,
                            severity=severity,
                            confidence=0.8,
                            first_seen=first_seen,
                            last_seen=datetime.utcnow(),
                            source=source,
                            tags=tags + ["extracted-from-url"],
                            mitre_tactics=[MITRETactic.COMMAND_AND_CONTROL],
                            mitre_techniques=["T1071"],
                            description=f"IP hosting malware: {threat_type}",
                            metadata={"extracted_from": url},
                            is_active=url_status == "online",
                            hit_count=0
                        )
                        iocs.append(ip_ioc)
                        
                except Exception as e:
                    logger.debug(f"Error parsing URLhaus row: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to parse URLhaus CSV: {e}")
        
        return iocs
    
    def _parse_feodo_json(self, content: bytes, source: str) -> List[IOCRecord]:
        """Parse Feodo Tracker JSON format"""
        iocs = []
        try:
            data = json.loads(content.decode("utf-8"))
            
            for entry in data:
                try:
                    ip = entry.get("ip_address", "")
                    if not ip:
                        continue
                    
                    port = entry.get("port", 0)
                    malware = entry.get("malware", "Unknown")
                    first_seen_str = entry.get("first_seen", "")
                    country = entry.get("country", "XX")
                    
                    try:
                        first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
                    except:
                        first_seen = datetime.utcnow()
                    
                    ioc = IOCRecord(
                        ioc_id=f"FEODO-{hashlib.md5(ip.encode()).hexdigest()[:8].upper()}",
                        ioc_type=IOCType.IPV4,
                        value=ip,
                        category=ThreatCategory.BOTNET,
                        severity=ThreatSeverity.CRITICAL,
                        confidence=0.95,
                        first_seen=first_seen,
                        last_seen=datetime.utcnow(),
                        source=source,
                        tags=[malware, "botnet", "c2"],
                        mitre_tactics=[MITRETactic.COMMAND_AND_CONTROL],
                        mitre_techniques=["T1071", "T1573"],
                        description=f"Botnet C2 server: {malware} on port {port}",
                        metadata={"port": port, "malware": malware, "country": country},
                        is_active=True,
                        hit_count=0
                    )
                    iocs.append(ioc)
                    
                except Exception as e:
                    logger.debug(f"Error parsing Feodo entry: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to parse Feodo JSON: {e}")
        
        return iocs
    
    def _parse_threatfox_json(self, content: bytes, source: str) -> List[IOCRecord]:
        """Parse ThreatFox JSON format"""
        iocs = []
        try:
            data = json.loads(content.decode("utf-8"))
            
            if "data" in data:
                entries = data["data"]
            else:
                entries = data if isinstance(data, list) else []
            
            for entry in entries:
                try:
                    ioc_value = entry.get("ioc", "")
                    ioc_type_str = entry.get("ioc_type", "")
                    threat_type = entry.get("threat_type", "")
                    malware = entry.get("malware", "Unknown")
                    confidence_level = entry.get("confidence_level", 50)
                    first_seen_str = entry.get("first_seen", "")
                    tags = entry.get("tags", [])
                    
                    if not ioc_value:
                        continue
                    
                    ioc_type = self._map_ioc_type(ioc_type_str)
                    if not ioc_type:
                        continue
                    
                    try:
                        first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
                    except:
                        first_seen = datetime.utcnow()
                    
                    category = self._map_threat_category(threat_type, tags if isinstance(tags, list) else [])
                    
                    ioc = IOCRecord(
                        ioc_id=f"THREATFOX-{hashlib.md5(ioc_value.encode()).hexdigest()[:8].upper()}",
                        ioc_type=ioc_type,
                        value=ioc_value,
                        category=category,
                        severity=self._confidence_to_severity(confidence_level),
                        confidence=confidence_level / 100.0,
                        first_seen=first_seen,
                        last_seen=datetime.utcnow(),
                        source=source,
                        tags=tags if isinstance(tags, list) else [],
                        mitre_tactics=self._get_mitre_tactics_for_category(category),
                        mitre_techniques=self._get_mitre_techniques_for_category(category),
                        description=f"{threat_type}: {malware}",
                        metadata={"malware": malware, "threat_type": threat_type},
                        is_active=True,
                        hit_count=0
                    )
                    iocs.append(ioc)
                    
                except Exception as e:
                    logger.debug(f"Error parsing ThreatFox entry: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to parse ThreatFox JSON: {e}")
        
        return iocs
    
    def _parse_sslbl_csv(self, content: bytes, source: str) -> List[IOCRecord]:
        """Parse SSL Blacklist CSV format"""
        iocs = []
        try:
            text = content.decode("utf-8", errors="ignore")
            lines = [l for l in text.split("\n") if l and not l.startswith("#")]
            
            reader = csv.reader(lines)
            for row in reader:
                if len(row) < 3:
                    continue
                
                try:
                    listing_date = row[0]
                    sha1 = row[1]
                    listing_reason = row[2] if len(row) > 2 else "malicious"
                    
                    try:
                        first_seen = datetime.strptime(listing_date, "%Y-%m-%d %H:%M:%S")
                    except:
                        first_seen = datetime.utcnow()
                    
                    ioc = IOCRecord(
                        ioc_id=f"SSLBL-{sha1[:16].upper()}",
                        ioc_type=IOCType.CERTIFICATE,
                        value=sha1,
                        category=ThreatCategory.MALWARE,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.9,
                        first_seen=first_seen,
                        last_seen=datetime.utcnow(),
                        source=source,
                        tags=["ssl", "certificate", "malicious"],
                        mitre_tactics=[MITRETactic.COMMAND_AND_CONTROL],
                        mitre_techniques=["T1573"],
                        description=f"Malicious SSL certificate: {listing_reason}",
                        metadata={"listing_reason": listing_reason},
                        is_active=True,
                        hit_count=0
                    )
                    iocs.append(ioc)
                    
                except Exception as e:
                    logger.debug(f"Error parsing SSLBL row: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to parse SSLBL CSV: {e}")
        
        return iocs
    
    def _parse_ip_list(self, content: bytes, source: str) -> List[IOCRecord]:
        """Parse simple IP list format"""
        iocs = []
        try:
            text = content.decode("utf-8", errors="ignore")
            
            for line in text.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                ip = line.split()[0] if " " in line else line
                
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                
                ioc = IOCRecord(
                    ioc_id=f"IPLIST-{hashlib.md5(ip.encode()).hexdigest()[:8].upper()}",
                    ioc_type=IOCType.IPV4 if "." in ip else IOCType.IPV6,
                    value=ip,
                    category=ThreatCategory.SCANNER,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.7,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    source=source,
                    tags=["blocklist", "scanner"],
                    mitre_tactics=[MITRETactic.DISCOVERY],
                    mitre_techniques=["T1046"],
                    description="IP from threat blocklist",
                    metadata={},
                    is_active=True,
                    hit_count=0
                )
                iocs.append(ioc)
                
        except Exception as e:
            logger.error(f"Failed to parse IP list: {e}")
        
        return iocs
    
    def _map_ioc_type(self, type_str: str) -> Optional[IOCType]:
        """Map string to IOCType"""
        type_map = {
            "ip:port": IOCType.IPV4,
            "ip": IOCType.IPV4,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "md5_hash": IOCType.MD5,
            "sha1_hash": IOCType.SHA1,
            "sha256_hash": IOCType.SHA256,
            "email": IOCType.EMAIL,
        }
        return type_map.get(type_str.lower())
    
    def _map_threat_category(self, threat_type: str, tags: List[str]) -> ThreatCategory:
        """Map threat type to category"""
        threat_type_lower = threat_type.lower()
        tags_lower = [t.lower() for t in tags]
        
        if "ransomware" in threat_type_lower or "ransomware" in tags_lower:
            return ThreatCategory.RANSOMWARE
        elif "botnet" in threat_type_lower or "botnet" in tags_lower:
            return ThreatCategory.BOTNET
        elif "c2" in threat_type_lower or "c&c" in threat_type_lower:
            return ThreatCategory.C2
        elif "phishing" in threat_type_lower or "phishing" in tags_lower:
            return ThreatCategory.PHISHING
        elif "rat" in threat_type_lower or "rat" in tags_lower:
            return ThreatCategory.RAT
        elif "stealer" in threat_type_lower or "stealer" in tags_lower:
            return ThreatCategory.STEALER
        elif "loader" in threat_type_lower or "loader" in tags_lower:
            return ThreatCategory.LOADER
        elif "dropper" in threat_type_lower or "dropper" in tags_lower:
            return ThreatCategory.DROPPER
        elif "backdoor" in threat_type_lower or "backdoor" in tags_lower:
            return ThreatCategory.BACKDOOR
        elif "trojan" in threat_type_lower or "trojan" in tags_lower:
            return ThreatCategory.TROJAN
        elif "miner" in threat_type_lower or "cryptominer" in tags_lower:
            return ThreatCategory.CRYPTOMINER
        else:
            return ThreatCategory.MALWARE
    
    def _confidence_to_severity(self, confidence: int) -> ThreatSeverity:
        """Convert confidence level to severity"""
        if confidence >= 90:
            return ThreatSeverity.CRITICAL
        elif confidence >= 70:
            return ThreatSeverity.HIGH
        elif confidence >= 50:
            return ThreatSeverity.MEDIUM
        elif confidence >= 30:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFO
    
    def _get_mitre_tactics_for_category(self, category: ThreatCategory) -> List[MITRETactic]:
        """Get MITRE tactics for threat category"""
        tactic_map = {
            ThreatCategory.MALWARE: [MITRETactic.EXECUTION, MITRETactic.PERSISTENCE],
            ThreatCategory.BOTNET: [MITRETactic.COMMAND_AND_CONTROL, MITRETactic.IMPACT],
            ThreatCategory.C2: [MITRETactic.COMMAND_AND_CONTROL],
            ThreatCategory.PHISHING: [MITRETactic.INITIAL_ACCESS],
            ThreatCategory.RANSOMWARE: [MITRETactic.IMPACT, MITRETactic.EXECUTION],
            ThreatCategory.RAT: [MITRETactic.COMMAND_AND_CONTROL, MITRETactic.COLLECTION],
            ThreatCategory.STEALER: [MITRETactic.CREDENTIAL_ACCESS, MITRETactic.COLLECTION],
            ThreatCategory.LOADER: [MITRETactic.EXECUTION],
            ThreatCategory.DROPPER: [MITRETactic.EXECUTION, MITRETactic.DEFENSE_EVASION],
            ThreatCategory.BACKDOOR: [MITRETactic.PERSISTENCE, MITRETactic.COMMAND_AND_CONTROL],
            ThreatCategory.CRYPTOMINER: [MITRETactic.IMPACT],
        }
        return tactic_map.get(category, [MITRETactic.EXECUTION])
    
    def _get_mitre_techniques_for_category(self, category: ThreatCategory) -> List[str]:
        """Get MITRE techniques for threat category"""
        technique_map = {
            ThreatCategory.MALWARE: ["T1204", "T1059"],
            ThreatCategory.BOTNET: ["T1071", "T1573"],
            ThreatCategory.C2: ["T1071", "T1573", "T1095"],
            ThreatCategory.PHISHING: ["T1566", "T1598"],
            ThreatCategory.RANSOMWARE: ["T1486", "T1490"],
            ThreatCategory.RAT: ["T1219", "T1071"],
            ThreatCategory.STEALER: ["T1555", "T1539"],
            ThreatCategory.LOADER: ["T1059", "T1106"],
            ThreatCategory.DROPPER: ["T1059", "T1027"],
            ThreatCategory.BACKDOOR: ["T1547", "T1071"],
            ThreatCategory.CRYPTOMINER: ["T1496"],
        }
        return technique_map.get(category, ["T1204"])
    
    def _extract_ip_from_url(self, url: str) -> Optional[str]:
        """Extract IP address from URL"""
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ip_pattern, url)
        if match:
            ip = match.group(1)
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                pass
        return None
    
    def ingest_feed(self, feed_config: ThreatFeedConfig) -> int:
        """Ingest single feed"""
        logger.info(f"Ingesting feed: {feed_config.name}")
        
        content = self._download_feed(feed_config.url, feed_config.feed_id)
        if not content:
            return 0
        
        parser_map = {
            "urlhaus_csv": self._parse_urlhaus_csv,
            "feodo_json": self._parse_feodo_json,
            "threatfox_json": self._parse_threatfox_json,
            "sslbl_csv": self._parse_sslbl_csv,
            "ip_list": self._parse_ip_list,
        }
        
        parser = parser_map.get(feed_config.parser)
        if not parser:
            logger.error(f"Unknown parser: {feed_config.parser}")
            return 0
        
        iocs = parser(content, feed_config.name)
        added = self.database.add_iocs_batch(iocs)
        
        logger.info(f"Ingested {added} IOCs from {feed_config.name}")
        return added
    
    def ingest_all_feeds(self) -> Dict[str, int]:
        """Ingest all enabled feeds"""
        results = {}
        for feed in self.FREE_FEEDS:
            if feed.enabled:
                results[feed.feed_id] = self.ingest_feed(feed)
        return results


class IOCMatcher:
    """Matches indicators against local threat intelligence"""
    
    def __init__(self, database: LocalThreatDatabase):
        self.database = database
        self._ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self._domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        self._url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        self._md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self._sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self._sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        self._email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    def extract_indicators(self, text: str) -> Dict[IOCType, Set[str]]:
        """Extract all indicators from text"""
        indicators = {
            IOCType.IPV4: set(),
            IOCType.DOMAIN: set(),
            IOCType.URL: set(),
            IOCType.MD5: set(),
            IOCType.SHA1: set(),
            IOCType.SHA256: set(),
            IOCType.EMAIL: set(),
        }
        
        for ip in self._ip_pattern.findall(text):
            try:
                ipaddress.ip_address(ip)
                indicators[IOCType.IPV4].add(ip)
            except ValueError:
                pass
        
        indicators[IOCType.URL].update(self._url_pattern.findall(text))
        
        for domain in self._domain_pattern.findall(text):
            if domain not in indicators[IOCType.URL]:
                indicators[IOCType.DOMAIN].add(domain.lower())
        
        indicators[IOCType.MD5].update(m.lower() for m in self._md5_pattern.findall(text))
        indicators[IOCType.SHA1].update(s.lower() for s in self._sha1_pattern.findall(text))
        indicators[IOCType.SHA256].update(s.lower() for s in self._sha256_pattern.findall(text))
        indicators[IOCType.EMAIL].update(e.lower() for e in self._email_pattern.findall(text))
        
        return indicators
    
    def match_indicator(self, value: str, ioc_type: IOCType = None) -> List[IOCMatch]:
        """Match single indicator against database"""
        matches = []
        
        iocs = self.database.lookup_ioc(value, ioc_type)
        for ioc in iocs:
            match = IOCMatch(
                ioc_record=ioc,
                matched_value=value,
                match_type="exact",
                context={},
                matched_at=datetime.utcnow()
            )
            matches.append(match)
            
            self.database.record_hit(ioc.ioc_id, value)
        
        return matches
    
    def match_text(self, text: str) -> List[IOCMatch]:
        """Match all indicators in text against database"""
        all_matches = []
        indicators = self.extract_indicators(text)
        
        for ioc_type, values in indicators.items():
            for value in values:
                matches = self.match_indicator(value, ioc_type)
                all_matches.extend(matches)
        
        return all_matches
    
    def match_file(self, file_path: str) -> List[IOCMatch]:
        """Match file hashes against database"""
        matches = []
        
        if not os.path.exists(file_path):
            return matches
        
        with open(file_path, "rb") as f:
            content = f.read()
        
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        matches.extend(self.match_indicator(md5_hash, IOCType.MD5))
        matches.extend(self.match_indicator(sha1_hash, IOCType.SHA1))
        matches.extend(self.match_indicator(sha256_hash, IOCType.SHA256))
        
        return matches
    
    def generate_report(self, query: str, matches: List[IOCMatch]) -> ThreatReport:
        """Generate threat report from matches"""
        if not matches:
            return ThreatReport(
                report_id=f"RPT-{hashlib.sha256(query.encode()).hexdigest()[:12].upper()}",
                query=query,
                query_type="unknown",
                matches=[],
                risk_score=0.0,
                risk_level=ThreatSeverity.INFO,
                mitre_coverage=[],
                recommendations=["No threats detected"],
                generated_at=datetime.utcnow()
            )
        
        severity_scores = {
            ThreatSeverity.CRITICAL: 100,
            ThreatSeverity.HIGH: 75,
            ThreatSeverity.MEDIUM: 50,
            ThreatSeverity.LOW: 25,
            ThreatSeverity.INFO: 10
        }
        
        max_score = max(severity_scores[m.ioc_record.severity] for m in matches)
        avg_confidence = sum(m.ioc_record.confidence for m in matches) / len(matches)
        risk_score = (max_score * 0.7 + avg_confidence * 100 * 0.3)
        
        if risk_score >= 80:
            risk_level = ThreatSeverity.CRITICAL
        elif risk_score >= 60:
            risk_level = ThreatSeverity.HIGH
        elif risk_score >= 40:
            risk_level = ThreatSeverity.MEDIUM
        elif risk_score >= 20:
            risk_level = ThreatSeverity.LOW
        else:
            risk_level = ThreatSeverity.INFO
        
        mitre_tactics = set()
        mitre_techniques = set()
        for match in matches:
            mitre_tactics.update(t.value for t in match.ioc_record.mitre_tactics)
            mitre_techniques.update(match.ioc_record.mitre_techniques)
        
        mitre_coverage = [
            {"tactic": tactic, "techniques": list(mitre_techniques)}
            for tactic in mitre_tactics
        ]
        
        recommendations = self._generate_recommendations(matches, risk_level)
        
        return ThreatReport(
            report_id=f"RPT-{hashlib.sha256(query.encode()).hexdigest()[:12].upper()}",
            query=query,
            query_type=matches[0].ioc_record.ioc_type.value if matches else "unknown",
            matches=matches,
            risk_score=risk_score,
            risk_level=risk_level,
            mitre_coverage=mitre_coverage,
            recommendations=recommendations,
            generated_at=datetime.utcnow()
        )
    
    def _generate_recommendations(self, matches: List[IOCMatch], risk_level: ThreatSeverity) -> List[str]:
        """Generate recommendations based on matches"""
        recommendations = []
        
        categories = set(m.ioc_record.category for m in matches)
        
        if ThreatCategory.RANSOMWARE in categories:
            recommendations.append("IMMEDIATE: Isolate affected systems from network")
            recommendations.append("Verify backup integrity and availability")
            recommendations.append("Engage incident response team")
        
        if ThreatCategory.BOTNET in categories or ThreatCategory.C2 in categories:
            recommendations.append("Block identified C2 IP addresses at firewall")
            recommendations.append("Scan network for additional compromised hosts")
            recommendations.append("Review DNS logs for C2 communication patterns")
        
        if ThreatCategory.PHISHING in categories:
            recommendations.append("Block identified phishing URLs at proxy")
            recommendations.append("Alert users about phishing campaign")
            recommendations.append("Review email logs for additional recipients")
        
        if ThreatCategory.STEALER in categories:
            recommendations.append("Force password reset for potentially affected accounts")
            recommendations.append("Review authentication logs for suspicious activity")
            recommendations.append("Enable MFA on critical accounts")
        
        if risk_level == ThreatSeverity.CRITICAL:
            recommendations.insert(0, "CRITICAL: Immediate containment required")
        elif risk_level == ThreatSeverity.HIGH:
            recommendations.insert(0, "HIGH PRIORITY: Investigate within 4 hours")
        
        if not recommendations:
            recommendations.append("Monitor for additional indicators")
            recommendations.append("Update threat intelligence feeds")
        
        return recommendations


class LocalThreatIntelligence:
    """Main interface for local threat intelligence"""
    
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
        
        self.database = LocalThreatDatabase()
        self.ingester = ThreatFeedIngester(self.database)
        self.matcher = IOCMatcher(self.database)
        self._update_thread = None
        self._stop_event = threading.Event()
    
    def start_auto_update(self, interval: int = None):
        """Start automatic feed updates"""
        interval = interval or FEED_UPDATE_INTERVAL
        
        def update_loop():
            while not self._stop_event.is_set():
                try:
                    self.ingester.ingest_all_feeds()
                except Exception as e:
                    logger.error(f"Feed update failed: {e}")
                self._stop_event.wait(interval)
        
        self._update_thread = threading.Thread(target=update_loop, daemon=True)
        self._update_thread.start()
        logger.info(f"Started auto-update with interval {interval}s")
    
    def stop_auto_update(self):
        """Stop automatic feed updates"""
        self._stop_event.set()
        if self._update_thread:
            self._update_thread.join(timeout=5)
    
    def update_feeds(self) -> Dict[str, int]:
        """Manually update all feeds"""
        return self.ingester.ingest_all_feeds()
    
    def lookup(self, value: str, ioc_type: IOCType = None) -> List[IOCRecord]:
        """Lookup IOC by value"""
        return self.database.lookup_ioc(value, ioc_type)
    
    def search(self, query: str = None, ioc_type: IOCType = None,
               category: ThreatCategory = None, severity: ThreatSeverity = None,
               limit: int = 100) -> List[IOCRecord]:
        """Search IOCs"""
        return self.database.search_iocs(query, ioc_type, category, severity, limit)
    
    def analyze_text(self, text: str) -> ThreatReport:
        """Analyze text for threats"""
        matches = self.matcher.match_text(text)
        return self.matcher.generate_report(text[:100], matches)
    
    def analyze_file(self, file_path: str) -> ThreatReport:
        """Analyze file for threats"""
        matches = self.matcher.match_file(file_path)
        return self.matcher.generate_report(file_path, matches)
    
    def analyze_ip(self, ip: str) -> ThreatReport:
        """Analyze IP address"""
        matches = self.matcher.match_indicator(ip, IOCType.IPV4)
        return self.matcher.generate_report(ip, matches)
    
    def analyze_domain(self, domain: str) -> ThreatReport:
        """Analyze domain"""
        matches = self.matcher.match_indicator(domain, IOCType.DOMAIN)
        return self.matcher.generate_report(domain, matches)
    
    def analyze_url(self, url: str) -> ThreatReport:
        """Analyze URL"""
        matches = self.matcher.match_indicator(url, IOCType.URL)
        return self.matcher.generate_report(url, matches)
    
    def analyze_hash(self, hash_value: str) -> ThreatReport:
        """Analyze file hash"""
        if len(hash_value) == 32:
            ioc_type = IOCType.MD5
        elif len(hash_value) == 40:
            ioc_type = IOCType.SHA1
        elif len(hash_value) == 64:
            ioc_type = IOCType.SHA256
        else:
            ioc_type = None
        
        matches = self.matcher.match_indicator(hash_value, ioc_type)
        return self.matcher.generate_report(hash_value, matches)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        return self.database.get_statistics()
    
    def add_custom_ioc(self, ioc_type: IOCType, value: str, category: ThreatCategory,
                       severity: ThreatSeverity, description: str = "",
                       tags: List[str] = None) -> bool:
        """Add custom IOC"""
        ioc = IOCRecord(
            ioc_id=f"CUSTOM-{hashlib.sha256(value.encode()).hexdigest()[:12].upper()}",
            ioc_type=ioc_type,
            value=value,
            category=category,
            severity=severity,
            confidence=1.0,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            source="custom",
            tags=tags or [],
            mitre_tactics=[],
            mitre_techniques=[],
            description=description,
            metadata={"added_by": "operator"},
            is_active=True,
            hit_count=0
        )
        return self.database.add_ioc(ioc)


def get_local_threat_intel() -> LocalThreatIntelligence:
    """Get singleton instance of LocalThreatIntelligence"""
    return LocalThreatIntelligence()
