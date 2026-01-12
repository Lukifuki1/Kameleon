"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - PERSON PROFILE STORAGE
Enterprise-grade SQLite-based person profile storage with photo management

This module implements:
- SQLite database for persistent person profile storage
- Photo storage (1-3 photos per person)
- Automatic connection detection between persons
- Link analysis with relationship strength calculation
- Person profile linking and marking connected persons

100% OPENSOURCE - NO EXTERNAL API DEPENDENCIES
Uses local SQLite database only

Classification: TOP SECRET // NSOC // TIER-5
"""

import os
import json
import hashlib
import logging
import sqlite3
import threading
import base64
import secrets
import re
from typing import Optional, List, Dict, Any, Tuple, Set
from datetime import datetime
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConnectionStrength(str, Enum):
    """Connection strength levels between persons"""
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    SUSPECTED = "SUSPECTED"


class ConnectionType(str, Enum):
    """Types of connections between persons"""
    FAMILY = "FAMILY"
    FRIEND = "FRIEND"
    COLLEAGUE = "COLLEAGUE"
    BUSINESS = "BUSINESS"
    ROMANTIC = "ROMANTIC"
    ACQUAINTANCE = "ACQUAINTANCE"
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    SHARED_LOCATION = "SHARED_LOCATION"
    SHARED_ORGANIZATION = "SHARED_ORGANIZATION"
    COMMUNICATION = "COMMUNICATION"
    FINANCIAL = "FINANCIAL"
    UNKNOWN = "UNKNOWN"


class PhotoSource(str, Enum):
    """Source of person photos"""
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    CAMERA_CAPTURE = "CAMERA_CAPTURE"
    MANUAL_UPLOAD = "MANUAL_UPLOAD"
    WEB_SCRAPE = "WEB_SCRAPE"
    REVERSE_IMAGE_SEARCH = "REVERSE_IMAGE_SEARCH"


@dataclass
class PersonPhoto:
    """Photo data for a person"""
    photo_id: str
    person_id: str
    photo_data: bytes
    photo_hash: str
    source: PhotoSource
    source_url: Optional[str]
    captured_at: str
    face_encoding: Optional[List[float]]
    metadata: Dict[str, Any]
    is_primary: bool


@dataclass
class PersonConnection:
    """Connection between two persons"""
    connection_id: str
    person_a_id: str
    person_b_id: str
    connection_type: ConnectionType
    strength: ConnectionStrength
    strength_score: float
    discovered_at: str
    discovery_source: str
    evidence: List[str]
    is_confirmed: bool
    notes: str


@dataclass
class StoredPersonProfile:
    """Person profile stored in database"""
    profile_id: str
    first_name: Optional[str]
    middle_name: Optional[str]
    last_name: Optional[str]
    full_name: Optional[str]
    aliases: List[str]
    date_of_birth: Optional[str]
    age: Optional[int]
    gender: Optional[str]
    nationality: Optional[str]
    languages: List[str]
    emails: List[str]
    phones: List[str]
    addresses: List[Dict[str, Any]]
    social_profiles: List[Dict[str, Any]]
    employment_history: List[Dict[str, Any]]
    education_history: List[Dict[str, Any]]
    photos: List[PersonPhoto]
    connections: List[PersonConnection]
    risk_score: float
    risk_factors: List[str]
    watchlist_matches: List[str]
    tags: List[str]
    notes: List[str]
    created_at: str
    updated_at: str
    last_seen_at: Optional[str]
    camera_sightings: List[Dict[str, Any]]
    raw_data: Dict[str, Any]


class PersonProfileDatabase:
    """SQLite-based person profile database with photo storage and connection detection"""
    
    DB_PATH = "/tmp/tyranthos/person_profiles.db"
    MAX_PHOTOS_PER_PERSON = 3
    
    def __init__(self):
        self._lock = threading.Lock()
        self._init_database()
        self._connection_cache: Dict[str, List[PersonConnection]] = {}
    
    def _init_database(self):
        """Initialize SQLite database with all required tables"""
        os.makedirs(os.path.dirname(self.DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS persons (
                profile_id TEXT PRIMARY KEY,
                first_name TEXT,
                middle_name TEXT,
                last_name TEXT,
                full_name TEXT,
                aliases TEXT,
                date_of_birth TEXT,
                age INTEGER,
                gender TEXT,
                nationality TEXT,
                languages TEXT,
                emails TEXT,
                phones TEXT,
                addresses TEXT,
                social_profiles TEXT,
                employment_history TEXT,
                education_history TEXT,
                risk_score REAL DEFAULT 0.0,
                risk_factors TEXT,
                watchlist_matches TEXT,
                tags TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_seen_at TEXT,
                camera_sightings TEXT,
                raw_data TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS person_photos (
                photo_id TEXT PRIMARY KEY,
                person_id TEXT NOT NULL,
                photo_data BLOB NOT NULL,
                photo_hash TEXT NOT NULL,
                source TEXT NOT NULL,
                source_url TEXT,
                captured_at TEXT NOT NULL,
                face_encoding TEXT,
                metadata TEXT,
                is_primary INTEGER DEFAULT 0,
                FOREIGN KEY (person_id) REFERENCES persons(profile_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS person_connections (
                connection_id TEXT PRIMARY KEY,
                person_a_id TEXT NOT NULL,
                person_b_id TEXT NOT NULL,
                connection_type TEXT NOT NULL,
                strength TEXT NOT NULL,
                strength_score REAL NOT NULL,
                discovered_at TEXT NOT NULL,
                discovery_source TEXT NOT NULL,
                evidence TEXT,
                is_confirmed INTEGER DEFAULT 0,
                notes TEXT,
                FOREIGN KEY (person_a_id) REFERENCES persons(profile_id),
                FOREIGN KEY (person_b_id) REFERENCES persons(profile_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS connection_evidence (
                evidence_id TEXT PRIMARY KEY,
                connection_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                evidence_data TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                confidence REAL NOT NULL,
                FOREIGN KEY (connection_id) REFERENCES person_connections(connection_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS camera_sightings (
                sighting_id TEXT PRIMARY KEY,
                person_id TEXT NOT NULL,
                camera_id TEXT NOT NULL,
                camera_location TEXT,
                timestamp TEXT NOT NULL,
                confidence REAL NOT NULL,
                snapshot_data BLOB,
                face_location TEXT,
                metadata TEXT,
                FOREIGN KEY (person_id) REFERENCES persons(profile_id)
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_persons_name ON persons(full_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_persons_emails ON persons(emails)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_photos_person ON person_photos(person_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_photos_hash ON person_photos(photo_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_connections_person_a ON person_connections(person_a_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_connections_person_b ON person_connections(person_b_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sightings_person ON camera_sightings(person_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sightings_camera ON camera_sightings(camera_id)")
        
        conn.commit()
        conn.close()
        logger.info(f"Person profile database initialized at {self.DB_PATH}")
    
    def create_profile(self, first_name: str = None, last_name: str = None,
                       email: str = None, phone: str = None,
                       **kwargs) -> StoredPersonProfile:
        """Create a new person profile in database"""
        profile_id = f"PERSON-{secrets.token_hex(8).upper()}"
        
        full_name = None
        if first_name and last_name:
            full_name = f"{first_name} {last_name}"
        elif first_name:
            full_name = first_name
        elif last_name:
            full_name = last_name
        
        now = datetime.utcnow().isoformat()
        
        profile = StoredPersonProfile(
            profile_id=profile_id,
            first_name=first_name,
            middle_name=kwargs.get("middle_name"),
            last_name=last_name,
            full_name=full_name,
            aliases=kwargs.get("aliases", []),
            date_of_birth=kwargs.get("date_of_birth"),
            age=kwargs.get("age"),
            gender=kwargs.get("gender"),
            nationality=kwargs.get("nationality"),
            languages=kwargs.get("languages", []),
            emails=[email] if email else [],
            phones=[phone] if phone else [],
            addresses=kwargs.get("addresses", []),
            social_profiles=kwargs.get("social_profiles", []),
            employment_history=kwargs.get("employment_history", []),
            education_history=kwargs.get("education_history", []),
            photos=[],
            connections=[],
            risk_score=kwargs.get("risk_score", 0.0),
            risk_factors=kwargs.get("risk_factors", []),
            watchlist_matches=kwargs.get("watchlist_matches", []),
            tags=kwargs.get("tags", []),
            notes=kwargs.get("notes", []),
            created_at=now,
            updated_at=now,
            last_seen_at=None,
            camera_sightings=[],
            raw_data=kwargs.get("raw_data", {})
        )
        
        self._save_profile_to_db(profile)
        
        logger.info(f"Created person profile: {profile_id}")
        return profile
    
    def _save_profile_to_db(self, profile: StoredPersonProfile):
        """Save profile to SQLite database"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO persons (
                profile_id, first_name, middle_name, last_name, full_name,
                aliases, date_of_birth, age, gender, nationality, languages,
                emails, phones, addresses, social_profiles, employment_history,
                education_history, risk_score, risk_factors, watchlist_matches,
                tags, notes, created_at, updated_at, last_seen_at, camera_sightings, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile.profile_id,
            profile.first_name,
            profile.middle_name,
            profile.last_name,
            profile.full_name,
            json.dumps(profile.aliases),
            profile.date_of_birth,
            profile.age,
            profile.gender,
            profile.nationality,
            json.dumps(profile.languages),
            json.dumps(profile.emails),
            json.dumps(profile.phones),
            json.dumps(profile.addresses),
            json.dumps(profile.social_profiles),
            json.dumps(profile.employment_history),
            json.dumps(profile.education_history),
            profile.risk_score,
            json.dumps(profile.risk_factors),
            json.dumps(profile.watchlist_matches),
            json.dumps(profile.tags),
            json.dumps(profile.notes),
            profile.created_at,
            profile.updated_at,
            profile.last_seen_at,
            json.dumps(profile.camera_sightings),
            json.dumps(profile.raw_data)
        ))
        
        conn.commit()
        conn.close()
    
    def get_profile(self, profile_id: str) -> Optional[StoredPersonProfile]:
        """Get profile by ID with all photos and connections"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM persons WHERE profile_id = ?", (profile_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        profile = self._row_to_profile(row)
        
        cursor.execute("SELECT * FROM person_photos WHERE person_id = ?", (profile_id,))
        photo_rows = cursor.fetchall()
        profile.photos = [self._row_to_photo(r) for r in photo_rows]
        
        cursor.execute("""
            SELECT * FROM person_connections 
            WHERE person_a_id = ? OR person_b_id = ?
        """, (profile_id, profile_id))
        conn_rows = cursor.fetchall()
        profile.connections = [self._row_to_connection(r) for r in conn_rows]
        
        conn.close()
        return profile
    
    def _row_to_profile(self, row) -> StoredPersonProfile:
        """Convert database row to StoredPersonProfile"""
        return StoredPersonProfile(
            profile_id=row[0],
            first_name=row[1],
            middle_name=row[2],
            last_name=row[3],
            full_name=row[4],
            aliases=json.loads(row[5]) if row[5] else [],
            date_of_birth=row[6],
            age=row[7],
            gender=row[8],
            nationality=row[9],
            languages=json.loads(row[10]) if row[10] else [],
            emails=json.loads(row[11]) if row[11] else [],
            phones=json.loads(row[12]) if row[12] else [],
            addresses=json.loads(row[13]) if row[13] else [],
            social_profiles=json.loads(row[14]) if row[14] else [],
            employment_history=json.loads(row[15]) if row[15] else [],
            education_history=json.loads(row[16]) if row[16] else [],
            photos=[],
            connections=[],
            risk_score=row[17] or 0.0,
            risk_factors=json.loads(row[18]) if row[18] else [],
            watchlist_matches=json.loads(row[19]) if row[19] else [],
            tags=json.loads(row[20]) if row[20] else [],
            notes=json.loads(row[21]) if row[21] else [],
            created_at=row[22],
            updated_at=row[23],
            last_seen_at=row[24],
            camera_sightings=json.loads(row[25]) if row[25] else [],
            raw_data=json.loads(row[26]) if row[26] else {}
        )
    
    def _row_to_photo(self, row) -> PersonPhoto:
        """Convert database row to PersonPhoto"""
        return PersonPhoto(
            photo_id=row[0],
            person_id=row[1],
            photo_data=row[2],
            photo_hash=row[3],
            source=PhotoSource(row[4]),
            source_url=row[5],
            captured_at=row[6],
            face_encoding=json.loads(row[7]) if row[7] else None,
            metadata=json.loads(row[8]) if row[8] else {},
            is_primary=bool(row[9])
        )
    
    def _row_to_connection(self, row) -> PersonConnection:
        """Convert database row to PersonConnection"""
        return PersonConnection(
            connection_id=row[0],
            person_a_id=row[1],
            person_b_id=row[2],
            connection_type=ConnectionType(row[3]),
            strength=ConnectionStrength(row[4]),
            strength_score=row[5],
            discovered_at=row[6],
            discovery_source=row[7],
            evidence=json.loads(row[8]) if row[8] else [],
            is_confirmed=bool(row[9]),
            notes=row[10] or ""
        )
    
    def add_photo(self, person_id: str, photo_data: bytes, source: PhotoSource,
                  source_url: str = None, face_encoding: List[float] = None,
                  metadata: Dict[str, Any] = None) -> Optional[PersonPhoto]:
        """Add photo to person profile (max 3 photos per person)"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT COUNT(*) FROM person_photos WHERE person_id = ?",
            (person_id,)
        )
        photo_count = cursor.fetchone()[0]
        
        if photo_count >= self.MAX_PHOTOS_PER_PERSON:
            cursor.execute("""
                SELECT photo_id FROM person_photos 
                WHERE person_id = ? AND is_primary = 0
                ORDER BY captured_at ASC
                LIMIT 1
            """, (person_id,))
            oldest = cursor.fetchone()
            if oldest:
                cursor.execute("DELETE FROM person_photos WHERE photo_id = ?", (oldest[0],))
                logger.info(f"Removed oldest photo {oldest[0]} to make room for new photo")
        
        photo_id = f"PHOTO-{secrets.token_hex(6).upper()}"
        photo_hash = hashlib.sha256(photo_data).hexdigest()
        now = datetime.utcnow().isoformat()
        
        is_primary = 1 if photo_count == 0 else 0
        
        cursor.execute("""
            INSERT INTO person_photos (
                photo_id, person_id, photo_data, photo_hash, source,
                source_url, captured_at, face_encoding, metadata, is_primary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            photo_id,
            person_id,
            photo_data,
            photo_hash,
            source.value,
            source_url,
            now,
            json.dumps(face_encoding) if face_encoding else None,
            json.dumps(metadata or {}),
            is_primary
        ))
        
        cursor.execute(
            "UPDATE persons SET updated_at = ? WHERE profile_id = ?",
            (now, person_id)
        )
        
        conn.commit()
        conn.close()
        
        photo = PersonPhoto(
            photo_id=photo_id,
            person_id=person_id,
            photo_data=photo_data,
            photo_hash=photo_hash,
            source=source,
            source_url=source_url,
            captured_at=now,
            face_encoding=face_encoding,
            metadata=metadata or {},
            is_primary=bool(is_primary)
        )
        
        logger.info(f"Added photo {photo_id} to person {person_id}")
        return photo
    
    def get_photos(self, person_id: str) -> List[PersonPhoto]:
        """Get all photos for a person"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM person_photos WHERE person_id = ? ORDER BY is_primary DESC, captured_at DESC",
            (person_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_photo(r) for r in rows]
    
    def set_primary_photo(self, person_id: str, photo_id: str) -> bool:
        """Set a photo as primary for a person"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE person_photos SET is_primary = 0 WHERE person_id = ?",
            (person_id,)
        )
        
        cursor.execute(
            "UPDATE person_photos SET is_primary = 1 WHERE photo_id = ? AND person_id = ?",
            (photo_id, person_id)
        )
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def add_connection(self, person_a_id: str, person_b_id: str,
                       connection_type: ConnectionType,
                       strength_score: float,
                       discovery_source: str,
                       evidence: List[str] = None,
                       notes: str = "") -> Optional[PersonConnection]:
        """Add connection between two persons"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT connection_id FROM person_connections
            WHERE (person_a_id = ? AND person_b_id = ?)
               OR (person_a_id = ? AND person_b_id = ?)
        """, (person_a_id, person_b_id, person_b_id, person_a_id))
        
        existing = cursor.fetchone()
        if existing:
            cursor.execute("""
                UPDATE person_connections
                SET strength_score = MAX(strength_score, ?),
                    evidence = ?,
                    notes = notes || ' | ' || ?
                WHERE connection_id = ?
            """, (
                strength_score,
                json.dumps(evidence or []),
                notes,
                existing[0]
            ))
            conn.commit()
            
            cursor.execute("SELECT * FROM person_connections WHERE connection_id = ?", (existing[0],))
            row = cursor.fetchone()
            conn.close()
            return self._row_to_connection(row)
        
        connection_id = f"CONN-{secrets.token_hex(6).upper()}"
        now = datetime.utcnow().isoformat()
        
        if strength_score >= 0.8:
            strength = ConnectionStrength.STRONG
        elif strength_score >= 0.5:
            strength = ConnectionStrength.MODERATE
        elif strength_score >= 0.3:
            strength = ConnectionStrength.WEAK
        else:
            strength = ConnectionStrength.SUSPECTED
        
        cursor.execute("""
            INSERT INTO person_connections (
                connection_id, person_a_id, person_b_id, connection_type,
                strength, strength_score, discovered_at, discovery_source,
                evidence, is_confirmed, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            connection_id,
            person_a_id,
            person_b_id,
            connection_type.value,
            strength.value,
            strength_score,
            now,
            discovery_source,
            json.dumps(evidence or []),
            0,
            notes
        ))
        
        conn.commit()
        conn.close()
        
        connection = PersonConnection(
            connection_id=connection_id,
            person_a_id=person_a_id,
            person_b_id=person_b_id,
            connection_type=connection_type,
            strength=strength,
            strength_score=strength_score,
            discovered_at=now,
            discovery_source=discovery_source,
            evidence=evidence or [],
            is_confirmed=False,
            notes=notes
        )
        
        logger.info(f"Added connection {connection_id} between {person_a_id} and {person_b_id}")
        return connection
    
    def get_connections(self, person_id: str) -> List[PersonConnection]:
        """Get all connections for a person"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM person_connections
            WHERE person_a_id = ? OR person_b_id = ?
            ORDER BY strength_score DESC
        """, (person_id, person_id))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_connection(r) for r in rows]
    
    def get_connected_persons(self, person_id: str) -> List[Tuple[str, PersonConnection]]:
        """Get all connected person IDs with their connections"""
        connections = self.get_connections(person_id)
        result = []
        
        for conn in connections:
            other_id = conn.person_b_id if conn.person_a_id == person_id else conn.person_a_id
            result.append((other_id, conn))
        
        return result
    
    def mark_as_connected(self, person_a_id: str, person_b_id: str) -> bool:
        """Mark two persons as connected (confirm connection)"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE person_connections
            SET is_confirmed = 1
            WHERE (person_a_id = ? AND person_b_id = ?)
               OR (person_a_id = ? AND person_b_id = ?)
        """, (person_a_id, person_b_id, person_b_id, person_a_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def detect_connections_automatically(self, person_id: str) -> List[PersonConnection]:
        """Automatically detect connections based on shared attributes"""
        profile = self.get_profile(person_id)
        if not profile:
            return []
        
        new_connections = []
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        for email in profile.emails:
            domain = email.split('@')[-1] if '@' in email else None
            if domain and domain not in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']:
                cursor.execute("""
                    SELECT profile_id, emails FROM persons
                    WHERE profile_id != ? AND emails LIKE ?
                """, (person_id, f'%{domain}%'))
                
                for row in cursor.fetchall():
                    other_id = row[0]
                    connection = self.add_connection(
                        person_id, other_id,
                        ConnectionType.SHARED_ORGANIZATION,
                        0.5,
                        "email_domain_match",
                        [f"Shared email domain: {domain}"]
                    )
                    if connection:
                        new_connections.append(connection)
        
        for employer in profile.employment_history:
            company = employer.get('company_name', '')
            if company:
                cursor.execute("""
                    SELECT profile_id, employment_history FROM persons
                    WHERE profile_id != ? AND employment_history LIKE ?
                """, (person_id, f'%{company}%'))
                
                for row in cursor.fetchall():
                    other_id = row[0]
                    connection = self.add_connection(
                        person_id, other_id,
                        ConnectionType.COLLEAGUE,
                        0.6,
                        "employer_match",
                        [f"Shared employer: {company}"]
                    )
                    if connection:
                        new_connections.append(connection)
        
        for edu in profile.education_history:
            institution = edu.get('institution', '')
            if institution:
                cursor.execute("""
                    SELECT profile_id, education_history FROM persons
                    WHERE profile_id != ? AND education_history LIKE ?
                """, (person_id, f'%{institution}%'))
                
                for row in cursor.fetchall():
                    other_id = row[0]
                    connection = self.add_connection(
                        person_id, other_id,
                        ConnectionType.ACQUAINTANCE,
                        0.4,
                        "education_match",
                        [f"Shared institution: {institution}"]
                    )
                    if connection:
                        new_connections.append(connection)
        
        for address in profile.addresses:
            city = address.get('city', '')
            country = address.get('country', '')
            if city and country:
                cursor.execute("""
                    SELECT profile_id, addresses FROM persons
                    WHERE profile_id != ? 
                    AND addresses LIKE ? AND addresses LIKE ?
                """, (person_id, f'%{city}%', f'%{country}%'))
                
                for row in cursor.fetchall():
                    other_id = row[0]
                    connection = self.add_connection(
                        person_id, other_id,
                        ConnectionType.SHARED_LOCATION,
                        0.3,
                        "location_match",
                        [f"Shared location: {city}, {country}"]
                    )
                    if connection:
                        new_connections.append(connection)
        
        conn.close()
        
        logger.info(f"Detected {len(new_connections)} automatic connections for {person_id}")
        return new_connections
    
    def search_profiles(self, query: str, limit: int = 50) -> List[StoredPersonProfile]:
        """Search profiles in database"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        query_lower = f"%{query.lower()}%"
        
        cursor.execute("""
            SELECT * FROM persons
            WHERE LOWER(full_name) LIKE ?
               OR LOWER(first_name) LIKE ?
               OR LOWER(last_name) LIKE ?
               OR LOWER(emails) LIKE ?
               OR LOWER(phones) LIKE ?
               OR LOWER(aliases) LIKE ?
            LIMIT ?
        """, (query_lower, query_lower, query_lower, query_lower, query_lower, query_lower, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        profiles = []
        for row in rows:
            profile = self._row_to_profile(row)
            profiles.append(profile)
        
        return profiles
    
    def add_camera_sighting(self, person_id: str, camera_id: str,
                            camera_location: str, confidence: float,
                            snapshot_data: bytes = None,
                            face_location: Dict[str, int] = None) -> Dict[str, Any]:
        """Record a camera sighting for a person"""
        sighting_id = f"SIGHT-{secrets.token_hex(6).upper()}"
        now = datetime.utcnow().isoformat()
        
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO camera_sightings (
                sighting_id, person_id, camera_id, camera_location,
                timestamp, confidence, snapshot_data, face_location, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sighting_id,
            person_id,
            camera_id,
            camera_location,
            now,
            confidence,
            snapshot_data,
            json.dumps(face_location) if face_location else None,
            json.dumps({})
        ))
        
        cursor.execute(
            "UPDATE persons SET last_seen_at = ?, updated_at = ? WHERE profile_id = ?",
            (now, now, person_id)
        )
        
        cursor.execute("SELECT camera_sightings FROM persons WHERE profile_id = ?", (person_id,))
        row = cursor.fetchone()
        sightings = json.loads(row[0]) if row and row[0] else []
        
        sightings.append({
            "sighting_id": sighting_id,
            "camera_id": camera_id,
            "camera_location": camera_location,
            "timestamp": now,
            "confidence": confidence
        })
        
        if len(sightings) > 100:
            sightings = sightings[-100:]
        
        cursor.execute(
            "UPDATE persons SET camera_sightings = ? WHERE profile_id = ?",
            (json.dumps(sightings), person_id)
        )
        
        conn.commit()
        conn.close()
        
        sighting = {
            "sighting_id": sighting_id,
            "person_id": person_id,
            "camera_id": camera_id,
            "camera_location": camera_location,
            "timestamp": now,
            "confidence": confidence
        }
        
        logger.info(f"Recorded camera sighting {sighting_id} for person {person_id}")
        return sighting
    
    def get_camera_sightings(self, person_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get camera sightings for a person"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT sighting_id, camera_id, camera_location, timestamp, confidence
            FROM camera_sightings
            WHERE person_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (person_id, limit))
        
        sightings = []
        for row in cursor.fetchall():
            sightings.append({
                "sighting_id": row[0],
                "camera_id": row[1],
                "camera_location": row[2],
                "timestamp": row[3],
                "confidence": row[4]
            })
        
        conn.close()
        return sightings
    
    def update_profile(self, profile_id: str, **updates) -> Optional[StoredPersonProfile]:
        """Update an existing profile"""
        profile = self.get_profile(profile_id)
        if not profile:
            return None
        
        for key, value in updates.items():
            if hasattr(profile, key) and key not in ['profile_id', 'created_at', 'photos', 'connections']:
                setattr(profile, key, value)
        
        profile.updated_at = datetime.utcnow().isoformat()
        
        self._save_profile_to_db(profile)
        
        return profile
    
    def list_profiles(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List all profiles with basic info"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT profile_id, full_name, emails, phones, created_at, updated_at, last_seen_at
            FROM persons
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        profiles = []
        for row in cursor.fetchall():
            cursor.execute(
                "SELECT COUNT(*) FROM person_photos WHERE person_id = ?",
                (row[0],)
            )
            photo_count = cursor.fetchone()[0]
            
            cursor.execute(
                "SELECT COUNT(*) FROM person_connections WHERE person_a_id = ? OR person_b_id = ?",
                (row[0], row[0])
            )
            connection_count = cursor.fetchone()[0]
            
            profiles.append({
                "profile_id": row[0],
                "full_name": row[1],
                "emails": json.loads(row[2]) if row[2] else [],
                "phones": json.loads(row[3]) if row[3] else [],
                "created_at": row[4],
                "updated_at": row[5],
                "last_seen_at": row[6],
                "photo_count": photo_count,
                "connection_count": connection_count
            })
        
        conn.close()
        return profiles
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM persons")
        total_profiles = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM person_photos")
        total_photos = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM person_connections")
        total_connections = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM camera_sightings")
        total_sightings = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM person_connections WHERE is_confirmed = 1")
        confirmed_connections = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT connection_type, COUNT(*) 
            FROM person_connections 
            GROUP BY connection_type
        """)
        connection_types = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT strength, COUNT(*) 
            FROM person_connections 
            GROUP BY strength
        """)
        connection_strengths = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            "total_profiles": total_profiles,
            "total_photos": total_photos,
            "total_connections": total_connections,
            "confirmed_connections": confirmed_connections,
            "total_camera_sightings": total_sightings,
            "connection_types": connection_types,
            "connection_strengths": connection_strengths,
            "timestamp": datetime.utcnow().isoformat()
        }


class LinkAnalysisSpider:
    """Spider for analyzing links between persons and discovering connections"""
    
    def __init__(self, profile_db: PersonProfileDatabase):
        self.profile_db = profile_db
        self.visited: Set[str] = set()
        self.connection_graph: Dict[str, Set[str]] = defaultdict(set)
    
    def crawl_connections(self, start_person_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """Crawl connections starting from a person"""
        self.visited.clear()
        self.connection_graph.clear()
        
        result = {
            "start_person": start_person_id,
            "persons_discovered": [],
            "connections_discovered": [],
            "depth_reached": 0,
            "total_persons": 0,
            "total_connections": 0
        }
        
        self._crawl_recursive(start_person_id, 0, max_depth, result)
        
        result["total_persons"] = len(result["persons_discovered"])
        result["total_connections"] = len(result["connections_discovered"])
        
        return result
    
    def _crawl_recursive(self, person_id: str, current_depth: int, 
                         max_depth: int, result: Dict[str, Any]):
        """Recursively crawl connections"""
        if current_depth > max_depth or person_id in self.visited:
            return
        
        self.visited.add(person_id)
        result["depth_reached"] = max(result["depth_reached"], current_depth)
        
        profile = self.profile_db.get_profile(person_id)
        if profile:
            result["persons_discovered"].append({
                "profile_id": profile.profile_id,
                "full_name": profile.full_name,
                "depth": current_depth
            })
        
        auto_connections = self.profile_db.detect_connections_automatically(person_id)
        for conn in auto_connections:
            result["connections_discovered"].append({
                "connection_id": conn.connection_id,
                "person_a": conn.person_a_id,
                "person_b": conn.person_b_id,
                "type": conn.connection_type.value,
                "strength": conn.strength_score
            })
        
        connected = self.profile_db.get_connected_persons(person_id)
        for other_id, connection in connected:
            self.connection_graph[person_id].add(other_id)
            self.connection_graph[other_id].add(person_id)
            
            if other_id not in self.visited:
                self._crawl_recursive(other_id, current_depth + 1, max_depth, result)
    
    def find_shortest_path(self, person_a_id: str, person_b_id: str) -> Optional[List[str]]:
        """Find shortest path between two persons"""
        if person_a_id == person_b_id:
            return [person_a_id]
        
        visited = {person_a_id}
        queue = [[person_a_id]]
        
        while queue:
            path = queue.pop(0)
            current = path[-1]
            
            connected = self.profile_db.get_connected_persons(current)
            for other_id, _ in connected:
                if other_id == person_b_id:
                    return path + [other_id]
                
                if other_id not in visited:
                    visited.add(other_id)
                    queue.append(path + [other_id])
        
        return None
    
    def analyze_network(self, person_id: str) -> Dict[str, Any]:
        """Analyze the network around a person"""
        crawl_result = self.crawl_connections(person_id, max_depth=2)
        
        degree_centrality = {}
        for pid in self.visited:
            connections = self.profile_db.get_connections(pid)
            degree_centrality[pid] = len(connections)
        
        clusters = self._detect_clusters()
        
        return {
            "center_person": person_id,
            "network_size": len(self.visited),
            "total_connections": crawl_result["total_connections"],
            "degree_centrality": degree_centrality,
            "clusters": clusters,
            "max_depth": crawl_result["depth_reached"]
        }
    
    def _detect_clusters(self) -> List[List[str]]:
        """Detect clusters in the connection graph"""
        clusters = []
        unvisited = set(self.connection_graph.keys())
        
        while unvisited:
            start = next(iter(unvisited))
            cluster = set()
            queue = [start]
            
            while queue:
                current = queue.pop(0)
                if current in cluster:
                    continue
                
                cluster.add(current)
                unvisited.discard(current)
                
                for neighbor in self.connection_graph.get(current, set()):
                    if neighbor not in cluster:
                        queue.append(neighbor)
            
            if len(cluster) > 1:
                clusters.append(list(cluster))
        
        return clusters


_profile_db: Optional[PersonProfileDatabase] = None
_db_lock = threading.Lock()


def get_person_profile_database() -> PersonProfileDatabase:
    """Get singleton instance of person profile database"""
    global _profile_db
    
    with _db_lock:
        if _profile_db is None:
            _profile_db = PersonProfileDatabase()
        return _profile_db


def get_link_analysis_spider() -> LinkAnalysisSpider:
    """Get link analysis spider instance"""
    return LinkAnalysisSpider(get_person_profile_database())
