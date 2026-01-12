"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - CAMERA FACE RECOGNITION
Enterprise-grade camera discovery with face recognition and person tracking

This module implements:
- Online camera discovery with geographic categorization (country/region/city/municipality)
- Face recognition search across cameras
- Image addition to search mechanism
- Auto-record sightings in person profiles
- SQLite database for camera and sighting storage

100% OPENSOURCE - NO EXTERNAL API DEPENDENCIES
Uses local face recognition and headless Selenium scraping

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
import time
from typing import Optional, List, Dict, Any, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import urllib.parse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CameraType(str, Enum):
    """Types of online cameras"""
    TRAFFIC = "TRAFFIC"
    WEATHER = "WEATHER"
    CITY = "CITY"
    BEACH = "BEACH"
    AIRPORT = "AIRPORT"
    PORT = "PORT"
    NATURE = "NATURE"
    TOURISM = "TOURISM"
    SECURITY = "SECURITY"
    INDUSTRIAL = "INDUSTRIAL"
    UNKNOWN = "UNKNOWN"


class CameraStatus(str, Enum):
    """Camera status"""
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


@dataclass
class DiscoveredCamera:
    """Represents a discovered online camera"""
    camera_id: str
    name: str
    url: str
    stream_url: Optional[str]
    thumbnail_url: Optional[str]
    camera_type: CameraType
    status: CameraStatus
    country: str
    country_code: str
    region: str
    city: str
    municipality: Optional[str]
    latitude: float
    longitude: float
    source: str
    discovered_at: str
    last_checked: str
    is_accessible: bool
    metadata: Dict[str, Any]


@dataclass
class FaceSearchTarget:
    """Target face for search across cameras"""
    target_id: str
    person_id: str
    face_encoding: List[float]
    reference_image_hash: str
    added_at: str
    is_active: bool
    match_threshold: float
    total_matches: int
    last_match_at: Optional[str]


@dataclass
class CameraSighting:
    """Face sighting from camera"""
    sighting_id: str
    target_id: str
    person_id: str
    camera_id: str
    timestamp: str
    confidence: float
    face_location: Dict[str, int]
    snapshot_data: Optional[bytes]
    camera_location: str
    is_verified: bool


class CameraDatabase:
    """SQLite database for camera storage and management"""
    
    DB_PATH = "/var/lib/tyranthos/cameras.db"
    
    def __init__(self):
        self._lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        os.makedirs(os.path.dirname(self.DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cameras (
                camera_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                stream_url TEXT,
                thumbnail_url TEXT,
                camera_type TEXT NOT NULL,
                status TEXT NOT NULL,
                country TEXT NOT NULL,
                country_code TEXT NOT NULL,
                region TEXT NOT NULL,
                city TEXT NOT NULL,
                municipality TEXT,
                latitude REAL,
                longitude REAL,
                source TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                last_checked TEXT NOT NULL,
                is_accessible INTEGER DEFAULT 1,
                metadata TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS face_search_targets (
                target_id TEXT PRIMARY KEY,
                person_id TEXT NOT NULL,
                face_encoding TEXT NOT NULL,
                reference_image_hash TEXT NOT NULL,
                added_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                match_threshold REAL DEFAULT 0.6,
                total_matches INTEGER DEFAULT 0,
                last_match_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS camera_sightings (
                sighting_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                person_id TEXT NOT NULL,
                camera_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                confidence REAL NOT NULL,
                face_location TEXT,
                snapshot_data BLOB,
                camera_location TEXT,
                is_verified INTEGER DEFAULT 0,
                FOREIGN KEY (target_id) REFERENCES face_search_targets(target_id),
                FOREIGN KEY (camera_id) REFERENCES cameras(camera_id)
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cameras_country ON cameras(country_code)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cameras_region ON cameras(region)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cameras_city ON cameras(city)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cameras_type ON cameras(camera_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sightings_person ON camera_sightings(person_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sightings_camera ON camera_sightings(camera_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sightings_timestamp ON camera_sightings(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_targets_person ON face_search_targets(person_id)")
        
        conn.commit()
        conn.close()
        logger.info(f"Camera database initialized at {self.DB_PATH}")
    
    def save_camera(self, camera: DiscoveredCamera):
        """Save camera to database"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO cameras (
                camera_id, name, url, stream_url, thumbnail_url, camera_type,
                status, country, country_code, region, city, municipality,
                latitude, longitude, source, discovered_at, last_checked,
                is_accessible, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            camera.camera_id,
            camera.name,
            camera.url,
            camera.stream_url,
            camera.thumbnail_url,
            camera.camera_type.value,
            camera.status.value,
            camera.country,
            camera.country_code,
            camera.region,
            camera.city,
            camera.municipality,
            camera.latitude,
            camera.longitude,
            camera.source,
            camera.discovered_at,
            camera.last_checked,
            1 if camera.is_accessible else 0,
            json.dumps(camera.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def get_camera(self, camera_id: str) -> Optional[DiscoveredCamera]:
        """Get camera by ID"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM cameras WHERE camera_id = ?", (camera_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_camera(row)
        return None
    
    def _row_to_camera(self, row) -> DiscoveredCamera:
        """Convert database row to DiscoveredCamera"""
        return DiscoveredCamera(
            camera_id=row[0],
            name=row[1],
            url=row[2],
            stream_url=row[3],
            thumbnail_url=row[4],
            camera_type=CameraType(row[5]),
            status=CameraStatus(row[6]),
            country=row[7],
            country_code=row[8],
            region=row[9],
            city=row[10],
            municipality=row[11],
            latitude=row[12] or 0.0,
            longitude=row[13] or 0.0,
            source=row[14],
            discovered_at=row[15],
            last_checked=row[16],
            is_accessible=bool(row[17]),
            metadata=json.loads(row[18]) if row[18] else {}
        )
    
    def get_cameras_by_country(self, country_code: str) -> List[DiscoveredCamera]:
        """Get all cameras in a country"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM cameras WHERE country_code = ? AND is_accessible = 1",
            (country_code.upper(),)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_camera(r) for r in rows]
    
    def get_cameras_by_region(self, country_code: str, region: str) -> List[DiscoveredCamera]:
        """Get all cameras in a region"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM cameras WHERE country_code = ? AND LOWER(region) = LOWER(?) AND is_accessible = 1",
            (country_code.upper(), region)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_camera(r) for r in rows]
    
    def get_cameras_by_city(self, country_code: str, city: str) -> List[DiscoveredCamera]:
        """Get all cameras in a city"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM cameras WHERE country_code = ? AND LOWER(city) = LOWER(?) AND is_accessible = 1",
            (country_code.upper(), city)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_camera(r) for r in rows]
    
    def get_cameras_by_municipality(self, country_code: str, municipality: str) -> List[DiscoveredCamera]:
        """Get all cameras in a municipality"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM cameras WHERE country_code = ? AND LOWER(municipality) = LOWER(?) AND is_accessible = 1",
            (country_code.upper(), municipality)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_camera(r) for r in rows]
    
    def get_geographic_hierarchy(self) -> Dict[str, Any]:
        """Get hierarchical view of cameras by geography"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        hierarchy = {}
        
        cursor.execute("""
            SELECT country_code, country, COUNT(*) as count
            FROM cameras WHERE is_accessible = 1
            GROUP BY country_code, country
            ORDER BY count DESC
        """)
        
        for row in cursor.fetchall():
            country_code = row[0]
            country_name = row[1]
            
            cursor.execute("""
                SELECT region, COUNT(*) as count
                FROM cameras WHERE country_code = ? AND is_accessible = 1
                GROUP BY region
                ORDER BY count DESC
            """, (country_code,))
            
            regions = {}
            for region_row in cursor.fetchall():
                region_name = region_row[0]
                
                cursor.execute("""
                    SELECT city, COUNT(*) as count
                    FROM cameras WHERE country_code = ? AND region = ? AND is_accessible = 1
                    GROUP BY city
                    ORDER BY count DESC
                """, (country_code, region_name))
                
                cities = {}
                for city_row in cursor.fetchall():
                    city_name = city_row[0]
                    
                    cursor.execute("""
                        SELECT municipality, COUNT(*) as count
                        FROM cameras WHERE country_code = ? AND region = ? AND city = ? 
                        AND municipality IS NOT NULL AND is_accessible = 1
                        GROUP BY municipality
                        ORDER BY count DESC
                    """, (country_code, region_name, city_name))
                    
                    municipalities = {m[0]: m[1] for m in cursor.fetchall()}
                    
                    cities[city_name] = {
                        "count": city_row[1],
                        "municipalities": municipalities
                    }
                
                regions[region_name] = {
                    "count": region_row[1],
                    "cities": cities
                }
            
            hierarchy[country_code] = {
                "name": country_name,
                "count": row[2],
                "regions": regions
            }
        
        conn.close()
        return hierarchy
    
    def save_face_target(self, target: FaceSearchTarget):
        """Save face search target"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO face_search_targets (
                target_id, person_id, face_encoding, reference_image_hash,
                added_at, is_active, match_threshold, total_matches, last_match_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target.target_id,
            target.person_id,
            json.dumps(target.face_encoding),
            target.reference_image_hash,
            target.added_at,
            1 if target.is_active else 0,
            target.match_threshold,
            target.total_matches,
            target.last_match_at
        ))
        
        conn.commit()
        conn.close()
    
    def get_active_targets(self) -> List[FaceSearchTarget]:
        """Get all active face search targets"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM face_search_targets WHERE is_active = 1")
        rows = cursor.fetchall()
        conn.close()
        
        targets = []
        for row in rows:
            targets.append(FaceSearchTarget(
                target_id=row[0],
                person_id=row[1],
                face_encoding=json.loads(row[2]),
                reference_image_hash=row[3],
                added_at=row[4],
                is_active=bool(row[5]),
                match_threshold=row[6],
                total_matches=row[7],
                last_match_at=row[8]
            ))
        
        return targets
    
    def save_sighting(self, sighting: CameraSighting):
        """Save camera sighting"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO camera_sightings (
                sighting_id, target_id, person_id, camera_id, timestamp,
                confidence, face_location, snapshot_data, camera_location, is_verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sighting.sighting_id,
            sighting.target_id,
            sighting.person_id,
            sighting.camera_id,
            sighting.timestamp,
            sighting.confidence,
            json.dumps(sighting.face_location),
            sighting.snapshot_data,
            sighting.camera_location,
            1 if sighting.is_verified else 0
        ))
        
        cursor.execute("""
            UPDATE face_search_targets
            SET total_matches = total_matches + 1, last_match_at = ?
            WHERE target_id = ?
        """, (sighting.timestamp, sighting.target_id))
        
        conn.commit()
        conn.close()
    
    def get_sightings_for_person(self, person_id: str, limit: int = 100) -> List[CameraSighting]:
        """Get all sightings for a person"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM camera_sightings
            WHERE person_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (person_id, limit))
        
        sightings = []
        for row in cursor.fetchall():
            sightings.append(CameraSighting(
                sighting_id=row[0],
                target_id=row[1],
                person_id=row[2],
                camera_id=row[3],
                timestamp=row[4],
                confidence=row[5],
                face_location=json.loads(row[6]) if row[6] else {},
                snapshot_data=row[7],
                camera_location=row[8],
                is_verified=bool(row[9])
            ))
        
        conn.close()
        return sightings
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM cameras WHERE is_accessible = 1")
        total_cameras = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT country_code) FROM cameras WHERE is_accessible = 1")
        total_countries = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM face_search_targets WHERE is_active = 1")
        active_targets = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM camera_sightings")
        total_sightings = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT camera_type, COUNT(*) 
            FROM cameras WHERE is_accessible = 1
            GROUP BY camera_type
        """)
        cameras_by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT country_code, COUNT(*) 
            FROM cameras WHERE is_accessible = 1
            GROUP BY country_code
            ORDER BY COUNT(*) DESC
            LIMIT 10
        """)
        top_countries = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            "total_cameras": total_cameras,
            "total_countries": total_countries,
            "active_face_targets": active_targets,
            "total_sightings": total_sightings,
            "cameras_by_type": cameras_by_type,
            "top_countries": top_countries,
            "timestamp": datetime.utcnow().isoformat()
        }


class CameraDiscoveryEngine:
    """Engine for discovering online cameras using headless Selenium"""
    
    CAMERA_SOURCES = [
        {"name": "insecam", "url": "http://www.insecam.org/en/byrating/"},
        {"name": "earthcam", "url": "https://www.earthcam.com/"},
        {"name": "opentopia", "url": "http://www.opentopia.com/"},
        {"name": "webcamtaxi", "url": "https://www.webcamtaxi.com/en/"},
    ]
    
    def __init__(self, camera_db: CameraDatabase):
        self.camera_db = camera_db
        self.driver = None
        self._lock = threading.Lock()
    
    def _init_selenium_driver(self):
        """Initialize headless Selenium WebDriver"""
        if self.driver:
            return
        
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            logger.info("Selenium WebDriver initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Selenium: {e}")
            self.driver = None
    
    def _close_selenium_driver(self):
        """Close Selenium WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
    
    def discover_cameras(self, sources: List[str] = None, max_per_source: int = 50) -> List[DiscoveredCamera]:
        """Discover cameras from various sources"""
        discovered = []
        
        if sources is None:
            sources = [s["name"] for s in self.CAMERA_SOURCES]
        
        self._init_selenium_driver()
        
        for source in sources:
            try:
                if source == "insecam":
                    cameras = self._crawl_insecam(max_per_source)
                elif source == "earthcam":
                    cameras = self._crawl_earthcam(max_per_source)
                elif source == "opentopia":
                    cameras = self._crawl_opentopia(max_per_source)
                elif source == "webcamtaxi":
                    cameras = self._crawl_webcamtaxi(max_per_source)
                else:
                    continue
                
                for camera in cameras:
                    self.camera_db.save_camera(camera)
                    discovered.append(camera)
                
                logger.info(f"Discovered {len(cameras)} cameras from {source}")
                
            except Exception as e:
                logger.error(f"Error crawling {source}: {e}")
        
        self._close_selenium_driver()
        
        return discovered
    
    def _crawl_insecam(self, max_cameras: int) -> List[DiscoveredCamera]:
        """Crawl insecam.org for cameras"""
        cameras = []
        
        if not self.driver:
            return cameras
        
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            
            countries_url = "http://www.insecam.org/en/bycountry/"
            self.driver.get(countries_url)
            time.sleep(2)
            
            country_links = self.driver.find_elements(By.CSS_SELECTOR, "a[href*='/en/bycountry/']")
            country_urls = []
            
            for link in country_links[:20]:
                href = link.get_attribute("href")
                if href and "/en/bycountry/" in href:
                    country_code = href.split("/")[-2].upper() if href.endswith("/") else href.split("/")[-1].upper()
                    country_name = link.text.strip()
                    if country_code and len(country_code) == 2:
                        country_urls.append({
                            "url": href,
                            "code": country_code,
                            "name": country_name
                        })
            
            for country_info in country_urls[:10]:
                if len(cameras) >= max_cameras:
                    break
                
                try:
                    self.driver.get(country_info["url"])
                    time.sleep(2)
                    
                    camera_elements = self.driver.find_elements(By.CSS_SELECTOR, ".thumbnail-item")
                    
                    for elem in camera_elements[:5]:
                        if len(cameras) >= max_cameras:
                            break
                        
                        try:
                            img = elem.find_element(By.TAG_NAME, "img")
                            thumbnail_url = img.get_attribute("src")
                            
                            link = elem.find_element(By.TAG_NAME, "a")
                            camera_url = link.get_attribute("href")
                            
                            title_elem = elem.find_elements(By.CSS_SELECTOR, ".thumbnail-item__title")
                            title = title_elem[0].text if title_elem else f"Camera in {country_info['name']}"
                            
                            location_elem = elem.find_elements(By.CSS_SELECTOR, ".thumbnail-item__caption")
                            location_text = location_elem[0].text if location_elem else ""
                            
                            city = ""
                            region = ""
                            if location_text:
                                parts = location_text.split(",")
                                if len(parts) >= 1:
                                    city = parts[0].strip()
                                if len(parts) >= 2:
                                    region = parts[1].strip()
                            
                            camera_id = f"CAM-{hashlib.md5(camera_url.encode()).hexdigest()[:12].upper()}"
                            
                            camera = DiscoveredCamera(
                                camera_id=camera_id,
                                name=title,
                                url=camera_url,
                                stream_url=None,
                                thumbnail_url=thumbnail_url,
                                camera_type=CameraType.UNKNOWN,
                                status=CameraStatus.ONLINE,
                                country=country_info["name"],
                                country_code=country_info["code"],
                                region=region or country_info["name"],
                                city=city or "Unknown",
                                municipality=None,
                                latitude=0.0,
                                longitude=0.0,
                                source="insecam",
                                discovered_at=datetime.utcnow().isoformat(),
                                last_checked=datetime.utcnow().isoformat(),
                                is_accessible=True,
                                metadata={"original_url": camera_url}
                            )
                            
                            cameras.append(camera)
                            
                        except Exception as e:
                            logger.debug(f"Error parsing camera element: {e}")
                            continue
                    
                except Exception as e:
                    logger.debug(f"Error crawling country {country_info['code']}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error crawling insecam: {e}")
        
        return cameras
    
    def _crawl_earthcam(self, max_cameras: int) -> List[DiscoveredCamera]:
        """Crawl earthcam.com for cameras"""
        cameras = []
        
        if not self.driver:
            return cameras
        
        try:
            from selenium.webdriver.common.by import By
            
            self.driver.get("https://www.earthcam.com/network/")
            time.sleep(3)
            
            camera_elements = self.driver.find_elements(By.CSS_SELECTOR, ".cam-thumb")
            
            for elem in camera_elements[:max_cameras]:
                try:
                    link = elem.find_element(By.TAG_NAME, "a")
                    camera_url = link.get_attribute("href")
                    
                    img = elem.find_element(By.TAG_NAME, "img")
                    thumbnail_url = img.get_attribute("src")
                    title = img.get_attribute("alt") or "EarthCam"
                    
                    location_parts = title.split(" - ")
                    city = location_parts[0] if location_parts else "Unknown"
                    country = location_parts[-1] if len(location_parts) > 1 else "Unknown"
                    
                    camera_id = f"CAM-{hashlib.md5(camera_url.encode()).hexdigest()[:12].upper()}"
                    
                    camera = DiscoveredCamera(
                        camera_id=camera_id,
                        name=title,
                        url=camera_url,
                        stream_url=None,
                        thumbnail_url=thumbnail_url,
                        camera_type=CameraType.CITY,
                        status=CameraStatus.ONLINE,
                        country=country,
                        country_code=self._get_country_code(country),
                        region=country,
                        city=city,
                        municipality=None,
                        latitude=0.0,
                        longitude=0.0,
                        source="earthcam",
                        discovered_at=datetime.utcnow().isoformat(),
                        last_checked=datetime.utcnow().isoformat(),
                        is_accessible=True,
                        metadata={"original_url": camera_url}
                    )
                    
                    cameras.append(camera)
                    
                except Exception as e:
                    logger.debug(f"Error parsing earthcam element: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error crawling earthcam: {e}")
        
        return cameras
    
    def _crawl_opentopia(self, max_cameras: int) -> List[DiscoveredCamera]:
        """Crawl opentopia.com for cameras"""
        cameras = []
        
        if not self.driver:
            return cameras
        
        try:
            from selenium.webdriver.common.by import By
            
            self.driver.get("http://www.opentopia.com/hiddencam.php")
            time.sleep(3)
            
            camera_elements = self.driver.find_elements(By.CSS_SELECTOR, ".webcam")
            
            for elem in camera_elements[:max_cameras]:
                try:
                    link = elem.find_element(By.TAG_NAME, "a")
                    camera_url = link.get_attribute("href")
                    
                    img_elements = elem.find_elements(By.TAG_NAME, "img")
                    thumbnail_url = img_elements[0].get_attribute("src") if img_elements else None
                    
                    title_elements = elem.find_elements(By.CSS_SELECTOR, ".title")
                    title = title_elements[0].text if title_elements else "Opentopia Camera"
                    
                    camera_id = f"CAM-{hashlib.md5(camera_url.encode()).hexdigest()[:12].upper()}"
                    
                    camera = DiscoveredCamera(
                        camera_id=camera_id,
                        name=title,
                        url=camera_url,
                        stream_url=None,
                        thumbnail_url=thumbnail_url,
                        camera_type=CameraType.UNKNOWN,
                        status=CameraStatus.ONLINE,
                        country="Unknown",
                        country_code="XX",
                        region="Unknown",
                        city="Unknown",
                        municipality=None,
                        latitude=0.0,
                        longitude=0.0,
                        source="opentopia",
                        discovered_at=datetime.utcnow().isoformat(),
                        last_checked=datetime.utcnow().isoformat(),
                        is_accessible=True,
                        metadata={"original_url": camera_url}
                    )
                    
                    cameras.append(camera)
                    
                except Exception as e:
                    logger.debug(f"Error parsing opentopia element: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error crawling opentopia: {e}")
        
        return cameras
    
    def _crawl_webcamtaxi(self, max_cameras: int) -> List[DiscoveredCamera]:
        """Crawl webcamtaxi.com for cameras"""
        cameras = []
        
        if not self.driver:
            return cameras
        
        try:
            from selenium.webdriver.common.by import By
            
            self.driver.get("https://www.webcamtaxi.com/en/")
            time.sleep(3)
            
            country_links = self.driver.find_elements(By.CSS_SELECTOR, "a.country-link")
            
            for country_link in country_links[:5]:
                if len(cameras) >= max_cameras:
                    break
                
                try:
                    country_url = country_link.get_attribute("href")
                    country_name = country_link.text.strip()
                    
                    self.driver.get(country_url)
                    time.sleep(2)
                    
                    camera_elements = self.driver.find_elements(By.CSS_SELECTOR, ".webcam-item")
                    
                    for elem in camera_elements[:5]:
                        if len(cameras) >= max_cameras:
                            break
                        
                        try:
                            link = elem.find_element(By.TAG_NAME, "a")
                            camera_url = link.get_attribute("href")
                            
                            img = elem.find_element(By.TAG_NAME, "img")
                            thumbnail_url = img.get_attribute("src")
                            title = img.get_attribute("alt") or f"Camera in {country_name}"
                            
                            camera_id = f"CAM-{hashlib.md5(camera_url.encode()).hexdigest()[:12].upper()}"
                            
                            camera = DiscoveredCamera(
                                camera_id=camera_id,
                                name=title,
                                url=camera_url,
                                stream_url=None,
                                thumbnail_url=thumbnail_url,
                                camera_type=CameraType.CITY,
                                status=CameraStatus.ONLINE,
                                country=country_name,
                                country_code=self._get_country_code(country_name),
                                region=country_name,
                                city="Unknown",
                                municipality=None,
                                latitude=0.0,
                                longitude=0.0,
                                source="webcamtaxi",
                                discovered_at=datetime.utcnow().isoformat(),
                                last_checked=datetime.utcnow().isoformat(),
                                is_accessible=True,
                                metadata={"original_url": camera_url}
                            )
                            
                            cameras.append(camera)
                            
                        except Exception as e:
                            logger.debug(f"Error parsing webcamtaxi element: {e}")
                            continue
                    
                except Exception as e:
                    logger.debug(f"Error crawling webcamtaxi country: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error crawling webcamtaxi: {e}")
        
        return cameras
    
    def _get_country_code(self, country_name: str) -> str:
        """Get country code from country name"""
        country_codes = {
            "united states": "US", "usa": "US", "america": "US",
            "united kingdom": "GB", "uk": "GB", "england": "GB",
            "germany": "DE", "france": "FR", "italy": "IT", "spain": "ES",
            "netherlands": "NL", "belgium": "BE", "switzerland": "CH",
            "austria": "AT", "poland": "PL", "czech republic": "CZ",
            "russia": "RU", "ukraine": "UA", "sweden": "SE", "norway": "NO",
            "finland": "FI", "denmark": "DK", "portugal": "PT", "greece": "GR",
            "japan": "JP", "china": "CN", "south korea": "KR", "india": "IN",
            "australia": "AU", "new zealand": "NZ", "canada": "CA",
            "brazil": "BR", "mexico": "MX", "argentina": "AR",
            "slovenia": "SI", "croatia": "HR", "serbia": "RS",
        }
        
        name_lower = country_name.lower().strip()
        return country_codes.get(name_lower, "XX")


class FaceRecognitionSearchEngine:
    """Engine for face recognition search across cameras"""
    
    def __init__(self, camera_db: CameraDatabase):
        self.camera_db = camera_db
        self.active_searches: Dict[str, FaceSearchTarget] = {}
        self._lock = threading.Lock()
        self._running = False
        self._search_thread = None
    
    def add_face_to_search(self, person_id: str, image_data: bytes,
                           match_threshold: float = 0.6) -> Optional[FaceSearchTarget]:
        """Add a face image to the search mechanism"""
        face_encoding = self._generate_face_encoding(image_data)
        if not face_encoding:
            logger.error("Could not generate face encoding from image")
            return None
        
        target_id = f"TARGET-{secrets.token_hex(6).upper()}"
        image_hash = hashlib.sha256(image_data).hexdigest()
        now = datetime.utcnow().isoformat()
        
        target = FaceSearchTarget(
            target_id=target_id,
            person_id=person_id,
            face_encoding=face_encoding,
            reference_image_hash=image_hash,
            added_at=now,
            is_active=True,
            match_threshold=match_threshold,
            total_matches=0,
            last_match_at=None
        )
        
        self.camera_db.save_face_target(target)
        
        with self._lock:
            self.active_searches[target_id] = target
        
        logger.info(f"Added face search target {target_id} for person {person_id}")
        return target
    
    def _generate_face_encoding(self, image_data: bytes) -> Optional[List[float]]:
        """Generate face encoding from image data"""
        try:
            import face_recognition
            import numpy as np
            from io import BytesIO
            from PIL import Image
            
            image = Image.open(BytesIO(image_data))
            if image.mode != 'RGB':
                image = image.convert('RGB')
            image_array = np.array(image)
            
            face_locations = face_recognition.face_locations(image_array)
            if not face_locations:
                logger.warning("No face detected in image")
                return None
            
            face_encodings = face_recognition.face_encodings(image_array, face_locations)
            if not face_encodings:
                logger.warning("Could not generate face encoding")
                return None
            
            return face_encodings[0].tolist()
            
        except ImportError:
            logger.warning("face_recognition library not available")
            return self._generate_fallback_encoding(image_data)
        except Exception as e:
            logger.error(f"Error generating face encoding: {e}")
            return None
    
    def _generate_fallback_encoding(self, image_data: bytes) -> List[float]:
        """Generate fallback encoding when face_recognition is not available"""
        image_hash = hashlib.sha256(image_data).digest()
        encoding = []
        for i in range(0, min(128, len(image_hash)), 1):
            encoding.append(float(image_hash[i]) / 255.0)
        
        while len(encoding) < 128:
            encoding.append(0.0)
        
        return encoding
    
    def search_camera_snapshot(self, camera_id: str, snapshot_data: bytes) -> List[CameraSighting]:
        """Search for faces in a camera snapshot"""
        sightings = []
        
        targets = self.camera_db.get_active_targets()
        if not targets:
            return sightings
        
        detected_faces = self._detect_faces_in_snapshot(snapshot_data)
        if not detected_faces:
            return sightings
        
        camera = self.camera_db.get_camera(camera_id)
        camera_location = f"{camera.city}, {camera.country}" if camera else "Unknown"
        
        for face_data in detected_faces:
            face_encoding = face_data.get("encoding")
            face_location = face_data.get("location")
            
            if not face_encoding:
                continue
            
            for target in targets:
                similarity = self._calculate_similarity(face_encoding, target.face_encoding)
                
                if similarity >= target.match_threshold:
                    sighting_id = f"SIGHT-{secrets.token_hex(6).upper()}"
                    now = datetime.utcnow().isoformat()
                    
                    sighting = CameraSighting(
                        sighting_id=sighting_id,
                        target_id=target.target_id,
                        person_id=target.person_id,
                        camera_id=camera_id,
                        timestamp=now,
                        confidence=similarity,
                        face_location=face_location,
                        snapshot_data=snapshot_data,
                        camera_location=camera_location,
                        is_verified=False
                    )
                    
                    self.camera_db.save_sighting(sighting)
                    sightings.append(sighting)
                    
                    self._update_person_profile(sighting)
                    
                    logger.info(f"Face match found: {target.person_id} at {camera_location} (confidence: {similarity:.2f})")
        
        return sightings
    
    def _detect_faces_in_snapshot(self, snapshot_data: bytes) -> List[Dict[str, Any]]:
        """Detect faces in snapshot and return encodings"""
        faces = []
        
        try:
            import face_recognition
            import numpy as np
            from io import BytesIO
            from PIL import Image
            
            image = Image.open(BytesIO(snapshot_data))
            if image.mode != 'RGB':
                image = image.convert('RGB')
            image_array = np.array(image)
            
            face_locations = face_recognition.face_locations(image_array)
            face_encodings = face_recognition.face_encodings(image_array, face_locations)
            
            for idx, (location, encoding) in enumerate(zip(face_locations, face_encodings)):
                faces.append({
                    "encoding": encoding.tolist(),
                    "location": {
                        "top": location[0],
                        "right": location[1],
                        "bottom": location[2],
                        "left": location[3]
                    }
                })
            
        except ImportError:
            logger.warning("face_recognition library not available for detection")
        except Exception as e:
            logger.error(f"Error detecting faces: {e}")
        
        return faces
    
    def _calculate_similarity(self, encoding1: List[float], encoding2: List[float]) -> float:
        """Calculate similarity between two face encodings"""
        try:
            import numpy as np
            
            enc1 = np.array(encoding1)
            enc2 = np.array(encoding2)
            
            distance = np.linalg.norm(enc1 - enc2)
            similarity = max(0, 1 - distance)
            
            return float(similarity)
            
        except Exception as e:
            logger.error(f"Error calculating similarity: {e}")
            return 0.0
    
    def _update_person_profile(self, sighting: CameraSighting):
        """Update person profile with sighting information"""
        try:
            from app.person_profile_storage import get_person_profile_database
            
            profile_db = get_person_profile_database()
            profile_db.add_camera_sighting(
                person_id=sighting.person_id,
                camera_id=sighting.camera_id,
                camera_location=sighting.camera_location,
                confidence=sighting.confidence,
                snapshot_data=sighting.snapshot_data,
                face_location=sighting.face_location
            )
            
            logger.info(f"Updated profile {sighting.person_id} with camera sighting")
            
        except ImportError:
            logger.warning("person_profile_storage not available")
        except Exception as e:
            logger.error(f"Error updating person profile: {e}")
    
    def remove_face_from_search(self, target_id: str) -> bool:
        """Remove a face from active search"""
        conn = sqlite3.connect(self.camera_db.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE face_search_targets SET is_active = 0 WHERE target_id = ?",
            (target_id,)
        )
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        with self._lock:
            if target_id in self.active_searches:
                del self.active_searches[target_id]
        
        return success
    
    def get_search_targets(self, person_id: str = None) -> List[FaceSearchTarget]:
        """Get search targets, optionally filtered by person"""
        targets = self.camera_db.get_active_targets()
        
        if person_id:
            targets = [t for t in targets if t.person_id == person_id]
        
        return targets
    
    def get_sightings(self, person_id: str = None, camera_id: str = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """Get sightings with optional filters"""
        conn = sqlite3.connect(self.camera_db.DB_PATH)
        cursor = conn.cursor()
        
        query = "SELECT * FROM camera_sightings WHERE 1=1"
        params = []
        
        if person_id:
            query += " AND person_id = ?"
            params.append(person_id)
        
        if camera_id:
            query += " AND camera_id = ?"
            params.append(camera_id)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        sightings = []
        for row in cursor.fetchall():
            sightings.append({
                "sighting_id": row[0],
                "target_id": row[1],
                "person_id": row[2],
                "camera_id": row[3],
                "timestamp": row[4],
                "confidence": row[5],
                "face_location": json.loads(row[6]) if row[6] else {},
                "camera_location": row[8],
                "is_verified": bool(row[9])
            })
        
        conn.close()
        return sightings


class CameraFaceRecognitionEngine:
    """Main engine coordinating camera discovery and face recognition"""
    
    def __init__(self):
        self.camera_db = CameraDatabase()
        self.discovery_engine = CameraDiscoveryEngine(self.camera_db)
        self.face_search_engine = FaceRecognitionSearchEngine(self.camera_db)
    
    def discover_cameras(self, sources: List[str] = None, max_per_source: int = 50) -> Dict[str, Any]:
        """Discover cameras from various sources"""
        cameras = self.discovery_engine.discover_cameras(sources, max_per_source)
        
        return {
            "cameras_discovered": len(cameras),
            "cameras": [asdict(c) for c in cameras[:20]],
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def get_cameras_by_location(self, country_code: str = None, region: str = None,
                                 city: str = None, municipality: str = None) -> List[Dict[str, Any]]:
        """Get cameras filtered by location"""
        if municipality and country_code:
            cameras = self.camera_db.get_cameras_by_municipality(country_code, municipality)
        elif city and country_code:
            cameras = self.camera_db.get_cameras_by_city(country_code, city)
        elif region and country_code:
            cameras = self.camera_db.get_cameras_by_region(country_code, region)
        elif country_code:
            cameras = self.camera_db.get_cameras_by_country(country_code)
        else:
            conn = sqlite3.connect(self.camera_db.DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cameras WHERE is_accessible = 1 LIMIT 100")
            cameras = [self.camera_db._row_to_camera(r) for r in cursor.fetchall()]
            conn.close()
        
        return [asdict(c) for c in cameras]
    
    def get_geographic_hierarchy(self) -> Dict[str, Any]:
        """Get hierarchical view of cameras by geography"""
        return self.camera_db.get_geographic_hierarchy()
    
    def add_person_to_search(self, person_id: str, image_data: bytes,
                             match_threshold: float = 0.6) -> Dict[str, Any]:
        """Add a person's face to the search mechanism"""
        target = self.face_search_engine.add_face_to_search(
            person_id, image_data, match_threshold
        )
        
        if target:
            return {
                "success": True,
                "target_id": target.target_id,
                "person_id": target.person_id,
                "added_at": target.added_at
            }
        
        return {
            "success": False,
            "error": "Could not add face to search"
        }
    
    def search_camera(self, camera_id: str, snapshot_data: bytes) -> Dict[str, Any]:
        """Search for faces in a camera snapshot"""
        sightings = self.face_search_engine.search_camera_snapshot(camera_id, snapshot_data)
        
        return {
            "camera_id": camera_id,
            "matches_found": len(sightings),
            "sightings": [
                {
                    "sighting_id": s.sighting_id,
                    "person_id": s.person_id,
                    "confidence": s.confidence,
                    "timestamp": s.timestamp,
                    "camera_location": s.camera_location
                }
                for s in sightings
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def get_person_sightings(self, person_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get all camera sightings for a person"""
        return self.face_search_engine.get_sightings(person_id=person_id, limit=limit)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        return self.camera_db.get_statistics()


_camera_engine: Optional[CameraFaceRecognitionEngine] = None
_engine_lock = threading.Lock()


def get_camera_face_recognition_engine() -> CameraFaceRecognitionEngine:
    """Get singleton instance of camera face recognition engine"""
    global _camera_engine
    
    with _engine_lock:
        if _camera_engine is None:
            _camera_engine = CameraFaceRecognitionEngine()
        return _camera_engine
