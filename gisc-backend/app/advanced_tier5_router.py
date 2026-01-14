"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - ADVANCED TIER 5 API ROUTER
Enterprise-grade API endpoints for advanced Tier 5 capabilities

This router provides endpoints for:
- Global attack visualization with geographic routes
- Malware capture and analysis
- Person intelligence with photo storage and connection detection
- Camera discovery with face recognition search

100% OPENSOURCE - NO EXTERNAL API DEPENDENCIES

Classification: TOP SECRET // NSOC // TIER-5
"""

import os
import json
import base64
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Body, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tier5/advanced", tags=["Advanced Tier 5"])


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class AttackVisualizationRequest(BaseModel):
    limit: int = Field(default=100, ge=1, le=500)
    refresh: bool = Field(default=False)


class MalwareCaptureRequest(BaseModel):
    url: str = Field(..., description="URL to capture malware from")
    timeout: int = Field(default=30, ge=5, le=120)


class MalwareAnalyzeRequest(BaseModel):
    file_data: str = Field(..., description="Base64 encoded file data")
    filename: str = Field(..., description="Original filename")


class PersonProfileCreateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    nationality: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class PersonPhotoAddRequest(BaseModel):
    person_id: str
    photo_data: str = Field(..., description="Base64 encoded photo data")
    source: str = Field(default="MANUAL_UPLOAD")
    source_url: Optional[str] = None


class PersonSearchRequest(BaseModel):
    query: str
    limit: int = Field(default=50, ge=1, le=200)


class CameraDiscoveryRequest(BaseModel):
    sources: Optional[List[str]] = None
    max_per_source: int = Field(default=50, ge=1, le=200)


class CameraLocationRequest(BaseModel):
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    municipality: Optional[str] = None


class FaceSearchAddRequest(BaseModel):
    person_id: str
    image_data: str = Field(..., description="Base64 encoded image data")
    match_threshold: float = Field(default=0.6, ge=0.3, le=0.95)


class CameraSearchRequest(BaseModel):
    camera_id: str
    snapshot_data: str = Field(..., description="Base64 encoded snapshot data")


# ============================================================================
# GLOBAL ATTACK VISUALIZATION ENDPOINTS
# ============================================================================

@router.get("/attack-visualization/routes")
async def get_attack_routes(
    limit: int = Query(default=100, ge=1, le=500),
    refresh: bool = Query(default=False)
):
    """Get active attack routes for map visualization"""
    try:
        from app.global_attack_visualization import get_attack_visualization_engine
        
        engine = get_attack_visualization_engine()
        
        if refresh:
            engine.generate_attack_routes(limit=limit)
        
        routes = engine.get_active_routes()
        
        return {
            "success": True,
            "routes": routes[:limit],
            "total_routes": len(routes),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting attack routes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-visualization/map-data")
async def get_map_data():
    """Get all data needed for map visualization including routes and statistics"""
    try:
        from app.global_attack_visualization import get_attack_visualization_engine
        
        engine = get_attack_visualization_engine()
        map_data = engine.get_routes_for_map()
        
        return {
            "success": True,
            "data": map_data
        }
        
    except Exception as e:
        logger.error(f"Error getting map data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-visualization/statistics")
async def get_attack_statistics():
    """Get global attack statistics"""
    try:
        from app.global_attack_visualization import get_attack_visualization_engine
        
        engine = get_attack_visualization_engine()
        stats = engine.get_statistics()
        
        return {
            "success": True,
            "statistics": {
                "total_attacks_today": stats.total_attacks_today,
                "attacks_per_hour": stats.attacks_per_hour,
                "top_source_countries": stats.top_source_countries,
                "top_target_countries": stats.top_target_countries,
                "top_malware_families": stats.top_malware_families,
                "attack_types_distribution": stats.attack_types_distribution,
                "severity_distribution": stats.severity_distribution,
                "active_routes": stats.active_routes,
                "timestamp": stats.timestamp
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting attack statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-visualization/refresh")
async def refresh_attack_routes(
    background_tasks: BackgroundTasks,
    limit: int = Query(default=100, ge=1, le=500)
):
    """Refresh attack routes from threat feeds"""
    try:
        from app.global_attack_visualization import get_attack_visualization_engine
        
        engine = get_attack_visualization_engine()
        
        def refresh_task():
            engine.generate_attack_routes(limit=limit)
        
        background_tasks.add_task(refresh_task)
        
        return {
            "success": True,
            "message": "Attack routes refresh started",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error refreshing attack routes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-visualization/start-realtime")
async def start_realtime_feed(
    interval_seconds: int = Query(default=30, ge=10, le=300)
):
    """Start real-time attack feed"""
    try:
        from app.global_attack_visualization import get_attack_visualization_engine
        
        engine = get_attack_visualization_engine()
        engine.start_realtime_feed(interval_seconds)
        
        return {
            "success": True,
            "message": f"Real-time feed started with {interval_seconds}s interval",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error starting real-time feed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-visualization/stop-realtime")
async def stop_realtime_feed():
    """Stop real-time attack feed"""
    try:
        from app.global_attack_visualization import get_attack_visualization_engine
        
        engine = get_attack_visualization_engine()
        engine.stop_realtime_feed()
        
        return {
            "success": True,
            "message": "Real-time feed stopped",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error stopping real-time feed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# MALWARE CAPTURE AND ANALYSIS ENDPOINTS
# ============================================================================

@router.post("/malware/capture")
async def capture_malware(request: MalwareCaptureRequest):
    """Capture malware from URL and perform full analysis"""
    try:
        from app.malware_capture import get_malware_capture_engine
        
        engine = get_malware_capture_engine()
        captured = engine.capture_and_analyze(request.url)
        
        if not captured:
            raise HTTPException(status_code=400, detail="Failed to capture malware from URL")
        
        return {
            "success": True,
            "capture_id": captured.capture_id,
            "filename": captured.filename,
            "file_size": captured.file_size,
            "file_type": captured.file_type,
            "hashes": captured.hashes,
            "is_packed": captured.is_packed,
            "packer_type": captured.packer_type.value,
            "is_obfuscated": captured.is_obfuscated,
            "obfuscation_type": captured.obfuscation_type.value,
            "category": captured.category.value,
            "threat_level": captured.threat_level,
            "yara_matches": captured.yara_matches,
            "mitre_techniques": captured.mitre_techniques,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error capturing malware: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/malware/analyze")
async def analyze_malware(request: MalwareAnalyzeRequest):
    """Analyze uploaded malware sample"""
    try:
        from app.malware_capture import get_malware_capture_engine
        
        file_data = base64.b64decode(request.file_data)
        
        engine = get_malware_capture_engine()
        captured = engine.analyze_sample(file_data, request.filename)
        
        return {
            "success": True,
            "capture_id": captured.capture_id,
            "filename": captured.filename,
            "file_size": captured.file_size,
            "file_type": captured.file_type,
            "hashes": captured.hashes,
            "is_packed": captured.is_packed,
            "packer_type": captured.packer_type.value,
            "is_obfuscated": captured.is_obfuscated,
            "obfuscation_type": captured.obfuscation_type.value,
            "category": captured.category.value,
            "threat_level": captured.threat_level,
            "extracted_strings": captured.extracted_strings[:50],
            "extracted_urls": captured.extracted_urls,
            "extracted_ips": captured.extracted_ips,
            "pe_info": captured.pe_info,
            "yara_matches": captured.yara_matches,
            "mitre_techniques": captured.mitre_techniques,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error analyzing malware: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/malware/list")
async def list_malware_captures(
    limit: int = Query(default=100, ge=1, le=500)
):
    """List all captured malware samples"""
    try:
        from app.malware_capture import get_malware_capture_engine
        
        engine = get_malware_capture_engine()
        captures = engine.list_captures(limit)
        
        return {
            "success": True,
            "captures": captures,
            "total": len(captures),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing malware captures: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/malware/{capture_id}")
async def get_malware_sample(capture_id: str):
    """Get captured malware sample details"""
    try:
        from app.malware_capture import get_malware_capture_engine
        
        engine = get_malware_capture_engine()
        sample = engine.get_captured_sample(capture_id)
        
        if not sample:
            raise HTTPException(status_code=404, detail="Sample not found")
        
        return {
            "success": True,
            "sample": sample
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting malware sample: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/malware/{capture_id}/code")
async def get_malware_code(capture_id: str):
    """Get malware code (hex dump, disassembly, decompiled)"""
    try:
        from app.malware_capture import get_malware_capture_engine
        
        engine = get_malware_capture_engine()
        sample = engine.get_captured_sample(capture_id)
        
        if not sample:
            raise HTTPException(status_code=404, detail="Sample not found")
        
        return {
            "success": True,
            "capture_id": capture_id,
            "hex_dump": sample.get("hex_dump", ""),
            "disassembly": sample.get("disassembly", ""),
            "decompiled_code": sample.get("decompiled_code", "")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting malware code: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# PERSON INTELLIGENCE ENDPOINTS
# ============================================================================

@router.get("/person/list")
async def list_persons(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0)
):
    """List all person profiles"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        profiles = db.list_profiles(limit, offset)
        
        return {
            "success": True,
            "profiles": profiles,
            "total": len(profiles),
            "offset": offset,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Error listing persons: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/person/statistics")
async def get_person_statistics():
    """Get person database statistics"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        stats = db.get_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Error getting person statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/person/create")
async def create_person_profile(request: PersonProfileCreateRequest):
    """Create a new person profile"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        profile = db.create_profile(
            first_name=request.first_name,
            last_name=request.last_name,
            email=request.email,
            phone=request.phone,
            aliases=request.aliases,
            date_of_birth=request.date_of_birth,
            gender=request.gender,
            nationality=request.nationality,
            tags=request.tags,
            notes=request.notes
        )
        
        return {
            "success": True,
            "profile_id": profile.profile_id,
            "full_name": profile.full_name,
            "created_at": profile.created_at
        }
        
    except Exception as e:
        logger.error(f"Error creating person profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/person/{profile_id}")
async def get_person_profile(profile_id: str):
    """Get person profile with photos and connections"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        profile = db.get_profile(profile_id)
        
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        photos_data = []
        for photo in profile.photos:
            photos_data.append({
                "photo_id": photo.photo_id,
                "source": photo.source.value,
                "captured_at": photo.captured_at,
                "is_primary": photo.is_primary,
                "photo_data_base64": base64.b64encode(photo.photo_data).decode('utf-8') if photo.photo_data else None
            })
        
        connections_data = []
        for conn in profile.connections:
            connections_data.append({
                "connection_id": conn.connection_id,
                "person_a_id": conn.person_a_id,
                "person_b_id": conn.person_b_id,
                "connection_type": conn.connection_type.value,
                "strength": conn.strength.value,
                "strength_score": conn.strength_score,
                "discovered_at": conn.discovered_at,
                "is_confirmed": conn.is_confirmed
            })
        
        return {
            "success": True,
            "profile": {
                "profile_id": profile.profile_id,
                "first_name": profile.first_name,
                "last_name": profile.last_name,
                "full_name": profile.full_name,
                "aliases": profile.aliases,
                "date_of_birth": profile.date_of_birth,
                "age": profile.age,
                "gender": profile.gender,
                "nationality": profile.nationality,
                "emails": profile.emails,
                "phones": profile.phones,
                "addresses": profile.addresses,
                "social_profiles": profile.social_profiles,
                "employment_history": profile.employment_history,
                "education_history": profile.education_history,
                "risk_score": profile.risk_score,
                "tags": profile.tags,
                "notes": profile.notes,
                "created_at": profile.created_at,
                "updated_at": profile.updated_at,
                "last_seen_at": profile.last_seen_at,
                "camera_sightings": profile.camera_sightings
            },
            "photos": photos_data,
            "connections": connections_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting person profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/person/{profile_id}/photo")
async def add_person_photo(profile_id: str, request: PersonPhotoAddRequest):
    """Add photo to person profile (max 3 photos)"""
    try:
        from app.person_profile_storage import get_person_profile_database, PhotoSource
        
        photo_data = base64.b64decode(request.photo_data)
        
        db = get_person_profile_database()
        
        try:
            source = PhotoSource(request.source)
        except ValueError:
            source = PhotoSource.MANUAL_UPLOAD
        
        photo = db.add_photo(
            person_id=profile_id,
            photo_data=photo_data,
            source=source,
            source_url=request.source_url
        )
        
        if not photo:
            raise HTTPException(status_code=400, detail="Failed to add photo")
        
        return {
            "success": True,
            "photo_id": photo.photo_id,
            "person_id": photo.person_id,
            "is_primary": photo.is_primary,
            "captured_at": photo.captured_at
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding person photo: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/person/{profile_id}/photos")
async def get_person_photos(profile_id: str):
    """Get all photos for a person"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        photos = db.get_photos(profile_id)
        
        photos_data = []
        for photo in photos:
            photos_data.append({
                "photo_id": photo.photo_id,
                "source": photo.source.value,
                "captured_at": photo.captured_at,
                "is_primary": photo.is_primary,
                "photo_data_base64": base64.b64encode(photo.photo_data).decode('utf-8') if photo.photo_data else None
            })
        
        return {
            "success": True,
            "photos": photos_data,
            "total": len(photos_data)
        }
        
    except Exception as e:
        logger.error(f"Error getting person photos: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/person/{profile_id}/connections")
async def get_person_connections(profile_id: str):
    """Get all connections for a person"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        connections = db.get_connections(profile_id)
        
        connections_data = []
        for conn in connections:
            other_id = conn.person_b_id if conn.person_a_id == profile_id else conn.person_a_id
            other_profile = db.get_profile(other_id)
            
            connections_data.append({
                "connection_id": conn.connection_id,
                "connected_person_id": other_id,
                "connected_person_name": other_profile.full_name if other_profile else "Unknown",
                "connection_type": conn.connection_type.value,
                "strength": conn.strength.value,
                "strength_score": conn.strength_score,
                "discovered_at": conn.discovered_at,
                "discovery_source": conn.discovery_source,
                "is_confirmed": conn.is_confirmed
            })
        
        return {
            "success": True,
            "connections": connections_data,
            "total": len(connections_data)
        }
        
    except Exception as e:
        logger.error(f"Error getting person connections: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/person/{profile_id}/detect-connections")
async def detect_person_connections(profile_id: str):
    """Automatically detect connections for a person"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        new_connections = db.detect_connections_automatically(profile_id)
        
        connections_data = []
        for conn in new_connections:
            connections_data.append({
                "connection_id": conn.connection_id,
                "person_a_id": conn.person_a_id,
                "person_b_id": conn.person_b_id,
                "connection_type": conn.connection_type.value,
                "strength_score": conn.strength_score,
                "discovery_source": conn.discovery_source
            })
        
        return {
            "success": True,
            "new_connections": connections_data,
            "total_detected": len(connections_data)
        }
        
    except Exception as e:
        logger.error(f"Error detecting connections: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/person/search")
async def search_persons(request: PersonSearchRequest):
    """Search person profiles"""
    try:
        from app.person_profile_storage import get_person_profile_database
        
        db = get_person_profile_database()
        profiles = db.search_profiles(request.query, request.limit)
        
        results = []
        for profile in profiles:
            results.append({
                "profile_id": profile.profile_id,
                "full_name": profile.full_name,
                "emails": profile.emails,
                "phones": profile.phones,
                "created_at": profile.created_at,
                "last_seen_at": profile.last_seen_at
            })
        
        return {
            "success": True,
            "results": results,
            "total": len(results)
        }
        
    except Exception as e:
        logger.error(f"Error searching persons: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/person/link-analysis/{profile_id}")
async def analyze_person_network(
    profile_id: str,
    max_depth: int = Query(default=2, ge=1, le=5)
):
    """Analyze network around a person using link analysis spider"""
    try:
        from app.person_profile_storage import get_link_analysis_spider
        
        spider = get_link_analysis_spider()
        result = spider.crawl_connections(profile_id, max_depth)
        
        return {
            "success": True,
            "analysis": result
        }
        
    except Exception as e:
        logger.error(f"Error analyzing person network: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CAMERA DISCOVERY AND FACE RECOGNITION ENDPOINTS
# ============================================================================

@router.post("/camera/discover")
async def discover_cameras(
    background_tasks: BackgroundTasks,
    request: CameraDiscoveryRequest
):
    """Discover online cameras from various sources"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        engine = get_camera_face_recognition_engine()
        
        def discovery_task():
            engine.discover_cameras(request.sources, request.max_per_source)
        
        background_tasks.add_task(discovery_task)
        
        return {
            "success": True,
            "message": "Camera discovery started",
            "sources": request.sources or ["insecam", "earthcam", "opentopia", "webcamtaxi"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error starting camera discovery: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/camera/by-location")
async def get_cameras_by_location(request: CameraLocationRequest):
    """Get cameras filtered by geographic location"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        engine = get_camera_face_recognition_engine()
        cameras = engine.get_cameras_by_location(
            country_code=request.country_code,
            region=request.region,
            city=request.city,
            municipality=request.municipality
        )
        
        return {
            "success": True,
            "cameras": cameras,
            "total": len(cameras),
            "filter": {
                "country_code": request.country_code,
                "region": request.region,
                "city": request.city,
                "municipality": request.municipality
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting cameras by location: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/camera/hierarchy")
async def get_camera_hierarchy():
    """Get hierarchical view of cameras by geography (country/region/city/municipality)"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        engine = get_camera_face_recognition_engine()
        hierarchy = engine.get_geographic_hierarchy()
        
        return {
            "success": True,
            "hierarchy": hierarchy
        }
        
    except Exception as e:
        logger.error(f"Error getting camera hierarchy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/camera/face-search/add")
async def add_face_to_search(request: FaceSearchAddRequest):
    """Add a person's face to the camera search mechanism"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        image_data = base64.b64decode(request.image_data)
        
        engine = get_camera_face_recognition_engine()
        result = engine.add_person_to_search(
            person_id=request.person_id,
            image_data=image_data,
            match_threshold=request.match_threshold
        )
        
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Failed to add face"))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding face to search: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/camera/face-search/search")
async def search_camera_for_faces(request: CameraSearchRequest):
    """Search for faces in a camera snapshot"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        snapshot_data = base64.b64decode(request.snapshot_data)
        
        engine = get_camera_face_recognition_engine()
        result = engine.search_camera(request.camera_id, snapshot_data)
        
        return {
            "success": True,
            **result
        }
        
    except Exception as e:
        logger.error(f"Error searching camera for faces: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/camera/face-search/targets")
async def get_face_search_targets(
    person_id: Optional[str] = Query(default=None)
):
    """Get active face search targets"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        engine = get_camera_face_recognition_engine()
        targets = engine.face_search_engine.get_search_targets(person_id)
        
        targets_data = []
        for target in targets:
            targets_data.append({
                "target_id": target.target_id,
                "person_id": target.person_id,
                "added_at": target.added_at,
                "is_active": target.is_active,
                "match_threshold": target.match_threshold,
                "total_matches": target.total_matches,
                "last_match_at": target.last_match_at
            })
        
        return {
            "success": True,
            "targets": targets_data,
            "total": len(targets_data)
        }
        
    except Exception as e:
        logger.error(f"Error getting face search targets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/camera/sightings/{person_id}")
async def get_person_camera_sightings(
    person_id: str,
    limit: int = Query(default=50, ge=1, le=200)
):
    """Get camera sightings for a person"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        engine = get_camera_face_recognition_engine()
        sightings = engine.get_person_sightings(person_id, limit)
        
        return {
            "success": True,
            "sightings": sightings,
            "total": len(sightings)
        }
        
    except Exception as e:
        logger.error(f"Error getting person sightings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/camera/face-search/{target_id}")
async def remove_face_from_search(target_id: str):
    """Remove a face from active search"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        engine = get_camera_face_recognition_engine()
        success = engine.face_search_engine.remove_face_from_search(target_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Target not found")
        
        return {
            "success": True,
            "message": f"Target {target_id} removed from search"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing face from search: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/camera/statistics")
async def get_camera_statistics():
    """Get camera database statistics"""
    try:
        from app.camera_face_recognition import get_camera_face_recognition_engine
        
        engine = get_camera_face_recognition_engine()
        stats = engine.get_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Error getting camera statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# COMBINED STATISTICS ENDPOINT
# ============================================================================

@router.get("/statistics")
async def get_all_statistics():
    """Get combined statistics for all advanced Tier 5 modules"""
    try:
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "modules": {}
        }
        
        try:
            from app.global_attack_visualization import get_attack_visualization_engine
            engine = get_attack_visualization_engine()
            attack_stats = engine.get_statistics()
            stats["modules"]["attack_visualization"] = {
                "total_attacks_today": attack_stats.total_attacks_today,
                "attacks_per_hour": attack_stats.attacks_per_hour,
                "active_routes": attack_stats.active_routes
            }
        except Exception as e:
            stats["modules"]["attack_visualization"] = {"error": str(e)}
        
        try:
            from app.malware_capture import get_malware_capture_engine
            engine = get_malware_capture_engine()
            captures = engine.list_captures(limit=1000)
            stats["modules"]["malware_capture"] = {
                "total_captures": len(captures)
            }
        except Exception as e:
            stats["modules"]["malware_capture"] = {"error": str(e)}
        
        try:
            from app.person_profile_storage import get_person_profile_database
            db = get_person_profile_database()
            person_stats = db.get_statistics()
            stats["modules"]["person_intelligence"] = person_stats
        except Exception as e:
            stats["modules"]["person_intelligence"] = {"error": str(e)}
        
        try:
            from app.camera_face_recognition import get_camera_face_recognition_engine
            engine = get_camera_face_recognition_engine()
            camera_stats = engine.get_statistics()
            stats["modules"]["camera_face_recognition"] = camera_stats
        except Exception as e:
            stats["modules"]["camera_face_recognition"] = {"error": str(e)}
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Error getting combined statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
