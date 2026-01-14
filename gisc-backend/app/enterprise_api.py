"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - ENTERPRISE API ENDPOINTS
Enterprise-grade API endpoints for real security operations

This module provides API endpoints for:
- Person Intelligence (search, profiling, connections)
- Attack Analysis (real-time monitoring, malware analysis)
- Scanner Engine (network, domain, web scanning)
- Web Crawler (link analysis, person mentions)
- Cryptography (encryption, signing, key management)

Classification: TOP SECRET // NSOC // TIER-0
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Form
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import base64
import hashlib
import json
import os

from app.real_web_scraper import create_web_scraper, create_person_search_scraper
from app.real_scanner_engine import create_scanner_engine
from app.real_attack_analysis import create_attack_analysis_engine
from app.real_web_crawler import create_web_crawler_engine
from app.real_cryptography import create_cryptography_engine
from app.real_pdf_generator import create_pdf_generator, ReportMetadata


router = APIRouter(prefix="/api/v1/enterprise", tags=["Enterprise Operations"])


class PersonSearchRequest(BaseModel):
    query: str = Field(..., description="Person name, email, phone, or username to search")
    search_engines: bool = Field(True, description="Search across search engines")
    social_media: bool = Field(True, description="Search social media platforms")
    people_search: bool = Field(True, description="Search people search websites")


class PersonSearchResponse(BaseModel):
    query: str
    timestamp: str
    search_engines: Optional[Dict[str, Any]]
    social_profiles: Optional[Dict[str, Any]]
    people_search_sites: Optional[Dict[str, Any]]
    total_results: int


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP, domain, or URL to scan")
    scan_ports: bool = Field(True, description="Perform port scanning")
    scan_domain: bool = Field(True, description="Perform domain scanning")
    scan_web: bool = Field(True, description="Perform web vulnerability scanning")
    scan_ssl: bool = Field(True, description="Perform SSL/TLS scanning")
    generate_pdf: bool = Field(True, description="Generate PDF report")


class ScanResponse(BaseModel):
    target: str
    scan_time: str
    summary: Dict[str, Any]
    port_scan: Optional[Dict[str, Any]]
    domain_scan: Optional[Dict[str, Any]]
    web_scan: Optional[Dict[str, Any]]
    ssl_scan: Optional[Dict[str, Any]]
    pdf_report: Optional[str]


class AttackAnalysisRequest(BaseModel):
    target: str = Field(..., description="Target system or identifier")
    events: Optional[List[Dict[str, Any]]] = Field(None, description="Attack events to analyze")
    generate_pdf: bool = Field(True, description="Generate PDF report")


class AttackAnalysisResponse(BaseModel):
    analysis_id: str
    target: str
    start_time: str
    end_time: str
    total_events: int
    risk_score: float
    summary: Dict[str, Any]
    attack_chain: List[Dict[str, Any]]
    recommendations: List[str]
    pdf_report: Optional[str]


class MalwareAnalysisRequest(BaseModel):
    file_data: str = Field(..., description="Base64 encoded file data")
    file_name: str = Field(..., description="Original file name")


class MalwareAnalysisResponse(BaseModel):
    sha256: str
    sha1: str
    md5: str
    file_name: str
    file_size: int
    file_type: str
    detection_names: List[str]
    tags: List[str]
    static_analysis: Dict[str, Any]
    dynamic_analysis: Dict[str, Any]
    iocs: List[Dict[str, Any]]


class WebCrawlRequest(BaseModel):
    seed_urls: List[str] = Field(..., description="Starting URLs for crawl")
    max_depth: int = Field(3, description="Maximum crawl depth")
    max_pages: int = Field(100, description="Maximum pages to crawl")
    respect_robots: bool = Field(True, description="Respect robots.txt")
    generate_pdf: bool = Field(True, description="Generate PDF report")


class WebCrawlResponse(BaseModel):
    crawl_id: str
    seed_urls: List[str]
    start_time: str
    end_time: str
    statistics: Dict[str, Any]
    domain_graph: Dict[str, Any]
    person_mentions: List[Dict[str, Any]]
    graph_analysis: Dict[str, Any]
    pdf_report: Optional[str]


class EncryptRequest(BaseModel):
    plaintext: str = Field(..., description="Data to encrypt (base64 encoded)")
    algorithm: str = Field("AES-256-GCM", description="Encryption algorithm")
    key: Optional[str] = Field(None, description="Encryption key (base64 encoded, optional)")


class EncryptResponse(BaseModel):
    ciphertext: str
    nonce: str
    tag: str
    algorithm: str
    key_id: str
    timestamp: str


class DecryptRequest(BaseModel):
    ciphertext: str = Field(..., description="Encrypted data (base64 encoded)")
    nonce: str = Field(..., description="Nonce (base64 encoded)")
    tag: str = Field(..., description="Authentication tag (base64 encoded)")
    key: str = Field(..., description="Decryption key (base64 encoded)")


class DecryptResponse(BaseModel):
    plaintext: str
    verified: bool
    algorithm: str
    timestamp: str


class SignRequest(BaseModel):
    message: str = Field(..., description="Message to sign (base64 encoded)")
    private_key: str = Field(..., description="Private key (base64 encoded)")
    algorithm: str = Field("Ed25519", description="Signature algorithm")


class SignResponse(BaseModel):
    signature: str
    algorithm: str
    key_id: str
    timestamp: str
    message_hash: str


class HashRequest(BaseModel):
    data: str = Field(..., description="Data to hash (base64 encoded)")
    algorithm: str = Field("SHA256", description="Hash algorithm")


class HashResponse(BaseModel):
    hash: str
    algorithm: str
    timestamp: str


class KeyPairRequest(BaseModel):
    algorithm: str = Field("Ed25519", description="Key algorithm (Ed25519 or RSA-4096)")


class KeyPairResponse(BaseModel):
    public_key: str
    private_key: str
    key_type: str
    key_size: int
    key_id: str
    created_at: str


scanner_engine = None
attack_engine = None
crawler_engine = None
crypto_engine = None


def get_scanner_engine():
    global scanner_engine
    if scanner_engine is None:
        scanner_engine = create_scanner_engine()
    return scanner_engine


def get_attack_engine():
    global attack_engine
    if attack_engine is None:
        attack_engine = create_attack_analysis_engine()
    return attack_engine


def get_crawler_engine():
    global crawler_engine
    if crawler_engine is None:
        crawler_engine = create_web_crawler_engine()
    return crawler_engine


def get_crypto_engine():
    global crypto_engine
    if crypto_engine is None:
        crypto_engine = create_cryptography_engine()
    return crypto_engine


@router.post("/person/search", response_model=PersonSearchResponse)
async def search_person(request: PersonSearchRequest):
    """
    Search for person across multiple sources including search engines,
    social media platforms, and people search websites.
    """
    try:
        scraper = create_person_search_scraper()
        
        try:
            result = scraper.comprehensive_person_search(request.query)
            
            return PersonSearchResponse(
                query=request.query,
                timestamp=result.get('timestamp', datetime.utcnow().isoformat()),
                search_engines=result.get('search_engines') if request.search_engines else None,
                social_profiles=result.get('social_profiles') if request.social_media else None,
                people_search_sites=result.get('people_search_sites') if request.people_search else None,
                total_results=result.get('total_results', 0)
            )
        finally:
            scraper.cleanup()
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Person search failed: {str(e)}")


@router.post("/scan/comprehensive", response_model=ScanResponse)
async def comprehensive_scan(request: ScanRequest):
    """
    Perform comprehensive security scan including port scanning,
    domain enumeration, web vulnerability assessment, and SSL analysis.
    """
    try:
        engine = get_scanner_engine()
        
        result = engine.comprehensive_scan(
            target=request.target,
            scan_ports=request.scan_ports,
            scan_domain=request.scan_domain,
            scan_web=request.scan_web,
            scan_ssl=request.scan_ssl,
            generate_pdf=request.generate_pdf
        )
        
        return ScanResponse(
            target=result['target'],
            scan_time=result['scan_time'],
            summary=result['summary'],
            port_scan=result.get('port_scan'),
            domain_scan=result.get('domain_scan'),
            web_scan=result.get('web_scan'),
            ssl_scan=result.get('ssl_scan'),
            pdf_report=result.get('pdf_report')
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/ports")
async def scan_ports(target: str, ports: str = "1-1024"):
    """Perform port scanning on target"""
    try:
        engine = get_scanner_engine()
        result = engine.port_scanner.scan_host(target)
        return {
            "target": target,
            "is_up": result.is_up,
            "open_ports": [
                {
                    "port": p.port,
                    "service": p.service,
                    "version": p.version,
                    "banner": p.banner
                }
                for p in result.open_ports
            ],
            "scan_time": result.scan_time,
            "response_time_ms": result.response_time_ms
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Port scan failed: {str(e)}")


@router.post("/scan/domain")
async def scan_domain(domain: str):
    """Perform domain scanning and enumeration"""
    try:
        engine = get_scanner_engine()
        result = engine.domain_scanner.scan_domain(domain)
        return {
            "domain": result.domain,
            "ip_addresses": result.ip_addresses,
            "nameservers": result.nameservers,
            "mx_records": result.mx_records,
            "txt_records": result.txt_records,
            "subdomains": result.subdomains,
            "ssl_info": result.ssl_info,
            "scan_time": result.scan_time
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Domain scan failed: {str(e)}")


@router.post("/scan/web")
async def scan_web(url: str):
    """Perform web vulnerability scanning"""
    try:
        engine = get_scanner_engine()
        result = engine.web_scanner.scan_url(url)
        return {
            "url": result.url,
            "status_code": result.status_code,
            "server": result.server,
            "technologies": result.technologies,
            "security_headers": result.security_headers,
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "title": v.title,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "recommendation": v.recommendation
                }
                for v in result.vulnerabilities
            ],
            "forms_found": len(result.forms),
            "links_found": len(result.links),
            "scan_time": result.scan_time
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Web scan failed: {str(e)}")


@router.post("/scan/ssl")
async def scan_ssl(host: str, port: int = 443):
    """Perform SSL/TLS scanning"""
    try:
        engine = get_scanner_engine()
        result = engine.ssl_scanner.scan_ssl(host, port)
        return {
            "host": result.host,
            "port": result.port,
            "is_valid": result.is_valid,
            "protocol_versions": result.protocol_versions,
            "cipher_suites": result.cipher_suites,
            "vulnerabilities": result.vulnerabilities,
            "expiry_date": result.expiry_date,
            "issuer": result.issuer,
            "subject": result.subject,
            "scan_time": result.scan_time
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL scan failed: {str(e)}")


@router.post("/attack/analyze", response_model=AttackAnalysisResponse)
async def analyze_attack(request: AttackAnalysisRequest):
    """
    Analyze attack events and generate comprehensive attack analysis report
    including kill chain mapping, IOC extraction, and recommendations.
    """
    try:
        engine = get_attack_engine()
        
        result = engine.analyze_attack(
            target=request.target,
            events=request.events,
            generate_pdf=request.generate_pdf
        )
        
        return AttackAnalysisResponse(
            analysis_id=result.analysis_id,
            target=result.target,
            start_time=result.start_time,
            end_time=result.end_time,
            total_events=result.total_events,
            risk_score=result.risk_score,
            summary=result.summary,
            attack_chain=result.attack_chain,
            recommendations=result.recommendations,
            pdf_report=result.summary.get('pdf_report')
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack analysis failed: {str(e)}")


@router.post("/attack/malware", response_model=MalwareAnalysisResponse)
async def analyze_malware(request: MalwareAnalysisRequest):
    """
    Analyze malware sample for IOCs, behaviors, and detection signatures.
    """
    try:
        engine = get_attack_engine()
        
        file_data = base64.b64decode(request.file_data)
        
        sample = engine.malware_analyzer.analyze_bytes(file_data, request.file_name)
        
        return MalwareAnalysisResponse(
            sha256=sample.sha256,
            sha1=sample.sha1,
            md5=sample.md5,
            file_name=sample.file_name,
            file_size=sample.file_size,
            file_type=sample.file_type,
            detection_names=sample.detection_names,
            tags=sample.tags,
            static_analysis=sample.static_analysis,
            dynamic_analysis=sample.dynamic_analysis,
            iocs=sample.iocs
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Malware analysis failed: {str(e)}")


@router.post("/attack/detect")
async def detect_attack(
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    protocol: str,
    payload: str
):
    """
    Analyze request payload for attack patterns in real-time.
    """
    try:
        engine = get_attack_engine()
        
        events = engine.attack_detector.analyze_request(
            source_ip=source_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            protocol=protocol,
            payload=payload
        )
        
        return {
            "detected_attacks": [
                {
                    "event_id": e.event_id,
                    "attack_type": e.attack_type,
                    "severity": e.severity,
                    "confidence": e.confidence,
                    "mitre_techniques": e.mitre_techniques,
                    "timestamp": e.timestamp
                }
                for e in events
            ],
            "total_detected": len(events)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack detection failed: {str(e)}")


@router.get("/attack/stats")
async def get_attack_stats():
    """Get real-time attack statistics"""
    try:
        engine = get_attack_engine()
        return engine.get_real_time_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")


@router.post("/crawler/crawl", response_model=WebCrawlResponse)
async def crawl_web(request: WebCrawlRequest):
    """
    Crawl websites starting from seed URLs, extracting links,
    person mentions, and building domain relationship graphs.
    """
    try:
        engine = get_crawler_engine()
        
        result = engine.crawl_and_analyze(
            seed_urls=request.seed_urls,
            max_depth=request.max_depth,
            max_pages=request.max_pages,
            respect_robots=request.respect_robots,
            generate_pdf=request.generate_pdf
        )
        
        return WebCrawlResponse(
            crawl_id=result['crawl_id'],
            seed_urls=result['seed_urls'],
            start_time=result['start_time'],
            end_time=result['end_time'],
            statistics=result['statistics'],
            domain_graph=result['domain_graph'],
            person_mentions=result['person_mentions'][:50],
            graph_analysis=result['graph_analysis'],
            pdf_report=result.get('pdf_report')
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Web crawl failed: {str(e)}")


@router.post("/crypto/encrypt", response_model=EncryptResponse)
async def encrypt_data(request: EncryptRequest):
    """
    Encrypt data using AES-256-GCM authenticated encryption.
    """
    try:
        engine = get_crypto_engine()
        
        plaintext = base64.b64decode(request.plaintext)
        key = base64.b64decode(request.key) if request.key else None
        
        result = engine.encrypt_symmetric(plaintext, key)
        
        return EncryptResponse(
            ciphertext=result['ciphertext'],
            nonce=result['nonce'],
            tag=result['tag'],
            algorithm=result['algorithm'],
            key_id=result['key_id'],
            timestamp=result['timestamp']
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")


@router.post("/crypto/decrypt", response_model=DecryptResponse)
async def decrypt_data(request: DecryptRequest):
    """
    Decrypt AES-256-GCM encrypted data.
    """
    try:
        engine = get_crypto_engine()
        
        key = base64.b64decode(request.key)
        
        encrypted_data = {
            'ciphertext': request.ciphertext,
            'nonce': request.nonce,
            'tag': request.tag
        }
        
        plaintext = engine.decrypt_symmetric(encrypted_data, key)
        
        return DecryptResponse(
            plaintext=base64.b64encode(plaintext).decode(),
            verified=True,
            algorithm="AES-256-GCM",
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")


@router.post("/crypto/sign", response_model=SignResponse)
async def sign_message(request: SignRequest):
    """
    Sign message using Ed25519 or RSA digital signatures.
    """
    try:
        engine = get_crypto_engine()
        
        message = base64.b64decode(request.message)
        private_key = base64.b64decode(request.private_key)
        
        result = engine.sign_message(message, private_key, request.algorithm)
        
        return SignResponse(
            signature=result['signature'],
            algorithm=result['algorithm'],
            key_id=result['key_id'],
            timestamp=result['timestamp'],
            message_hash=result['message_hash']
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")


@router.post("/crypto/verify")
async def verify_signature(
    message: str,
    signature: str,
    public_key: str,
    algorithm: str = "Ed25519"
):
    """
    Verify digital signature.
    """
    try:
        engine = get_crypto_engine()
        
        message_bytes = base64.b64decode(message)
        public_key_bytes = base64.b64decode(public_key)
        
        signature_data = {
            'signature': signature,
            'algorithm': algorithm
        }
        
        is_valid = engine.verify_signature(message_bytes, signature_data, public_key_bytes)
        
        return {
            "valid": is_valid,
            "algorithm": algorithm,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@router.post("/crypto/hash", response_model=HashResponse)
async def hash_data(request: HashRequest):
    """
    Compute cryptographic hash of data.
    """
    try:
        engine = get_crypto_engine()
        
        data = base64.b64decode(request.data)
        hash_value = engine.hash_data(data, request.algorithm)
        
        return HashResponse(
            hash=hash_value,
            algorithm=request.algorithm,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hashing failed: {str(e)}")


@router.post("/crypto/keypair", response_model=KeyPairResponse)
async def generate_keypair(request: KeyPairRequest):
    """
    Generate cryptographic key pair.
    """
    try:
        engine = get_crypto_engine()
        
        result = engine.generate_keypair(request.algorithm)
        
        return KeyPairResponse(
            public_key=result['public_key'],
            private_key=result['private_key'],
            key_type=result['key_type'],
            key_size=result['key_size'],
            key_id=result['key_id'],
            created_at=result['created_at']
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")


@router.post("/crypto/derive-key")
async def derive_key(password: str, salt: str = None, algorithm: str = "PBKDF2"):
    """
    Derive encryption key from password.
    """
    try:
        engine = get_crypto_engine()
        
        salt_bytes = base64.b64decode(salt) if salt else None
        result = engine.derive_key(password, salt_bytes, algorithm)
        
        return {
            "key": result['key'],
            "salt": result['salt'],
            "algorithm": result['algorithm'],
            "iterations": result['iterations'],
            "key_id": result['key_id']
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key derivation failed: {str(e)}")


@router.get("/crypto/random")
async def generate_random(length: int = 32, format: str = "hex"):
    """
    Generate cryptographically secure random data.
    """
    try:
        engine = get_crypto_engine()
        
        if format == "bytes":
            data = engine.generate_random(length, format)
            return {"data": base64.b64encode(data).decode(), "format": "base64"}
        else:
            data = engine.generate_random(length, format)
            return {"data": data, "format": format}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Random generation failed: {str(e)}")


@router.post("/report/generate")
async def generate_report(
    report_type: str,
    title: str,
    data: Dict[str, Any]
):
    """
    Generate PDF report for various analysis types.
    """
    try:
        generator = create_pdf_generator()
        
        metadata = ReportMetadata(
            title=title,
            subtitle=f"Report Type: {report_type}",
            classification="CONFIDENTIAL",
            author="GISC Enterprise Engine",
            organization="Global Intelligence Security Command Center",
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            report_id=hashlib.md5(f"{title}{datetime.now()}".encode()).hexdigest()[:12].upper(),
            version="1.0"
        )
        
        if report_type == "security_scan":
            pdf_path = generator.generate_security_scan_report(
                metadata=metadata,
                summary=data.get('summary', {}),
                findings=data.get('findings', []),
                vulnerabilities=data.get('vulnerabilities', []),
                network_data=data.get('network_data')
            )
        elif report_type == "person_intelligence":
            pdf_path = generator.generate_person_intelligence_report(
                metadata=metadata,
                person_data=data
            )
        elif report_type == "attack_analysis":
            pdf_path = generator.generate_attack_analysis_report(
                metadata=metadata,
                attack_data=data
            )
        else:
            pdf_path = generator.generate_combined_report(
                metadata=metadata,
                summary=data.get('summary', {}),
                findings=data.get('findings'),
                vulnerabilities=data.get('vulnerabilities'),
                network_data=data.get('network_data'),
                person_data=data.get('person_data'),
                attack_data=data.get('attack_data')
            )
        
        return {
            "report_path": pdf_path,
            "report_type": report_type,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/status")
async def get_enterprise_status():
    """Get status of enterprise engines"""
    return {
        "status": "OPERATIONAL",
        "engines": {
            "scanner": "active" if scanner_engine else "not_initialized",
            "attack_analysis": "active" if attack_engine else "not_initialized",
            "web_crawler": "active" if crawler_engine else "not_initialized",
            "cryptography": "active" if crypto_engine else "not_initialized"
        },
        "timestamp": datetime.utcnow().isoformat(),
        "classification": "TOP SECRET // NSOC // TIER-0"
    }
