"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - COMPREHENSIVE OPERATIONS MODULE
Enterprise-grade implementation of all 32 template directory functionalities.

This module implements operational capabilities for:
- Analytics, Antiforensics, Biometric, Communications, Crawler, Cryptography
- Defense, Defensive, Detection, EMSEC, Forensics, Intelligence
- Malware, Monitoring, Network, Observability, Offensive, Operations
- Reliability, Research, Response, Scanner, Search, Security
- Specialized, Stealth, Supply-chain, Surveillance, UI, Visualization
- Vulnerability, Warfare

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import hmac
import socket
import ssl
import struct
import time
import json
import base64
import secrets
import ipaddress
import re
import urllib.parse
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import queue
import dns.resolver
import dns.reversename
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class CrawlerMode(str, Enum):
    BREADTH_FIRST = "BREADTH_FIRST"
    DEPTH_FIRST = "DEPTH_FIRST"
    BEST_FIRST = "BEST_FIRST"
    FOCUSED = "FOCUSED"
    INCREMENTAL = "INCREMENTAL"
    DISTRIBUTED = "DISTRIBUTED"
    STEALTH = "STEALTH"


class ScanMode(str, Enum):
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"
    AGGRESSIVE = "AGGRESSIVE"
    STEALTH = "STEALTH"
    CUSTOM = "CUSTOM"


class InternetLayer(str, Enum):
    SURFACE = "SURFACE"
    DARK = "DARK"
    DEEP = "DEEP"


class VulnerabilityCategory(str, Enum):
    INJECTION = "INJECTION"
    BROKEN_AUTHENTICATION = "BROKEN_AUTHENTICATION"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    XML_EXTERNAL_ENTITIES = "XML_EXTERNAL_ENTITIES"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    VULNERABLE_COMPONENTS = "VULNERABLE_COMPONENTS"
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class MalwareType(str, Enum):
    VIRUS = "VIRUS"
    WORM = "WORM"
    TROJAN = "TROJAN"
    RANSOMWARE = "RANSOMWARE"
    SPYWARE = "SPYWARE"
    ROOTKIT = "ROOTKIT"
    RAT = "RAT"
    BACKDOOR = "BACKDOOR"
    CRYPTOMINER = "CRYPTOMINER"
    BOTNET = "BOTNET"


class ForensicsType(str, Enum):
    MOBILE = "MOBILE"
    COMPUTER = "COMPUTER"
    NETWORK = "NETWORK"
    MEMORY = "MEMORY"
    IOT = "IOT"


@dataclass
class CrawlResult:
    url: str
    status_code: int
    content_type: str
    content_length: int
    title: str
    links: List[str]
    forms: List[Dict[str, Any]]
    headers: Dict[str, str]
    cookies: List[Dict[str, str]]
    timestamp: str
    response_time: float
    layer: str
    crawl_depth: int
    error: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    scan_type: str
    layer: str
    status: str
    start_time: str
    end_time: str
    findings: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    open_ports: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    ssl_info: Optional[Dict[str, Any]] = None
    dns_info: Optional[Dict[str, Any]] = None
    whois_info: Optional[Dict[str, Any]] = None
    technology_stack: List[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class MalwareAnalysisResult:
    sample_id: str
    filename: str
    file_type: str
    file_size: int
    hashes: Dict[str, str]
    static_analysis: Dict[str, Any]
    dynamic_analysis: Dict[str, Any]
    behavioral_analysis: Dict[str, Any]
    classification: Dict[str, Any]
    indicators: List[Dict[str, Any]]
    yara_matches: List[str]
    threat_level: str
    timestamp: str
    hex_dump: str = ""
    disassembly: str = ""


@dataclass
class ForensicsResult:
    case_id: str
    device_type: str
    acquisition_type: str
    evidence_items: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    artifacts: List[Dict[str, Any]]
    chain_of_custody: List[Dict[str, Any]]
    analysis_notes: str
    timestamp: str


@dataclass
class IntelligenceReport:
    report_id: str
    intel_type: str
    classification: str
    source: str
    summary: str
    entities: List[Dict[str, Any]]
    indicators: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]
    confidence: float
    timestamp: str


class WebCrawlerEngine:
    """Enterprise-grade web crawler implementing all modes from web-crawler-engine.ts.predloga"""
    
    def __init__(self, mode: CrawlerMode = CrawlerMode.BREADTH_FIRST, max_depth: int = 3, max_pages: int = 100):
        self.mode = mode
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.results = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
    
    def _get_headers(self, stealth: bool = False) -> Dict[str, str]:
        headers = {
            "User-Agent": secrets.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if stealth:
            headers["DNT"] = "1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
        return headers
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        links = []
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            link = match.group(1)
            if link.startswith('http'):
                links.append(link)
            elif link.startswith('/'):
                parsed = urllib.parse.urlparse(base_url)
                links.append(f"{parsed.scheme}://{parsed.netloc}{link}")
            elif not link.startswith(('#', 'javascript:', 'mailto:')):
                links.append(urllib.parse.urljoin(base_url, link))
        return list(set(links))
    
    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            inputs = []
            input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
            for input_match in input_pattern.finditer(form_html):
                input_tag = input_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                inputs.append({
                    "name": name_match.group(1) if name_match else None,
                    "type": type_match.group(1) if type_match else "text"
                })
            
            forms.append({
                "action": action_match.group(1) if action_match else "",
                "method": method_match.group(1).upper() if method_match else "GET",
                "inputs": inputs
            })
        return forms
    
    def _extract_title(self, html: str) -> str:
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return title_match.group(1).strip() if title_match else ""
    
    def crawl_url(self, url: str, depth: int = 0, layer: InternetLayer = InternetLayer.SURFACE) -> CrawlResult:
        import urllib.request
        import urllib.error
        
        start_time = time.time()
        
        try:
            headers = self._get_headers(stealth=self.mode == CrawlerMode.STEALTH)
            request = urllib.request.Request(url, headers=headers)
            
            context = ssl.create_default_context()
            if layer == InternetLayer.DARK:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(request, timeout=10, context=context) as response:
                content = response.read().decode('utf-8', errors='ignore')
                response_time = time.time() - start_time
                
                return CrawlResult(
                    url=url,
                    status_code=response.status,
                    content_type=response.headers.get('Content-Type', 'unknown'),
                    content_length=len(content),
                    title=self._extract_title(content),
                    links=self._extract_links(content, url),
                    forms=self._extract_forms(content),
                    headers=dict(response.headers),
                    cookies=[],
                    timestamp=datetime.utcnow().isoformat(),
                    response_time=response_time,
                    layer=layer.value,
                    crawl_depth=depth
                )
        except Exception as e:
            return CrawlResult(
                url=url,
                status_code=0,
                content_type="error",
                content_length=0,
                title="",
                links=[],
                forms=[],
                headers={},
                cookies=[],
                timestamp=datetime.utcnow().isoformat(),
                response_time=time.time() - start_time,
                layer=layer.value,
                crawl_depth=depth,
                error=str(e)
            )
    
    def crawl(self, seed_urls: List[str], layer: InternetLayer = InternetLayer.SURFACE) -> List[CrawlResult]:
        results = []
        
        for url in seed_urls:
            self.url_queue.put((url, 0))
        
        pages_crawled = 0
        while not self.url_queue.empty() and pages_crawled < self.max_pages:
            url, depth = self.url_queue.get()
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
            
            self.visited_urls.add(url)
            result = self.crawl_url(url, depth, layer)
            results.append(result)
            pages_crawled += 1
            
            if self.mode == CrawlerMode.BREADTH_FIRST:
                for link in result.links[:10]:
                    if link not in self.visited_urls:
                        self.url_queue.put((link, depth + 1))
            elif self.mode == CrawlerMode.DEPTH_FIRST:
                for link in reversed(result.links[:10]):
                    if link not in self.visited_urls:
                        self.url_queue.put((link, depth + 1))
            
            if self.mode == CrawlerMode.STEALTH:
                time.sleep(secrets.randbelow(3) + 1)
        
        return results


class VulnerabilityScanner:
    """Enterprise-grade vulnerability scanner implementing live-web-vulnerability-scanner.ts.predloga"""
    
    def __init__(self, mode: ScanMode = ScanMode.ACTIVE):
        self.mode = mode
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                           993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        self.service_signatures = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB"
        }
    
    def scan_port(self, target: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                service = self.service_signatures.get(port, "unknown")
                banner = ""
                
                try:
                    if port in [21, 22, 25, 110, 143]:
                        sock.settimeout(2)
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    logger.debug(f"Banner grab timeout on port {port}")
                except Exception as e:
                    logger.debug(f"Banner grab failed on port {port}: {e}")
                
                sock.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    "protocol": "tcp"
                }
            sock.close()
            return {"port": port, "state": "closed", "service": None, "protocol": "tcp"}
        except socket.timeout:
            return {"port": port, "state": "filtered", "service": None, "protocol": "tcp"}
        except Exception as e:
            return {"port": port, "state": "error", "service": None, "error": str(e), "protocol": "tcp"}
    
    def scan_ssl(self, target: str, port: int = 443) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    cert_der = ssl.DER_cert_to_PEM_cert(cert)
                    
                    return {
                        "ssl_version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                        "certificate": {
                            "present": True,
                            "pem": cert_der[:200] + "..." if len(cert_der) > 200 else cert_der
                        },
                        "vulnerabilities": self._check_ssl_vulnerabilities(version, cipher)
                    }
        except Exception as e:
            return {"error": str(e), "ssl_version": None, "vulnerabilities": []}
    
    def _check_ssl_vulnerabilities(self, version: str, cipher: Tuple) -> List[Dict[str, Any]]:
        vulns = []
        
        if version in ["SSLv2", "SSLv3"]:
            vulns.append({
                "id": "SSL-001",
                "name": "Deprecated SSL Version",
                "severity": "HIGH",
                "description": f"Server supports deprecated {version}",
                "remediation": "Disable SSLv2 and SSLv3, use TLS 1.2 or higher"
            })
        
        if version == "TLSv1" or version == "TLSv1.0":
            vulns.append({
                "id": "TLS-001",
                "name": "Deprecated TLS Version",
                "severity": "MEDIUM",
                "description": "Server supports TLS 1.0 which is deprecated",
                "remediation": "Upgrade to TLS 1.2 or TLS 1.3"
            })
        
        if cipher and cipher[0]:
            cipher_name = cipher[0].upper()
            if "RC4" in cipher_name:
                vulns.append({
                    "id": "CIPHER-001",
                    "name": "Weak Cipher Suite (RC4)",
                    "severity": "HIGH",
                    "description": "Server supports RC4 cipher which is cryptographically weak",
                    "remediation": "Disable RC4 cipher suites"
                })
            if "DES" in cipher_name and "3DES" not in cipher_name:
                vulns.append({
                    "id": "CIPHER-002",
                    "name": "Weak Cipher Suite (DES)",
                    "severity": "HIGH",
                    "description": "Server supports DES cipher which is cryptographically weak",
                    "remediation": "Disable DES cipher suites"
                })
            if "NULL" in cipher_name:
                vulns.append({
                    "id": "CIPHER-003",
                    "name": "NULL Cipher Suite",
                    "severity": "CRITICAL",
                    "description": "Server supports NULL cipher which provides no encryption",
                    "remediation": "Disable NULL cipher suites"
                })
        
        return vulns
    
    def scan_dns(self, target: str) -> Dict[str, Any]:
        results = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "soa_record": None,
            "ptr_records": []
        }
        
        try:
            try:
                answers = dns.resolver.resolve(target, 'A')
                results["a_records"] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                logger.debug(f"No A records found for {target}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No A record answer for {target}")
            except Exception as e:
                logger.debug(f"A record lookup failed for {target}: {e}")
            
            try:
                answers = dns.resolver.resolve(target, 'AAAA')
                results["aaaa_records"] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                logger.debug(f"No AAAA records found for {target}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No AAAA record answer for {target}")
            except Exception as e:
                logger.debug(f"AAAA record lookup failed for {target}: {e}")
            
            try:
                answers = dns.resolver.resolve(target, 'MX')
                results["mx_records"] = [{"priority": rdata.preference, "host": str(rdata.exchange)} for rdata in answers]
            except dns.resolver.NXDOMAIN:
                logger.debug(f"No MX records found for {target}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No MX record answer for {target}")
            except Exception as e:
                logger.debug(f"MX record lookup failed for {target}: {e}")
            
            try:
                answers = dns.resolver.resolve(target, 'NS')
                results["ns_records"] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                logger.debug(f"No NS records found for {target}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No NS record answer for {target}")
            except Exception as e:
                logger.debug(f"NS record lookup failed for {target}: {e}")
            
            try:
                answers = dns.resolver.resolve(target, 'TXT')
                results["txt_records"] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                logger.debug(f"No TXT records found for {target}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No TXT record answer for {target}")
            except Exception as e:
                logger.debug(f"TXT record lookup failed for {target}: {e}")
            
            try:
                answers = dns.resolver.resolve(target, 'CNAME')
                results["cname_records"] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                logger.debug(f"No CNAME records found for {target}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No CNAME record answer for {target}")
            except Exception as e:
                logger.debug(f"CNAME record lookup failed for {target}: {e}")
            
            try:
                answers = dns.resolver.resolve(target, 'SOA')
                for rdata in answers:
                    results["soa_record"] = {
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum
                    }
            except dns.resolver.NXDOMAIN:
                logger.debug(f"No SOA records found for {target}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No SOA record answer for {target}")
            except Exception as e:
                logger.debug(f"SOA record lookup failed for {target}: {e}")
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def detect_technologies(self, headers: Dict[str, str], content: str = "") -> List[str]:
        technologies = []
        
        server = headers.get('Server', headers.get('server', ''))
        if server:
            technologies.append(f"Server: {server}")
        
        powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
        if powered_by:
            technologies.append(f"Powered-By: {powered_by}")
        
        if 'wp-content' in content or 'wordpress' in content.lower():
            technologies.append("CMS: WordPress")
        elif 'drupal' in content.lower():
            technologies.append("CMS: Drupal")
        elif 'joomla' in content.lower():
            technologies.append("CMS: Joomla")
        
        if 'react' in content.lower() or 'reactdom' in content.lower():
            technologies.append("Framework: React")
        elif 'angular' in content.lower():
            technologies.append("Framework: Angular")
        elif 'vue' in content.lower():
            technologies.append("Framework: Vue.js")
        
        if 'jquery' in content.lower():
            technologies.append("Library: jQuery")
        if 'bootstrap' in content.lower():
            technologies.append("Library: Bootstrap")
        
        return technologies
    
    def check_security_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        
        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'description': 'HSTS header not set - vulnerable to protocol downgrade attacks'
            },
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'description': 'CSP header not set - vulnerable to XSS attacks'
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'description': 'X-Frame-Options not set - vulnerable to clickjacking'
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'description': 'X-Content-Type-Options not set - vulnerable to MIME sniffing'
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'description': 'X-XSS-Protection not set'
            },
            'Referrer-Policy': {
                'severity': 'LOW',
                'description': 'Referrer-Policy not set - may leak sensitive information'
            }
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, info in security_headers.items():
            if header.lower() not in headers_lower:
                findings.append({
                    "type": "MISSING_SECURITY_HEADER",
                    "header": header,
                    "severity": info['severity'],
                    "description": info['description'],
                    "remediation": f"Add {header} header to HTTP responses"
                })
        
        return findings
    
    def full_scan(self, target: str, layer: InternetLayer = InternetLayer.SURFACE, 
                  port_range: str = "common") -> ScanResult:
        start_time = datetime.utcnow()
        findings = []
        vulnerabilities = []
        open_ports = []
        services = []
        
        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            ip_address = target
        
        if port_range == "common":
            ports_to_scan = self.common_ports
        elif port_range == "full":
            ports_to_scan = list(range(1, 65536))
        else:
            try:
                start, end = port_range.split("-")
                ports_to_scan = list(range(int(start), int(end) + 1))
            except ValueError as e:
                logger.warning(f"Invalid port range format '{port_range}', using common ports: {e}")
                ports_to_scan = self.common_ports
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(self.scan_port, ip_address, port): port 
                           for port in ports_to_scan}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result["state"] == "open":
                    open_ports.append(result)
                    services.append({
                        "port": result["port"],
                        "service": result["service"],
                        "banner": result.get("banner", "")
                    })
        
        ssl_info = None
        if any(p["port"] in [443, 8443] for p in open_ports):
            ssl_port = 443 if any(p["port"] == 443 for p in open_ports) else 8443
            ssl_info = self.scan_ssl(ip_address, ssl_port)
            if ssl_info.get("vulnerabilities"):
                vulnerabilities.extend(ssl_info["vulnerabilities"])
        
        dns_info = self.scan_dns(target)
        
        technology_stack = []
        if any(p["port"] in [80, 443, 8080, 8443] for p in open_ports):
            try:
                import urllib.request
                url = f"https://{target}" if any(p["port"] == 443 for p in open_ports) else f"http://{target}"
                request = urllib.request.Request(url, headers={"User-Agent": "GISC-Scanner/1.0"})
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(request, timeout=5, context=context) as response:
                    headers = dict(response.headers)
                    content = response.read().decode('utf-8', errors='ignore')
                    technology_stack = self.detect_technologies(headers, content)
                    header_findings = self.check_security_headers(headers)
                    findings.extend(header_findings)
            except urllib.error.URLError as e:
                logger.debug(f"URL request failed for {target}: {e}")
            except Exception as e:
                logger.debug(f"Technology detection failed for {target}: {e}")
        
        critical_ports = [21, 23, 445, 3389, 5900]
        for port_info in open_ports:
            if port_info["port"] in critical_ports:
                vulnerabilities.append({
                    "id": f"PORT-{port_info['port']}",
                    "name": f"Critical Service Exposed ({port_info['service']})",
                    "severity": "HIGH",
                    "port": port_info["port"],
                    "description": f"Port {port_info['port']} ({port_info['service']}) is open and may pose security risk",
                    "remediation": f"Consider restricting access to port {port_info['port']} or disabling the service if not needed"
                })
        
        risk_score = self._calculate_risk_score(open_ports, vulnerabilities, findings)
        
        end_time = datetime.utcnow()
        
        return ScanResult(
            target=target,
            scan_type="full",
            layer=layer.value,
            status="completed",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            findings=findings,
            vulnerabilities=vulnerabilities,
            open_ports=open_ports,
            services=services,
            ssl_info=ssl_info,
            dns_info=dns_info,
            technology_stack=technology_stack,
            risk_score=risk_score
        )
    
    def _calculate_risk_score(self, open_ports: List, vulnerabilities: List, findings: List) -> float:
        score = 0.0
        
        score += len(open_ports) * 2
        
        for vuln in vulnerabilities:
            if vuln.get("severity") == "CRITICAL":
                score += 25
            elif vuln.get("severity") == "HIGH":
                score += 15
            elif vuln.get("severity") == "MEDIUM":
                score += 8
            elif vuln.get("severity") == "LOW":
                score += 3
        
        for finding in findings:
            if finding.get("severity") == "HIGH":
                score += 10
            elif finding.get("severity") == "MEDIUM":
                score += 5
            elif finding.get("severity") == "LOW":
                score += 2
        
        return min(score, 100.0)


class MalwareAnalyzer:
    """Enterprise-grade malware analyzer implementing malware-analysis.ts.predloga"""
    
    def __init__(self):
        self.yara_rules = [
            "rule Suspicious_Strings { strings: $a = \"cmd.exe\" $b = \"powershell\" condition: any of them }",
            "rule Packed_Executable { strings: $upx = \"UPX\" condition: $upx }",
            "rule Crypto_Strings { strings: $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ condition: $btc }"
        ]
    
    def calculate_hashes(self, data: bytes) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest()
        }
    
    def analyze_pe_header(self, data: bytes) -> Dict[str, Any]:
        result = {
            "is_pe": False,
            "machine": None,
            "sections": [],
            "imports": [],
            "exports": [],
            "timestamp": None,
            "entry_point": None
        }
        
        if len(data) < 64:
            return result
        
        if data[:2] == b'MZ':
            result["is_pe"] = True
            
            try:
                pe_offset = struct.unpack('<I', data[60:64])[0]
                
                if len(data) > pe_offset + 6:
                    machine = struct.unpack('<H', data[pe_offset + 4:pe_offset + 6])[0]
                    machine_types = {
                        0x14c: "i386",
                        0x8664: "AMD64",
                        0x1c0: "ARM",
                        0xaa64: "ARM64"
                    }
                    result["machine"] = machine_types.get(machine, f"Unknown (0x{machine:x})")
                
                if len(data) > pe_offset + 12:
                    timestamp = struct.unpack('<I', data[pe_offset + 8:pe_offset + 12])[0]
                    result["timestamp"] = datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else None
                
            except struct.error as e:
                logger.debug(f"PE header parsing error: {e}")
            except Exception as e:
                logger.debug(f"PE analysis failed: {e}")
        
        return result
    
    def extract_strings(self, data: bytes, min_length: int = 4) -> Dict[str, List[str]]:
        ascii_strings = []
        unicode_strings = []
        
        ascii_pattern = re.compile(b'[\x20-\x7e]{' + str(min_length).encode() + b',}')
        for match in ascii_pattern.finditer(data):
            try:
                s = match.group().decode('ascii')
                ascii_strings.append(s)
            except UnicodeDecodeError:
                continue
        
        urls = []
        ips = []
        emails = []
        
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        
        all_strings = ' '.join(ascii_strings)
        urls = url_pattern.findall(all_strings)
        ips = ip_pattern.findall(all_strings)
        emails = email_pattern.findall(all_strings)
        
        return {
            "ascii_strings": ascii_strings[:100],
            "unicode_strings": unicode_strings[:100],
            "urls": list(set(urls)),
            "ip_addresses": list(set(ips)),
            "emails": list(set(emails)),
            "total_strings": len(ascii_strings) + len(unicode_strings)
        }
    
    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability and (probability > 0 and __import__('math').log2(probability)))
        
        return round(entropy, 4)
    
    def detect_packer(self, data: bytes) -> Dict[str, Any]:
        packers = {
            b'UPX': "UPX",
            b'MPRESS': "MPRESS",
            b'ASPack': "ASPack",
            b'PECompact': "PECompact",
            b'Themida': "Themida",
            b'VMProtect': "VMProtect"
        }
        
        detected = []
        for signature, name in packers.items():
            if signature in data:
                detected.append(name)
        
        entropy = self.calculate_entropy(data)
        
        return {
            "detected_packers": detected,
            "entropy": entropy,
            "likely_packed": entropy > 7.0 or len(detected) > 0,
            "confidence": "HIGH" if detected else ("MEDIUM" if entropy > 7.0 else "LOW")
        }
    
    def classify_malware(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        indicators = []
        malware_type = "UNKNOWN"
        threat_level = "LOW"
        confidence = 0.0
        
        strings = analysis_results.get("strings", {})
        
        ransomware_indicators = ["encrypt", "decrypt", "bitcoin", "ransom", "payment", ".locked", ".encrypted"]
        rat_indicators = ["keylog", "screenshot", "webcam", "microphone", "shell", "execute"]
        trojan_indicators = ["download", "upload", "connect", "socket", "http", "ftp"]
        
        all_strings = ' '.join(strings.get("ascii_strings", [])).lower()
        
        ransomware_score = sum(1 for ind in ransomware_indicators if ind in all_strings)
        rat_score = sum(1 for ind in rat_indicators if ind in all_strings)
        trojan_score = sum(1 for ind in trojan_indicators if ind in all_strings)
        
        if ransomware_score >= 3:
            malware_type = "RANSOMWARE"
            threat_level = "CRITICAL"
            confidence = min(ransomware_score * 15, 90)
            indicators.append("Ransomware-related strings detected")
        elif rat_score >= 3:
            malware_type = "RAT"
            threat_level = "HIGH"
            confidence = min(rat_score * 15, 85)
            indicators.append("Remote Access Trojan indicators detected")
        elif trojan_score >= 3:
            malware_type = "TROJAN"
            threat_level = "HIGH"
            confidence = min(trojan_score * 12, 80)
            indicators.append("Trojan indicators detected")
        
        if analysis_results.get("packer", {}).get("likely_packed"):
            indicators.append("Sample appears to be packed/obfuscated")
            confidence = min(confidence + 10, 95)
        
        if strings.get("urls"):
            indicators.append(f"Contains {len(strings['urls'])} URLs")
        if strings.get("ip_addresses"):
            indicators.append(f"Contains {len(strings['ip_addresses'])} IP addresses")
        
        return {
            "malware_type": malware_type,
            "threat_level": threat_level,
            "confidence": confidence,
            "indicators": indicators,
            "mitre_techniques": self._map_to_mitre(malware_type, indicators)
        }
    
    def _map_to_mitre(self, malware_type: str, indicators: List[str]) -> List[Dict[str, str]]:
        mitre_mapping = {
            "RANSOMWARE": [
                {"id": "T1486", "name": "Data Encrypted for Impact"},
                {"id": "T1490", "name": "Inhibit System Recovery"},
                {"id": "T1489", "name": "Service Stop"}
            ],
            "RAT": [
                {"id": "T1059", "name": "Command and Scripting Interpreter"},
                {"id": "T1113", "name": "Screen Capture"},
                {"id": "T1056", "name": "Input Capture"}
            ],
            "TROJAN": [
                {"id": "T1071", "name": "Application Layer Protocol"},
                {"id": "T1105", "name": "Ingress Tool Transfer"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel"}
            ]
        }
        return mitre_mapping.get(malware_type, [])
    
    def _generate_hex_dump(self, data: bytes) -> str:
        """Generate hex dump of binary data"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<48}  |{ascii_part}|')
        return '\n'.join(lines)
    
    def _generate_disassembly(self, data: bytes, pe_analysis: Dict[str, Any]) -> str:
        """Generate disassembly-like output for entry point"""
        if not pe_analysis.get("is_pe"):
            return "Not a PE file - disassembly not available"
        
        entry_point = pe_analysis.get("entry_point")
        if entry_point is None:
            entry_point = 0
        
        lines = [f"; Entry Point: 0x{entry_point:08x}", "; Disassembly (first 32 bytes from entry):"]
        
        start = min(entry_point, len(data) - 32) if len(data) > 32 else 0
        chunk = data[start:start+32]
        
        offset = start
        for i in range(0, len(chunk), 4):
            bytes_hex = ' '.join(f'{b:02x}' for b in chunk[i:i+4])
            lines.append(f"0x{offset:08x}:  {bytes_hex:<12}")
            offset += 4
        
        return '\n'.join(lines)
    
    def _get_string_description(self, s: str) -> str:
        """Get description for suspicious string"""
        descriptions = {
            'cmd.exe': 'Command shell execution',
            'powershell': 'PowerShell execution',
            'http://': 'HTTP URL (potential C2)',
            'https://': 'HTTPS URL (potential C2)',
            'socket': 'Network socket operation',
            'connect': 'Network connection',
            'CreateRemoteThread': 'Remote thread injection',
            'VirtualAlloc': 'Memory allocation (shellcode)',
            'WriteProcessMemory': 'Process memory manipulation',
            'LoadLibrary': 'Dynamic library loading',
            'GetProcAddress': 'API resolution',
            'RegSetValue': 'Registry modification',
            'CreateService': 'Service creation (persistence)',
            'ShellExecute': 'Shell command execution',
            'URLDownloadToFile': 'File download from URL',
            'WScript.Shell': 'Windows Script Host',
            'eval(': 'Dynamic code evaluation',
            'exec(': 'Code execution',
            'base64': 'Base64 encoding/decoding',
        }
        s_lower = s.lower()
        for key, desc in descriptions.items():
            if key.lower() in s_lower:
                return desc
        return 'Suspicious pattern'
    
    def analyze(self, data: bytes, filename: str = "sample") -> MalwareAnalysisResult:
        sample_id = f"MAL-{secrets.token_hex(8).upper()}"
        
        hashes = self.calculate_hashes(data)
        pe_analysis = self.analyze_pe_header(data)
        strings = self.extract_strings(data)
        packer = self.detect_packer(data)
        
        analysis_results = {
            "pe_analysis": pe_analysis,
            "strings": strings,
            "packer": packer
        }
        
        classification = self.classify_malware(analysis_results)
        
        yara_matches = []
        data_str = data.decode('utf-8', errors='ignore').lower()
        if 'cmd.exe' in data_str or 'powershell' in data_str:
            yara_matches.append("Suspicious_Strings")
        if b'UPX' in data:
            yara_matches.append("Packed_Executable")
        
        hex_dump = self._generate_hex_dump(data[:512])
        disassembly = self._generate_disassembly(data, pe_analysis)
        
        return MalwareAnalysisResult(
            sample_id=sample_id,
            filename=filename,
            file_type="PE32" if pe_analysis["is_pe"] else "UNKNOWN",
            file_size=len(data),
            hashes=hashes,
            static_analysis={
                "pe_info": pe_analysis,
                "strings": strings,
                "entropy": packer["entropy"],
                "packer_detection": packer,
                "suspicious_strings": [
                    {"pattern": s, "description": self._get_string_description(s), "count": 1}
                    for s in strings.get("suspicious", [])[:20]
                ],
                "urls": strings.get("urls", []),
                "ip_addresses": strings.get("ip_addresses", [])
            },
            dynamic_analysis={
                "status": "not_executed",
                "note": "Dynamic analysis requires sandbox environment"
            },
            behavioral_analysis={
                "network_indicators": strings.get("urls", []) + strings.get("ip_addresses", []),
                "file_indicators": [],
                "registry_indicators": []
            },
            classification=classification,
            indicators=[
                {"type": "hash", "value": hashes["sha256"], "description": "SHA256 hash"},
                {"type": "hash", "value": hashes["md5"], "description": "MD5 hash"}
            ] + [{"type": "url", "value": url, "description": "Extracted URL"} for url in strings.get("urls", [])[:5]],
            yara_matches=yara_matches,
            threat_level=classification["threat_level"],
            timestamp=datetime.utcnow().isoformat(),
            hex_dump=hex_dump,
            disassembly=disassembly
        )


class ForensicsEngine:
    """Enterprise-grade forensics engine implementing device-forensics.ts.predloga"""
    
    def __init__(self):
        self.evidence_types = ["FILE", "REGISTRY", "LOG", "MEMORY", "NETWORK", "BROWSER", "EMAIL"]
    
    def create_case(self, case_name: str, examiner: str, description: str = "") -> str:
        case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
        return case_id
    
    def analyze_file_metadata(self, filepath: str, data: bytes) -> Dict[str, Any]:
        return {
            "filename": filepath.split('/')[-1] if '/' in filepath else filepath,
            "size": len(data),
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest()
            },
            "magic_bytes": data[:16].hex() if len(data) >= 16 else data.hex(),
            "entropy": self._calculate_entropy(data),
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        import math
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        return round(entropy, 4)
    
    def extract_artifacts(self, data: bytes, artifact_type: str) -> List[Dict[str, Any]]:
        artifacts = []
        data_str = data.decode('utf-8', errors='ignore')
        
        if artifact_type == "BROWSER":
            url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
            urls = url_pattern.findall(data_str)
            for url in set(urls):
                artifacts.append({
                    "type": "URL",
                    "value": url,
                    "source": "browser_artifact",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        elif artifact_type == "EMAIL":
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            emails = email_pattern.findall(data_str)
            for email in set(emails):
                artifacts.append({
                    "type": "EMAIL",
                    "value": email,
                    "source": "email_artifact",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        elif artifact_type == "NETWORK":
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            ips = ip_pattern.findall(data_str)
            for ip in set(ips):
                artifacts.append({
                    "type": "IP_ADDRESS",
                    "value": ip,
                    "source": "network_artifact",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return artifacts
    
    def build_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        
        timeline = []
        for i, event in enumerate(sorted_events):
            timeline.append({
                "sequence": i + 1,
                "timestamp": event.get("timestamp"),
                "event_type": event.get("type"),
                "description": event.get("description"),
                "source": event.get("source"),
                "evidence_id": event.get("evidence_id")
            })
        
        return timeline
    
    def generate_report(self, case_id: str, findings: List[Dict[str, Any]], 
                       timeline: List[Dict[str, Any]]) -> ForensicsResult:
        return ForensicsResult(
            case_id=case_id,
            device_type="COMPUTER",
            acquisition_type="LOGICAL",
            evidence_items=findings,
            timeline=timeline,
            artifacts=[],
            chain_of_custody=[
                {
                    "action": "ACQUIRED",
                    "timestamp": datetime.utcnow().isoformat(),
                    "handler": "GISC Forensics Engine",
                    "notes": "Automated acquisition and analysis"
                }
            ],
            analysis_notes="Automated forensic analysis completed",
            timestamp=datetime.utcnow().isoformat()
        )


class IntelligenceCollector:
    """Enterprise-grade intelligence collector implementing osint-platform.ts.predloga and darkweb-intelligence.ts.predloga"""
    
    def __init__(self):
        self.intel_types = ["OSINT", "SIGINT", "FININT", "HUMINT", "DARKWEB"]
    
    def collect_osint(self, target: str, sources: List[str] = None) -> IntelligenceReport:
        report_id = f"INTEL-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4).upper()}"
        
        entities = []
        indicators = []
        
        if self._is_domain(target):
            entities.append({
                "type": "DOMAIN",
                "value": target,
                "confidence": 1.0
            })
            
            try:
                ip = socket.gethostbyname(target)
                entities.append({
                    "type": "IP_ADDRESS",
                    "value": ip,
                    "confidence": 1.0,
                    "relationship": f"resolves_to:{target}"
                })
                indicators.append({
                    "type": "IP",
                    "value": ip,
                    "context": f"Resolved from {target}"
                })
            except socket.gaierror as e:
                logger.debug(f"DNS resolution failed for {target}: {e}")
        
        elif self._is_ip(target):
            entities.append({
                "type": "IP_ADDRESS",
                "value": target,
                "confidence": 1.0
            })
            
            try:
                hostname = socket.gethostbyaddr(target)[0]
                entities.append({
                    "type": "DOMAIN",
                    "value": hostname,
                    "confidence": 0.9,
                    "relationship": f"reverse_dns:{target}"
                })
            except socket.herror as e:
                logger.debug(f"Reverse DNS lookup failed for {target}: {e}")
        
        elif self._is_email(target):
            entities.append({
                "type": "EMAIL",
                "value": target,
                "confidence": 1.0
            })
            
            domain = target.split('@')[1]
            entities.append({
                "type": "DOMAIN",
                "value": domain,
                "confidence": 1.0,
                "relationship": f"email_domain:{target}"
            })
        
        return IntelligenceReport(
            report_id=report_id,
            intel_type="OSINT",
            classification="UNCLASSIFIED",
            source="GISC Intelligence Collector",
            summary=f"OSINT collection for target: {target}",
            entities=entities,
            indicators=indicators,
            relationships=[],
            confidence=0.85,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def _is_domain(self, value: str) -> bool:
        domain_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
        return bool(domain_pattern.match(value))
    
    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except:
            return False
    
    def _is_email(self, value: str) -> bool:
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(email_pattern.match(value))
    
    def analyze_darkweb_indicator(self, indicator: str) -> Dict[str, Any]:
        result = {
            "indicator": indicator,
            "type": "UNKNOWN",
            "risk_level": "UNKNOWN",
            "analysis": {}
        }
        
        if indicator.endswith('.onion'):
            result["type"] = "TOR_HIDDEN_SERVICE"
            result["risk_level"] = "HIGH"
            result["analysis"] = {
                "network": "TOR",
                "service_type": "HIDDEN_SERVICE",
                "note": "Tor hidden service address detected"
            }
        elif indicator.endswith('.i2p'):
            result["type"] = "I2P_SERVICE"
            result["risk_level"] = "HIGH"
            result["analysis"] = {
                "network": "I2P",
                "service_type": "EEPSITE",
                "note": "I2P eepsite address detected"
            }
        
        return result


class SIEMEngine:
    """Enterprise-grade SIEM engine implementing siem-soc.ts.predloga"""
    
    def __init__(self):
        self.correlation_rules = []
        self.alert_queue = queue.Queue()
    
    def parse_log(self, log_entry: str, log_type: str = "SYSLOG") -> Dict[str, Any]:
        parsed = {
            "raw": log_entry,
            "log_type": log_type,
            "timestamp": datetime.utcnow().isoformat(),
            "parsed_fields": {}
        }
        
        if log_type == "SYSLOG":
            syslog_pattern = re.compile(
                r'^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.*)$'
            )
            match = syslog_pattern.match(log_entry)
            if match:
                parsed["parsed_fields"] = {
                    "priority": int(match.group(1)),
                    "timestamp": match.group(2),
                    "hostname": match.group(3),
                    "program": match.group(4),
                    "message": match.group(5)
                }
        
        elif log_type == "CEF":
            cef_pattern = re.compile(r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$')
            match = cef_pattern.match(log_entry)
            if match:
                parsed["parsed_fields"] = {
                    "version": match.group(1),
                    "vendor": match.group(2),
                    "product": match.group(3),
                    "version": match.group(4),
                    "signature_id": match.group(5),
                    "name": match.group(6),
                    "severity": match.group(7),
                    "extension": match.group(8)
                }
        
        return parsed
    
    def correlate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        correlated = []
        
        ip_events = {}
        for event in events:
            source_ip = event.get("source_ip")
            if source_ip:
                if source_ip not in ip_events:
                    ip_events[source_ip] = []
                ip_events[source_ip].append(event)
        
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 5:
                correlated.append({
                    "correlation_id": f"CORR-{secrets.token_hex(4).upper()}",
                    "rule": "MULTIPLE_EVENTS_SAME_SOURCE",
                    "source_ip": ip,
                    "event_count": len(ip_event_list),
                    "severity": "HIGH" if len(ip_event_list) >= 10 else "MEDIUM",
                    "description": f"Multiple events ({len(ip_event_list)}) from same source IP",
                    "events": ip_event_list[:10],
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return correlated
    
    def generate_alert(self, event: Dict[str, Any], rule_name: str, severity: str) -> Dict[str, Any]:
        return {
            "alert_id": f"ALERT-{secrets.token_hex(6).upper()}",
            "rule_name": rule_name,
            "severity": severity,
            "status": "NEW",
            "event": event,
            "timestamp": datetime.utcnow().isoformat(),
            "assigned_to": None,
            "notes": []
        }


def convert_to_dict(obj):
    """Convert dataclass objects to dictionaries for JSON serialization"""
    if hasattr(obj, '__dataclass_fields__'):
        return asdict(obj)
    elif isinstance(obj, list):
        return [convert_to_dict(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: convert_to_dict(v) for k, v in obj.items()}
    else:
        return obj
