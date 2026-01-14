"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - REAL SCANNER ENGINE
Enterprise-grade network, application, and domain scanning implementation

This module provides:
- Network scanning (port scanning, service detection)
- Domain scanning (DNS enumeration, subdomain discovery)
- Application scanning (web vulnerability assessment)
- SSL/TLS analysis
- HTTP header analysis
- Technology fingerprinting
- PDF report generation for all findings

Classification: TOP SECRET // NSOC // TIER-0
"""

import socket
import ssl
import struct
import time
import hashlib
import json
import re
import logging
import threading
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

import requests
from bs4 import BeautifulSoup

from app.real_pdf_generator import PDFReportGenerator, ReportMetadata, create_pdf_generator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PortScanResult:
    port: int
    state: str
    service: str
    version: Optional[str]
    banner: Optional[str]
    protocol: str


@dataclass
class HostScanResult:
    ip: str
    hostname: Optional[str]
    is_up: bool
    open_ports: List[PortScanResult]
    os_fingerprint: Optional[str]
    mac_address: Optional[str]
    scan_time: str
    response_time_ms: int


@dataclass
class DomainScanResult:
    domain: str
    ip_addresses: List[str]
    nameservers: List[str]
    mx_records: List[str]
    txt_records: List[str]
    subdomains: List[str]
    whois_data: Dict[str, Any]
    ssl_info: Optional[Dict[str, Any]]
    scan_time: str


@dataclass
class WebVulnerability:
    vuln_id: str
    title: str
    severity: str
    cvss_score: Optional[float]
    description: str
    affected_url: str
    evidence: str
    recommendation: str
    cwe_id: Optional[str]
    references: List[str]


@dataclass
class WebScanResult:
    url: str
    status_code: int
    server: Optional[str]
    technologies: List[str]
    headers: Dict[str, str]
    security_headers: Dict[str, bool]
    vulnerabilities: List[WebVulnerability]
    forms: List[Dict[str, Any]]
    links: List[str]
    scan_time: str


@dataclass
class SSLScanResult:
    host: str
    port: int
    certificate: Dict[str, Any]
    protocol_versions: List[str]
    cipher_suites: List[str]
    vulnerabilities: List[str]
    expiry_date: Optional[str]
    issuer: Optional[str]
    subject: Optional[str]
    is_valid: bool
    scan_time: str


class PortScanner:
    """Real TCP/UDP port scanner"""
    
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090, 27017
    ]
    
    SERVICE_SIGNATURES = {
        21: ('FTP', [b'220', b'FTP']),
        22: ('SSH', [b'SSH-', b'OpenSSH']),
        23: ('Telnet', [b'\xff\xfd', b'\xff\xfb']),
        25: ('SMTP', [b'220', b'SMTP', b'ESMTP']),
        53: ('DNS', []),
        80: ('HTTP', [b'HTTP/', b'<!DOCTYPE', b'<html']),
        110: ('POP3', [b'+OK', b'POP3']),
        143: ('IMAP', [b'* OK', b'IMAP']),
        443: ('HTTPS', []),
        445: ('SMB', []),
        3306: ('MySQL', [b'\x00\x00\x00\x0a', b'mysql']),
        3389: ('RDP', []),
        5432: ('PostgreSQL', []),
        5900: ('VNC', [b'RFB']),
        8080: ('HTTP-Proxy', [b'HTTP/']),
        27017: ('MongoDB', []),
    }
    
    def __init__(self, timeout: float = 2.0, max_threads: int = 50):
        self.timeout = timeout
        self.max_threads = max_threads
    
    def scan_port(self, host: str, port: int, protocol: str = 'tcp') -> Optional[PortScanResult]:
        """Scan a single port"""
        try:
            if protocol == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            
            if result == 0:
                banner = None
                service = self.SERVICE_SIGNATURES.get(port, ('Unknown', []))[0]
                version = None
                
                try:
                    if protocol == 'tcp':
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner_data = sock.recv(1024)
                        banner = banner_data.decode('utf-8', errors='ignore')[:200]
                        
                        for svc_port, (svc_name, signatures) in self.SERVICE_SIGNATURES.items():
                            for sig in signatures:
                                if sig in banner_data:
                                    service = svc_name
                                    break
                        
                        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
                        if version_match:
                            version = version_match.group(1)
                except socket.timeout:
                    logger.debug(f"Banner grab timeout on {host}:{port}")
                except socket.error as e:
                    logger.debug(f"Banner grab error on {host}:{port}: {e}")
                
                sock.close()
                
                return PortScanResult(
                    port=port,
                    state='open',
                    service=service,
                    version=version,
                    banner=banner,
                    protocol=protocol
                )
            
            sock.close()
            return None
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port}: {e}")
            return None
    
    def scan_host(self, host: str, ports: List[int] = None) -> HostScanResult:
        """Scan all specified ports on a host"""
        if ports is None:
            ports = self.COMMON_PORTS
        
        start_time = time.time()
        open_ports = []
        
        hostname = None
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except socket.herror as e:
            logger.debug(f"Reverse DNS lookup failed for {host}: {e}")
        
        is_up = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, 80))
            if result == 0:
                is_up = True
            sock.close()
        except socket.error as e:
            logger.debug(f"Port 80 check failed for {host}: {e}")
        
        if not is_up:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, 443))
                if result == 0:
                    is_up = True
                sock.close()
            except socket.error as e:
                logger.debug(f"Port 443 check failed for {host}: {e}")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    is_up = True
        
        response_time = int((time.time() - start_time) * 1000)
        
        return HostScanResult(
            ip=host,
            hostname=hostname,
            is_up=is_up,
            open_ports=sorted(open_ports, key=lambda x: x.port),
            os_fingerprint=None,
            mac_address=None,
            scan_time=datetime.utcnow().isoformat(),
            response_time_ms=response_time
        )
    
    def scan_network(self, network: str, ports: List[int] = None) -> List[HostScanResult]:
        """Scan an entire network range"""
        results = []
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())[:256]
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.scan_host, str(host), ports): host for host in hosts}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result.is_up:
                        results.append(result)
        
        except Exception as e:
            logger.error(f"Error scanning network {network}: {e}")
        
        return results


class DomainScanner:
    """Real domain and DNS scanner"""
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'admin', 'api', 'dev', 'staging',
        'test', 'beta', 'app', 'mobile', 'cdn', 'static', 'assets', 'img', 'images',
        'media', 'video', 'blog', 'shop', 'store', 'secure', 'vpn', 'remote',
        'portal', 'login', 'auth', 'sso', 'dashboard', 'panel', 'cpanel', 'webdisk',
        'autodiscover', 'autoconfig', 'imap', 'pop3', 'calendar', 'cloud', 'backup',
        'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'kibana',
        'grafana', 'prometheus', 'jenkins', 'gitlab', 'github', 'bitbucket', 'jira',
        'confluence', 'slack', 'teams', 'zoom', 'meet', 'chat', 'support', 'help',
        'docs', 'wiki', 'forum', 'community', 'status', 'monitor', 'health'
    ]
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            return list(set(socket.gethostbyname_ex(domain)[2]))
        except socket.gaierror as e:
            logger.debug(f"DNS resolution failed for {domain}: {e}")
            return []
    
    def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for domain"""
        nameservers = []
        try:
            import subprocess
            result = subprocess.run(
                ['nslookup', '-type=NS', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'nameserver' in line.lower() or 'name server' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        ns = parts[1].strip().rstrip('.')
                        if ns:
                            nameservers.append(ns)
        except subprocess.TimeoutExpired:
            logger.debug(f"Nameserver lookup timeout for {domain}")
        except Exception as e:
            logger.debug(f"Nameserver lookup failed for {domain}: {e}")
        return nameservers
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for domain"""
        mx_records = []
        try:
            import subprocess
            result = subprocess.run(
                ['nslookup', '-type=MX', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'mail exchanger' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        mx = parts[1].strip().split()[-1].rstrip('.')
                        if mx:
                            mx_records.append(mx)
        except subprocess.TimeoutExpired:
            logger.debug(f"MX record lookup timeout for {domain}")
        except Exception as e:
            logger.debug(f"MX record lookup failed for {domain}: {e}")
        return mx_records
    
    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for domain"""
        txt_records = []
        try:
            import subprocess
            result = subprocess.run(
                ['nslookup', '-type=TXT', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'text' in line.lower() and '=' in line:
                    parts = line.split('=')
                    if len(parts) > 1:
                        txt = parts[1].strip().strip('"')
                        if txt:
                            txt_records.append(txt)
        except subprocess.TimeoutExpired:
            logger.debug(f"TXT record lookup timeout for {domain}")
        except Exception as e:
            logger.debug(f"TXT record lookup failed for {domain}: {e}")
        return txt_records
    
    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains"""
        found_subdomains = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {}
            for subdomain in self.COMMON_SUBDOMAINS:
                full_domain = f"{subdomain}.{domain}"
                futures[executor.submit(self.resolve_domain, full_domain)] = full_domain
            
            for future in as_completed(futures):
                full_domain = futures[future]
                try:
                    ips = future.result()
                    if ips:
                        found_subdomains.append(full_domain)
                except Exception as e:
                    logger.debug(f"Subdomain enumeration error for {full_domain}: {e}")
        
        return sorted(found_subdomains)
    
    def get_ssl_info(self, domain: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    
                    import subprocess
                    result = subprocess.run(
                        ['openssl', 'x509', '-inform', 'DER', '-text', '-noout'],
                        input=cert,
                        capture_output=True,
                        timeout=10
                    )
                    
                    cert_text = result.stdout.decode('utf-8', errors='ignore')
                    
                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert_text': cert_text[:2000],
                        'valid': True
                    }
                    
                    issuer_match = re.search(r'Issuer:(.+?)(?=Subject:|$)', cert_text, re.DOTALL)
                    if issuer_match:
                        ssl_info['issuer'] = issuer_match.group(1).strip()[:200]
                    
                    subject_match = re.search(r'Subject:(.+?)(?=Subject Public|$)', cert_text, re.DOTALL)
                    if subject_match:
                        ssl_info['subject'] = subject_match.group(1).strip()[:200]
                    
                    validity_match = re.search(r'Not After\s*:\s*(.+)', cert_text)
                    if validity_match:
                        ssl_info['expiry'] = validity_match.group(1).strip()
                    
                    return ssl_info
                    
        except Exception as e:
            logger.debug(f"Error getting SSL info for {domain}: {e}")
            return None
    
    def scan_domain(self, domain: str) -> DomainScanResult:
        """Perform comprehensive domain scan"""
        ip_addresses = self.resolve_domain(domain)
        nameservers = self.get_nameservers(domain)
        mx_records = self.get_mx_records(domain)
        txt_records = self.get_txt_records(domain)
        subdomains = self.enumerate_subdomains(domain)
        ssl_info = self.get_ssl_info(domain)
        
        return DomainScanResult(
            domain=domain,
            ip_addresses=ip_addresses,
            nameservers=nameservers,
            mx_records=mx_records,
            txt_records=txt_records,
            subdomains=subdomains,
            whois_data={},
            ssl_info=ssl_info,
            scan_time=datetime.utcnow().isoformat()
        )


class WebScanner:
    """Real web application vulnerability scanner"""
    
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
        'Cross-Origin-Embedder-Policy'
    ]
    
    TECHNOLOGY_SIGNATURES = {
        'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
        'Drupal': [r'Drupal', r'sites/default', r'drupal.js'],
        'Joomla': [r'Joomla', r'/components/', r'/modules/'],
        'Django': [r'csrfmiddlewaretoken', r'__admin__'],
        'Laravel': [r'laravel_session', r'XSRF-TOKEN'],
        'Express': [r'X-Powered-By: Express'],
        'ASP.NET': [r'ASP.NET', r'__VIEWSTATE', r'__EVENTVALIDATION'],
        'PHP': [r'X-Powered-By: PHP', r'PHPSESSID'],
        'Ruby on Rails': [r'X-Powered-By: Phusion', r'_session_id'],
        'Angular': [r'ng-app', r'ng-controller', r'angular'],
        'React': [r'react', r'__REACT', r'data-reactroot'],
        'Vue.js': [r'vue', r'v-bind', r'v-model'],
        'jQuery': [r'jquery', r'jQuery'],
        'Bootstrap': [r'bootstrap', r'Bootstrap'],
        'Nginx': [r'nginx', r'Server: nginx'],
        'Apache': [r'Apache', r'Server: Apache'],
        'IIS': [r'IIS', r'Server: Microsoft-IIS'],
        'Cloudflare': [r'cloudflare', r'cf-ray'],
    }
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def scan_url(self, url: str) -> WebScanResult:
        """Scan a single URL for vulnerabilities"""
        vulnerabilities = []
        technologies = []
        forms = []
        links = []
        headers = {}
        security_headers = {}
        status_code = 0
        server = None
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            status_code = response.status_code
            headers = dict(response.headers)
            server = headers.get('Server')
            
            for header in self.SECURITY_HEADERS:
                security_headers[header] = header in response.headers
            
            content = response.text
            
            for tech, patterns in self.TECHNOLOGY_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, str(headers), re.IGNORECASE):
                        if tech not in technologies:
                            technologies.append(tech)
                        break
            
            soup = BeautifulSoup(content, 'lxml')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'id': inp.get('id', '')
                    })
                forms.append(form_data)
            
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('http'):
                    links.append(href)
                elif href.startswith('/'):
                    links.append(urljoin(url, href))
            
            vulnerabilities.extend(self._check_security_headers(url, security_headers))
            vulnerabilities.extend(self._check_information_disclosure(url, headers, content))
            vulnerabilities.extend(self._check_forms(url, forms))
            
        except requests.exceptions.SSLError:
            vulnerabilities.append(WebVulnerability(
                vuln_id=f"SSL-001-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                title="SSL/TLS Certificate Error",
                severity="HIGH",
                cvss_score=7.5,
                description="The SSL/TLS certificate is invalid, expired, or self-signed",
                affected_url=url,
                evidence="SSL certificate validation failed",
                recommendation="Install a valid SSL certificate from a trusted CA",
                cwe_id="CWE-295",
                references=["https://cwe.mitre.org/data/definitions/295.html"]
            ))
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
        
        return WebScanResult(
            url=url,
            status_code=status_code,
            server=server,
            technologies=technologies,
            headers=headers,
            security_headers=security_headers,
            vulnerabilities=vulnerabilities,
            forms=forms,
            links=links[:100],
            scan_time=datetime.utcnow().isoformat()
        )
    
    def _check_security_headers(self, url: str, security_headers: Dict[str, bool]) -> List[WebVulnerability]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        header_info = {
            'Strict-Transport-Security': ('HIGH', 7.5, 'CWE-319', 'Enforce HTTPS connections'),
            'Content-Security-Policy': ('MEDIUM', 5.0, 'CWE-79', 'Prevent XSS attacks'),
            'X-Content-Type-Options': ('LOW', 3.0, 'CWE-16', 'Prevent MIME sniffing'),
            'X-Frame-Options': ('MEDIUM', 5.0, 'CWE-1021', 'Prevent clickjacking'),
            'X-XSS-Protection': ('LOW', 3.0, 'CWE-79', 'Enable browser XSS filter'),
        }
        
        for header, present in security_headers.items():
            if not present and header in header_info:
                severity, cvss, cwe, desc = header_info[header]
                vulnerabilities.append(WebVulnerability(
                    vuln_id=f"HDR-{hashlib.md5(f'{url}{header}'.encode()).hexdigest()[:8]}",
                    title=f"Missing Security Header: {header}",
                    severity=severity,
                    cvss_score=cvss,
                    description=f"The {header} header is not set. {desc}",
                    affected_url=url,
                    evidence=f"Header '{header}' not found in response",
                    recommendation=f"Add the {header} header to your server configuration",
                    cwe_id=cwe,
                    references=[f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}"]
                ))
        
        return vulnerabilities
    
    def _check_information_disclosure(self, url: str, headers: Dict[str, str], content: str) -> List[WebVulnerability]:
        """Check for information disclosure vulnerabilities"""
        vulnerabilities = []
        
        server = headers.get('Server', '')
        if server and re.search(r'\d+\.\d+', server):
            vulnerabilities.append(WebVulnerability(
                vuln_id=f"INFO-001-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                title="Server Version Disclosure",
                severity="LOW",
                cvss_score=2.0,
                description="The server is disclosing its version information",
                affected_url=url,
                evidence=f"Server header: {server}",
                recommendation="Configure the server to hide version information",
                cwe_id="CWE-200",
                references=["https://cwe.mitre.org/data/definitions/200.html"]
            ))
        
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            vulnerabilities.append(WebVulnerability(
                vuln_id=f"INFO-002-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                title="Technology Stack Disclosure",
                severity="LOW",
                cvss_score=2.0,
                description="The X-Powered-By header reveals technology information",
                affected_url=url,
                evidence=f"X-Powered-By: {powered_by}",
                recommendation="Remove the X-Powered-By header",
                cwe_id="CWE-200",
                references=["https://cwe.mitre.org/data/definitions/200.html"]
            ))
        
        sensitive_patterns = [
            (r'(?i)password\s*[:=]\s*["\']?[\w@#$%^&*]+', 'Password in source'),
            (r'(?i)api[_-]?key\s*[:=]\s*["\']?[\w-]+', 'API key in source'),
            (r'(?i)secret[_-]?key\s*[:=]\s*["\']?[\w-]+', 'Secret key in source'),
            (r'(?i)aws[_-]?access[_-]?key', 'AWS credentials in source'),
        ]
        
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, content):
                vulnerabilities.append(WebVulnerability(
                    vuln_id=f"INFO-003-{hashlib.md5(f'{url}{pattern}'.encode()).hexdigest()[:8]}",
                    title=f"Sensitive Information Disclosure: {desc}",
                    severity="HIGH",
                    cvss_score=7.5,
                    description=f"Potential sensitive information found in page source: {desc}",
                    affected_url=url,
                    evidence=f"Pattern matched: {pattern}",
                    recommendation="Remove sensitive information from client-side code",
                    cwe_id="CWE-200",
                    references=["https://cwe.mitre.org/data/definitions/200.html"]
                ))
        
        return vulnerabilities
    
    def _check_forms(self, url: str, forms: List[Dict[str, Any]]) -> List[WebVulnerability]:
        """Check forms for potential vulnerabilities"""
        vulnerabilities = []
        
        for form in forms:
            has_csrf = False
            for inp in form.get('inputs', []):
                name = inp.get('name', '').lower()
                if 'csrf' in name or 'token' in name or '_token' in name:
                    has_csrf = True
                    break
            
            if form.get('method') == 'POST' and not has_csrf:
                vulnerabilities.append(WebVulnerability(
                    vuln_id=f"CSRF-001-{hashlib.md5(f'{url}{form}'.encode()).hexdigest()[:8]}",
                    title="Potential CSRF Vulnerability",
                    severity="MEDIUM",
                    cvss_score=5.0,
                    description="A POST form was found without apparent CSRF protection",
                    affected_url=url,
                    evidence=f"Form action: {form.get('action', 'N/A')}",
                    recommendation="Implement CSRF tokens for all state-changing forms",
                    cwe_id="CWE-352",
                    references=["https://cwe.mitre.org/data/definitions/352.html"]
                ))
            
            for inp in form.get('inputs', []):
                if inp.get('type') == 'password':
                    if not url.startswith('https://'):
                        vulnerabilities.append(WebVulnerability(
                            vuln_id=f"AUTH-001-{hashlib.md5(f'{url}{inp}'.encode()).hexdigest()[:8]}",
                            title="Password Transmitted Over HTTP",
                            severity="CRITICAL",
                            cvss_score=9.0,
                            description="A password field was found on a non-HTTPS page",
                            affected_url=url,
                            evidence=f"Password input: {inp.get('name', 'N/A')}",
                            recommendation="Use HTTPS for all pages with sensitive forms",
                            cwe_id="CWE-319",
                            references=["https://cwe.mitre.org/data/definitions/319.html"]
                        ))
        
        return vulnerabilities


class SSLScanner:
    """Real SSL/TLS scanner"""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    def scan_ssl(self, host: str, port: int = 443) -> SSLScanResult:
        """Perform comprehensive SSL/TLS scan"""
        certificate = {}
        protocol_versions = []
        cipher_suites = []
        vulnerabilities = []
        expiry_date = None
        issuer = None
        subject = None
        is_valid = False
        
        protocols_to_test = [
            ('TLSv1.3', ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None),
            ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
            ('TLSv1.1', ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
            ('TLSv1.0', ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None),
        ]
        
        for proto_name, proto_version in protocols_to_test:
            if proto_version is None:
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = proto_version
                context.maximum_version = proto_version
                
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        protocol_versions.append(proto_name)
                        cipher_suites.append(ssock.cipher()[0])
            except ssl.SSLError as e:
                logger.debug(f"SSL protocol {proto_name} not supported on {host}:{port}: {e}")
            except socket.error as e:
                logger.debug(f"Connection error testing {proto_name} on {host}:{port}: {e}")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    is_valid = True
                    
                    if cert:
                        certificate = cert
                        
                        if 'notAfter' in cert:
                            expiry_date = cert['notAfter']
                        
                        if 'issuer' in cert:
                            issuer_parts = []
                            for item in cert['issuer']:
                                for key, value in item:
                                    issuer_parts.append(f"{key}={value}")
                            issuer = ', '.join(issuer_parts)
                        
                        if 'subject' in cert:
                            subject_parts = []
                            for item in cert['subject']:
                                for key, value in item:
                                    subject_parts.append(f"{key}={value}")
                            subject = ', '.join(subject_parts)
        except ssl.SSLCertVerificationError as e:
            vulnerabilities.append(f"Certificate verification failed: {str(e)}")
        except Exception as e:
            logger.debug(f"Error in SSL scan: {e}")
        
        if 'TLSv1.0' in protocol_versions:
            vulnerabilities.append("TLSv1.0 is enabled (deprecated, vulnerable to BEAST)")
        if 'TLSv1.1' in protocol_versions:
            vulnerabilities.append("TLSv1.1 is enabled (deprecated)")
        
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
        for cipher in cipher_suites:
            for weak in weak_ciphers:
                if weak in cipher.upper():
                    vulnerabilities.append(f"Weak cipher suite: {cipher}")
                    break
        
        return SSLScanResult(
            host=host,
            port=port,
            certificate=certificate,
            protocol_versions=protocol_versions,
            cipher_suites=list(set(cipher_suites)),
            vulnerabilities=vulnerabilities,
            expiry_date=expiry_date,
            issuer=issuer,
            subject=subject,
            is_valid=is_valid,
            scan_time=datetime.utcnow().isoformat()
        )


class ScannerEngine:
    """Main scanner engine coordinating all scanning capabilities"""
    
    def __init__(self):
        self.port_scanner = PortScanner()
        self.domain_scanner = DomainScanner()
        self.web_scanner = WebScanner()
        self.ssl_scanner = SSLScanner()
        self.pdf_generator = create_pdf_generator()
    
    def comprehensive_scan(
        self,
        target: str,
        scan_ports: bool = True,
        scan_domain: bool = True,
        scan_web: bool = True,
        scan_ssl: bool = True,
        generate_pdf: bool = True
    ) -> Dict[str, Any]:
        """Perform comprehensive scan of target"""
        results = {
            'target': target,
            'scan_time': datetime.utcnow().isoformat(),
            'port_scan': None,
            'domain_scan': None,
            'web_scan': None,
            'ssl_scan': None,
            'summary': {},
            'pdf_report': None
        }
        
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False
        
        if scan_ports:
            if is_ip:
                results['port_scan'] = asdict(self.port_scanner.scan_host(target))
            else:
                ips = self.domain_scanner.resolve_domain(target)
                if ips:
                    results['port_scan'] = asdict(self.port_scanner.scan_host(ips[0]))
        
        if scan_domain and not is_ip:
            results['domain_scan'] = asdict(self.domain_scanner.scan_domain(target))
        
        if scan_web:
            url = target if target.startswith('http') else f"https://{target}"
            results['web_scan'] = asdict(self.web_scanner.scan_url(url))
        
        if scan_ssl:
            host = target
            if target.startswith('http'):
                parsed = urlparse(target)
                host = parsed.hostname
            if host and not is_ip:
                results['ssl_scan'] = asdict(self.ssl_scanner.scan_ssl(host))
        
        results['summary'] = self._generate_summary(results)
        
        if generate_pdf:
            results['pdf_report'] = self._generate_pdf_report(results)
        
        return results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary"""
        summary = {
            'total_open_ports': 0,
            'total_vulnerabilities': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'technologies_detected': [],
            'subdomains_found': 0,
            'ssl_valid': False,
            'risk_level': 'LOW'
        }
        
        if results.get('port_scan'):
            summary['total_open_ports'] = len(results['port_scan'].get('open_ports', []))
        
        if results.get('domain_scan'):
            summary['subdomains_found'] = len(results['domain_scan'].get('subdomains', []))
        
        if results.get('web_scan'):
            summary['technologies_detected'] = results['web_scan'].get('technologies', [])
            for vuln in results['web_scan'].get('vulnerabilities', []):
                summary['total_vulnerabilities'] += 1
                severity = vuln.get('severity', 'LOW').upper()
                if severity == 'CRITICAL':
                    summary['critical_findings'] += 1
                elif severity == 'HIGH':
                    summary['high_findings'] += 1
                elif severity == 'MEDIUM':
                    summary['medium_findings'] += 1
                else:
                    summary['low_findings'] += 1
        
        if results.get('ssl_scan'):
            summary['ssl_valid'] = results['ssl_scan'].get('is_valid', False)
            summary['total_vulnerabilities'] += len(results['ssl_scan'].get('vulnerabilities', []))
        
        if summary['critical_findings'] > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['high_findings'] > 0:
            summary['risk_level'] = 'HIGH'
        elif summary['medium_findings'] > 0:
            summary['risk_level'] = 'MEDIUM'
        
        return summary
    
    def _generate_pdf_report(self, results: Dict[str, Any]) -> str:
        """Generate PDF report from scan results"""
        metadata = ReportMetadata(
            title="Security Scan Report",
            subtitle=f"Target: {results['target']}",
            classification="CONFIDENTIAL",
            author="GISC Scanner Engine",
            organization="Global Intelligence Security Command Center",
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            report_id=hashlib.md5(f"{results['target']}{results['scan_time']}".encode()).hexdigest()[:12].upper(),
            version="1.0"
        )
        
        summary = {
            'overview': f"Comprehensive security scan of {results['target']} completed at {results['scan_time']}.",
            'key_findings': [],
            'risk_level': results['summary'].get('risk_level', 'LOW'),
            'statistics': {
                'Open Ports': results['summary'].get('total_open_ports', 0),
                'Vulnerabilities Found': results['summary'].get('total_vulnerabilities', 0),
                'Critical Findings': results['summary'].get('critical_findings', 0),
                'High Findings': results['summary'].get('high_findings', 0),
                'Subdomains Found': results['summary'].get('subdomains_found', 0),
                'SSL Valid': 'Yes' if results['summary'].get('ssl_valid') else 'No'
            }
        }
        
        if results['summary'].get('critical_findings', 0) > 0:
            summary['key_findings'].append(f"{results['summary']['critical_findings']} critical vulnerabilities require immediate attention")
        if results['summary'].get('high_findings', 0) > 0:
            summary['key_findings'].append(f"{results['summary']['high_findings']} high severity issues detected")
        if not results['summary'].get('ssl_valid'):
            summary['key_findings'].append("SSL/TLS certificate issues detected")
        
        findings = []
        if results.get('web_scan'):
            for vuln in results['web_scan'].get('vulnerabilities', []):
                findings.append({
                    'title': vuln.get('title', 'Unknown'),
                    'severity': vuln.get('severity', 'LOW'),
                    'description': vuln.get('description', ''),
                    'affected_assets': [vuln.get('affected_url', '')],
                    'evidence': vuln.get('evidence', ''),
                    'recommendation': vuln.get('recommendation', ''),
                    'cvss_score': vuln.get('cvss_score'),
                    'cve_ids': []
                })
        
        vulnerabilities = []
        for i, finding in enumerate(findings, 1):
            vulnerabilities.append({
                'id': f"VULN-{i:03d}",
                'title': finding['title'],
                'severity': finding['severity'],
                'cvss_score': finding.get('cvss_score', 'N/A'),
                'status': 'Open'
            })
        
        network_data = None
        if results.get('port_scan'):
            port_scan = results['port_scan']
            network_data = {
                'hosts': [{
                    'ip': port_scan.get('ip', 'N/A'),
                    'hostname': port_scan.get('hostname', 'Unknown'),
                    'os': port_scan.get('os_fingerprint', 'Unknown'),
                    'open_ports': len(port_scan.get('open_ports', [])),
                    'services': [p.get('service', 'Unknown') for p in port_scan.get('open_ports', [])][:5]
                }]
            }
        
        return self.pdf_generator.generate_security_scan_report(
            metadata=metadata,
            summary=summary,
            findings=findings,
            vulnerabilities=vulnerabilities,
            network_data=network_data
        )


def create_scanner_engine() -> ScannerEngine:
    """Factory function to create scanner engine instance"""
    return ScannerEngine()
