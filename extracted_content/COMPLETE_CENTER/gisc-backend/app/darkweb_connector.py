"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - DARK WEB CONNECTOR MODULE
Enterprise-grade Tor and I2P network connectivity for dark web intelligence

This module implements:
- Tor SOCKS5 proxy integration with circuit management
- I2P SAM bridge integration
- .onion site crawling capabilities
- Dark web marketplace monitoring
- Tor hidden service hosting
- Circuit isolation for operational security

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import socket
import logging
import time
import hashlib
import secrets
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
from contextlib import contextmanager

import requests
import socks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


TOR_SOCKS_HOST = os.environ.get("TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT = int(os.environ.get("TOR_SOCKS_PORT", "9050"))
TOR_CONTROL_HOST = os.environ.get("TOR_CONTROL_HOST", "127.0.0.1")
TOR_CONTROL_PORT = int(os.environ.get("TOR_CONTROL_PORT", "9051"))
TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "")
I2P_SAM_HOST = os.environ.get("I2P_SAM_HOST", "127.0.0.1")
I2P_SAM_PORT = int(os.environ.get("I2P_SAM_PORT", "7656"))
I2P_HTTP_PROXY_HOST = os.environ.get("I2P_HTTP_PROXY_HOST", "127.0.0.1")
I2P_HTTP_PROXY_PORT = int(os.environ.get("I2P_HTTP_PROXY_PORT", "4444"))
DARKWEB_REQUEST_TIMEOUT = int(os.environ.get("DARKWEB_REQUEST_TIMEOUT", "60"))
MAX_CIRCUIT_REUSE = int(os.environ.get("MAX_CIRCUIT_REUSE", "10"))


class NetworkType(str, Enum):
    CLEARNET = "clearnet"
    TOR = "tor"
    I2P = "i2p"


class CircuitStatus(str, Enum):
    BUILDING = "building"
    BUILT = "built"
    CLOSED = "closed"
    FAILED = "failed"


@dataclass
class TorCircuit:
    circuit_id: str
    status: CircuitStatus
    path: List[str]
    created_at: datetime
    request_count: int = 0
    last_used: datetime = None
    purpose: str = "general"


@dataclass
class DarkWebRequest:
    request_id: str
    url: str
    network_type: NetworkType
    method: str
    status_code: int
    response_size: int
    latency_ms: float
    circuit_id: Optional[str]
    timestamp: datetime
    success: bool
    error: Optional[str] = None


class TorControlConnection:
    def __init__(self, host: str = None, port: int = None, password: str = None):
        self.host = host or TOR_CONTROL_HOST
        self.port = port or TOR_CONTROL_PORT
        self.password = password or TOR_CONTROL_PASSWORD
        self._socket: Optional[socket.socket] = None
        self._lock = threading.Lock()
    
    def connect(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(10)
            self._socket.connect((self.host, self.port))
            
            response = self._recv()
            if not response.startswith("250"):
                logger.error(f"Tor control connection failed: {response}")
                return False
            
            if self.password:
                self._send(f'AUTHENTICATE "{self.password}"')
                response = self._recv()
                if not response.startswith("250"):
                    logger.error(f"Tor authentication failed: {response}")
                    return False
            else:
                self._send("AUTHENTICATE")
                response = self._recv()
                if not response.startswith("250"):
                    logger.error(f"Tor authentication failed: {response}")
                    return False
            
            logger.info("Tor control connection established")
            return True
            
        except Exception as e:
            logger.error(f"Tor control connection error: {e}")
            return False
    
    def _send(self, command: str):
        if self._socket:
            self._socket.send(f"{command}\r\n".encode())
    
    def _recv(self) -> str:
        if self._socket:
            return self._socket.recv(4096).decode().strip()
        return ""
    
    def close(self):
        if self._socket:
            try:
                self._send("QUIT")
                self._socket.close()
            except Exception:
                pass
            self._socket = None
    
    def signal_newnym(self) -> bool:
        with self._lock:
            try:
                self._send("SIGNAL NEWNYM")
                response = self._recv()
                return response.startswith("250")
            except Exception as e:
                logger.error(f"Failed to signal NEWNYM: {e}")
                return False
    
    def get_circuit_status(self) -> List[TorCircuit]:
        circuits = []
        with self._lock:
            try:
                self._send("GETINFO circuit-status")
                response = self._recv()
                
                for line in response.split("\n"):
                    if line.startswith("250+circuit-status=") or line.startswith("250-circuit-status="):
                        continue
                    if line.startswith("250 "):
                        break
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        circuit_id = parts[0]
                        status = parts[1]
                        path = parts[2].split(",") if len(parts) > 2 else []
                        
                        circuits.append(TorCircuit(
                            circuit_id=circuit_id,
                            status=CircuitStatus(status.lower()) if status.lower() in [s.value for s in CircuitStatus] else CircuitStatus.BUILDING,
                            path=path,
                            created_at=datetime.utcnow()
                        ))
                
            except Exception as e:
                logger.error(f"Failed to get circuit status: {e}")
        
        return circuits
    
    def get_info(self, key: str) -> str:
        with self._lock:
            try:
                self._send(f"GETINFO {key}")
                response = self._recv()
                if response.startswith("250-"):
                    return response.split("=", 1)[1] if "=" in response else response
                return ""
            except Exception as e:
                logger.error(f"Failed to get info {key}: {e}")
                return ""


class TorSession:
    def __init__(self, socks_host: str = None, socks_port: int = None):
        self.socks_host = socks_host or TOR_SOCKS_HOST
        self.socks_port = socks_port or TOR_SOCKS_PORT
        self._session: Optional[requests.Session] = None
        self._circuit_id: Optional[str] = None
        self._request_count = 0
        self._created_at = datetime.utcnow()
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.proxies = {
            "http": f"socks5h://{self.socks_host}:{self.socks_port}",
            "https": f"socks5h://{self.socks_host}:{self.socks_port}"
        }
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        return session
    
    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = self._create_session()
        return self._session
    
    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DARKWEB_REQUEST_TIMEOUT)
        self._request_count += 1
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DARKWEB_REQUEST_TIMEOUT)
        self._request_count += 1
        return self.session.post(url, **kwargs)
    
    def close(self):
        if self._session:
            self._session.close()
            self._session = None


class I2PSession:
    def __init__(self, proxy_host: str = None, proxy_port: int = None):
        self.proxy_host = proxy_host or I2P_HTTP_PROXY_HOST
        self.proxy_port = proxy_port or I2P_HTTP_PROXY_PORT
        self._session: Optional[requests.Session] = None
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.proxies = {
            "http": f"http://{self.proxy_host}:{self.proxy_port}",
            "https": f"http://{self.proxy_host}:{self.proxy_port}"
        }
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        })
        return session
    
    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = self._create_session()
        return self._session
    
    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DARKWEB_REQUEST_TIMEOUT)
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DARKWEB_REQUEST_TIMEOUT)
        return self.session.post(url, **kwargs)
    
    def close(self):
        if self._session:
            self._session.close()
            self._session = None


class I2PSAMBridge:
    def __init__(self, host: str = None, port: int = None):
        self.host = host or I2P_SAM_HOST
        self.port = port or I2P_SAM_PORT
        self._socket: Optional[socket.socket] = None
        self._session_id: Optional[str] = None
        self._destination: Optional[str] = None
    
    def connect(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(30)
            self._socket.connect((self.host, self.port))
            
            self._send("HELLO VERSION MIN=3.0 MAX=3.3")
            response = self._recv()
            
            if "RESULT=OK" not in response:
                logger.error(f"I2P SAM handshake failed: {response}")
                return False
            
            logger.info("I2P SAM bridge connected")
            return True
            
        except Exception as e:
            logger.error(f"I2P SAM connection error: {e}")
            return False
    
    def _send(self, message: str):
        if self._socket:
            self._socket.send(f"{message}\n".encode())
    
    def _recv(self) -> str:
        if self._socket:
            return self._socket.recv(65536).decode().strip()
        return ""
    
    def create_session(self, session_id: str = None, style: str = "STREAM") -> bool:
        try:
            self._session_id = session_id or f"tyranthos_{secrets.token_hex(8)}"
            
            self._send(f"SESSION CREATE STYLE={style} ID={self._session_id} DESTINATION=TRANSIENT")
            response = self._recv()
            
            if "RESULT=OK" in response:
                for part in response.split():
                    if part.startswith("DESTINATION="):
                        self._destination = part.split("=", 1)[1]
                        break
                logger.info(f"I2P session created: {self._session_id}")
                return True
            
            logger.error(f"I2P session creation failed: {response}")
            return False
            
        except Exception as e:
            logger.error(f"I2P session creation error: {e}")
            return False
    
    def lookup_destination(self, name: str) -> Optional[str]:
        try:
            self._send(f"NAMING LOOKUP NAME={name}")
            response = self._recv()
            
            if "RESULT=OK" in response:
                for part in response.split():
                    if part.startswith("VALUE="):
                        return part.split("=", 1)[1]
            
            return None
            
        except Exception as e:
            logger.error(f"I2P lookup error: {e}")
            return None
    
    def close(self):
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None


class DarkWebConnector:
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
        
        self._tor_control: Optional[TorControlConnection] = None
        self._tor_sessions: Dict[str, TorSession] = {}
        self._i2p_sessions: Dict[str, I2PSession] = {}
        self._i2p_sam: Optional[I2PSAMBridge] = None
        self._request_log: List[DarkWebRequest] = []
        self._session_lock = threading.Lock()
    
    def check_tor_connectivity(self) -> Dict[str, Any]:
        result = {
            "available": False,
            "socks_proxy": f"{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            "control_port": f"{TOR_CONTROL_HOST}:{TOR_CONTROL_PORT}",
            "version": None,
            "circuits": 0,
            "external_ip": None,
            "error": None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock_result = sock.connect_ex((TOR_SOCKS_HOST, TOR_SOCKS_PORT))
            sock.close()
            
            if sock_result != 0:
                result["error"] = "Tor SOCKS proxy not reachable"
                return result
            
            session = TorSession()
            response = session.get("https://check.torproject.org/api/ip", timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                result["available"] = data.get("IsTor", False)
                result["external_ip"] = data.get("IP")
            
            session.close()
            
            if self._tor_control is None:
                self._tor_control = TorControlConnection()
                if self._tor_control.connect():
                    result["version"] = self._tor_control.get_info("version")
                    circuits = self._tor_control.get_circuit_status()
                    result["circuits"] = len([c for c in circuits if c.status == CircuitStatus.BUILT])
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def check_i2p_connectivity(self) -> Dict[str, Any]:
        result = {
            "available": False,
            "http_proxy": f"{I2P_HTTP_PROXY_HOST}:{I2P_HTTP_PROXY_PORT}",
            "sam_bridge": f"{I2P_SAM_HOST}:{I2P_SAM_PORT}",
            "router_info": None,
            "error": None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock_result = sock.connect_ex((I2P_HTTP_PROXY_HOST, I2P_HTTP_PROXY_PORT))
            sock.close()
            
            if sock_result != 0:
                result["error"] = "I2P HTTP proxy not reachable"
                return result
            
            session = I2PSession()
            try:
                response = session.get("http://127.0.0.1:7070/", timeout=10)
                if response.status_code == 200:
                    result["available"] = True
                    result["router_info"] = "I2P router console accessible"
            except Exception:
                pass
            
            session.close()
            
            sam = I2PSAMBridge()
            if sam.connect():
                result["available"] = True
                result["router_info"] = "I2P SAM bridge connected"
                sam.close()
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def get_tor_session(self, session_id: str = None) -> TorSession:
        session_id = session_id or "default"
        
        with self._session_lock:
            if session_id not in self._tor_sessions:
                self._tor_sessions[session_id] = TorSession()
            
            session = self._tor_sessions[session_id]
            
            if session._request_count >= MAX_CIRCUIT_REUSE:
                session.close()
                self._tor_sessions[session_id] = TorSession()
                session = self._tor_sessions[session_id]
            
            return session
    
    def get_i2p_session(self, session_id: str = None) -> I2PSession:
        session_id = session_id or "default"
        
        with self._session_lock:
            if session_id not in self._i2p_sessions:
                self._i2p_sessions[session_id] = I2PSession()
            return self._i2p_sessions[session_id]
    
    def new_tor_identity(self) -> bool:
        if self._tor_control is None:
            self._tor_control = TorControlConnection()
            if not self._tor_control.connect():
                return False
        
        return self._tor_control.signal_newnym()
    
    def request(self, url: str, method: str = "GET", network: NetworkType = None,
                session_id: str = None, **kwargs) -> Tuple[Optional[requests.Response], DarkWebRequest]:
        
        if network is None:
            if ".onion" in url:
                network = NetworkType.TOR
            elif ".i2p" in url:
                network = NetworkType.I2P
            else:
                network = NetworkType.CLEARNET
        
        request_id = f"req_{secrets.token_hex(8)}"
        start_time = time.time()
        response = None
        error = None
        status_code = 0
        response_size = 0
        
        try:
            if network == NetworkType.TOR:
                session = self.get_tor_session(session_id)
                if method.upper() == "GET":
                    response = session.get(url, **kwargs)
                elif method.upper() == "POST":
                    response = session.post(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")
            
            elif network == NetworkType.I2P:
                session = self.get_i2p_session(session_id)
                if method.upper() == "GET":
                    response = session.get(url, **kwargs)
                elif method.upper() == "POST":
                    response = session.post(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")
            
            else:
                if method.upper() == "GET":
                    response = requests.get(url, **kwargs)
                elif method.upper() == "POST":
                    response = requests.post(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")
            
            status_code = response.status_code
            response_size = len(response.content)
            
        except Exception as e:
            error = str(e)
            logger.error(f"Dark web request failed: {e}")
        
        latency_ms = (time.time() - start_time) * 1000
        
        request_log = DarkWebRequest(
            request_id=request_id,
            url=url,
            network_type=network,
            method=method.upper(),
            status_code=status_code,
            response_size=response_size,
            latency_ms=latency_ms,
            circuit_id=None,
            timestamp=datetime.utcnow(),
            success=response is not None and status_code < 400,
            error=error
        )
        
        self._request_log.append(request_log)
        
        if len(self._request_log) > 10000:
            self._request_log = self._request_log[-5000:]
        
        return response, request_log
    
    def crawl_onion(self, onion_url: str, max_depth: int = 2, max_pages: int = 100,
                    session_id: str = None) -> Dict[str, Any]:
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse
        
        visited = set()
        to_visit = [(onion_url, 0)]
        pages = []
        links_found = set()
        
        while to_visit and len(pages) < max_pages:
            url, depth = to_visit.pop(0)
            
            if url in visited:
                continue
            
            if depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                response, request_log = self.request(url, network=NetworkType.TOR, session_id=session_id)
                
                if response is None or response.status_code != 200:
                    continue
                
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    continue
                
                soup = BeautifulSoup(response.content, "html.parser")
                
                title = soup.title.string if soup.title else ""
                text_content = soup.get_text(separator=" ", strip=True)[:5000]
                
                page_data = {
                    "url": url,
                    "title": title,
                    "content_preview": text_content[:500],
                    "content_length": len(response.content),
                    "depth": depth,
                    "timestamp": datetime.utcnow().isoformat(),
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                }
                
                pages.append(page_data)
                
                if depth < max_depth:
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_url = urljoin(url, href)
                        parsed = urlparse(full_url)
                        
                        if ".onion" in parsed.netloc:
                            links_found.add(full_url)
                            if full_url not in visited:
                                to_visit.append((full_url, depth + 1))
                
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")
        
        return {
            "start_url": onion_url,
            "pages_crawled": len(pages),
            "unique_links_found": len(links_found),
            "max_depth_reached": max(p["depth"] for p in pages) if pages else 0,
            "pages": pages,
            "links": list(links_found)[:1000],
        }
    
    def search_onion_directories(self, query: str) -> List[Dict[str, Any]]:
        directories = [
            "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
            "http://donionsixbjtiohce24abfgsffo2l4tk26qx464zylumgejukfq2vead.onion",
        ]
        
        results = []
        
        for directory in directories:
            try:
                search_url = f"{directory}/search?q={query}"
                response, _ = self.request(search_url, network=NetworkType.TOR)
                
                if response and response.status_code == 200:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, "html.parser")
                    
                    for result in soup.find_all("div", class_="result")[:20]:
                        link = result.find("a")
                        if link:
                            results.append({
                                "title": link.get_text(strip=True),
                                "url": link.get("href", ""),
                                "source": directory,
                            })
                
            except Exception as e:
                logger.error(f"Directory search failed for {directory}: {e}")
        
        return results
    
    def get_request_statistics(self) -> Dict[str, Any]:
        if not self._request_log:
            return {
                "total_requests": 0,
                "success_rate": 0,
                "avg_latency_ms": 0,
                "by_network": {},
            }
        
        total = len(self._request_log)
        successful = sum(1 for r in self._request_log if r.success)
        avg_latency = sum(r.latency_ms for r in self._request_log) / total
        
        by_network = {}
        for network in NetworkType:
            network_requests = [r for r in self._request_log if r.network_type == network]
            if network_requests:
                by_network[network.value] = {
                    "count": len(network_requests),
                    "success_rate": sum(1 for r in network_requests if r.success) / len(network_requests) * 100,
                    "avg_latency_ms": sum(r.latency_ms for r in network_requests) / len(network_requests),
                }
        
        return {
            "total_requests": total,
            "success_rate": successful / total * 100,
            "avg_latency_ms": avg_latency,
            "by_network": by_network,
        }
    
    def close_all_sessions(self):
        with self._session_lock:
            for session in self._tor_sessions.values():
                session.close()
            self._tor_sessions.clear()
            
            for session in self._i2p_sessions.values():
                session.close()
            self._i2p_sessions.clear()
        
        if self._tor_control:
            self._tor_control.close()
            self._tor_control = None
        
        if self._i2p_sam:
            self._i2p_sam.close()
            self._i2p_sam = None


def get_darkweb_connector() -> DarkWebConnector:
    return DarkWebConnector()
