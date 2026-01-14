"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - SECURITY TOOLS INTEGRATION MODULE
Enterprise-grade integration with opensource security tools.

This module provides integration with:
- Suricata IDS/IPS
- Zeek Network Security Monitor
- Snort IDS
- Arkime Full Packet Capture
- Elasticsearch/OpenSearch
- ntopng Network Traffic Monitor
- Tor Dark Web Connectivity

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import json
import subprocess
import socket
import time
import re
import hashlib
import threading
import queue
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityToolStatus(str, Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SuricataAlert:
    timestamp: str
    alert_id: str
    signature: str
    signature_id: int
    severity: str
    category: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    action: str
    payload: Optional[str] = None


@dataclass
class ZeekConnection:
    uid: str
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    service: str
    duration: float
    bytes_sent: int
    bytes_received: int
    connection_state: str
    history: str


@dataclass
class NetworkFlow:
    flow_id: str
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    packets: int
    bytes_total: int
    duration: float
    application: str
    country: str


class SuricataIntegration:
    """Integration with Suricata IDS/IPS"""
    
    def __init__(self, config_path: str = "/etc/suricata/suricata.yaml", log_path: str = "/var/log/suricata"):
        self.config_path = config_path
        self.log_path = log_path
        self.eve_log_path = os.path.join(log_path, "eve.json")
        self.rules_path = "/etc/suricata/rules"
        
    def get_status(self) -> Dict[str, Any]:
        status = {
            "service": "Suricata",
            "status": SecurityToolStatus.UNKNOWN.value,
            "version": None,
            "rules_loaded": 0,
            "alerts_today": 0,
            "last_check": datetime.utcnow().isoformat()
        }
        
        try:
            result = subprocess.run(
                ["pgrep", "-x", "suricata"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                status["status"] = SecurityToolStatus.RUNNING.value
                status["pid"] = int(result.stdout.decode().strip().split('\n')[0])
            else:
                status["status"] = SecurityToolStatus.STOPPED.value
        except Exception as e:
            status["status"] = SecurityToolStatus.ERROR.value
            status["error"] = str(e)
        
        try:
            result = subprocess.run(
                ["suricata", "--build-info"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.decode()
                version_match = re.search(r'Suricata version:\s*(\S+)', output)
                if version_match:
                    status["version"] = version_match.group(1)
        except FileNotFoundError:
            logger.debug("Suricata binary not found")
        except Exception as e:
            logger.debug(f"Failed to get Suricata version: {e}")
        
        try:
            rules_count = 0
            if os.path.exists(self.rules_path):
                for f in os.listdir(self.rules_path):
                    if f.endswith('.rules'):
                        with open(os.path.join(self.rules_path, f), 'r') as rf:
                            rules_count += sum(1 for line in rf if line.strip() and not line.startswith('#'))
            status["rules_loaded"] = rules_count
        except OSError as e:
            logger.debug(f"Failed to count Suricata rules: {e}")
        
        try:
            if os.path.exists(self.eve_log_path):
                today = datetime.utcnow().strftime("%Y-%m-%d")
                alerts_count = 0
                with open(self.eve_log_path, 'r') as f:
                    for line in f:
                        try:
                            event = json.loads(line)
                            if event.get("event_type") == "alert" and today in event.get("timestamp", ""):
                                alerts_count += 1
                        except json.JSONDecodeError:
                            continue
                status["alerts_today"] = alerts_count
        except OSError as e:
            logger.debug(f"Failed to read Suricata eve log: {e}")
        
        return status
    
    def get_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[SuricataAlert]:
        alerts = []
        
        if not os.path.exists(self.eve_log_path):
            return alerts
        
        try:
            with open(self.eve_log_path, 'r') as f:
                lines = f.readlines()[-limit*2:]
                
            for line in reversed(lines):
                if len(alerts) >= limit:
                    break
                    
                try:
                    event = json.loads(line)
                    if event.get("event_type") != "alert":
                        continue
                    
                    alert_data = event.get("alert", {})
                    alert_severity = self._map_severity(alert_data.get("severity", 3))
                    
                    if severity and alert_severity != severity:
                        continue
                    
                    alert = SuricataAlert(
                        timestamp=event.get("timestamp", ""),
                        alert_id=f"SUR-{hashlib.md5(line.encode()).hexdigest()[:8].upper()}",
                        signature=alert_data.get("signature", "Unknown"),
                        signature_id=alert_data.get("signature_id", 0),
                        severity=alert_severity,
                        category=alert_data.get("category", "Unknown"),
                        source_ip=event.get("src_ip", ""),
                        source_port=event.get("src_port", 0),
                        destination_ip=event.get("dest_ip", ""),
                        destination_port=event.get("dest_port", 0),
                        protocol=event.get("proto", ""),
                        action=alert_data.get("action", "allowed"),
                        payload=event.get("payload", None)
                    )
                    alerts.append(alert)
                except json.JSONDecodeError:
                    continue
        except OSError as e:
            logger.debug(f"Failed to read Suricata alerts: {e}")
        
        return alerts
    
    def _map_severity(self, suricata_severity: int) -> str:
        severity_map = {
            1: AlertSeverity.CRITICAL.value,
            2: AlertSeverity.HIGH.value,
            3: AlertSeverity.MEDIUM.value,
            4: AlertSeverity.LOW.value
        }
        return severity_map.get(suricata_severity, AlertSeverity.INFO.value)
    
    def add_rule(self, rule: str, rule_file: str = "local.rules") -> Dict[str, Any]:
        rule_path = os.path.join(self.rules_path, rule_file)
        
        try:
            with open(rule_path, 'a') as f:
                f.write(f"\n{rule}\n")
            
            return {
                "status": "success",
                "message": f"Rule added to {rule_file}",
                "rule": rule
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def reload_rules(self) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                ["suricatasc", "-c", "reload-rules"],
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return {"status": "success", "message": "Rules reloaded"}
            else:
                return {"status": "error", "message": result.stderr.decode()}
        except Exception as e:
            return {"status": "error", "message": str(e)}


class ZeekIntegration:
    """Integration with Zeek Network Security Monitor"""
    
    def __init__(self, log_path: str = "/opt/zeek/logs/current"):
        self.log_path = log_path
        self.zeek_bin = "/opt/zeek/bin/zeek"
        if not os.path.exists(self.zeek_bin):
            self.zeek_bin = "zeek"
    
    def get_status(self) -> Dict[str, Any]:
        status = {
            "service": "Zeek",
            "status": SecurityToolStatus.UNKNOWN.value,
            "version": None,
            "workers": 0,
            "connections_today": 0,
            "last_check": datetime.utcnow().isoformat()
        }
        
        try:
            result = subprocess.run(
                ["pgrep", "-f", "zeek"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                pids = result.stdout.decode().strip().split('\n')
                status["status"] = SecurityToolStatus.RUNNING.value
                status["workers"] = len(pids)
            else:
                status["status"] = SecurityToolStatus.STOPPED.value
        except Exception as e:
            status["status"] = SecurityToolStatus.ERROR.value
            status["error"] = str(e)
        
        try:
            result = subprocess.run(
                [self.zeek_bin, "--version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.decode()
                version_match = re.search(r'zeek version (\S+)', output, re.IGNORECASE)
                if version_match:
                    status["version"] = version_match.group(1)
        except FileNotFoundError:
            logger.debug("Zeek binary not found")
        except Exception as e:
            logger.debug(f"Failed to get Zeek version: {e}")
        
        try:
            conn_log = os.path.join(self.log_path, "conn.log")
            if os.path.exists(conn_log):
                with open(conn_log, 'r') as f:
                    status["connections_today"] = sum(1 for line in f if not line.startswith('#'))
        except OSError as e:
            logger.debug(f"Failed to read Zeek connection log: {e}")
        
        return status
    
    def get_connections(self, limit: int = 100) -> List[ZeekConnection]:
        connections = []
        conn_log = os.path.join(self.log_path, "conn.log")
        
        if not os.path.exists(conn_log):
            return connections
        
        try:
            with open(conn_log, 'r') as f:
                lines = [l for l in f.readlines() if not l.startswith('#')][-limit:]
            
            for line in reversed(lines):
                if len(connections) >= limit:
                    break
                
                try:
                    fields = line.strip().split('\t')
                    if len(fields) >= 15:
                        conn = ZeekConnection(
                            uid=fields[1],
                            timestamp=fields[0],
                            source_ip=fields[2],
                            source_port=int(fields[3]) if fields[3] != '-' else 0,
                            destination_ip=fields[4],
                            destination_port=int(fields[5]) if fields[5] != '-' else 0,
                            protocol=fields[6],
                            service=fields[7] if fields[7] != '-' else "unknown",
                            duration=float(fields[8]) if fields[8] != '-' else 0.0,
                            bytes_sent=int(fields[9]) if fields[9] != '-' else 0,
                            bytes_received=int(fields[10]) if fields[10] != '-' else 0,
                            connection_state=fields[11] if fields[11] != '-' else "unknown",
                            history=fields[14] if len(fields) > 14 and fields[14] != '-' else ""
                        )
                        connections.append(conn)
                except (ValueError, IndexError):
                    continue
        except OSError as e:
            logger.debug(f"Failed to read Zeek connections: {e}")
        
        return connections
    
    def get_dns_queries(self, limit: int = 100) -> List[Dict[str, Any]]:
        queries = []
        dns_log = os.path.join(self.log_path, "dns.log")
        
        if not os.path.exists(dns_log):
            return queries
        
        try:
            with open(dns_log, 'r') as f:
                lines = [l for l in f.readlines() if not l.startswith('#')][-limit:]
            
            for line in reversed(lines):
                if len(queries) >= limit:
                    break
                
                try:
                    fields = line.strip().split('\t')
                    if len(fields) >= 10:
                        queries.append({
                            "timestamp": fields[0],
                            "uid": fields[1],
                            "source_ip": fields[2],
                            "source_port": int(fields[3]) if fields[3] != '-' else 0,
                            "destination_ip": fields[4],
                            "destination_port": int(fields[5]) if fields[5] != '-' else 0,
                            "query": fields[9] if len(fields) > 9 else "",
                            "query_type": fields[13] if len(fields) > 13 else "",
                            "response_code": fields[15] if len(fields) > 15 else ""
                        })
                except (ValueError, IndexError):
                    continue
        except OSError as e:
            logger.debug(f"Failed to read Zeek DNS queries: {e}")
        
        return queries
    
    def get_http_requests(self, limit: int = 100) -> List[Dict[str, Any]]:
        requests = []
        http_log = os.path.join(self.log_path, "http.log")
        
        if not os.path.exists(http_log):
            return requests
        
        try:
            with open(http_log, 'r') as f:
                lines = [l for l in f.readlines() if not l.startswith('#')][-limit:]
            
            for line in reversed(lines):
                if len(requests) >= limit:
                    break
                
                try:
                    fields = line.strip().split('\t')
                    if len(fields) >= 12:
                        requests.append({
                            "timestamp": fields[0],
                            "uid": fields[1],
                            "source_ip": fields[2],
                            "source_port": int(fields[3]) if fields[3] != '-' else 0,
                            "destination_ip": fields[4],
                            "destination_port": int(fields[5]) if fields[5] != '-' else 0,
                            "method": fields[7] if len(fields) > 7 else "",
                            "host": fields[8] if len(fields) > 8 else "",
                            "uri": fields[9] if len(fields) > 9 else "",
                            "user_agent": fields[12] if len(fields) > 12 else "",
                            "status_code": int(fields[15]) if len(fields) > 15 and fields[15] != '-' else 0
                        })
                except (ValueError, IndexError):
                    continue
        except OSError as e:
            logger.debug(f"Failed to read Zeek HTTP requests: {e}")
        
        return requests


class ElasticsearchIntegration:
    """Integration with Elasticsearch/OpenSearch"""
    
    def __init__(self, host: str = "localhost", port: int = 9200):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
    
    def get_status(self) -> Dict[str, Any]:
        status = {
            "service": "Elasticsearch",
            "status": SecurityToolStatus.UNKNOWN.value,
            "version": None,
            "cluster_name": None,
            "cluster_status": None,
            "indices_count": 0,
            "documents_count": 0,
            "last_check": datetime.utcnow().isoformat()
        }
        
        try:
            import urllib.request
            
            with urllib.request.urlopen(self.base_url, timeout=5) as response:
                data = json.loads(response.read().decode())
                status["status"] = SecurityToolStatus.RUNNING.value
                status["version"] = data.get("version", {}).get("number")
                status["cluster_name"] = data.get("cluster_name")
            
            with urllib.request.urlopen(f"{self.base_url}/_cluster/health", timeout=5) as response:
                health = json.loads(response.read().decode())
                status["cluster_status"] = health.get("status")
            
            with urllib.request.urlopen(f"{self.base_url}/_cat/indices?format=json", timeout=5) as response:
                indices = json.loads(response.read().decode())
                status["indices_count"] = len(indices)
                status["documents_count"] = sum(int(idx.get("docs.count", 0)) for idx in indices)
        except Exception as e:
            status["status"] = SecurityToolStatus.STOPPED.value
            status["error"] = str(e)
        
        return status
    
    def search(self, index: str, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        try:
            import urllib.request
            
            url = f"{self.base_url}/{index}/_search"
            data = json.dumps({"query": query, "size": size}).encode()
            
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def index_document(self, index: str, document: Dict[str, Any], doc_id: Optional[str] = None) -> Dict[str, Any]:
        try:
            import urllib.request
            
            if doc_id:
                url = f"{self.base_url}/{index}/_doc/{doc_id}"
            else:
                url = f"{self.base_url}/{index}/_doc"
            
            data = json.dumps(document).encode()
            
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def create_index(self, index: str, mappings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            import urllib.request
            
            url = f"{self.base_url}/{index}"
            body = {}
            if mappings:
                body["mappings"] = mappings
            
            data = json.dumps(body).encode() if body else None
            
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"} if data else {},
                method="PUT"
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}


class NtopngIntegration:
    """Integration with ntopng Network Traffic Monitor"""
    
    def __init__(self, host: str = "localhost", port: int = 3000):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
    
    def get_status(self) -> Dict[str, Any]:
        status = {
            "service": "ntopng",
            "status": SecurityToolStatus.UNKNOWN.value,
            "version": None,
            "interfaces": [],
            "active_hosts": 0,
            "active_flows": 0,
            "last_check": datetime.utcnow().isoformat()
        }
        
        try:
            result = subprocess.run(
                ["pgrep", "-x", "ntopng"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                status["status"] = SecurityToolStatus.RUNNING.value
                status["pid"] = int(result.stdout.decode().strip().split('\n')[0])
            else:
                status["status"] = SecurityToolStatus.STOPPED.value
        except Exception as e:
            status["status"] = SecurityToolStatus.ERROR.value
            status["error"] = str(e)
        
        try:
            import urllib.request
            
            with urllib.request.urlopen(f"{self.base_url}/lua/rest/v2/get/ntopng/interfaces.lua", timeout=5) as response:
                data = json.loads(response.read().decode())
                if data.get("rc") == 0:
                    status["interfaces"] = list(data.get("rsp", {}).keys())
        except urllib.error.URLError as e:
            logger.debug(f"Failed to get ntopng interfaces: {e}")
        except Exception as e:
            logger.debug(f"ntopng API error: {e}")
        
        return status
    
    def get_flows(self, interface: str = "0", limit: int = 100) -> List[NetworkFlow]:
        flows = []
        
        try:
            import urllib.request
            
            url = f"{self.base_url}/lua/rest/v2/get/flow/active.lua?ifid={interface}&currentPage=1&perPage={limit}"
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                if data.get("rc") == 0:
                    for flow_data in data.get("rsp", {}).get("data", []):
                        flow = NetworkFlow(
                            flow_id=f"FLOW-{hashlib.md5(str(flow_data).encode()).hexdigest()[:8].upper()}",
                            timestamp=datetime.utcnow().isoformat(),
                            source_ip=flow_data.get("cli.ip", ""),
                            source_port=flow_data.get("cli.port", 0),
                            destination_ip=flow_data.get("srv.ip", ""),
                            destination_port=flow_data.get("srv.port", 0),
                            protocol=flow_data.get("proto.ndpi", "unknown"),
                            packets=flow_data.get("packets", 0),
                            bytes_total=flow_data.get("bytes", 0),
                            duration=flow_data.get("duration", 0),
                            application=flow_data.get("proto.ndpi_app", "unknown"),
                            country=flow_data.get("cli.country", "")
                        )
                        flows.append(flow)
        except urllib.error.URLError as e:
            logger.debug(f"Failed to get ntopng flows: {e}")
        except Exception as e:
            logger.debug(f"ntopng flows API error: {e}")
        
        return flows
    
    def get_top_talkers(self, interface: str = "0", limit: int = 10) -> List[Dict[str, Any]]:
        talkers = []
        
        try:
            import urllib.request
            
            url = f"{self.base_url}/lua/rest/v2/get/host/active.lua?ifid={interface}&currentPage=1&perPage={limit}&sortColumn=bytes&sortOrder=desc"
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                if data.get("rc") == 0:
                    for host_data in data.get("rsp", {}).get("data", []):
                        talkers.append({
                            "ip": host_data.get("ip", ""),
                            "name": host_data.get("name", ""),
                            "bytes_sent": host_data.get("bytes.sent", 0),
                            "bytes_received": host_data.get("bytes.rcvd", 0),
                            "packets": host_data.get("packets", 0),
                            "flows": host_data.get("active_flows", 0),
                            "country": host_data.get("country", ""),
                            "os": host_data.get("os", "")
                        })
        except urllib.error.URLError as e:
            logger.debug(f"Failed to get ntopng top talkers: {e}")
        except Exception as e:
            logger.debug(f"ntopng top talkers API error: {e}")
        
        return talkers


class TorIntegration:
    """Integration with Tor for Dark Web connectivity"""
    
    def __init__(self, socks_port: int = 9050, control_port: int = 9051):
        self.socks_port = socks_port
        self.control_port = control_port
    
    def get_status(self) -> Dict[str, Any]:
        status = {
            "service": "Tor",
            "status": SecurityToolStatus.UNKNOWN.value,
            "version": None,
            "socks_port": self.socks_port,
            "control_port": self.control_port,
            "circuits": 0,
            "last_check": datetime.utcnow().isoformat()
        }
        
        try:
            result = subprocess.run(
                ["pgrep", "-x", "tor"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                status["status"] = SecurityToolStatus.RUNNING.value
                status["pid"] = int(result.stdout.decode().strip().split('\n')[0])
            else:
                status["status"] = SecurityToolStatus.STOPPED.value
        except Exception as e:
            status["status"] = SecurityToolStatus.ERROR.value
            status["error"] = str(e)
        
        try:
            result = subprocess.run(
                ["tor", "--version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                output = result.stdout.decode()
                version_match = re.search(r'Tor version (\S+)', output)
                if version_match:
                    status["version"] = version_match.group(1)
        except FileNotFoundError:
            logger.debug("Tor binary not found")
        except Exception as e:
            logger.debug(f"Failed to get Tor version: {e}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', self.socks_port))
            sock.close()
            if result == 0:
                status["socks_available"] = True
            else:
                status["socks_available"] = False
        except socket.error as e:
            logger.debug(f"Failed to check Tor SOCKS port: {e}")
            status["socks_available"] = False
        
        return status
    
    def fetch_onion(self, onion_url: str, timeout: int = 30) -> Dict[str, Any]:
        result = {
            "url": onion_url,
            "status": "error",
            "content": None,
            "headers": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if not onion_url.endswith('.onion') and '.onion/' not in onion_url:
            result["error"] = "Not a valid .onion URL"
            return result
        
        try:
            import socks
            import urllib.request
            
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
            socket.socket = socks.socksocket
            
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0')]
            
            with opener.open(onion_url, timeout=timeout) as response:
                result["status"] = "success"
                result["status_code"] = response.status
                result["content"] = response.read().decode('utf-8', errors='ignore')[:10000]
                result["headers"] = dict(response.headers)
        except ImportError:
            result["error"] = "PySocks library not installed"
        except Exception as e:
            result["error"] = str(e)
        
        return result


class PacketCaptureEngine:
    """Internal packet capture engine using scapy"""
    
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.capture_running = False
        self.packets = []
        self.capture_thread = None
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "service": "Packet Capture Engine",
            "status": SecurityToolStatus.RUNNING.value if self.capture_running else SecurityToolStatus.STOPPED.value,
            "interface": self.interface,
            "packets_captured": len(self.packets),
            "last_check": datetime.utcnow().isoformat()
        }
    
    def start_capture(self, count: int = 100, filter_expr: str = "") -> Dict[str, Any]:
        if self.capture_running:
            return {"status": "error", "message": "Capture already running"}
        
        try:
            from scapy.all import sniff, IP, TCP, UDP
            
            self.capture_running = True
            self.packets = []
            
            def packet_callback(packet):
                if IP in packet:
                    pkt_info = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "source_ip": packet[IP].src,
                        "destination_ip": packet[IP].dst,
                        "protocol": packet[IP].proto,
                        "length": len(packet)
                    }
                    
                    if TCP in packet:
                        pkt_info["source_port"] = packet[TCP].sport
                        pkt_info["destination_port"] = packet[TCP].dport
                        pkt_info["flags"] = str(packet[TCP].flags)
                    elif UDP in packet:
                        pkt_info["source_port"] = packet[UDP].sport
                        pkt_info["destination_port"] = packet[UDP].dport
                    
                    self.packets.append(pkt_info)
            
            def capture_thread_func():
                try:
                    sniff(
                        iface=self.interface,
                        prn=packet_callback,
                        count=count,
                        filter=filter_expr if filter_expr else None,
                        store=False
                    )
                except Exception as e:
                    logger.error(f"Packet capture error: {e}")
                finally:
                    self.capture_running = False
            
            self.capture_thread = threading.Thread(target=capture_thread_func)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            return {
                "status": "success",
                "message": f"Capture started on {self.interface}",
                "count": count,
                "filter": filter_expr
            }
        except ImportError:
            self.capture_running = False
            return {"status": "error", "message": "scapy library not installed"}
        except Exception as e:
            self.capture_running = False
            return {"status": "error", "message": str(e)}
    
    def stop_capture(self) -> Dict[str, Any]:
        self.capture_running = False
        return {
            "status": "success",
            "message": "Capture stopped",
            "packets_captured": len(self.packets)
        }
    
    def get_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.packets[-limit:]


class SecurityToolsManager:
    """Central manager for all security tools"""
    
    def __init__(self):
        self.suricata = SuricataIntegration()
        self.zeek = ZeekIntegration()
        self.elasticsearch = ElasticsearchIntegration()
        self.ntopng = NtopngIntegration()
        self.tor = TorIntegration()
        self.packet_capture = PacketCaptureEngine()
    
    def get_all_status(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": {
                "suricata": self.suricata.get_status(),
                "zeek": self.zeek.get_status(),
                "elasticsearch": self.elasticsearch.get_status(),
                "ntopng": self.ntopng.get_status(),
                "tor": self.tor.get_status(),
                "packet_capture": self.packet_capture.get_status()
            }
        }
    
    def get_unified_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        alerts = []
        
        suricata_alerts = self.suricata.get_alerts(limit=limit)
        for alert in suricata_alerts:
            alerts.append({
                "source": "Suricata",
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp,
                "severity": alert.severity,
                "signature": alert.signature,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "protocol": alert.protocol,
                "action": alert.action
            })
        
        alerts.sort(key=lambda x: x["timestamp"], reverse=True)
        return alerts[:limit]
    
    def get_unified_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        connections = []
        
        zeek_conns = self.zeek.get_connections(limit=limit)
        for conn in zeek_conns:
            connections.append({
                "source": "Zeek",
                "connection_id": conn.uid,
                "timestamp": conn.timestamp,
                "source_ip": conn.source_ip,
                "source_port": conn.source_port,
                "destination_ip": conn.destination_ip,
                "destination_port": conn.destination_port,
                "protocol": conn.protocol,
                "service": conn.service,
                "duration": conn.duration,
                "bytes_sent": conn.bytes_sent,
                "bytes_received": conn.bytes_received
            })
        
        ntopng_flows = self.ntopng.get_flows(limit=limit)
        for flow in ntopng_flows:
            connections.append({
                "source": "ntopng",
                "connection_id": flow.flow_id,
                "timestamp": flow.timestamp,
                "source_ip": flow.source_ip,
                "source_port": flow.source_port,
                "destination_ip": flow.destination_ip,
                "destination_port": flow.destination_port,
                "protocol": flow.protocol,
                "service": flow.application,
                "duration": flow.duration,
                "bytes_total": flow.bytes_total
            })
        
        connections.sort(key=lambda x: x["timestamp"], reverse=True)
        return connections[:limit]


def convert_dataclass_to_dict(obj):
    if hasattr(obj, '__dataclass_fields__'):
        return asdict(obj)
    elif isinstance(obj, list):
        return [convert_dataclass_to_dict(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: convert_dataclass_to_dict(v) for k, v in obj.items()}
    else:
        return obj
