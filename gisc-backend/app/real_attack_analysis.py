"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - REAL ATTACK ANALYSIS ENGINE
Enterprise-grade real-time attack monitoring and malware analysis implementation

This module provides:
- Real-time attack detection and monitoring
- Attack script capture and analysis
- Malware static and dynamic analysis
- IOC (Indicators of Compromise) extraction
- Kill chain mapping
- Attack attribution
- Threat intelligence correlation
- PDF report generation

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import re
import json
import time
import hashlib
import struct
import logging
import threading
import subprocess
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import binascii

from app.real_pdf_generator import PDFReportGenerator, ReportMetadata, create_pdf_generator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class IOC:
    ioc_type: str
    value: str
    confidence: float
    source: str
    first_seen: str
    last_seen: str
    tags: List[str]
    context: Dict[str, Any]


@dataclass
class MalwareSample:
    sha256: str
    sha1: str
    md5: str
    file_name: str
    file_size: int
    file_type: str
    mime_type: str
    first_seen: str
    last_seen: str
    detection_names: List[str]
    tags: List[str]
    static_analysis: Dict[str, Any]
    dynamic_analysis: Dict[str, Any]
    iocs: List[IOC]


@dataclass
class AttackEvent:
    event_id: str
    timestamp: str
    attack_type: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    payload: Optional[str]
    payload_hash: Optional[str]
    severity: str
    confidence: float
    mitre_techniques: List[str]
    iocs: List[IOC]
    raw_data: Dict[str, Any]


@dataclass
class AttackChainStage:
    stage: str
    stage_number: int
    description: str
    techniques: List[str]
    indicators: List[str]
    timestamp: str
    evidence: Dict[str, Any]


@dataclass
class AttackAnalysisResult:
    analysis_id: str
    target: str
    start_time: str
    end_time: str
    total_events: int
    attack_events: List[AttackEvent]
    malware_samples: List[MalwareSample]
    attack_chain: List[AttackChainStage]
    attribution: Dict[str, Any]
    recommendations: List[str]
    risk_score: float
    summary: Dict[str, Any]


class MalwareAnalyzer:
    """Static and dynamic malware analysis"""
    
    SUSPICIOUS_STRINGS = [
        (r'cmd\.exe', 'Command execution'),
        (r'powershell', 'PowerShell execution'),
        (r'WScript\.Shell', 'Windows Script Host'),
        (r'CreateObject', 'COM object creation'),
        (r'eval\s*\(', 'Dynamic code evaluation'),
        (r'exec\s*\(', 'Code execution'),
        (r'base64_decode', 'Base64 decoding'),
        (r'fromCharCode', 'Character code conversion'),
        (r'\\x[0-9a-fA-F]{2}', 'Hex encoded data'),
        (r'socket\s*\(', 'Network socket'),
        (r'connect\s*\(', 'Network connection'),
        (r'recv\s*\(', 'Network receive'),
        (r'send\s*\(', 'Network send'),
        (r'CreateRemoteThread', 'Remote thread creation'),
        (r'VirtualAlloc', 'Memory allocation'),
        (r'WriteProcessMemory', 'Process memory write'),
        (r'LoadLibrary', 'Library loading'),
        (r'GetProcAddress', 'Function address resolution'),
        (r'RegSetValue', 'Registry modification'),
        (r'CreateService', 'Service creation'),
        (r'ShellExecute', 'Shell execution'),
        (r'URLDownloadToFile', 'File download'),
        (r'InternetOpen', 'Internet connection'),
        (r'HttpSendRequest', 'HTTP request'),
        (r'CryptEncrypt', 'Encryption'),
        (r'CryptDecrypt', 'Decryption'),
    ]
    
    MAGIC_BYTES = {
        b'MZ': 'PE Executable (Windows)',
        b'\x7fELF': 'ELF Executable (Linux)',
        b'PK\x03\x04': 'ZIP Archive',
        b'PK\x05\x06': 'ZIP Archive (empty)',
        b'\x1f\x8b': 'GZIP Archive',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'%PDF': 'PDF Document',
        b'\xd0\xcf\x11\xe0': 'MS Office Document (OLE)',
        b'{\rtf': 'RTF Document',
        b'<script': 'JavaScript/HTML',
        b'<?php': 'PHP Script',
        b'#!/': 'Shell Script',
        b'\xca\xfe\xba\xbe': 'Java Class/Mach-O',
        b'\x50\x4b\x03\x04': 'Office Open XML',
    }
    
    PE_SUSPICIOUS_SECTIONS = ['.text', '.data', '.rdata', '.rsrc', '.reloc', 'UPX0', 'UPX1', '.packed']
    
    def __init__(self):
        self.analysis_cache: Dict[str, MalwareSample] = {}
    
    def analyze_file(self, file_path: str) -> Optional[MalwareSample]:
        """Perform comprehensive malware analysis on a file"""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return None
        
        return self.analyze_bytes(file_data, os.path.basename(file_path))
    
    def analyze_bytes(self, data: bytes, file_name: str = "unknown") -> MalwareSample:
        """Analyze raw bytes for malware indicators"""
        sha256 = hashlib.sha256(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        
        if sha256 in self.analysis_cache:
            return self.analysis_cache[sha256]
        
        file_type = self._detect_file_type(data)
        mime_type = self._detect_mime_type(data, file_name)
        
        static_analysis = self._perform_static_analysis(data, file_type)
        dynamic_analysis = self._perform_dynamic_analysis(data, file_type)
        iocs = self._extract_iocs(data, static_analysis)
        
        detection_names = self._generate_detection_names(static_analysis, dynamic_analysis)
        tags = self._generate_tags(static_analysis, dynamic_analysis)
        
        sample = MalwareSample(
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            file_name=file_name,
            file_size=len(data),
            file_type=file_type,
            mime_type=mime_type,
            first_seen=datetime.utcnow().isoformat(),
            last_seen=datetime.utcnow().isoformat(),
            detection_names=detection_names,
            tags=tags,
            static_analysis=static_analysis,
            dynamic_analysis=dynamic_analysis,
            iocs=[asdict(ioc) for ioc in iocs]
        )
        
        self.analysis_cache[sha256] = sample
        return sample
    
    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type from magic bytes"""
        for magic, file_type in self.MAGIC_BYTES.items():
            if data.startswith(magic):
                return file_type
        
        try:
            data.decode('utf-8')
            return 'Text/Script'
        except UnicodeDecodeError:
            return 'Unknown Binary'
    
    def _detect_mime_type(self, data: bytes, file_name: str) -> str:
        """Detect MIME type"""
        ext = os.path.splitext(file_name)[1].lower()
        
        mime_map = {
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.zip': 'application/zip',
            '.js': 'application/javascript',
            '.vbs': 'application/x-vbs',
            '.ps1': 'application/x-powershell',
            '.bat': 'application/x-bat',
            '.sh': 'application/x-sh',
            '.py': 'text/x-python',
            '.php': 'application/x-php',
        }
        
        return mime_map.get(ext, 'application/octet-stream')
    
    def _perform_static_analysis(self, data: bytes, file_type: str) -> Dict[str, Any]:
        """Perform static analysis on file"""
        analysis = {
            'entropy': self._calculate_entropy(data),
            'suspicious_strings': [],
            'urls': [],
            'ip_addresses': [],
            'email_addresses': [],
            'file_paths': [],
            'registry_keys': [],
            'imports': [],
            'exports': [],
            'sections': [],
            'packed': False,
            'obfuscated': False,
            'encrypted_sections': False,
        }
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = data.decode('latin-1', errors='ignore')
        
        for pattern, description in self.SUSPICIOUS_STRINGS:
            matches = re.findall(pattern, text_data, re.IGNORECASE)
            if matches:
                analysis['suspicious_strings'].append({
                    'pattern': pattern,
                    'description': description,
                    'count': len(matches),
                    'samples': list(set(matches))[:5]
                })
        
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
        analysis['urls'] = list(set(re.findall(url_pattern, text_data)))[:50]
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        potential_ips = re.findall(ip_pattern, text_data)
        analysis['ip_addresses'] = [ip for ip in set(potential_ips) 
                                    if not ip.startswith('0.') and not ip.startswith('255.')][:50]
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        analysis['email_addresses'] = list(set(re.findall(email_pattern, text_data)))[:20]
        
        path_pattern = r'[A-Za-z]:\\[^\s<>"\'|*?]+|/(?:usr|etc|var|tmp|home|root)/[^\s<>"\'|*?]+'
        analysis['file_paths'] = list(set(re.findall(path_pattern, text_data)))[:30]
        
        reg_pattern = r'HKEY_[A-Z_]+\\[^\s<>"\']+|HKLM\\[^\s<>"\']+|HKCU\\[^\s<>"\']+'
        analysis['registry_keys'] = list(set(re.findall(reg_pattern, text_data)))[:30]
        
        if analysis['entropy'] > 7.0:
            analysis['packed'] = True
            analysis['encrypted_sections'] = True
        
        if len(analysis['suspicious_strings']) > 5:
            analysis['obfuscated'] = True
        
        if 'PE Executable' in file_type:
            analysis.update(self._analyze_pe(data))
        
        return analysis
    
    def _analyze_pe(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE executable structure"""
        pe_info = {
            'pe_type': 'Unknown',
            'machine': 'Unknown',
            'timestamp': None,
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
        }
        
        try:
            if len(data) < 64:
                return pe_info
            
            if data[:2] != b'MZ':
                return pe_info
            
            pe_offset = struct.unpack('<I', data[60:64])[0]
            
            if pe_offset + 24 > len(data):
                return pe_info
            
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return pe_info
            
            machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
            machine_types = {
                0x14c: 'i386',
                0x8664: 'AMD64',
                0x1c0: 'ARM',
                0xaa64: 'ARM64',
            }
            pe_info['machine'] = machine_types.get(machine, f'Unknown (0x{machine:x})')
            
            timestamp = struct.unpack('<I', data[pe_offset+8:pe_offset+12])[0]
            pe_info['timestamp'] = datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else None
            
            num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
            optional_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
            
            section_offset = pe_offset + 24 + optional_header_size
            
            for i in range(min(num_sections, 20)):
                if section_offset + 40 > len(data):
                    break
                
                section_data = data[section_offset:section_offset+40]
                section_name = section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', section_data[8:12])[0]
                raw_size = struct.unpack('<I', section_data[16:20])[0]
                characteristics = struct.unpack('<I', section_data[36:40])[0]
                
                pe_info['sections'].append({
                    'name': section_name,
                    'virtual_size': virtual_size,
                    'raw_size': raw_size,
                    'executable': bool(characteristics & 0x20000000),
                    'writable': bool(characteristics & 0x80000000),
                    'readable': bool(characteristics & 0x40000000),
                })
                
                section_offset += 40
            
        except Exception as e:
            logger.debug(f"Error analyzing PE: {e}")
        
        return pe_info
    
    def _perform_dynamic_analysis(self, data: bytes, file_type: str) -> Dict[str, Any]:
        """Perform dynamic analysis indicators (behavioral patterns)"""
        analysis = {
            'behaviors': [],
            'network_indicators': [],
            'file_operations': [],
            'registry_operations': [],
            'process_operations': [],
            'persistence_mechanisms': [],
            'evasion_techniques': [],
            'data_exfiltration': [],
        }
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = data.decode('latin-1', errors='ignore')
        
        behavior_patterns = [
            (r'CreateRemoteThread|NtCreateThreadEx', 'Process Injection'),
            (r'VirtualAllocEx|NtAllocateVirtualMemory', 'Memory Allocation in Remote Process'),
            (r'WriteProcessMemory|NtWriteVirtualMemory', 'Remote Process Memory Write'),
            (r'SetWindowsHookEx', 'Keyboard/Mouse Hooking'),
            (r'CreateService|StartService', 'Service Installation'),
            (r'RegSetValue|RegCreateKey', 'Registry Modification'),
            (r'ShellExecute|CreateProcess|WinExec', 'Process Execution'),
            (r'URLDownloadToFile|InternetReadFile', 'File Download'),
            (r'CryptEncrypt|CryptDecrypt', 'Cryptographic Operations'),
            (r'GetClipboardData|SetClipboardData', 'Clipboard Access'),
            (r'keybd_event|SendInput', 'Keyboard Simulation'),
            (r'GetAsyncKeyState|GetKeyState', 'Keylogging'),
            (r'BitBlt|GetDC|CreateCompatibleDC', 'Screen Capture'),
            (r'socket|connect|send|recv', 'Network Communication'),
            (r'WSAStartup|WSASocket', 'Winsock Initialization'),
        ]
        
        for pattern, behavior in behavior_patterns:
            if re.search(pattern, text_data, re.IGNORECASE):
                analysis['behaviors'].append(behavior)
        
        persistence_patterns = [
            (r'CurrentVersion\\Run', 'Registry Run Key'),
            (r'CurrentVersion\\RunOnce', 'Registry RunOnce Key'),
            (r'Startup', 'Startup Folder'),
            (r'schtasks|at\.exe', 'Scheduled Task'),
            (r'sc\.exe|CreateService', 'Windows Service'),
            (r'HKLM\\SYSTEM\\CurrentControlSet\\Services', 'Service Registry'),
        ]
        
        for pattern, mechanism in persistence_patterns:
            if re.search(pattern, text_data, re.IGNORECASE):
                analysis['persistence_mechanisms'].append(mechanism)
        
        evasion_patterns = [
            (r'IsDebuggerPresent|CheckRemoteDebuggerPresent', 'Anti-Debugging'),
            (r'GetTickCount|QueryPerformanceCounter', 'Timing Check'),
            (r'VirtualBox|VMware|QEMU|Xen', 'VM Detection'),
            (r'SbieDll|Sandboxie', 'Sandbox Detection'),
            (r'wine_get_unix_file_name', 'Wine Detection'),
            (r'NtQueryInformationProcess', 'Process Information Query'),
        ]
        
        for pattern, technique in evasion_patterns:
            if re.search(pattern, text_data, re.IGNORECASE):
                analysis['evasion_techniques'].append(technique)
        
        return analysis
    
    def _extract_iocs(self, data: bytes, static_analysis: Dict[str, Any]) -> List[IOC]:
        """Extract Indicators of Compromise"""
        iocs = []
        timestamp = datetime.utcnow().isoformat()
        
        for url in static_analysis.get('urls', []):
            iocs.append(IOC(
                ioc_type='url',
                value=url,
                confidence=0.7,
                source='static_analysis',
                first_seen=timestamp,
                last_seen=timestamp,
                tags=['extracted', 'url'],
                context={'extraction_method': 'regex'}
            ))
        
        for ip in static_analysis.get('ip_addresses', []):
            if not ip.startswith('127.') and not ip.startswith('192.168.') and not ip.startswith('10.'):
                iocs.append(IOC(
                    ioc_type='ip',
                    value=ip,
                    confidence=0.6,
                    source='static_analysis',
                    first_seen=timestamp,
                    last_seen=timestamp,
                    tags=['extracted', 'ip'],
                    context={'extraction_method': 'regex'}
                ))
        
        for email in static_analysis.get('email_addresses', []):
            iocs.append(IOC(
                ioc_type='email',
                value=email,
                confidence=0.5,
                source='static_analysis',
                first_seen=timestamp,
                last_seen=timestamp,
                tags=['extracted', 'email'],
                context={'extraction_method': 'regex'}
            ))
        
        sha256 = hashlib.sha256(data).hexdigest()
        iocs.append(IOC(
            ioc_type='hash_sha256',
            value=sha256,
            confidence=1.0,
            source='file_hash',
            first_seen=timestamp,
            last_seen=timestamp,
            tags=['file_hash', 'sha256'],
            context={'file_size': len(data)}
        ))
        
        return iocs
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        import math
        
        if not data:
            return 0.0
        
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    def _generate_detection_names(self, static: Dict, dynamic: Dict) -> List[str]:
        """Generate detection names based on analysis"""
        names = []
        
        if static.get('packed'):
            names.append('Packed.Generic')
        
        if static.get('obfuscated'):
            names.append('Obfuscated.Generic')
        
        if 'Process Injection' in dynamic.get('behaviors', []):
            names.append('Trojan.Injector')
        
        if 'Keylogging' in dynamic.get('behaviors', []):
            names.append('Spyware.Keylogger')
        
        if 'Screen Capture' in dynamic.get('behaviors', []):
            names.append('Spyware.ScreenCapture')
        
        if dynamic.get('persistence_mechanisms'):
            names.append('Trojan.Persistent')
        
        if dynamic.get('evasion_techniques'):
            names.append('Trojan.Evasive')
        
        if 'Cryptographic Operations' in dynamic.get('behaviors', []):
            names.append('Ransom.Generic')
        
        if not names:
            names.append('Suspicious.Generic')
        
        return names
    
    def _generate_tags(self, static: Dict, dynamic: Dict) -> List[str]:
        """Generate tags based on analysis"""
        tags = []
        
        if static.get('entropy', 0) > 7.0:
            tags.append('high-entropy')
        
        if static.get('packed'):
            tags.append('packed')
        
        if static.get('obfuscated'):
            tags.append('obfuscated')
        
        if static.get('urls'):
            tags.append('network-activity')
        
        if dynamic.get('persistence_mechanisms'):
            tags.append('persistence')
        
        if dynamic.get('evasion_techniques'):
            tags.append('evasive')
        
        for behavior in dynamic.get('behaviors', []):
            tags.append(behavior.lower().replace(' ', '-'))
        
        return list(set(tags))


class AttackDetector:
    """Real-time attack detection and monitoring"""
    
    ATTACK_SIGNATURES = {
        'SQL_INJECTION': [
            r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"(?i)\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"(?i)((\%27)|(\'))union",
            r"(?i)exec(\s|\+)+(s|x)p\w+",
        ],
        'XSS': [
            r"(?i)<script[^>]*>[\s\S]*?</script>",
            r"(?i)javascript\s*:",
            r"(?i)on\w+\s*=",
            r"(?i)<img[^>]+onerror\s*=",
            r"(?i)<svg[^>]+onload\s*=",
        ],
        'PATH_TRAVERSAL': [
            r"(?i)\.\.\/",
            r"(?i)\.\.\\",
            r"(?i)%2e%2e%2f",
            r"(?i)%2e%2e/",
            r"(?i)\.\.%2f",
        ],
        'COMMAND_INJECTION': [
            r"(?i)[;&|`$]",
            r"(?i)\|\s*\w+",
            r"(?i);\s*\w+",
            r"(?i)`[^`]+`",
            r"(?i)\$\([^)]+\)",
        ],
        'LDAP_INJECTION': [
            r"(?i)[)(|*\\]",
            r"(?i)\x00",
        ],
        'XML_INJECTION': [
            r"(?i)<!ENTITY",
            r"(?i)<!DOCTYPE",
            r"(?i)<!\[CDATA\[",
        ],
        'BRUTE_FORCE': [],
        'DOS': [],
        'PORT_SCAN': [],
        'CREDENTIAL_STUFFING': [],
    }
    
    MITRE_MAPPING = {
        'SQL_INJECTION': ['T1190', 'T1059'],
        'XSS': ['T1189', 'T1059.007'],
        'PATH_TRAVERSAL': ['T1083', 'T1005'],
        'COMMAND_INJECTION': ['T1059', 'T1203'],
        'LDAP_INJECTION': ['T1087', 'T1069'],
        'XML_INJECTION': ['T1059', 'T1203'],
        'BRUTE_FORCE': ['T1110'],
        'DOS': ['T1498', 'T1499'],
        'PORT_SCAN': ['T1046'],
        'CREDENTIAL_STUFFING': ['T1110.004'],
    }
    
    def __init__(self):
        self.event_buffer: List[AttackEvent] = []
        self.ip_request_counts: Dict[str, List[float]] = defaultdict(list)
        self.failed_auth_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def analyze_request(
        self,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        protocol: str,
        payload: str,
        headers: Dict[str, str] = None
    ) -> List[AttackEvent]:
        """Analyze a request for attack patterns"""
        events = []
        timestamp = datetime.utcnow().isoformat()
        
        for attack_type, patterns in self.ATTACK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, payload):
                    event = AttackEvent(
                        event_id=hashlib.md5(f"{timestamp}{source_ip}{payload}".encode()).hexdigest()[:16],
                        timestamp=timestamp,
                        attack_type=attack_type,
                        source_ip=source_ip,
                        source_port=0,
                        dest_ip=dest_ip,
                        dest_port=dest_port,
                        protocol=protocol,
                        payload=payload[:1000],
                        payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
                        severity=self._get_severity(attack_type),
                        confidence=0.8,
                        mitre_techniques=self.MITRE_MAPPING.get(attack_type, []),
                        iocs=[],
                        raw_data={'headers': headers, 'pattern_matched': pattern}
                    )
                    events.append(event)
                    break
        
        with self._lock:
            current_time = time.time()
            self.ip_request_counts[source_ip].append(current_time)
            self.ip_request_counts[source_ip] = [
                t for t in self.ip_request_counts[source_ip] 
                if current_time - t < 60
            ]
            
            if len(self.ip_request_counts[source_ip]) > 100:
                event = AttackEvent(
                    event_id=hashlib.md5(f"{timestamp}{source_ip}DOS".encode()).hexdigest()[:16],
                    timestamp=timestamp,
                    attack_type='DOS',
                    source_ip=source_ip,
                    source_port=0,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    protocol=protocol,
                    payload=None,
                    payload_hash=None,
                    severity='HIGH',
                    confidence=0.9,
                    mitre_techniques=self.MITRE_MAPPING.get('DOS', []),
                    iocs=[],
                    raw_data={'request_count': len(self.ip_request_counts[source_ip])}
                )
                events.append(event)
        
        with self._lock:
            self.event_buffer.extend(events)
            if len(self.event_buffer) > 10000:
                self.event_buffer = self.event_buffer[-5000:]
        
        return events
    
    def record_failed_auth(self, source_ip: str, username: str) -> Optional[AttackEvent]:
        """Record failed authentication attempt"""
        with self._lock:
            self.failed_auth_counts[source_ip] += 1
            
            if self.failed_auth_counts[source_ip] >= 5:
                timestamp = datetime.utcnow().isoformat()
                event = AttackEvent(
                    event_id=hashlib.md5(f"{timestamp}{source_ip}BRUTE".encode()).hexdigest()[:16],
                    timestamp=timestamp,
                    attack_type='BRUTE_FORCE',
                    source_ip=source_ip,
                    source_port=0,
                    dest_ip='',
                    dest_port=0,
                    protocol='HTTP',
                    payload=None,
                    payload_hash=None,
                    severity='HIGH',
                    confidence=0.85,
                    mitre_techniques=self.MITRE_MAPPING.get('BRUTE_FORCE', []),
                    iocs=[],
                    raw_data={
                        'failed_attempts': self.failed_auth_counts[source_ip],
                        'username': username
                    }
                )
                self.event_buffer.append(event)
                return event
        
        return None
    
    def _get_severity(self, attack_type: str) -> str:
        """Get severity level for attack type"""
        severity_map = {
            'SQL_INJECTION': 'CRITICAL',
            'COMMAND_INJECTION': 'CRITICAL',
            'XSS': 'HIGH',
            'PATH_TRAVERSAL': 'HIGH',
            'LDAP_INJECTION': 'HIGH',
            'XML_INJECTION': 'MEDIUM',
            'BRUTE_FORCE': 'HIGH',
            'DOS': 'HIGH',
            'PORT_SCAN': 'MEDIUM',
            'CREDENTIAL_STUFFING': 'HIGH',
        }
        return severity_map.get(attack_type, 'MEDIUM')
    
    def get_recent_events(self, minutes: int = 60) -> List[AttackEvent]:
        """Get recent attack events"""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        cutoff_str = cutoff.isoformat()
        
        with self._lock:
            return [e for e in self.event_buffer if e.timestamp >= cutoff_str]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get attack statistics"""
        with self._lock:
            events = self.event_buffer
        
        stats = {
            'total_events': len(events),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_source_ip': defaultdict(int),
            'top_attackers': [],
            'recent_critical': [],
        }
        
        for event in events:
            stats['by_type'][event.attack_type] += 1
            stats['by_severity'][event.severity] += 1
            stats['by_source_ip'][event.source_ip] += 1
        
        stats['top_attackers'] = sorted(
            stats['by_source_ip'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        stats['recent_critical'] = [
            asdict(e) for e in events 
            if e.severity == 'CRITICAL'
        ][-10:]
        
        stats['by_type'] = dict(stats['by_type'])
        stats['by_severity'] = dict(stats['by_severity'])
        stats['by_source_ip'] = dict(stats['by_source_ip'])
        
        return stats


class KillChainAnalyzer:
    """Analyze attack kill chain stages"""
    
    KILL_CHAIN_STAGES = [
        ('RECONNAISSANCE', 1, 'Information gathering and target identification'),
        ('WEAPONIZATION', 2, 'Creating malicious payload'),
        ('DELIVERY', 3, 'Transmitting payload to target'),
        ('EXPLOITATION', 4, 'Exploiting vulnerability to execute code'),
        ('INSTALLATION', 5, 'Installing malware/backdoor'),
        ('COMMAND_AND_CONTROL', 6, 'Establishing C2 communication'),
        ('ACTIONS_ON_OBJECTIVES', 7, 'Achieving attack goals'),
    ]
    
    STAGE_INDICATORS = {
        'RECONNAISSANCE': ['PORT_SCAN', 'DNS_ENUM', 'WHOIS_LOOKUP', 'SOCIAL_ENGINEERING'],
        'WEAPONIZATION': ['MALWARE_CREATION', 'EXPLOIT_DEVELOPMENT'],
        'DELIVERY': ['PHISHING', 'DRIVE_BY', 'USB_DROP', 'WATERING_HOLE'],
        'EXPLOITATION': ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'BUFFER_OVERFLOW'],
        'INSTALLATION': ['PERSISTENCE', 'ROOTKIT', 'BACKDOOR', 'RAT'],
        'COMMAND_AND_CONTROL': ['C2_BEACON', 'DNS_TUNNELING', 'HTTP_C2', 'ENCRYPTED_CHANNEL'],
        'ACTIONS_ON_OBJECTIVES': ['DATA_EXFILTRATION', 'RANSOMWARE', 'DESTRUCTION', 'LATERAL_MOVEMENT'],
    }
    
    def analyze_attack_chain(self, events: List[AttackEvent], malware_samples: List[MalwareSample]) -> List[AttackChainStage]:
        """Analyze events and samples to determine kill chain stages"""
        stages = []
        timestamp = datetime.utcnow().isoformat()
        
        detected_indicators = set()
        
        for event in events:
            detected_indicators.add(event.attack_type)
        
        for sample in malware_samples:
            for behavior in sample.dynamic_analysis.get('behaviors', []):
                detected_indicators.add(behavior.upper().replace(' ', '_'))
            
            if sample.dynamic_analysis.get('persistence_mechanisms'):
                detected_indicators.add('PERSISTENCE')
            
            if sample.static_analysis.get('urls'):
                detected_indicators.add('C2_BEACON')
        
        for stage_name, stage_num, description in self.KILL_CHAIN_STAGES:
            stage_indicators = self.STAGE_INDICATORS.get(stage_name, [])
            matched_indicators = detected_indicators.intersection(set(stage_indicators))
            
            if matched_indicators or (stage_name == 'EXPLOITATION' and events):
                techniques = []
                for indicator in matched_indicators:
                    techniques.extend(AttackDetector.MITRE_MAPPING.get(indicator, []))
                
                stages.append(AttackChainStage(
                    stage=stage_name,
                    stage_number=stage_num,
                    description=description,
                    techniques=list(set(techniques)),
                    indicators=list(matched_indicators),
                    timestamp=timestamp,
                    evidence={'matched_indicators': list(matched_indicators)}
                ))
        
        return sorted(stages, key=lambda x: x.stage_number)


class AttackAnalysisEngine:
    """Main attack analysis engine coordinating all analysis capabilities"""
    
    def __init__(self):
        self.malware_analyzer = MalwareAnalyzer()
        self.attack_detector = AttackDetector()
        self.kill_chain_analyzer = KillChainAnalyzer()
        self.pdf_generator = create_pdf_generator()
    
    def analyze_attack(
        self,
        target: str,
        events: List[Dict[str, Any]] = None,
        malware_files: List[str] = None,
        malware_bytes: List[Tuple[bytes, str]] = None,
        generate_pdf: bool = True
    ) -> AttackAnalysisResult:
        """Perform comprehensive attack analysis"""
        start_time = datetime.utcnow().isoformat()
        
        attack_events = []
        if events:
            for event_data in events:
                detected = self.attack_detector.analyze_request(
                    source_ip=event_data.get('source_ip', '0.0.0.0'),
                    dest_ip=event_data.get('dest_ip', '0.0.0.0'),
                    dest_port=event_data.get('dest_port', 80),
                    protocol=event_data.get('protocol', 'HTTP'),
                    payload=event_data.get('payload', ''),
                    headers=event_data.get('headers', {})
                )
                attack_events.extend(detected)
        
        malware_samples = []
        
        if malware_files:
            for file_path in malware_files:
                sample = self.malware_analyzer.analyze_file(file_path)
                if sample:
                    malware_samples.append(sample)
        
        if malware_bytes:
            for data, name in malware_bytes:
                sample = self.malware_analyzer.analyze_bytes(data, name)
                malware_samples.append(sample)
        
        attack_chain = self.kill_chain_analyzer.analyze_attack_chain(attack_events, malware_samples)
        
        attribution = self._perform_attribution(attack_events, malware_samples)
        
        recommendations = self._generate_recommendations(attack_events, malware_samples, attack_chain)
        
        risk_score = self._calculate_risk_score(attack_events, malware_samples, attack_chain)
        
        end_time = datetime.utcnow().isoformat()
        
        result = AttackAnalysisResult(
            analysis_id=hashlib.md5(f"{start_time}{target}".encode()).hexdigest()[:16],
            target=target,
            start_time=start_time,
            end_time=end_time,
            total_events=len(attack_events),
            attack_events=[asdict(e) for e in attack_events],
            malware_samples=[asdict(s) for s in malware_samples],
            attack_chain=[asdict(s) for s in attack_chain],
            attribution=attribution,
            recommendations=recommendations,
            risk_score=risk_score,
            summary=self._generate_summary(attack_events, malware_samples, attack_chain, risk_score)
        )
        
        if generate_pdf:
            result.summary['pdf_report'] = self._generate_pdf_report(result)
        
        return result
    
    def _perform_attribution(
        self,
        events: List[AttackEvent],
        samples: List[MalwareSample]
    ) -> Dict[str, Any]:
        """Perform attack attribution analysis"""
        attribution = {
            'confidence': 'LOW',
            'threat_actor': 'Unknown',
            'campaign': 'Unknown',
            'motivation': 'Unknown',
            'ttps': [],
            'indicators': [],
        }
        
        all_techniques = set()
        for event in events:
            all_techniques.update(event.mitre_techniques)
        
        for sample in samples:
            for behavior in sample.dynamic_analysis.get('behaviors', []):
                all_techniques.update(AttackDetector.MITRE_MAPPING.get(
                    behavior.upper().replace(' ', '_'), []
                ))
        
        attribution['ttps'] = list(all_techniques)
        
        for sample in samples:
            attribution['indicators'].extend([
                {'type': 'hash', 'value': sample.sha256},
            ])
            for ioc in sample.iocs:
                if isinstance(ioc, dict):
                    attribution['indicators'].append({
                        'type': ioc.get('ioc_type'),
                        'value': ioc.get('value')
                    })
        
        if len(all_techniques) > 5:
            attribution['confidence'] = 'MEDIUM'
        if len(samples) > 0 and len(events) > 10:
            attribution['confidence'] = 'HIGH'
        
        return attribution
    
    def _generate_recommendations(
        self,
        events: List[AttackEvent],
        samples: List[MalwareSample],
        chain: List[AttackChainStage]
    ) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        attack_types = set(e.attack_type for e in events)
        
        if 'SQL_INJECTION' in attack_types:
            recommendations.append("Implement parameterized queries and input validation to prevent SQL injection")
        
        if 'XSS' in attack_types:
            recommendations.append("Implement Content Security Policy (CSP) and output encoding to prevent XSS")
        
        if 'COMMAND_INJECTION' in attack_types:
            recommendations.append("Avoid shell command execution; use safe APIs and input validation")
        
        if 'BRUTE_FORCE' in attack_types:
            recommendations.append("Implement rate limiting, account lockout, and multi-factor authentication")
        
        if 'DOS' in attack_types:
            recommendations.append("Deploy DDoS protection, rate limiting, and traffic analysis")
        
        if samples:
            recommendations.append("Isolate affected systems and perform forensic analysis")
            recommendations.append("Update antivirus signatures and scan all endpoints")
            recommendations.append("Review and update endpoint detection and response (EDR) rules")
        
        for stage in chain:
            if stage.stage == 'COMMAND_AND_CONTROL':
                recommendations.append("Block identified C2 infrastructure at network perimeter")
                recommendations.append("Implement network segmentation to limit lateral movement")
            
            if stage.stage == 'INSTALLATION':
                recommendations.append("Review and harden endpoint security configurations")
                recommendations.append("Implement application whitelisting")
        
        if not recommendations:
            recommendations.append("Continue monitoring and maintain security posture")
        
        return list(set(recommendations))
    
    def _calculate_risk_score(
        self,
        events: List[AttackEvent],
        samples: List[MalwareSample],
        chain: List[AttackChainStage]
    ) -> float:
        """Calculate overall risk score (0-100)"""
        score = 0.0
        
        severity_weights = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3}
        for event in events[:20]:
            score += severity_weights.get(event.severity, 5)
        
        score += len(samples) * 10
        
        score += len(chain) * 5
        
        advanced_stages = ['COMMAND_AND_CONTROL', 'ACTIONS_ON_OBJECTIVES']
        for stage in chain:
            if stage.stage in advanced_stages:
                score += 15
        
        return min(100.0, score)
    
    def _generate_summary(
        self,
        events: List[AttackEvent],
        samples: List[MalwareSample],
        chain: List[AttackChainStage],
        risk_score: float
    ) -> Dict[str, Any]:
        """Generate analysis summary"""
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for event in events:
            severity_counts[event.severity] += 1
            type_counts[event.attack_type] += 1
        
        return {
            'total_events': len(events),
            'total_malware_samples': len(samples),
            'kill_chain_stages_detected': len(chain),
            'risk_score': risk_score,
            'risk_level': 'CRITICAL' if risk_score >= 75 else 'HIGH' if risk_score >= 50 else 'MEDIUM' if risk_score >= 25 else 'LOW',
            'severity_breakdown': dict(severity_counts),
            'attack_type_breakdown': dict(type_counts),
            'most_advanced_stage': chain[-1].stage if chain else 'NONE',
        }
    
    def _generate_pdf_report(self, result: AttackAnalysisResult) -> str:
        """Generate PDF report from analysis results"""
        metadata = ReportMetadata(
            title="Attack Analysis Report",
            subtitle=f"Target: {result.target}",
            classification="TOP SECRET",
            author="GISC Attack Analysis Engine",
            organization="Global Intelligence Security Command Center",
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            report_id=result.analysis_id.upper(),
            version="1.0"
        )
        
        attack_data = {
            'attack_summary': {
                'type': result.summary.get('attack_type_breakdown', {}),
                'vector': 'Multiple' if len(result.attack_events) > 1 else 'Single',
                'source_ip': result.attack_events[0].get('source_ip', 'Unknown') if result.attack_events else 'Unknown',
                'target': result.target,
                'timestamp': result.start_time,
                'severity': result.summary.get('risk_level', 'Unknown'),
            },
            'attack_chain': [
                {
                    'stage': stage.get('stage'),
                    'description': stage.get('description')
                }
                for stage in result.attack_chain
            ],
        }
        
        if result.malware_samples:
            sample = result.malware_samples[0]
            attack_data['malware_analysis'] = {
                'sha256': sample.get('sha256', 'N/A'),
                'file_type': sample.get('file_type', 'N/A'),
                'detection_rate': f"{len(sample.get('detection_names', []))} detections",
                'behaviors': sample.get('dynamic_analysis', {}).get('behaviors', [])[:10],
                'iocs': sample.get('iocs', [])[:10],
            }
        
        return self.pdf_generator.generate_attack_analysis_report(
            metadata=metadata,
            attack_data=attack_data
        )
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time attack statistics"""
        return self.attack_detector.get_statistics()


def create_attack_analysis_engine() -> AttackAnalysisEngine:
    """Factory function to create attack analysis engine instance"""
    return AttackAnalysisEngine()
