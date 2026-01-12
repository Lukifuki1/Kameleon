"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - YARA ENGINE
Enterprise-grade YARA rule matching for malware detection and forensics

This module implements:
- YARA rule compilation and management
- File scanning with YARA rules
- Memory scanning capabilities
- Rule repository management
- Match result aggregation
- Custom rule creation

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import hashlib
import logging
import time
import secrets
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import threading
import tempfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


YARA_RULES_DIR = os.environ.get("YARA_RULES_DIR", "/opt/yara-rules")
YARA_TIMEOUT = int(os.environ.get("YARA_TIMEOUT", "60"))
MAX_FILE_SIZE = int(os.environ.get("YARA_MAX_FILE_SIZE", str(100 * 1024 * 1024)))


try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not available, using fallback regex-based matching")


@dataclass
class YaraMatch:
    rule_name: str
    rule_namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Dict[str, Any]]
    match_offset: int
    match_length: int


@dataclass
class YaraScanResult:
    scan_id: str
    target: str
    target_type: str
    target_hash: Optional[str]
    target_size: int
    matches: List[YaraMatch]
    rules_checked: int
    scan_time_ms: int
    status: str
    error: Optional[str]
    scanned_at: str


@dataclass
class YaraRule:
    rule_id: str
    name: str
    namespace: str
    source: str
    tags: List[str]
    meta: Dict[str, Any]
    is_compiled: bool
    file_path: Optional[str]
    created_at: str
    updated_at: str


class YaraRuleManager:
    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or YARA_RULES_DIR
        self._rules: Dict[str, YaraRule] = {}
        self._compiled_rules = None
        self._lock = threading.Lock()
        self._load_builtin_rules()
    
    def _load_builtin_rules(self):
        builtin_rules = [
            {
                "name": "suspicious_strings",
                "namespace": "builtin",
                "source": '''
rule suspicious_strings {
    meta:
        description = "Detects suspicious strings commonly found in malware"
        author = "TYRANTHOS"
        severity = "medium"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "WScript.Shell" nocase
        $s4 = "CreateObject" nocase
        $s5 = "HKEY_LOCAL_MACHINE" nocase
        $s6 = "RegWrite" nocase
        $s7 = "Shell.Application" nocase
        $s8 = "Scripting.FileSystemObject" nocase
    condition:
        3 of them
}
''',
                "tags": ["malware", "suspicious"],
            },
            {
                "name": "base64_encoded_pe",
                "namespace": "builtin",
                "source": '''
rule base64_encoded_pe {
    meta:
        description = "Detects Base64 encoded PE files"
        author = "TYRANTHOS"
        severity = "high"
    strings:
        $b64_mz = "TVqQAAMAAAAEAAAA" ascii
        $b64_mz2 = "TVpQAAIAAAAEAA8A" ascii
        $b64_mz3 = "TVoAAAAAAAAAAAAA" ascii
    condition:
        any of them
}
''',
                "tags": ["malware", "encoded", "pe"],
            },
            {
                "name": "webshell_generic",
                "namespace": "builtin",
                "source": '''
rule webshell_generic {
    meta:
        description = "Detects generic webshell patterns"
        author = "TYRANTHOS"
        severity = "critical"
    strings:
        $php1 = "<?php" nocase
        $php2 = "eval(" nocase
        $php3 = "base64_decode(" nocase
        $php4 = "shell_exec(" nocase
        $php5 = "system(" nocase
        $php6 = "passthru(" nocase
        $php7 = "exec(" nocase
        $php8 = "popen(" nocase
        $asp1 = "<%@ " nocase
        $asp2 = "Request(" nocase
        $asp3 = "Execute(" nocase
        $jsp1 = "Runtime.getRuntime()" nocase
        $jsp2 = "ProcessBuilder" nocase
    condition:
        ($php1 and 2 of ($php2, $php3, $php4, $php5, $php6, $php7, $php8)) or
        ($asp1 and $asp2 and $asp3) or
        ($jsp1 or $jsp2)
}
''',
                "tags": ["webshell", "backdoor"],
            },
            {
                "name": "ransomware_indicators",
                "namespace": "builtin",
                "source": '''
rule ransomware_indicators {
    meta:
        description = "Detects common ransomware indicators"
        author = "TYRANTHOS"
        severity = "critical"
    strings:
        $r1 = "Your files have been encrypted" nocase
        $r2 = "bitcoin" nocase
        $r3 = "decrypt" nocase
        $r4 = "ransom" nocase
        $r5 = ".onion" nocase
        $r6 = "wallet" nocase
        $r7 = "payment" nocase
        $r8 = "CryptoLocker" nocase
        $r9 = "WannaCry" nocase
        $r10 = "Locky" nocase
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
    condition:
        3 of ($r*) or 2 of ($ext*)
}
''',
                "tags": ["ransomware", "malware"],
            },
            {
                "name": "credential_harvester",
                "namespace": "builtin",
                "source": '''
rule credential_harvester {
    meta:
        description = "Detects credential harvesting patterns"
        author = "TYRANTHOS"
        severity = "high"
    strings:
        $c1 = "password" nocase
        $c2 = "credential" nocase
        $c3 = "login" nocase
        $c4 = "username" nocase
        $c5 = "keylog" nocase
        $c6 = "GetAsyncKeyState" nocase
        $c7 = "SetWindowsHookEx" nocase
        $c8 = "Chrome\\User Data" nocase
        $c9 = "Firefox\\Profiles" nocase
        $c10 = "Login Data" nocase
    condition:
        4 of them
}
''',
                "tags": ["credential", "stealer"],
            },
            {
                "name": "network_indicators",
                "namespace": "builtin",
                "source": '''
rule network_indicators {
    meta:
        description = "Detects suspicious network-related strings"
        author = "TYRANTHOS"
        severity = "medium"
    strings:
        $n1 = "socket" nocase
        $n2 = "connect" nocase
        $n3 = "recv" nocase
        $n4 = "send" nocase
        $n5 = "bind" nocase
        $n6 = "listen" nocase
        $n7 = "accept" nocase
        $n8 = "WSAStartup" nocase
        $n9 = "InternetOpen" nocase
        $n10 = "HttpSendRequest" nocase
        $n11 = "URLDownloadToFile" nocase
    condition:
        5 of them
}
''',
                "tags": ["network", "c2"],
            },
            {
                "name": "packer_upx",
                "namespace": "builtin",
                "source": '''
rule packer_upx {
    meta:
        description = "Detects UPX packed executables"
        author = "TYRANTHOS"
        severity = "low"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX2" ascii
        $upx4 = "UPX!" ascii
    condition:
        2 of them
}
''',
                "tags": ["packer", "upx"],
            },
            {
                "name": "exploit_cve_generic",
                "namespace": "builtin",
                "source": '''
rule exploit_cve_generic {
    meta:
        description = "Detects generic exploit patterns"
        author = "TYRANTHOS"
        severity = "high"
    strings:
        $e1 = "NtQuerySystemInformation" nocase
        $e2 = "ZwQuerySystemInformation" nocase
        $e3 = "VirtualProtect" nocase
        $e4 = "VirtualAlloc" nocase
        $e5 = "WriteProcessMemory" nocase
        $e6 = "CreateRemoteThread" nocase
        $e7 = "NtAllocateVirtualMemory" nocase
        $e8 = "shellcode" nocase
        $e9 = { 90 90 90 90 90 90 90 90 }
    condition:
        4 of them
}
''',
                "tags": ["exploit", "shellcode"],
            },
        ]
        
        for rule_data in builtin_rules:
            rule = YaraRule(
                rule_id=f"YARA-{secrets.token_hex(8).upper()}",
                name=rule_data["name"],
                namespace=rule_data["namespace"],
                source=rule_data["source"],
                tags=rule_data["tags"],
                meta={},
                is_compiled=False,
                file_path=None,
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat()
            )
            self._rules[rule.name] = rule
        
        self._compile_rules()
    
    def _compile_rules(self):
        if not YARA_AVAILABLE:
            return
        
        with self._lock:
            try:
                sources = {}
                for name, rule in self._rules.items():
                    sources[f"{rule.namespace}_{name}"] = rule.source
                
                self._compiled_rules = yara.compile(sources=sources)
                
                for rule in self._rules.values():
                    rule.is_compiled = True
                
                logger.info(f"Compiled {len(self._rules)} YARA rules")
                
            except Exception as e:
                logger.error(f"Failed to compile YARA rules: {e}")
                self._compiled_rules = None
    
    def add_rule(self, name: str, source: str, namespace: str = "custom",
                 tags: List[str] = None, meta: Dict[str, Any] = None) -> YaraRule:
        rule = YaraRule(
            rule_id=f"YARA-{secrets.token_hex(8).upper()}",
            name=name,
            namespace=namespace,
            source=source,
            tags=tags or [],
            meta=meta or {},
            is_compiled=False,
            file_path=None,
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat()
        )
        
        self._rules[name] = rule
        self._compile_rules()
        
        return rule
    
    def load_rules_from_file(self, file_path: str, namespace: str = "file") -> List[YaraRule]:
        loaded_rules = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            rule = YaraRule(
                rule_id=f"YARA-{secrets.token_hex(8).upper()}",
                name=Path(file_path).stem,
                namespace=namespace,
                source=content,
                tags=[],
                meta={"file_path": file_path},
                is_compiled=False,
                file_path=file_path,
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat()
            )
            
            self._rules[rule.name] = rule
            loaded_rules.append(rule)
            
            self._compile_rules()
            
        except Exception as e:
            logger.error(f"Failed to load rules from {file_path}: {e}")
        
        return loaded_rules
    
    def load_rules_from_directory(self, directory: str = None) -> List[YaraRule]:
        directory = directory or self.rules_dir
        loaded_rules = []
        
        if not os.path.exists(directory):
            logger.warning(f"Rules directory does not exist: {directory}")
            return loaded_rules
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.yar', '.yara', '.rule')):
                    file_path = os.path.join(root, file)
                    rules = self.load_rules_from_file(file_path)
                    loaded_rules.extend(rules)
        
        return loaded_rules
    
    def get_rule(self, name: str) -> Optional[YaraRule]:
        return self._rules.get(name)
    
    def list_rules(self) -> List[YaraRule]:
        return list(self._rules.values())
    
    def remove_rule(self, name: str) -> bool:
        if name in self._rules:
            del self._rules[name]
            self._compile_rules()
            return True
        return False
    
    def get_compiled_rules(self):
        return self._compiled_rules


class YaraScanner:
    def __init__(self, rule_manager: YaraRuleManager = None):
        self.rule_manager = rule_manager or YaraRuleManager()
        self._lock = threading.Lock()
    
    def scan_file(self, file_path: str, timeout: int = None) -> YaraScanResult:
        timeout = timeout or YARA_TIMEOUT
        start_time = time.time()
        scan_id = f"SCAN-{secrets.token_hex(8).upper()}"
        
        if not os.path.exists(file_path):
            return YaraScanResult(
                scan_id=scan_id,
                target=file_path,
                target_type="file",
                target_hash=None,
                target_size=0,
                matches=[],
                rules_checked=0,
                scan_time_ms=0,
                status="error",
                error="File not found",
                scanned_at=datetime.utcnow().isoformat()
            )
        
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            return YaraScanResult(
                scan_id=scan_id,
                target=file_path,
                target_type="file",
                target_hash=None,
                target_size=file_size,
                matches=[],
                rules_checked=0,
                scan_time_ms=0,
                status="error",
                error=f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE})",
                scanned_at=datetime.utcnow().isoformat()
            )
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        matches = self._scan_data(file_content, timeout)
        
        scan_time_ms = int((time.time() - start_time) * 1000)
        
        return YaraScanResult(
            scan_id=scan_id,
            target=file_path,
            target_type="file",
            target_hash=file_hash,
            target_size=file_size,
            matches=matches,
            rules_checked=len(self.rule_manager.list_rules()),
            scan_time_ms=scan_time_ms,
            status="completed",
            error=None,
            scanned_at=datetime.utcnow().isoformat()
        )
    
    def scan_data(self, data: bytes, identifier: str = "memory") -> YaraScanResult:
        start_time = time.time()
        scan_id = f"SCAN-{secrets.token_hex(8).upper()}"
        
        data_hash = hashlib.sha256(data).hexdigest()
        
        matches = self._scan_data(data, YARA_TIMEOUT)
        
        scan_time_ms = int((time.time() - start_time) * 1000)
        
        return YaraScanResult(
            scan_id=scan_id,
            target=identifier,
            target_type="memory",
            target_hash=data_hash,
            target_size=len(data),
            matches=matches,
            rules_checked=len(self.rule_manager.list_rules()),
            scan_time_ms=scan_time_ms,
            status="completed",
            error=None,
            scanned_at=datetime.utcnow().isoformat()
        )
    
    def _scan_data(self, data: bytes, timeout: int) -> List[YaraMatch]:
        matches = []
        
        if YARA_AVAILABLE:
            compiled_rules = self.rule_manager.get_compiled_rules()
            if compiled_rules:
                try:
                    yara_matches = compiled_rules.match(data=data, timeout=timeout)
                    
                    for match in yara_matches:
                        string_matches = []
                        for string_match in match.strings:
                            for instance in string_match.instances:
                                string_matches.append({
                                    "identifier": string_match.identifier,
                                    "offset": instance.offset,
                                    "matched_data": instance.matched_data[:100].hex() if instance.matched_data else ""
                                })
                        
                        matches.append(YaraMatch(
                            rule_name=match.rule,
                            rule_namespace=match.namespace,
                            tags=list(match.tags),
                            meta=dict(match.meta),
                            strings=string_matches,
                            match_offset=string_matches[0]["offset"] if string_matches else 0,
                            match_length=len(string_matches)
                        ))
                
                except yara.TimeoutError:
                    logger.warning("YARA scan timed out")
                except Exception as e:
                    logger.error(f"YARA scan error: {e}")
        else:
            matches = self._fallback_regex_scan(data)
        
        return matches
    
    def _fallback_regex_scan(self, data: bytes) -> List[YaraMatch]:
        import re
        matches = []
        
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except:
            text_data = ""
        
        patterns = {
            "suspicious_command": (rb'cmd\.exe|powershell|wscript\.shell', ["suspicious"]),
            "base64_pe": (rb'TVqQAAMAAAAEAAAA|TVpQAAIAAAAEAA8A', ["encoded", "pe"]),
            "webshell_php": (rb'<\?php.*?(eval|shell_exec|system|passthru)\s*\(', ["webshell"]),
            "ransomware_text": (rb'your files have been encrypted|bitcoin|decrypt.*ransom', ["ransomware"]),
            "credential_strings": (rb'password|credential|keylog|GetAsyncKeyState', ["credential"]),
        }
        
        for pattern_name, (pattern, tags) in patterns.items():
            try:
                found = re.findall(pattern, data, re.IGNORECASE)
                if found:
                    matches.append(YaraMatch(
                        rule_name=f"fallback_{pattern_name}",
                        rule_namespace="fallback",
                        tags=tags,
                        meta={"fallback": True},
                        strings=[{"identifier": "$pattern", "offset": 0, "matched_data": str(found[0][:50])}],
                        match_offset=0,
                        match_length=len(found)
                    ))
            except Exception as e:
                logger.error(f"Regex pattern error for {pattern_name}: {e}")
        
        return matches
    
    def scan_directory(self, directory: str, recursive: bool = True,
                       extensions: List[str] = None) -> List[YaraScanResult]:
        results = []
        
        if not os.path.exists(directory):
            return results
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if extensions:
                        if not any(file.endswith(ext) for ext in extensions):
                            continue
                    
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)
                    results.append(result)
        else:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path):
                    if extensions:
                        if not any(file.endswith(ext) for ext in extensions):
                            continue
                    
                    result = self.scan_file(file_path)
                    results.append(result)
        
        return results


class YaraEngine:
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
        
        self.rule_manager = YaraRuleManager()
        self.scanner = YaraScanner(self.rule_manager)
    
    def scan_file(self, file_path: str) -> YaraScanResult:
        return self.scanner.scan_file(file_path)
    
    def scan_data(self, data: bytes, identifier: str = "memory") -> YaraScanResult:
        return self.scanner.scan_data(data, identifier)
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[YaraScanResult]:
        return self.scanner.scan_directory(directory, recursive)
    
    def add_rule(self, name: str, source: str, **kwargs) -> YaraRule:
        return self.rule_manager.add_rule(name, source, **kwargs)
    
    def list_rules(self) -> List[YaraRule]:
        return self.rule_manager.list_rules()
    
    def get_status(self) -> Dict[str, Any]:
        return {
            "yara_available": YARA_AVAILABLE,
            "rules_loaded": len(self.rule_manager.list_rules()),
            "rules_compiled": self.rule_manager.get_compiled_rules() is not None,
            "rules_directory": YARA_RULES_DIR,
            "max_file_size": MAX_FILE_SIZE,
            "timeout": YARA_TIMEOUT,
        }


def get_yara_engine() -> YaraEngine:
    return YaraEngine()
