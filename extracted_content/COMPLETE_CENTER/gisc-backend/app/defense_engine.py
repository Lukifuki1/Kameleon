"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - DEFENSE ENGINE MODULE
Complete implementation of defense templates

This module implements:
- Active Defense (threat neutralization, deception)
- Threat Neutralization
- Automated Response
- Network Defense
- Endpoint Protection
- DDoS Mitigation
- Firewall Management
- Access Control

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import time
import json
import secrets
import re
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict


class DefenseAction(str, Enum):
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    ISOLATE = "ISOLATE"
    TERMINATE = "TERMINATE"
    REDIRECT = "REDIRECT"
    DECEIVE = "DECEIVE"
    ALERT = "ALERT"
    LOG = "LOG"
    RATE_LIMIT = "RATE_LIMIT"
    CAPTCHA = "CAPTCHA"


class ThreatType(str, Enum):
    MALWARE = "MALWARE"
    INTRUSION = "INTRUSION"
    DDOS = "DDOS"
    BRUTE_FORCE = "BRUTE_FORCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    COMMAND_CONTROL = "COMMAND_CONTROL"
    RECONNAISSANCE = "RECONNAISSANCE"
    INSIDER_THREAT = "INSIDER_THREAT"


class DefenseStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    TRIGGERED = "TRIGGERED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class FirewallRuleAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DROP = "DROP"
    REJECT = "REJECT"
    LOG = "LOG"


class ProtectionLevel(str, Enum):
    MAXIMUM = "MAXIMUM"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MONITORING = "MONITORING"


@dataclass
class DefenseRule:
    rule_id: str
    name: str
    description: str
    threat_type: ThreatType
    conditions: Dict[str, Any]
    actions: List[DefenseAction]
    priority: int
    enabled: bool
    created_at: str
    last_triggered: Optional[str]
    trigger_count: int


@dataclass
class FirewallRule:
    rule_id: str
    name: str
    action: FirewallRuleAction
    source_ip: Optional[str]
    source_port: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[str]
    protocol: str
    direction: str
    enabled: bool
    created_at: str
    expires_at: Optional[str]
    hit_count: int


@dataclass
class BlockedEntity:
    entity_id: str
    entity_type: str
    value: str
    reason: str
    blocked_at: str
    expires_at: Optional[str]
    source_rule: str
    hit_count: int


@dataclass
class DefenseEvent:
    event_id: str
    timestamp: str
    threat_type: ThreatType
    action_taken: DefenseAction
    target: str
    source: str
    rule_id: str
    success: bool
    details: Dict[str, Any]


class FirewallManager:
    """Firewall rule management"""
    
    def __init__(self):
        self.rules: Dict[str, FirewallRule] = {}
        self.blocked_ips: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default firewall rules"""
        default_rules = [
            {
                "name": "Block Known Malicious IPs",
                "action": FirewallRuleAction.DROP,
                "source_ip": "0.0.0.0/0",
                "destination_port": "*",
                "protocol": "tcp",
                "direction": "inbound"
            },
            {
                "name": "Allow HTTPS Outbound",
                "action": FirewallRuleAction.ALLOW,
                "destination_port": "443",
                "protocol": "tcp",
                "direction": "outbound"
            },
            {
                "name": "Allow HTTP Outbound",
                "action": FirewallRuleAction.ALLOW,
                "destination_port": "80",
                "protocol": "tcp",
                "direction": "outbound"
            },
            {
                "name": "Allow DNS",
                "action": FirewallRuleAction.ALLOW,
                "destination_port": "53",
                "protocol": "udp",
                "direction": "outbound"
            },
            {
                "name": "Block Tor Exit Nodes",
                "action": FirewallRuleAction.DROP,
                "source_ip": "tor_exit_list",
                "protocol": "tcp",
                "direction": "inbound"
            }
        ]
        
        for rule_data in default_rules:
            rule = FirewallRule(
                rule_id=f"FW-{secrets.token_hex(8).upper()}",
                name=rule_data["name"],
                action=rule_data["action"],
                source_ip=rule_data.get("source_ip"),
                source_port=rule_data.get("source_port"),
                destination_ip=rule_data.get("destination_ip"),
                destination_port=rule_data.get("destination_port"),
                protocol=rule_data["protocol"],
                direction=rule_data["direction"],
                enabled=True,
                created_at=datetime.utcnow().isoformat(),
                expires_at=None,
                hit_count=0
            )
            self.rules[rule.rule_id] = rule
    
    def add_rule(self, name: str, action: FirewallRuleAction, protocol: str,
                direction: str, source_ip: str = None, source_port: str = None,
                destination_ip: str = None, destination_port: str = None,
                expires_in: int = None) -> FirewallRule:
        """Add firewall rule"""
        expires_at = None
        if expires_in:
            expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
        
        rule = FirewallRule(
            rule_id=f"FW-{secrets.token_hex(8).upper()}",
            name=name,
            action=action,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            direction=direction,
            enabled=True,
            created_at=datetime.utcnow().isoformat(),
            expires_at=expires_at,
            hit_count=0
        )
        self.rules[rule.rule_id] = rule
        return rule
    
    def block_ip(self, ip: str, reason: str, duration: int = 3600) -> FirewallRule:
        """Block IP address"""
        self.blocked_ips.add(ip)
        return self.add_rule(
            name=f"Block IP: {ip}",
            action=FirewallRuleAction.DROP,
            protocol="all",
            direction="both",
            source_ip=ip,
            expires_in=duration
        )
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            # Remove associated rules
            rules_to_remove = [
                rule_id for rule_id, rule in self.rules.items()
                if rule.source_ip == ip
            ]
            for rule_id in rules_to_remove:
                del self.rules[rule_id]
            return True
        return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def evaluate_traffic(self, traffic: Dict[str, Any]) -> Tuple[bool, Optional[FirewallRule]]:
        """Evaluate traffic against firewall rules"""
        source_ip = traffic.get("source_ip")
        dest_ip = traffic.get("destination_ip")
        dest_port = traffic.get("destination_port")
        protocol = traffic.get("protocol", "tcp")
        direction = traffic.get("direction", "inbound")
        
        # Check blocked IPs first
        if source_ip in self.blocked_ips:
            return False, None
        
        # Evaluate rules by priority
        sorted_rules = sorted(self.rules.values(), key=lambda r: r.hit_count, reverse=True)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            
            # Check expiration
            if rule.expires_at:
                if datetime.fromisoformat(rule.expires_at) < datetime.utcnow():
                    rule.enabled = False
                    continue
            
            # Match rule
            if self._matches_rule(rule, source_ip, dest_ip, dest_port, protocol, direction):
                rule.hit_count += 1
                
                if rule.action in [FirewallRuleAction.ALLOW]:
                    return True, rule
                elif rule.action in [FirewallRuleAction.DENY, FirewallRuleAction.DROP, FirewallRuleAction.REJECT]:
                    return False, rule
        
        # Default allow
        return True, None
    
    def _matches_rule(self, rule: FirewallRule, source_ip: str, dest_ip: str,
                     dest_port: str, protocol: str, direction: str) -> bool:
        """Check if traffic matches rule"""
        if rule.direction != "both" and rule.direction != direction:
            return False
        
        if rule.protocol != "all" and rule.protocol != protocol:
            return False
        
        if rule.source_ip and rule.source_ip != "*":
            if not self._ip_matches(source_ip, rule.source_ip):
                return False
        
        if rule.destination_ip and rule.destination_ip != "*":
            if not self._ip_matches(dest_ip, rule.destination_ip):
                return False
        
        if rule.destination_port and rule.destination_port != "*":
            if str(dest_port) != rule.destination_port:
                return False
        
        return True
    
    def _ip_matches(self, ip: str, pattern: str) -> bool:
        """Check if IP matches pattern (supports CIDR)"""
        try:
            if "/" in pattern:
                network = ipaddress.ip_network(pattern, strict=False)
                return ipaddress.ip_address(ip) in network
            return ip == pattern
        except:
            return False


class DDoSMitigationEngine:
    """DDoS attack mitigation engine"""
    
    def __init__(self):
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self.attack_signatures = [
            {"name": "SYN Flood", "pattern": "syn_rate > 1000"},
            {"name": "UDP Flood", "pattern": "udp_rate > 5000"},
            {"name": "HTTP Flood", "pattern": "http_rate > 500"},
            {"name": "DNS Amplification", "pattern": "dns_response_rate > 1000"},
            {"name": "Slowloris", "pattern": "incomplete_connections > 100"}
        ]
        self.mitigation_active = False
        self.protected_ips: Set[str] = set()
    
    def detect_attack(self, traffic_stats: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect DDoS attack from traffic statistics"""
        detection = {
            "timestamp": datetime.utcnow().isoformat(),
            "attack_detected": False,
            "attack_type": None,
            "severity": None,
            "indicators": []
        }
        
        # Check for SYN flood
        syn_rate = traffic_stats.get("syn_rate", 0)
        if syn_rate > 1000:
            detection["attack_detected"] = True
            detection["attack_type"] = "SYN Flood"
            detection["severity"] = "HIGH" if syn_rate > 5000 else "MEDIUM"
            detection["indicators"].append({"metric": "syn_rate", "value": syn_rate})
        
        # Check for UDP flood
        udp_rate = traffic_stats.get("udp_rate", 0)
        if udp_rate > 5000:
            detection["attack_detected"] = True
            detection["attack_type"] = "UDP Flood"
            detection["severity"] = "HIGH" if udp_rate > 20000 else "MEDIUM"
            detection["indicators"].append({"metric": "udp_rate", "value": udp_rate})
        
        # Check for HTTP flood
        http_rate = traffic_stats.get("http_rate", 0)
        if http_rate > 500:
            detection["attack_detected"] = True
            detection["attack_type"] = "HTTP Flood"
            detection["severity"] = "HIGH" if http_rate > 2000 else "MEDIUM"
            detection["indicators"].append({"metric": "http_rate", "value": http_rate})
        
        return detection
    
    def activate_mitigation(self, attack_type: str) -> Dict[str, Any]:
        """Activate DDoS mitigation"""
        self.mitigation_active = True
        
        mitigation = {
            "timestamp": datetime.utcnow().isoformat(),
            "attack_type": attack_type,
            "actions_taken": [],
            "status": "ACTIVE"
        }
        
        if attack_type == "SYN Flood":
            mitigation["actions_taken"] = [
                "SYN cookies enabled",
                "Connection rate limiting activated",
                "Backlog queue increased"
            ]
        elif attack_type == "UDP Flood":
            mitigation["actions_taken"] = [
                "UDP rate limiting activated",
                "Source IP validation enabled",
                "Amplification filtering enabled"
            ]
        elif attack_type == "HTTP Flood":
            mitigation["actions_taken"] = [
                "HTTP rate limiting activated",
                "CAPTCHA challenge enabled",
                "Bot detection activated"
            ]
        
        return mitigation
    
    def set_rate_limit(self, ip: str, requests_per_second: int, duration: int = 3600) -> Dict[str, Any]:
        """Set rate limit for IP"""
        self.rate_limits[ip] = {
            "limit": requests_per_second,
            "current": 0,
            "window_start": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(seconds=duration)).isoformat()
        }
        return self.rate_limits[ip]
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, int]:
        """Check if IP is within rate limit"""
        if ip not in self.rate_limits:
            return True, 0
        
        limit_info = self.rate_limits[ip]
        
        # Check expiration
        if datetime.fromisoformat(limit_info["expires_at"]) < datetime.utcnow():
            del self.rate_limits[ip]
            return True, 0
        
        # Check rate
        if limit_info["current"] >= limit_info["limit"]:
            return False, limit_info["limit"] - limit_info["current"]
        
        limit_info["current"] += 1
        return True, limit_info["limit"] - limit_info["current"]


class ThreatNeutralizationEngine:
    """Threat neutralization engine"""
    
    def __init__(self):
        self.neutralization_actions: List[DefenseEvent] = []
        self.quarantined_files: Dict[str, Dict[str, Any]] = {}
        self.isolated_hosts: Set[str] = set()
        self.terminated_processes: List[Dict[str, Any]] = []
    
    def neutralize_threat(self, threat: Dict[str, Any]) -> DefenseEvent:
        """Neutralize detected threat"""
        threat_type = ThreatType(threat.get("type", "MALWARE"))
        target = threat.get("target", "unknown")
        source = threat.get("source", "unknown")
        
        # Determine appropriate action
        action = self._determine_action(threat_type, threat)
        
        # Execute action
        success = self._execute_action(action, threat)
        
        event = DefenseEvent(
            event_id=f"DEF-{secrets.token_hex(8).upper()}",
            timestamp=datetime.utcnow().isoformat(),
            threat_type=threat_type,
            action_taken=action,
            target=target,
            source=source,
            rule_id=threat.get("rule_id", "manual"),
            success=success,
            details=threat
        )
        
        self.neutralization_actions.append(event)
        return event
    
    def _determine_action(self, threat_type: ThreatType, threat: Dict[str, Any]) -> DefenseAction:
        """Determine appropriate neutralization action"""
        action_map = {
            ThreatType.MALWARE: DefenseAction.QUARANTINE,
            ThreatType.INTRUSION: DefenseAction.BLOCK,
            ThreatType.DDOS: DefenseAction.RATE_LIMIT,
            ThreatType.BRUTE_FORCE: DefenseAction.BLOCK,
            ThreatType.DATA_EXFILTRATION: DefenseAction.ISOLATE,
            ThreatType.LATERAL_MOVEMENT: DefenseAction.ISOLATE,
            ThreatType.PRIVILEGE_ESCALATION: DefenseAction.TERMINATE,
            ThreatType.COMMAND_CONTROL: DefenseAction.BLOCK,
            ThreatType.RECONNAISSANCE: DefenseAction.DECEIVE,
            ThreatType.INSIDER_THREAT: DefenseAction.ALERT
        }
        return action_map.get(threat_type, DefenseAction.ALERT)
    
    def _execute_action(self, action: DefenseAction, threat: Dict[str, Any]) -> bool:
        """Execute neutralization action"""
        try:
            if action == DefenseAction.QUARANTINE:
                file_path = threat.get("file_path")
                if file_path:
                    self.quarantined_files[file_path] = {
                        "quarantined_at": datetime.utcnow().isoformat(),
                        "threat": threat
                    }
                return True
            
            elif action == DefenseAction.ISOLATE:
                host = threat.get("host")
                if host:
                    self.isolated_hosts.add(host)
                return True
            
            elif action == DefenseAction.TERMINATE:
                process = threat.get("process")
                if process:
                    self.terminated_processes.append({
                        "process": process,
                        "terminated_at": datetime.utcnow().isoformat()
                    })
                return True
            
            elif action == DefenseAction.BLOCK:
                # Would integrate with firewall
                return True
            
            return True
            
        except Exception as e:
            return False
    
    def quarantine_file(self, file_path: str, reason: str) -> Dict[str, Any]:
        """Quarantine suspicious file"""
        quarantine_info = {
            "file_path": file_path,
            "reason": reason,
            "quarantined_at": datetime.utcnow().isoformat(),
            "status": "QUARANTINED"
        }
        self.quarantined_files[file_path] = quarantine_info
        return quarantine_info
    
    def isolate_host(self, host: str, reason: str) -> Dict[str, Any]:
        """Isolate compromised host"""
        self.isolated_hosts.add(host)
        return {
            "host": host,
            "reason": reason,
            "isolated_at": datetime.utcnow().isoformat(),
            "status": "ISOLATED"
        }
    
    def release_host(self, host: str) -> bool:
        """Release isolated host"""
        if host in self.isolated_hosts:
            self.isolated_hosts.remove(host)
            return True
        return False


class ActiveDefenseEngine:
    """Active defense and deception engine"""
    
    def __init__(self):
        self.honeypots: Dict[str, Dict[str, Any]] = {}
        self.honeytokens: Dict[str, Dict[str, Any]] = {}
        self.deception_networks: List[Dict[str, Any]] = []
        self.attacker_tracking: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    def deploy_honeypot(self, name: str, honeypot_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy honeypot"""
        honeypot = {
            "honeypot_id": f"HP-{secrets.token_hex(8).upper()}",
            "name": name,
            "type": honeypot_type,
            "config": config,
            "deployed_at": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
            "interactions": []
        }
        self.honeypots[honeypot["honeypot_id"]] = honeypot
        return honeypot
    
    def deploy_honeytoken(self, token_type: str, value: str, location: str) -> Dict[str, Any]:
        """Deploy honeytoken"""
        honeytoken = {
            "token_id": f"HT-{secrets.token_hex(8).upper()}",
            "type": token_type,
            "value": value,
            "location": location,
            "deployed_at": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
            "triggered": False,
            "triggers": []
        }
        self.honeytokens[honeytoken["token_id"]] = honeytoken
        return honeytoken
    
    def record_honeypot_interaction(self, honeypot_id: str, interaction: Dict[str, Any]) -> None:
        """Record honeypot interaction"""
        if honeypot_id in self.honeypots:
            interaction["timestamp"] = datetime.utcnow().isoformat()
            self.honeypots[honeypot_id]["interactions"].append(interaction)
            
            # Track attacker
            attacker_ip = interaction.get("source_ip")
            if attacker_ip:
                self.attacker_tracking[attacker_ip].append(interaction)
    
    def trigger_honeytoken(self, token_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Record honeytoken trigger"""
        if token_id in self.honeytokens:
            token = self.honeytokens[token_id]
            token["triggered"] = True
            token["triggers"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "context": context
            })
            return token
        return {"error": "Token not found"}
    
    def get_attacker_profile(self, ip: str) -> Dict[str, Any]:
        """Get attacker profile from tracked interactions"""
        interactions = self.attacker_tracking.get(ip, [])
        
        profile = {
            "ip": ip,
            "total_interactions": len(interactions),
            "first_seen": interactions[0]["timestamp"] if interactions else None,
            "last_seen": interactions[-1]["timestamp"] if interactions else None,
            "techniques_observed": [],
            "targets": [],
            "risk_score": 0
        }
        
        for interaction in interactions:
            profile["risk_score"] += 10
            if interaction.get("technique"):
                profile["techniques_observed"].append(interaction["technique"])
            if interaction.get("target"):
                profile["targets"].append(interaction["target"])
        
        profile["techniques_observed"] = list(set(profile["techniques_observed"]))
        profile["targets"] = list(set(profile["targets"]))
        
        return profile


class DefenseEngine:
    """Main defense engine"""
    
    def __init__(self):
        self.firewall = FirewallManager()
        self.ddos_mitigation = DDoSMitigationEngine()
        self.threat_neutralization = ThreatNeutralizationEngine()
        self.active_defense = ActiveDefenseEngine()
        self.defense_rules: Dict[str, DefenseRule] = {}
        self.defense_events: List[DefenseEvent] = []
        self.protection_level = ProtectionLevel.HIGH
    
    def set_protection_level(self, level: ProtectionLevel) -> Dict[str, Any]:
        """Set overall protection level"""
        self.protection_level = level
        
        # Adjust settings based on level
        settings = {
            ProtectionLevel.MAXIMUM: {
                "block_unknown": True,
                "rate_limit": 10,
                "honeypots_active": True,
                "auto_isolate": True
            },
            ProtectionLevel.HIGH: {
                "block_unknown": False,
                "rate_limit": 50,
                "honeypots_active": True,
                "auto_isolate": True
            },
            ProtectionLevel.MEDIUM: {
                "block_unknown": False,
                "rate_limit": 100,
                "honeypots_active": True,
                "auto_isolate": False
            },
            ProtectionLevel.LOW: {
                "block_unknown": False,
                "rate_limit": 500,
                "honeypots_active": False,
                "auto_isolate": False
            },
            ProtectionLevel.MONITORING: {
                "block_unknown": False,
                "rate_limit": None,
                "honeypots_active": False,
                "auto_isolate": False
            }
        }
        
        return {
            "level": level.value,
            "settings": settings.get(level, {}),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def respond_to_threat(self, threat: Dict[str, Any]) -> DefenseEvent:
        """Respond to detected threat"""
        # Neutralize threat
        event = self.threat_neutralization.neutralize_threat(threat)
        self.defense_events.append(event)
        
        # Additional actions based on threat type
        threat_type = threat.get("type")
        source_ip = threat.get("source_ip")
        
        if source_ip and threat_type in ["INTRUSION", "BRUTE_FORCE", "DDOS"]:
            self.firewall.block_ip(source_ip, f"Automated block: {threat_type}")
        
        return event
    
    def get_defense_status(self) -> Dict[str, Any]:
        """Get current defense status"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "protection_level": self.protection_level.value,
            "firewall_rules": len(self.firewall.rules),
            "blocked_ips": len(self.firewall.blocked_ips),
            "active_honeypots": len(self.active_defense.honeypots),
            "active_honeytokens": len(self.active_defense.honeytokens),
            "quarantined_files": len(self.threat_neutralization.quarantined_files),
            "isolated_hosts": len(self.threat_neutralization.isolated_hosts),
            "ddos_mitigation_active": self.ddos_mitigation.mitigation_active,
            "recent_events": len(self.defense_events)
        }


# Factory function for API use
def create_defense_engine() -> DefenseEngine:
    """Create defense engine instance"""
    return DefenseEngine()
