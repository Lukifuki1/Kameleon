"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - SURVEILLANCE ENGINE MODULE
Complete implementation of surveillance templates

This module implements:
- Network Surveillance
- Communications Monitoring
- Target Tracking
- Pattern Analysis
- Geolocation Services
- Metadata Collection
- Traffic Analysis
- Behavioral Surveillance

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import secrets
import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class SurveillanceType(str, Enum):
    NETWORK = "NETWORK"
    COMMUNICATIONS = "COMMUNICATIONS"
    PHYSICAL = "PHYSICAL"
    DIGITAL = "DIGITAL"
    FINANCIAL = "FINANCIAL"
    SOCIAL = "SOCIAL"
    BEHAVIORAL = "BEHAVIORAL"


class TargetStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ARCHIVED = "ARCHIVED"
    PRIORITY = "PRIORITY"


class CollectionMethod(str, Enum):
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"
    TARGETED = "TARGETED"
    BULK = "BULK"


class DataType(str, Enum):
    METADATA = "METADATA"
    CONTENT = "CONTENT"
    LOCATION = "LOCATION"
    BEHAVIORAL = "BEHAVIORAL"
    FINANCIAL = "FINANCIAL"
    SOCIAL = "SOCIAL"


@dataclass
class SurveillanceTarget:
    target_id: str
    name: str
    identifiers: Dict[str, List[str]]
    status: TargetStatus
    priority: int
    surveillance_types: List[SurveillanceType]
    collection_methods: List[CollectionMethod]
    data_collected: Dict[str, int]
    first_observed: str
    last_activity: str
    notes: List[Dict[str, Any]]


@dataclass
class CollectionTask:
    task_id: str
    target_id: str
    surveillance_type: SurveillanceType
    collection_method: CollectionMethod
    data_types: List[DataType]
    start_time: str
    end_time: Optional[str]
    status: str
    results_count: int


@dataclass
class NetworkSession:
    session_id: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    start_time: str
    end_time: Optional[str]
    flags: List[str]
    metadata: Dict[str, Any]


@dataclass
class CommunicationRecord:
    record_id: str
    communication_type: str
    source: str
    destination: str
    timestamp: str
    duration: Optional[int]
    metadata: Dict[str, Any]
    content_hash: Optional[str]
    flags: List[str]


class NetworkSurveillanceEngine:
    """Network surveillance and traffic analysis"""
    
    def __init__(self):
        self.sessions: Dict[str, NetworkSession] = {}
        self.traffic_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "bytes_in": 0,
            "bytes_out": 0,
            "packets_in": 0,
            "packets_out": 0,
            "connections": 0
        })
        self.watched_ips: Set[str] = set()
        self.watched_ports: Set[int] = set()
        self.alerts: List[Dict[str, Any]] = []
    
    def record_session(self, source_ip: str, source_port: int,
                      destination_ip: str, destination_port: int,
                      protocol: str, bytes_sent: int, bytes_received: int) -> NetworkSession:
        """Record network session"""
        session = NetworkSession(
            session_id=f"SES-{secrets.token_hex(8).upper()}",
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            packets_sent=0,
            packets_received=0,
            start_time=datetime.utcnow().isoformat(),
            end_time=None,
            flags=[],
            metadata={}
        )
        
        self.sessions[session.session_id] = session
        
        # Update traffic stats
        self.traffic_stats[source_ip]["bytes_out"] += bytes_sent
        self.traffic_stats[source_ip]["connections"] += 1
        self.traffic_stats[destination_ip]["bytes_in"] += bytes_received
        
        # Check for watched entities
        if source_ip in self.watched_ips or destination_ip in self.watched_ips:
            session.flags.append("WATCHED_IP")
            self._generate_alert("WATCHED_IP_ACTIVITY", session)
        
        if destination_port in self.watched_ports:
            session.flags.append("WATCHED_PORT")
            self._generate_alert("WATCHED_PORT_ACTIVITY", session)
        
        return session
    
    def add_watch(self, entity_type: str, value: str) -> Dict[str, Any]:
        """Add entity to watch list"""
        if entity_type == "ip":
            self.watched_ips.add(value)
        elif entity_type == "port":
            self.watched_ports.add(int(value))
        
        return {
            "type": entity_type,
            "value": value,
            "added_at": datetime.utcnow().isoformat()
        }
    
    def analyze_traffic(self, ip: str = None, time_range: int = 3600) -> Dict[str, Any]:
        """Analyze network traffic"""
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "time_range_seconds": time_range,
            "total_sessions": 0,
            "total_bytes": 0,
            "protocols": defaultdict(int),
            "top_talkers": [],
            "suspicious_activity": []
        }
        
        cutoff = datetime.utcnow() - timedelta(seconds=time_range)
        
        for session in self.sessions.values():
            session_time = datetime.fromisoformat(session.start_time)
            if session_time < cutoff:
                continue
            
            if ip and session.source_ip != ip and session.destination_ip != ip:
                continue
            
            analysis["total_sessions"] += 1
            analysis["total_bytes"] += session.bytes_sent + session.bytes_received
            analysis["protocols"][session.protocol] += 1
            
            if session.flags:
                analysis["suspicious_activity"].append({
                    "session_id": session.session_id,
                    "flags": session.flags
                })
        
        # Calculate top talkers
        sorted_stats = sorted(
            self.traffic_stats.items(),
            key=lambda x: x[1]["bytes_out"] + x[1]["bytes_in"],
            reverse=True
        )
        analysis["top_talkers"] = [
            {"ip": ip, "stats": stats}
            for ip, stats in sorted_stats[:10]
        ]
        
        return analysis
    
    def _generate_alert(self, alert_type: str, session: NetworkSession) -> None:
        """Generate surveillance alert"""
        alert = {
            "alert_id": f"ALT-{secrets.token_hex(8).upper()}",
            "type": alert_type,
            "session_id": session.session_id,
            "source_ip": session.source_ip,
            "destination_ip": session.destination_ip,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.alerts.append(alert)


class CommunicationsMonitoringEngine:
    """Communications monitoring and analysis"""
    
    def __init__(self):
        self.records: Dict[str, CommunicationRecord] = {}
        self.selectors: Dict[str, Dict[str, Any]] = {}
        self.intercepts: List[Dict[str, Any]] = []
    
    def add_selector(self, selector_type: str, value: str,
                    priority: int = 1) -> Dict[str, Any]:
        """Add communication selector"""
        selector_id = f"SEL-{secrets.token_hex(8).upper()}"
        
        selector = {
            "selector_id": selector_id,
            "type": selector_type,
            "value": value,
            "priority": priority,
            "status": "ACTIVE",
            "hits": 0,
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.selectors[selector_id] = selector
        return selector
    
    def record_communication(self, comm_type: str, source: str,
                            destination: str, metadata: Dict[str, Any],
                            content: bytes = None) -> CommunicationRecord:
        """Record communication"""
        content_hash = None
        if content:
            content_hash = hashlib.sha256(content).hexdigest()
        
        record = CommunicationRecord(
            record_id=f"COM-{secrets.token_hex(8).upper()}",
            communication_type=comm_type,
            source=source,
            destination=destination,
            timestamp=datetime.utcnow().isoformat(),
            duration=metadata.get("duration"),
            metadata=metadata,
            content_hash=content_hash,
            flags=[]
        )
        
        self.records[record.record_id] = record
        
        # Check selectors
        for selector in self.selectors.values():
            if selector["status"] != "ACTIVE":
                continue
            
            if self._matches_selector(record, selector):
                selector["hits"] += 1
                record.flags.append(f"SELECTOR_HIT:{selector['selector_id']}")
                self._record_intercept(record, selector)
        
        return record
    
    def _matches_selector(self, record: CommunicationRecord,
                         selector: Dict[str, Any]) -> bool:
        """Check if record matches selector"""
        selector_type = selector["type"]
        value = selector["value"].lower()
        
        if selector_type == "email":
            return value in record.source.lower() or value in record.destination.lower()
        elif selector_type == "phone":
            return value in record.source or value in record.destination
        elif selector_type == "keyword":
            return value in str(record.metadata).lower()
        
        return False
    
    def _record_intercept(self, record: CommunicationRecord,
                         selector: Dict[str, Any]) -> None:
        """Record intercept"""
        intercept = {
            "intercept_id": f"INT-{secrets.token_hex(8).upper()}",
            "record_id": record.record_id,
            "selector_id": selector["selector_id"],
            "timestamp": datetime.utcnow().isoformat()
        }
        self.intercepts.append(intercept)
    
    def analyze_communications(self, entity: str = None,
                              time_range: int = 86400) -> Dict[str, Any]:
        """Analyze communications"""
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "time_range_seconds": time_range,
            "total_records": 0,
            "by_type": defaultdict(int),
            "contacts": defaultdict(int),
            "patterns": []
        }
        
        cutoff = datetime.utcnow() - timedelta(seconds=time_range)
        
        for record in self.records.values():
            record_time = datetime.fromisoformat(record.timestamp)
            if record_time < cutoff:
                continue
            
            if entity:
                if entity not in record.source and entity not in record.destination:
                    continue
            
            analysis["total_records"] += 1
            analysis["by_type"][record.communication_type] += 1
            
            if entity:
                contact = record.destination if record.source == entity else record.source
                analysis["contacts"][contact] += 1
        
        return analysis


class TargetTrackingEngine:
    """Target tracking and management"""
    
    def __init__(self):
        self.targets: Dict[str, SurveillanceTarget] = {}
        self.tasks: Dict[str, CollectionTask] = {}
        self.location_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    def create_target(self, name: str, identifiers: Dict[str, List[str]],
                     priority: int = 1) -> SurveillanceTarget:
        """Create surveillance target"""
        target = SurveillanceTarget(
            target_id=f"TGT-{secrets.token_hex(8).upper()}",
            name=name,
            identifiers=identifiers,
            status=TargetStatus.ACTIVE,
            priority=priority,
            surveillance_types=[],
            collection_methods=[],
            data_collected={},
            first_observed=datetime.utcnow().isoformat(),
            last_activity=datetime.utcnow().isoformat(),
            notes=[]
        )
        
        self.targets[target.target_id] = target
        return target
    
    def update_target_status(self, target_id: str, status: TargetStatus) -> SurveillanceTarget:
        """Update target status"""
        if target_id not in self.targets:
            raise ValueError(f"Target not found: {target_id}")
        
        target = self.targets[target_id]
        target.status = status
        target.last_activity = datetime.utcnow().isoformat()
        
        return target
    
    def add_identifier(self, target_id: str, identifier_type: str,
                      value: str) -> SurveillanceTarget:
        """Add identifier to target"""
        if target_id not in self.targets:
            raise ValueError(f"Target not found: {target_id}")
        
        target = self.targets[target_id]
        
        if identifier_type not in target.identifiers:
            target.identifiers[identifier_type] = []
        
        if value not in target.identifiers[identifier_type]:
            target.identifiers[identifier_type].append(value)
        
        target.last_activity = datetime.utcnow().isoformat()
        
        return target
    
    def record_location(self, target_id: str, latitude: float,
                       longitude: float, accuracy: float,
                       source: str) -> Dict[str, Any]:
        """Record target location"""
        location = {
            "location_id": f"LOC-{secrets.token_hex(8).upper()}",
            "target_id": target_id,
            "latitude": latitude,
            "longitude": longitude,
            "accuracy": accuracy,
            "source": source,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.location_history[target_id].append(location)
        
        if target_id in self.targets:
            self.targets[target_id].last_activity = datetime.utcnow().isoformat()
        
        return location
    
    def create_collection_task(self, target_id: str,
                              surveillance_type: SurveillanceType,
                              collection_method: CollectionMethod,
                              data_types: List[DataType]) -> CollectionTask:
        """Create collection task"""
        task = CollectionTask(
            task_id=f"TSK-{secrets.token_hex(8).upper()}",
            target_id=target_id,
            surveillance_type=surveillance_type,
            collection_method=collection_method,
            data_types=data_types,
            start_time=datetime.utcnow().isoformat(),
            end_time=None,
            status="ACTIVE",
            results_count=0
        )
        
        self.tasks[task.task_id] = task
        
        if target_id in self.targets:
            target = self.targets[target_id]
            if surveillance_type not in target.surveillance_types:
                target.surveillance_types.append(surveillance_type)
            if collection_method not in target.collection_methods:
                target.collection_methods.append(collection_method)
        
        return task
    
    def get_target_profile(self, target_id: str) -> Dict[str, Any]:
        """Get comprehensive target profile"""
        if target_id not in self.targets:
            return {"error": "Target not found"}
        
        target = self.targets[target_id]
        locations = self.location_history.get(target_id, [])
        tasks = [t for t in self.tasks.values() if t.target_id == target_id]
        
        profile = {
            "target": asdict(target),
            "location_count": len(locations),
            "last_known_location": locations[-1] if locations else None,
            "active_tasks": len([t for t in tasks if t.status == "ACTIVE"]),
            "total_tasks": len(tasks)
        }
        
        return profile


class PatternAnalysisEngine:
    """Pattern analysis for surveillance data"""
    
    def __init__(self):
        self.patterns: Dict[str, Dict[str, Any]] = {}
        self.anomalies: List[Dict[str, Any]] = []
    
    def analyze_behavior_pattern(self, target_id: str,
                                data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze behavioral patterns"""
        pattern = {
            "pattern_id": f"PAT-{secrets.token_hex(8).upper()}",
            "target_id": target_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data_points": len(data),
            "temporal_patterns": self._analyze_temporal(data),
            "location_patterns": self._analyze_locations(data),
            "communication_patterns": self._analyze_communications(data),
            "anomalies_detected": []
        }
        
        self.patterns[pattern["pattern_id"]] = pattern
        return pattern
    
    def _analyze_temporal(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal patterns"""
        hourly_activity = defaultdict(int)
        daily_activity = defaultdict(int)
        
        for item in data:
            timestamp = item.get("timestamp")
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    hourly_activity[dt.hour] += 1
                    daily_activity[dt.strftime("%A")] += 1
                except ValueError as e:
                    logger.debug(f"Failed to parse timestamp {timestamp}: {e}")
        
        return {
            "hourly_distribution": dict(hourly_activity),
            "daily_distribution": dict(daily_activity),
            "peak_hours": sorted(hourly_activity.keys(), 
                               key=lambda x: hourly_activity[x], reverse=True)[:3]
        }
    
    def _analyze_locations(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze location patterns"""
        locations = [d for d in data if "latitude" in d and "longitude" in d]
        
        if not locations:
            return {"location_count": 0}
        
        return {
            "location_count": len(locations),
            "unique_locations": len(set((l["latitude"], l["longitude"]) for l in locations)),
            "most_frequent": None  # Would calculate most frequent location
        }
    
    def _analyze_communications(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze communication patterns"""
        contacts = defaultdict(int)
        
        for item in data:
            if "destination" in item:
                contacts[item["destination"]] += 1
            if "source" in item:
                contacts[item["source"]] += 1
        
        return {
            "unique_contacts": len(contacts),
            "top_contacts": sorted(contacts.items(), key=lambda x: x[1], reverse=True)[:5]
        }
    
    def detect_anomaly(self, target_id: str, current_data: Dict[str, Any],
                      baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect anomalies in behavior"""
        anomaly = None
        
        # Simple anomaly detection
        if "location" in current_data and "typical_locations" in baseline:
            current_loc = (current_data["location"]["latitude"],
                         current_data["location"]["longitude"])
            if current_loc not in baseline["typical_locations"]:
                anomaly = {
                    "anomaly_id": f"ANO-{secrets.token_hex(8).upper()}",
                    "target_id": target_id,
                    "type": "LOCATION_ANOMALY",
                    "description": "Target at unusual location",
                    "data": current_data,
                    "timestamp": datetime.utcnow().isoformat()
                }
        
        if anomaly:
            self.anomalies.append(anomaly)
        
        return anomaly


class SurveillanceEngine:
    """Main surveillance engine"""
    
    def __init__(self):
        self.network = NetworkSurveillanceEngine()
        self.communications = CommunicationsMonitoringEngine()
        self.tracking = TargetTrackingEngine()
        self.patterns = PatternAnalysisEngine()
    
    def create_target(self, name: str, identifiers: Dict[str, List[str]],
                     priority: int = 1) -> SurveillanceTarget:
        """Create surveillance target"""
        return self.tracking.create_target(name, identifiers, priority)
    
    def add_selector(self, selector_type: str, value: str) -> Dict[str, Any]:
        """Add communication selector"""
        return self.communications.add_selector(selector_type, value)
    
    def add_network_watch(self, entity_type: str, value: str) -> Dict[str, Any]:
        """Add network watch"""
        return self.network.add_watch(entity_type, value)
    
    def get_surveillance_status(self) -> Dict[str, Any]:
        """Get surveillance status"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "active_targets": len([t for t in self.tracking.targets.values() 
                                  if t.status == TargetStatus.ACTIVE]),
            "total_targets": len(self.tracking.targets),
            "active_selectors": len([s for s in self.communications.selectors.values()
                                    if s["status"] == "ACTIVE"]),
            "network_sessions": len(self.network.sessions),
            "communication_records": len(self.communications.records),
            "intercepts": len(self.communications.intercepts),
            "alerts": len(self.network.alerts),
            "patterns_analyzed": len(self.patterns.patterns),
            "anomalies_detected": len(self.patterns.anomalies)
        }


# Import for Set type hint
from typing import Set

# Factory function for API use
def create_surveillance_engine() -> SurveillanceEngine:
    """Create surveillance engine instance"""
    return SurveillanceEngine()
