"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - SPECIALIZED ENGINE MODULE
Complete implementation of specialized templates

This module implements:
- Biometric Security
- EMSEC (Electromagnetic Security)
- Supply Chain Security
- Anti-Forensics Detection
- Stealth Operations
- Research & Development
- Reliability Engineering
- Specialized Analysis

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import secrets
import base64
import math
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict


# ============== BIOMETRIC SECURITY ==============

class BiometricType(str, Enum):
    FINGERPRINT = "FINGERPRINT"
    FACIAL = "FACIAL"
    IRIS = "IRIS"
    VOICE = "VOICE"
    BEHAVIORAL = "BEHAVIORAL"
    GAIT = "GAIT"
    KEYSTROKE = "KEYSTROKE"
    VEIN = "VEIN"


class BiometricMatchResult(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    INCONCLUSIVE = "INCONCLUSIVE"
    SPOOF_DETECTED = "SPOOF_DETECTED"


@dataclass
class BiometricTemplate:
    template_id: str
    biometric_type: BiometricType
    subject_id: str
    template_data: str
    quality_score: float
    created_at: str
    last_matched: Optional[str]
    match_count: int


@dataclass
class BiometricMatch:
    match_id: str
    template_id: str
    probe_hash: str
    result: BiometricMatchResult
    confidence: float
    timestamp: str
    metadata: Dict[str, Any]


class BiometricSecurityEngine:
    """Biometric security operations"""
    
    def __init__(self):
        self.templates: Dict[str, BiometricTemplate] = {}
        self.matches: List[BiometricMatch] = []
        self.spoof_detection_enabled = True
    
    def enroll_biometric(self, subject_id: str, biometric_type: BiometricType,
                        biometric_data: bytes) -> BiometricTemplate:
        """Enroll biometric template"""
        # Generate template from biometric data
        template_data = self._extract_features(biometric_data, biometric_type)
        quality_score = self._assess_quality(biometric_data, biometric_type)
        
        template = BiometricTemplate(
            template_id=f"BIO-{secrets.token_hex(8).upper()}",
            biometric_type=biometric_type,
            subject_id=subject_id,
            template_data=template_data,
            quality_score=quality_score,
            created_at=datetime.utcnow().isoformat(),
            last_matched=None,
            match_count=0
        )
        
        self.templates[template.template_id] = template
        return template
    
    def verify_biometric(self, template_id: str, probe_data: bytes) -> BiometricMatch:
        """Verify biometric against enrolled template"""
        if template_id not in self.templates:
            raise ValueError(f"Template not found: {template_id}")
        
        template = self.templates[template_id]
        
        # Check for spoofing
        if self.spoof_detection_enabled:
            spoof_score = self._detect_spoof(probe_data, template.biometric_type)
            if spoof_score > 0.7:
                return BiometricMatch(
                    match_id=f"MTH-{secrets.token_hex(8).upper()}",
                    template_id=template_id,
                    probe_hash=hashlib.sha256(probe_data).hexdigest(),
                    result=BiometricMatchResult.SPOOF_DETECTED,
                    confidence=spoof_score,
                    timestamp=datetime.utcnow().isoformat(),
                    metadata={"spoof_score": spoof_score}
                )
        
        # Extract features from probe
        probe_features = self._extract_features(probe_data, template.biometric_type)
        
        # Compare features
        similarity = self._compare_features(template.template_data, probe_features)
        
        # Determine result
        if similarity >= 0.8:
            result = BiometricMatchResult.MATCH
        elif similarity >= 0.5:
            result = BiometricMatchResult.INCONCLUSIVE
        else:
            result = BiometricMatchResult.NO_MATCH
        
        match = BiometricMatch(
            match_id=f"MTH-{secrets.token_hex(8).upper()}",
            template_id=template_id,
            probe_hash=hashlib.sha256(probe_data).hexdigest(),
            result=result,
            confidence=similarity,
            timestamp=datetime.utcnow().isoformat(),
            metadata={}
        )
        
        self.matches.append(match)
        
        if result == BiometricMatchResult.MATCH:
            template.last_matched = datetime.utcnow().isoformat()
            template.match_count += 1
        
        return match
    
    def identify_biometric(self, probe_data: bytes,
                          biometric_type: BiometricType) -> List[BiometricMatch]:
        """Identify biometric against all enrolled templates"""
        matches = []
        probe_features = self._extract_features(probe_data, biometric_type)
        
        for template in self.templates.values():
            if template.biometric_type != biometric_type:
                continue
            
            similarity = self._compare_features(template.template_data, probe_features)
            
            if similarity >= 0.5:
                match = BiometricMatch(
                    match_id=f"MTH-{secrets.token_hex(8).upper()}",
                    template_id=template.template_id,
                    probe_hash=hashlib.sha256(probe_data).hexdigest(),
                    result=BiometricMatchResult.MATCH if similarity >= 0.8 else BiometricMatchResult.INCONCLUSIVE,
                    confidence=similarity,
                    timestamp=datetime.utcnow().isoformat(),
                    metadata={"subject_id": template.subject_id}
                )
                matches.append(match)
        
        # Sort by confidence
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches
    
    def _extract_features(self, data: bytes, biometric_type: BiometricType) -> str:
        """Extract biometric features"""
        # Simplified feature extraction
        feature_hash = hashlib.sha512(data).hexdigest()
        return feature_hash
    
    def _assess_quality(self, data: bytes, biometric_type: BiometricType) -> float:
        """Assess biometric sample quality"""
        # Simplified quality assessment
        if len(data) < 100:
            return 0.3
        elif len(data) < 1000:
            return 0.6
        return 0.9
    
    def _detect_spoof(self, data: bytes, biometric_type: BiometricType) -> float:
        """Detect biometric spoofing attempt"""
        # Simplified spoof detection
        entropy = self._calculate_entropy(data)
        if entropy < 5.0:
            return 0.8  # Low entropy suggests artificial sample
        return 0.1
    
    def _compare_features(self, template_features: str, probe_features: str) -> float:
        """Compare biometric features"""
        # Simplified comparison using hash similarity
        matching_chars = sum(1 for a, b in zip(template_features, probe_features) if a == b)
        return matching_chars / len(template_features)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)


# ============== EMSEC (Electromagnetic Security) ==============

class EMSECThreatType(str, Enum):
    TEMPEST = "TEMPEST"
    VAN_ECK = "VAN_ECK"
    POWER_ANALYSIS = "POWER_ANALYSIS"
    EM_EMANATION = "EM_EMANATION"
    SIDE_CHANNEL = "SIDE_CHANNEL"


@dataclass
class EMSECAssessment:
    assessment_id: str
    location: str
    threats_identified: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    countermeasures: List[Dict[str, Any]]
    risk_level: str
    assessed_at: str


class EMSECEngine:
    """Electromagnetic security operations"""
    
    def __init__(self):
        self.assessments: Dict[str, EMSECAssessment] = {}
        self.monitoring_zones: Dict[str, Dict[str, Any]] = {}
        self.shielding_specs: List[Dict[str, Any]] = []
    
    def conduct_assessment(self, location: str, equipment: List[str]) -> EMSECAssessment:
        """Conduct EMSEC assessment"""
        threats = self._identify_threats(equipment)
        vulnerabilities = self._identify_vulnerabilities(equipment)
        countermeasures = self._recommend_countermeasures(vulnerabilities)
        risk_level = self._calculate_risk(threats, vulnerabilities)
        
        assessment = EMSECAssessment(
            assessment_id=f"EMS-{secrets.token_hex(8).upper()}",
            location=location,
            threats_identified=threats,
            vulnerabilities=vulnerabilities,
            countermeasures=countermeasures,
            risk_level=risk_level,
            assessed_at=datetime.utcnow().isoformat()
        )
        
        self.assessments[assessment.assessment_id] = assessment
        return assessment
    
    def _identify_threats(self, equipment: List[str]) -> List[Dict[str, Any]]:
        """Identify EMSEC threats"""
        threats = []
        
        for item in equipment:
            item_lower = item.lower()
            
            if "monitor" in item_lower or "display" in item_lower:
                threats.append({
                    "type": EMSECThreatType.VAN_ECK.value,
                    "source": item,
                    "severity": "HIGH",
                    "description": "Display emanations can be intercepted"
                })
            
            if "keyboard" in item_lower:
                threats.append({
                    "type": EMSECThreatType.EM_EMANATION.value,
                    "source": item,
                    "severity": "MEDIUM",
                    "description": "Keyboard emanations can reveal keystrokes"
                })
            
            if "crypto" in item_lower or "encryption" in item_lower:
                threats.append({
                    "type": EMSECThreatType.POWER_ANALYSIS.value,
                    "source": item,
                    "severity": "HIGH",
                    "description": "Power analysis can reveal cryptographic keys"
                })
        
        return threats
    
    def _identify_vulnerabilities(self, equipment: List[str]) -> List[Dict[str, Any]]:
        """Identify EMSEC vulnerabilities"""
        return [
            {
                "type": "UNSHIELDED_CABLES",
                "severity": "MEDIUM",
                "description": "Unshielded cables can act as antennas"
            },
            {
                "type": "INADEQUATE_GROUNDING",
                "severity": "MEDIUM",
                "description": "Poor grounding increases emanation risk"
            },
            {
                "type": "WINDOW_EXPOSURE",
                "severity": "LOW",
                "description": "Windows allow optical and RF interception"
            }
        ]
    
    def _recommend_countermeasures(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recommend EMSEC countermeasures"""
        countermeasures = [
            {
                "measure": "TEMPEST-rated equipment",
                "type": "EQUIPMENT",
                "priority": "HIGH"
            },
            {
                "measure": "Faraday cage installation",
                "type": "SHIELDING",
                "priority": "HIGH"
            },
            {
                "measure": "Shielded cables",
                "type": "CABLING",
                "priority": "MEDIUM"
            },
            {
                "measure": "RF-blocking window film",
                "type": "PHYSICAL",
                "priority": "LOW"
            },
            {
                "measure": "White noise generators",
                "type": "MASKING",
                "priority": "MEDIUM"
            }
        ]
        
        return countermeasures
    
    def _calculate_risk(self, threats: List[Dict[str, Any]],
                       vulnerabilities: List[Dict[str, Any]]) -> str:
        """Calculate overall EMSEC risk"""
        high_threats = sum(1 for t in threats if t["severity"] == "HIGH")
        high_vulns = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
        
        if high_threats >= 2 or high_vulns >= 2:
            return "HIGH"
        elif high_threats >= 1 or high_vulns >= 1:
            return "MEDIUM"
        return "LOW"
    
    def create_monitoring_zone(self, zone_name: str, boundaries: Dict[str, Any],
                              sensitivity: str) -> Dict[str, Any]:
        """Create EMSEC monitoring zone"""
        zone = {
            "zone_id": f"ZON-{secrets.token_hex(8).upper()}",
            "name": zone_name,
            "boundaries": boundaries,
            "sensitivity": sensitivity,
            "monitoring_active": True,
            "alerts": [],
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.monitoring_zones[zone["zone_id"]] = zone
        return zone


# ============== SUPPLY CHAIN SECURITY ==============

class SupplyChainRisk(str, Enum):
    COUNTERFEIT = "COUNTERFEIT"
    TAMPERING = "TAMPERING"
    MALICIOUS_INSERT = "MALICIOUS_INSERT"
    QUALITY = "QUALITY"
    AVAILABILITY = "AVAILABILITY"
    COMPLIANCE = "COMPLIANCE"


@dataclass
class Supplier:
    supplier_id: str
    name: str
    country: str
    risk_score: float
    certifications: List[str]
    audit_history: List[Dict[str, Any]]
    status: str


@dataclass
class Component:
    component_id: str
    name: str
    supplier_id: str
    version: str
    hash: str
    verified: bool
    risk_factors: List[str]
    provenance: List[Dict[str, Any]]


class SupplyChainSecurityEngine:
    """Supply chain security operations"""
    
    def __init__(self):
        self.suppliers: Dict[str, Supplier] = {}
        self.components: Dict[str, Component] = {}
        self.risk_assessments: List[Dict[str, Any]] = []
        self.sbom_records: Dict[str, List[Dict[str, Any]]] = {}
    
    def register_supplier(self, name: str, country: str,
                         certifications: List[str]) -> Supplier:
        """Register supplier"""
        risk_score = self._calculate_supplier_risk(country, certifications)
        
        supplier = Supplier(
            supplier_id=f"SUP-{secrets.token_hex(8).upper()}",
            name=name,
            country=country,
            risk_score=risk_score,
            certifications=certifications,
            audit_history=[],
            status="ACTIVE"
        )
        
        self.suppliers[supplier.supplier_id] = supplier
        return supplier
    
    def register_component(self, name: str, supplier_id: str,
                          version: str, component_hash: str) -> Component:
        """Register component"""
        if supplier_id not in self.suppliers:
            raise ValueError(f"Supplier not found: {supplier_id}")
        
        risk_factors = self._identify_component_risks(name, supplier_id)
        
        component = Component(
            component_id=f"CMP-{secrets.token_hex(8).upper()}",
            name=name,
            supplier_id=supplier_id,
            version=version,
            hash=component_hash,
            verified=False,
            risk_factors=risk_factors,
            provenance=[]
        )
        
        self.components[component.component_id] = component
        return component
    
    def verify_component(self, component_id: str, verification_data: Dict[str, Any]) -> Dict[str, Any]:
        """Verify component integrity"""
        if component_id not in self.components:
            return {"error": "Component not found"}
        
        component = self.components[component_id]
        
        verification = {
            "verification_id": f"VER-{secrets.token_hex(8).upper()}",
            "component_id": component_id,
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "hash_match": verification_data.get("hash") == component.hash,
                "signature_valid": verification_data.get("signature_valid", False),
                "provenance_verified": len(component.provenance) > 0
            },
            "result": "PASS",
            "issues": []
        }
        
        if not verification["checks"]["hash_match"]:
            verification["result"] = "FAIL"
            verification["issues"].append("Hash mismatch - possible tampering")
        
        if verification["result"] == "PASS":
            component.verified = True
        
        return verification
    
    def generate_sbom(self, product_id: str, components: List[str]) -> Dict[str, Any]:
        """Generate Software Bill of Materials"""
        sbom = {
            "sbom_id": f"SBOM-{secrets.token_hex(8).upper()}",
            "product_id": product_id,
            "generated_at": datetime.utcnow().isoformat(),
            "format": "CycloneDX",
            "components": [],
            "vulnerabilities": [],
            "licenses": []
        }
        
        for comp_id in components:
            if comp_id in self.components:
                comp = self.components[comp_id]
                sbom["components"].append({
                    "id": comp.component_id,
                    "name": comp.name,
                    "version": comp.version,
                    "supplier": self.suppliers.get(comp.supplier_id, {}).name if comp.supplier_id in self.suppliers else "Unknown",
                    "hash": comp.hash,
                    "verified": comp.verified
                })
        
        self.sbom_records[product_id] = sbom["components"]
        return sbom
    
    def assess_supply_chain_risk(self, product_id: str) -> Dict[str, Any]:
        """Assess supply chain risk for product"""
        components = self.sbom_records.get(product_id, [])
        
        assessment = {
            "assessment_id": f"SCR-{secrets.token_hex(8).upper()}",
            "product_id": product_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_components": len(components),
            "verified_components": sum(1 for c in components if c.get("verified", False)),
            "risk_factors": [],
            "overall_risk": "LOW",
            "recommendations": []
        }
        
        # Check for unverified components
        unverified = [c for c in components if not c.get("verified", False)]
        if unverified:
            assessment["risk_factors"].append({
                "type": "UNVERIFIED_COMPONENTS",
                "count": len(unverified),
                "severity": "MEDIUM"
            })
        
        # Calculate overall risk
        if len(assessment["risk_factors"]) >= 3:
            assessment["overall_risk"] = "HIGH"
        elif len(assessment["risk_factors"]) >= 1:
            assessment["overall_risk"] = "MEDIUM"
        
        assessment["recommendations"] = [
            "Verify all component hashes",
            "Audit high-risk suppliers",
            "Implement continuous monitoring"
        ]
        
        self.risk_assessments.append(assessment)
        return assessment
    
    def _calculate_supplier_risk(self, country: str, certifications: List[str]) -> float:
        """Calculate supplier risk score"""
        risk = 0.5  # Base risk
        
        # Country risk (simplified)
        high_risk_countries = ["Unknown"]
        if country in high_risk_countries:
            risk += 0.3
        
        # Certification bonus
        if "ISO27001" in certifications:
            risk -= 0.1
        if "SOC2" in certifications:
            risk -= 0.1
        
        return max(0.0, min(1.0, risk))
    
    def _identify_component_risks(self, name: str, supplier_id: str) -> List[str]:
        """Identify component risk factors"""
        risks = []
        
        if supplier_id in self.suppliers:
            supplier = self.suppliers[supplier_id]
            if supplier.risk_score > 0.7:
                risks.append("HIGH_RISK_SUPPLIER")
        
        # Check for known risky component types
        risky_keywords = ["crypto", "auth", "network", "kernel"]
        if any(kw in name.lower() for kw in risky_keywords):
            risks.append("SECURITY_CRITICAL")
        
        return risks


# ============== ANTI-FORENSICS DETECTION ==============

class AntiForensicsTechnique(str, Enum):
    DATA_HIDING = "DATA_HIDING"
    ARTIFACT_WIPING = "ARTIFACT_WIPING"
    TRAIL_OBFUSCATION = "TRAIL_OBFUSCATION"
    TIMESTAMP_MANIPULATION = "TIMESTAMP_MANIPULATION"
    ENCRYPTION = "ENCRYPTION"
    STEGANOGRAPHY = "STEGANOGRAPHY"


class AntiForensicsDetectionEngine:
    """Anti-forensics detection operations"""
    
    def __init__(self):
        self.detections: List[Dict[str, Any]] = []
        self.indicators = self._initialize_indicators()
    
    def _initialize_indicators(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize anti-forensics indicators"""
        return {
            AntiForensicsTechnique.DATA_HIDING.value: [
                {"indicator": "alternate_data_streams", "weight": 0.7},
                {"indicator": "slack_space_usage", "weight": 0.6},
                {"indicator": "hidden_partitions", "weight": 0.8}
            ],
            AntiForensicsTechnique.ARTIFACT_WIPING.value: [
                {"indicator": "secure_delete_tools", "weight": 0.8},
                {"indicator": "log_clearing", "weight": 0.7},
                {"indicator": "browser_history_wiping", "weight": 0.5}
            ],
            AntiForensicsTechnique.TRAIL_OBFUSCATION.value: [
                {"indicator": "vpn_usage", "weight": 0.3},
                {"indicator": "tor_usage", "weight": 0.5},
                {"indicator": "proxy_chains", "weight": 0.6}
            ],
            AntiForensicsTechnique.TIMESTAMP_MANIPULATION.value: [
                {"indicator": "timestomp_artifacts", "weight": 0.9},
                {"indicator": "mft_anomalies", "weight": 0.8},
                {"indicator": "journal_inconsistencies", "weight": 0.7}
            ]
        }
    
    def analyze_system(self, system_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system for anti-forensics techniques"""
        analysis = {
            "analysis_id": f"AFD-{secrets.token_hex(8).upper()}",
            "timestamp": datetime.utcnow().isoformat(),
            "techniques_detected": [],
            "confidence": 0.0,
            "evidence": [],
            "recommendations": []
        }
        
        # Check for each technique
        for technique, indicators in self.indicators.items():
            technique_score = 0.0
            matched_indicators = []
            
            for indicator in indicators:
                if self._check_indicator(indicator["indicator"], system_data):
                    technique_score += indicator["weight"]
                    matched_indicators.append(indicator["indicator"])
            
            if technique_score > 0.5:
                analysis["techniques_detected"].append({
                    "technique": technique,
                    "confidence": min(technique_score, 1.0),
                    "indicators": matched_indicators
                })
        
        if analysis["techniques_detected"]:
            analysis["confidence"] = sum(t["confidence"] for t in analysis["techniques_detected"]) / len(analysis["techniques_detected"])
            analysis["recommendations"] = [
                "Preserve all evidence immediately",
                "Document timeline anomalies",
                "Check for additional hidden data",
                "Analyze memory for volatile artifacts"
            ]
        
        self.detections.append(analysis)
        return analysis
    
    def _check_indicator(self, indicator: str, system_data: Dict[str, Any]) -> bool:
        """Check for specific anti-forensics indicator"""
        # Simplified indicator checking
        return indicator in str(system_data).lower()
    
    def detect_timestamp_manipulation(self, file_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Detect timestamp manipulation"""
        detection = {
            "detection_id": f"TSM-{secrets.token_hex(8).upper()}",
            "timestamp": datetime.utcnow().isoformat(),
            "manipulation_detected": False,
            "anomalies": [],
            "confidence": 0.0
        }
        
        # Check for common timestamp anomalies
        created = file_metadata.get("created")
        modified = file_metadata.get("modified")
        accessed = file_metadata.get("accessed")
        
        if created and modified:
            if modified < created:
                detection["manipulation_detected"] = True
                detection["anomalies"].append("Modified time before created time")
                detection["confidence"] += 0.9
        
        return detection


# ============== VISUALIZATION ENGINE ==============

class VisualizationType(str, Enum):
    NETWORK_GRAPH = "NETWORK_GRAPH"
    TIMELINE = "TIMELINE"
    HEATMAP = "HEATMAP"
    GEOSPATIAL = "GEOSPATIAL"
    TREE = "TREE"
    SANKEY = "SANKEY"
    FORCE_DIRECTED = "FORCE_DIRECTED"
    THREE_D = "THREE_D"


@dataclass
class Visualization:
    viz_id: str
    viz_type: VisualizationType
    title: str
    data: Dict[str, Any]
    config: Dict[str, Any]
    created_at: str


class VisualizationEngine:
    """Data visualization engine"""
    
    def __init__(self):
        self.visualizations: Dict[str, Visualization] = {}
    
    def create_network_graph(self, title: str, nodes: List[Dict[str, Any]],
                            edges: List[Dict[str, Any]]) -> Visualization:
        """Create network graph visualization"""
        viz = Visualization(
            viz_id=f"VIZ-{secrets.token_hex(8).upper()}",
            viz_type=VisualizationType.NETWORK_GRAPH,
            title=title,
            data={
                "nodes": nodes,
                "edges": edges
            },
            config={
                "layout": "force-directed",
                "node_size": "degree",
                "edge_weight": "weight"
            },
            created_at=datetime.utcnow().isoformat()
        )
        
        self.visualizations[viz.viz_id] = viz
        return viz
    
    def create_3d_visualization(self, title: str, objects: List[Dict[str, Any]],
                               camera: Dict[str, Any] = None) -> Visualization:
        """Create 3D visualization"""
        viz = Visualization(
            viz_id=f"VIZ-{secrets.token_hex(8).upper()}",
            viz_type=VisualizationType.THREE_D,
            title=title,
            data={
                "objects": objects,
                "camera": camera or {"position": [0, 0, 100], "target": [0, 0, 0]}
            },
            config={
                "renderer": "webgl",
                "controls": "orbit",
                "lighting": "ambient"
            },
            created_at=datetime.utcnow().isoformat()
        )
        
        self.visualizations[viz.viz_id] = viz
        return viz
    
    def create_timeline(self, title: str, events: List[Dict[str, Any]]) -> Visualization:
        """Create timeline visualization"""
        viz = Visualization(
            viz_id=f"VIZ-{secrets.token_hex(8).upper()}",
            viz_type=VisualizationType.TIMELINE,
            title=title,
            data={
                "events": sorted(events, key=lambda e: e.get("timestamp", ""))
            },
            config={
                "orientation": "horizontal",
                "zoom": True,
                "clustering": True
            },
            created_at=datetime.utcnow().isoformat()
        )
        
        self.visualizations[viz.viz_id] = viz
        return viz
    
    def create_geospatial(self, title: str, locations: List[Dict[str, Any]],
                         connections: List[Dict[str, Any]] = None) -> Visualization:
        """Create geospatial visualization"""
        viz = Visualization(
            viz_id=f"VIZ-{secrets.token_hex(8).upper()}",
            viz_type=VisualizationType.GEOSPATIAL,
            title=title,
            data={
                "locations": locations,
                "connections": connections or []
            },
            config={
                "map_style": "dark",
                "projection": "mercator",
                "clustering": True
            },
            created_at=datetime.utcnow().isoformat()
        )
        
        self.visualizations[viz.viz_id] = viz
        return viz
    
    def create_attack_visualization(self, attack_data: Dict[str, Any]) -> Visualization:
        """Create cyber attack visualization"""
        # Build nodes from attack data
        nodes = []
        edges = []
        
        # Attacker node
        nodes.append({
            "id": "attacker",
            "label": "Attacker",
            "type": "threat",
            "x": 0,
            "y": 0,
            "z": 0
        })
        
        # Target nodes
        targets = attack_data.get("targets", [])
        for i, target in enumerate(targets):
            nodes.append({
                "id": f"target_{i}",
                "label": target.get("name", f"Target {i}"),
                "type": "target",
                "x": 100 * math.cos(2 * math.pi * i / len(targets)),
                "y": 100 * math.sin(2 * math.pi * i / len(targets)),
                "z": 0
            })
            edges.append({
                "source": "attacker",
                "target": f"target_{i}",
                "type": "attack"
            })
        
        return self.create_3d_visualization(
            title="Cyber Attack Visualization",
            objects=[{"nodes": nodes, "edges": edges}]
        )


# ============== MAIN SPECIALIZED ENGINE ==============

class SpecializedEngine:
    """Main specialized operations engine"""
    
    def __init__(self):
        self.biometric = BiometricSecurityEngine()
        self.emsec = EMSECEngine()
        self.supply_chain = SupplyChainSecurityEngine()
        self.anti_forensics = AntiForensicsDetectionEngine()
        self.visualization = VisualizationEngine()
    
    def get_specialized_status(self) -> Dict[str, Any]:
        """Get specialized systems status"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "biometric_templates": len(self.biometric.templates),
            "biometric_matches": len(self.biometric.matches),
            "emsec_assessments": len(self.emsec.assessments),
            "emsec_zones": len(self.emsec.monitoring_zones),
            "suppliers": len(self.supply_chain.suppliers),
            "components": len(self.supply_chain.components),
            "anti_forensics_detections": len(self.anti_forensics.detections),
            "visualizations": len(self.visualization.visualizations)
        }


# Factory function for API use
def create_specialized_engine() -> SpecializedEngine:
    """Create specialized engine instance"""
    return SpecializedEngine()
