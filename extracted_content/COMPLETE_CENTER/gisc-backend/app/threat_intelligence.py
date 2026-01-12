"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - THREAT INTELLIGENCE MODULE
Enterprise-grade threat intelligence integrations with external feeds

This module implements:
- VirusTotal API integration for malware analysis
- Shodan API integration for internet-wide scanning
- AlienVault OTX integration for threat indicators
- MISP integration for threat sharing
- Have I Been Pwned API integration
- Abuse.ch feeds integration
- Real-time threat feed aggregation

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import json
import hashlib
import logging
import time
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from concurrent.futures import ThreadPoolExecutor

import requests
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
ALIENVAULT_OTX_API_KEY = os.environ.get("ALIENVAULT_OTX_API_KEY", "")
MISP_URL = os.environ.get("MISP_URL", "")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")


class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    APT = "apt"
    EXPLOIT = "exploit"
    VULNERABILITY = "vulnerability"
    INDICATOR = "indicator"
    CAMPAIGN = "campaign"


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    YARA = "yara"


@dataclass
class ThreatIndicator:
    indicator_type: IndicatorType
    value: str
    source: str
    confidence: float
    severity: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    related_indicators: List[str] = field(default_factory=list)


@dataclass
class ThreatReport:
    report_id: str
    title: str
    threat_type: ThreatType
    severity: str
    confidence: float
    source: str
    indicators: List[ThreatIndicator]
    description: str
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json"
        })
        self._rate_limit_remaining = 4
        self._rate_limit_reset = time.time()
    
    def _check_rate_limit(self):
        if self._rate_limit_remaining <= 0:
            wait_time = self._rate_limit_reset - time.time()
            if wait_time > 0:
                time.sleep(wait_time)
            self._rate_limit_remaining = 4
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        if not self.api_key:
            raise ValueError("VirusTotal API key not configured")
        
        self._check_rate_limit()
        
        url = f"{self.BASE_URL}/{endpoint}"
        response = self.session.request(method, url, **kwargs)
        
        self._rate_limit_remaining = int(response.headers.get("x-api-quota-remaining", 4))
        
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            self._rate_limit_reset = time.time() + retry_after
            raise Exception(f"Rate limited. Retry after {retry_after} seconds")
        
        response.raise_for_status()
        return response.json()
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        result = self._make_request("GET", f"files/{file_hash}")
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        return {
            "hash": file_hash,
            "type": attributes.get("type_description", "unknown"),
            "size": attributes.get("size", 0),
            "names": attributes.get("names", []),
            "first_submission": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()),
            "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "tags": attributes.get("tags", []),
            "signature_info": attributes.get("signature_info", {}),
            "sandbox_verdicts": attributes.get("sandbox_verdicts", {}),
            "popular_threat_classification": attributes.get("popular_threat_classification", {}),
        }
    
    def get_url_report(self, url: str) -> Dict[str, Any]:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        result = self._make_request("GET", f"urls/{url_id}")
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        return {
            "url": url,
            "final_url": attributes.get("last_final_url", url),
            "title": attributes.get("title", ""),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "trackers": attributes.get("trackers", {}),
        }
    
    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        result = self._make_request("GET", f"domains/{domain}")
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        return {
            "domain": domain,
            "registrar": attributes.get("registrar", ""),
            "creation_date": attributes.get("creation_date"),
            "last_update_date": attributes.get("last_update_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "categories": attributes.get("categories", {}),
            "popularity_ranks": attributes.get("popularity_ranks", {}),
            "whois": attributes.get("whois", ""),
            "dns_records": attributes.get("last_dns_records", []),
        }
    
    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        result = self._make_request("GET", f"ip_addresses/{ip}")
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        return {
            "ip": ip,
            "asn": attributes.get("asn", 0),
            "as_owner": attributes.get("as_owner", ""),
            "country": attributes.get("country", ""),
            "continent": attributes.get("continent", ""),
            "network": attributes.get("network", ""),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "whois": attributes.get("whois", ""),
            "tags": attributes.get("tags", []),
        }
    
    def submit_file(self, file_content: bytes, filename: str = "sample") -> Dict[str, Any]:
        files = {"file": (filename, file_content)}
        result = self._make_request("POST", "files", files=files)
        
        return {
            "analysis_id": result.get("data", {}).get("id"),
            "type": result.get("data", {}).get("type"),
        }
    
    def submit_url(self, url: str) -> Dict[str, Any]:
        result = self._make_request("POST", "urls", data={"url": url})
        
        return {
            "analysis_id": result.get("data", {}).get("id"),
            "type": result.get("data", {}).get("type"),
        }
    
    def get_analysis(self, analysis_id: str) -> Dict[str, Any]:
        result = self._make_request("GET", f"analyses/{analysis_id}")
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "status": attributes.get("status"),
            "stats": attributes.get("stats", {}),
            "results": attributes.get("results", {}),
        }


class ShodanClient:
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or SHODAN_API_KEY
        self.session = requests.Session()
    
    def _make_request(self, endpoint: str, params: Dict = None) -> Dict[str, Any]:
        if not self.api_key:
            raise ValueError("Shodan API key not configured")
        
        params = params or {}
        params["key"] = self.api_key
        
        url = f"{self.BASE_URL}/{endpoint}"
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_host_info(self, ip: str) -> Dict[str, Any]:
        result = self._make_request(f"shodan/host/{ip}")
        
        return {
            "ip": result.get("ip_str", ip),
            "hostnames": result.get("hostnames", []),
            "domains": result.get("domains", []),
            "country": result.get("country_name", ""),
            "country_code": result.get("country_code", ""),
            "city": result.get("city", ""),
            "region": result.get("region_code", ""),
            "postal_code": result.get("postal_code", ""),
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "asn": result.get("asn", ""),
            "isp": result.get("isp", ""),
            "org": result.get("org", ""),
            "os": result.get("os"),
            "ports": result.get("ports", []),
            "vulns": result.get("vulns", []),
            "tags": result.get("tags", []),
            "last_update": result.get("last_update"),
            "services": [
                {
                    "port": service.get("port"),
                    "transport": service.get("transport"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "cpe": service.get("cpe", []),
                    "banner": service.get("data", "")[:500],
                    "ssl": service.get("ssl", {}),
                    "http": service.get("http", {}),
                }
                for service in result.get("data", [])
            ],
        }
    
    def search(self, query: str, page: int = 1, limit: int = 100) -> Dict[str, Any]:
        result = self._make_request("shodan/host/search", {
            "query": query,
            "page": page,
        })
        
        return {
            "total": result.get("total", 0),
            "matches": [
                {
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "transport": match.get("transport"),
                    "hostnames": match.get("hostnames", []),
                    "domains": match.get("domains", []),
                    "org": match.get("org", ""),
                    "isp": match.get("isp", ""),
                    "asn": match.get("asn", ""),
                    "country": match.get("location", {}).get("country_name", ""),
                    "city": match.get("location", {}).get("city", ""),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "os": match.get("os"),
                    "timestamp": match.get("timestamp"),
                }
                for match in result.get("matches", [])[:limit]
            ],
            "facets": result.get("facets", {}),
        }
    
    def search_count(self, query: str) -> Dict[str, Any]:
        result = self._make_request("shodan/host/count", {"query": query})
        
        return {
            "total": result.get("total", 0),
            "facets": result.get("facets", {}),
        }
    
    def get_dns_resolve(self, hostnames: List[str]) -> Dict[str, str]:
        result = self._make_request("dns/resolve", {
            "hostnames": ",".join(hostnames)
        })
        return result
    
    def get_dns_reverse(self, ips: List[str]) -> Dict[str, List[str]]:
        result = self._make_request("dns/reverse", {
            "ips": ",".join(ips)
        })
        return result
    
    def get_exploits(self, query: str) -> Dict[str, Any]:
        result = self._make_request("api-ms/exploits/search", {"query": query})
        
        return {
            "total": result.get("total", 0),
            "matches": result.get("matches", []),
        }
    
    def get_vulnerabilities(self, cve: str) -> Dict[str, Any]:
        result = self._make_request(f"api-ms/cve/{cve}")
        
        return {
            "cve_id": result.get("cve_id", cve),
            "summary": result.get("summary", ""),
            "cvss": result.get("cvss", 0),
            "cvss_version": result.get("cvss_version", 0),
            "references": result.get("references", []),
            "published_time": result.get("published_time"),
            "epss": result.get("epss", {}),
            "kev": result.get("kev", {}),
            "ransomware_campaign": result.get("ransomware_campaign"),
        }


class AlienVaultOTXClient:
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or ALIENVAULT_OTX_API_KEY
        self.session = requests.Session()
        self.session.headers.update({
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json"
        })
    
    def _make_request(self, endpoint: str, params: Dict = None) -> Dict[str, Any]:
        if not self.api_key:
            raise ValueError("AlienVault OTX API key not configured")
        
        url = f"{self.BASE_URL}/{endpoint}"
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_indicator_ipv4(self, ip: str, section: str = "general") -> Dict[str, Any]:
        result = self._make_request(f"indicators/IPv4/{ip}/{section}")
        
        if section == "general":
            return {
                "ip": ip,
                "reputation": result.get("reputation", 0),
                "indicator": result.get("indicator", ip),
                "type": result.get("type", "IPv4"),
                "type_title": result.get("type_title", "IPv4"),
                "asn": result.get("asn", ""),
                "country_code": result.get("country_code", ""),
                "country_name": result.get("country_name", ""),
                "city": result.get("city", ""),
                "latitude": result.get("latitude"),
                "longitude": result.get("longitude"),
                "pulse_count": result.get("pulse_info", {}).get("count", 0),
                "pulses": result.get("pulse_info", {}).get("pulses", []),
                "validation": result.get("validation", []),
                "whois": result.get("whois", ""),
            }
        
        return result
    
    def get_indicator_domain(self, domain: str, section: str = "general") -> Dict[str, Any]:
        result = self._make_request(f"indicators/domain/{domain}/{section}")
        
        if section == "general":
            return {
                "domain": domain,
                "indicator": result.get("indicator", domain),
                "type": result.get("type", "domain"),
                "alexa": result.get("alexa", ""),
                "whois": result.get("whois", ""),
                "pulse_count": result.get("pulse_info", {}).get("count", 0),
                "pulses": result.get("pulse_info", {}).get("pulses", []),
                "validation": result.get("validation", []),
            }
        
        return result
    
    def get_indicator_hostname(self, hostname: str, section: str = "general") -> Dict[str, Any]:
        result = self._make_request(f"indicators/hostname/{hostname}/{section}")
        return result
    
    def get_indicator_file(self, file_hash: str, section: str = "general") -> Dict[str, Any]:
        result = self._make_request(f"indicators/file/{file_hash}/{section}")
        
        if section == "general":
            return {
                "hash": file_hash,
                "indicator": result.get("indicator", file_hash),
                "type": result.get("type", "FileHash-SHA256"),
                "pulse_count": result.get("pulse_info", {}).get("count", 0),
                "pulses": result.get("pulse_info", {}).get("pulses", []),
                "analysis": result.get("analysis", {}),
            }
        
        return result
    
    def get_indicator_url(self, url: str, section: str = "general") -> Dict[str, Any]:
        result = self._make_request(f"indicators/url/{url}/{section}")
        return result
    
    def get_indicator_cve(self, cve: str) -> Dict[str, Any]:
        result = self._make_request(f"indicators/cve/{cve}/general")
        
        return {
            "cve": cve,
            "indicator": result.get("indicator", cve),
            "description": result.get("description", ""),
            "cvss": result.get("cvss", {}),
            "date_created": result.get("date_created"),
            "date_modified": result.get("date_modified"),
            "pulse_count": result.get("pulse_info", {}).get("count", 0),
            "pulses": result.get("pulse_info", {}).get("pulses", []),
        }
    
    def get_pulses_subscribed(self, page: int = 1, limit: int = 50) -> Dict[str, Any]:
        result = self._make_request("pulses/subscribed", {
            "page": page,
            "limit": limit
        })
        
        return {
            "count": result.get("count", 0),
            "pulses": [
                {
                    "id": pulse.get("id"),
                    "name": pulse.get("name"),
                    "description": pulse.get("description", ""),
                    "author_name": pulse.get("author_name", ""),
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tags": pulse.get("tags", []),
                    "targeted_countries": pulse.get("targeted_countries", []),
                    "malware_families": pulse.get("malware_families", []),
                    "attack_ids": pulse.get("attack_ids", []),
                    "industries": pulse.get("industries", []),
                    "tlp": pulse.get("tlp", "white"),
                    "indicator_count": pulse.get("indicator_count", 0),
                }
                for pulse in result.get("results", [])
            ],
        }
    
    def get_pulse_details(self, pulse_id: str) -> Dict[str, Any]:
        result = self._make_request(f"pulses/{pulse_id}")
        
        return {
            "id": result.get("id"),
            "name": result.get("name"),
            "description": result.get("description", ""),
            "author_name": result.get("author_name", ""),
            "created": result.get("created"),
            "modified": result.get("modified"),
            "tags": result.get("tags", []),
            "references": result.get("references", []),
            "targeted_countries": result.get("targeted_countries", []),
            "malware_families": result.get("malware_families", []),
            "attack_ids": result.get("attack_ids", []),
            "industries": result.get("industries", []),
            "tlp": result.get("tlp", "white"),
            "indicators": result.get("indicators", []),
        }
    
    def search_pulses(self, query: str, page: int = 1, limit: int = 50) -> Dict[str, Any]:
        result = self._make_request("search/pulses", {
            "q": query,
            "page": page,
            "limit": limit
        })
        
        return {
            "count": result.get("count", 0),
            "pulses": result.get("results", []),
        }


class MISPClient:
    def __init__(self, url: str = None, api_key: str = None, verify_ssl: bool = True):
        self.url = (url or MISP_URL).rstrip("/")
        self.api_key = api_key or MISP_API_KEY
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Dict[str, Any]:
        if not self.url or not self.api_key:
            raise ValueError("MISP URL and API key not configured")
        
        url = f"{self.url}/{endpoint}"
        response = self.session.request(
            method, url, json=data, verify=self.verify_ssl
        )
        response.raise_for_status()
        return response.json()
    
    def get_events(self, limit: int = 50, page: int = 1, **filters) -> List[Dict[str, Any]]:
        data = {
            "limit": limit,
            "page": page,
            **filters
        }
        result = self._make_request("POST", "events/restSearch", data)
        
        return [
            {
                "id": event.get("Event", {}).get("id"),
                "uuid": event.get("Event", {}).get("uuid"),
                "info": event.get("Event", {}).get("info"),
                "date": event.get("Event", {}).get("date"),
                "threat_level_id": event.get("Event", {}).get("threat_level_id"),
                "analysis": event.get("Event", {}).get("analysis"),
                "org": event.get("Event", {}).get("Org", {}).get("name"),
                "orgc": event.get("Event", {}).get("Orgc", {}).get("name"),
                "attribute_count": event.get("Event", {}).get("attribute_count"),
                "timestamp": event.get("Event", {}).get("timestamp"),
                "tags": [
                    tag.get("name") for tag in event.get("Event", {}).get("Tag", [])
                ],
            }
            for event in result.get("response", [])
        ]
    
    def get_event(self, event_id: str) -> Dict[str, Any]:
        result = self._make_request("GET", f"events/view/{event_id}")
        
        event = result.get("Event", {})
        return {
            "id": event.get("id"),
            "uuid": event.get("uuid"),
            "info": event.get("info"),
            "date": event.get("date"),
            "threat_level_id": event.get("threat_level_id"),
            "analysis": event.get("analysis"),
            "org": event.get("Org", {}).get("name"),
            "orgc": event.get("Orgc", {}).get("name"),
            "timestamp": event.get("timestamp"),
            "tags": [tag.get("name") for tag in event.get("Tag", [])],
            "attributes": [
                {
                    "id": attr.get("id"),
                    "type": attr.get("type"),
                    "category": attr.get("category"),
                    "value": attr.get("value"),
                    "to_ids": attr.get("to_ids"),
                    "comment": attr.get("comment"),
                    "timestamp": attr.get("timestamp"),
                }
                for attr in event.get("Attribute", [])
            ],
            "objects": event.get("Object", []),
            "galaxies": event.get("Galaxy", []),
        }
    
    def search_attributes(self, **filters) -> List[Dict[str, Any]]:
        result = self._make_request("POST", "attributes/restSearch", filters)
        
        return [
            {
                "id": attr.get("Attribute", {}).get("id"),
                "event_id": attr.get("Attribute", {}).get("event_id"),
                "type": attr.get("Attribute", {}).get("type"),
                "category": attr.get("Attribute", {}).get("category"),
                "value": attr.get("Attribute", {}).get("value"),
                "to_ids": attr.get("Attribute", {}).get("to_ids"),
                "comment": attr.get("Attribute", {}).get("comment"),
                "timestamp": attr.get("Attribute", {}).get("timestamp"),
            }
            for attr in result.get("response", {}).get("Attribute", [])
        ]
    
    def add_event(self, info: str, threat_level: int = 2, analysis: int = 0,
                  distribution: int = 0, attributes: List[Dict] = None) -> Dict[str, Any]:
        data = {
            "Event": {
                "info": info,
                "threat_level_id": threat_level,
                "analysis": analysis,
                "distribution": distribution,
                "Attribute": attributes or []
            }
        }
        result = self._make_request("POST", "events/add", data)
        return result.get("Event", {})
    
    def add_attribute(self, event_id: str, attr_type: str, value: str,
                      category: str = "Network activity", to_ids: bool = True,
                      comment: str = "") -> Dict[str, Any]:
        data = {
            "type": attr_type,
            "value": value,
            "category": category,
            "to_ids": to_ids,
            "comment": comment
        }
        result = self._make_request("POST", f"attributes/add/{event_id}", data)
        return result.get("Attribute", {})


class HaveIBeenPwnedClient:
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or HIBP_API_KEY
        self.session = requests.Session()
        self.session.headers.update({
            "hibp-api-key": self.api_key,
            "User-Agent": "TYRANTHOS-TIER0-Intelligence"
        })
    
    def _make_request(self, endpoint: str) -> Union[List, Dict]:
        if not self.api_key:
            raise ValueError("Have I Been Pwned API key not configured")
        
        url = f"{self.BASE_URL}/{endpoint}"
        response = self.session.get(url)
        
        if response.status_code == 404:
            return []
        
        response.raise_for_status()
        return response.json()
    
    def get_breaches_for_account(self, email: str, truncate: bool = False,
                                  domain: str = None, include_unverified: bool = False) -> List[Dict[str, Any]]:
        endpoint = f"breachedaccount/{email}"
        params = []
        if truncate:
            params.append("truncateResponse=true")
        if domain:
            params.append(f"domain={domain}")
        if include_unverified:
            params.append("includeUnverified=true")
        
        if params:
            endpoint += "?" + "&".join(params)
        
        result = self._make_request(endpoint)
        
        if not result:
            return []
        
        return [
            {
                "name": breach.get("Name"),
                "title": breach.get("Title"),
                "domain": breach.get("Domain"),
                "breach_date": breach.get("BreachDate"),
                "added_date": breach.get("AddedDate"),
                "modified_date": breach.get("ModifiedDate"),
                "pwn_count": breach.get("PwnCount"),
                "description": breach.get("Description"),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified"),
                "is_fabricated": breach.get("IsFabricated"),
                "is_sensitive": breach.get("IsSensitive"),
                "is_retired": breach.get("IsRetired"),
                "is_spam_list": breach.get("IsSpamList"),
                "is_malware": breach.get("IsMalware"),
            }
            for breach in result
        ]
    
    def get_all_breaches(self, domain: str = None) -> List[Dict[str, Any]]:
        endpoint = "breaches"
        if domain:
            endpoint += f"?domain={domain}"
        
        result = self._make_request(endpoint)
        return result
    
    def get_breach(self, name: str) -> Dict[str, Any]:
        result = self._make_request(f"breach/{name}")
        return result
    
    def get_pastes_for_account(self, email: str) -> List[Dict[str, Any]]:
        result = self._make_request(f"pasteaccount/{email}")
        
        if not result:
            return []
        
        return [
            {
                "source": paste.get("Source"),
                "id": paste.get("Id"),
                "title": paste.get("Title"),
                "date": paste.get("Date"),
                "email_count": paste.get("EmailCount"),
            }
            for paste in result
        ]


class AbuseIPDBClient:
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or ABUSEIPDB_API_KEY
        self.session = requests.Session()
        self.session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json"
        })
    
    def _make_request(self, endpoint: str, params: Dict = None) -> Dict[str, Any]:
        if not self.api_key:
            raise ValueError("AbuseIPDB API key not configured")
        
        url = f"{self.BASE_URL}/{endpoint}"
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def check_ip(self, ip: str, max_age_days: int = 90, verbose: bool = True) -> Dict[str, Any]:
        result = self._make_request("check", {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": verbose
        })
        
        data = result.get("data", {})
        return {
            "ip": data.get("ipAddress", ip),
            "is_public": data.get("isPublic"),
            "ip_version": data.get("ipVersion"),
            "is_whitelisted": data.get("isWhitelisted"),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode", ""),
            "country_name": data.get("countryName", ""),
            "usage_type": data.get("usageType", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "hostnames": data.get("hostnames", []),
            "is_tor": data.get("isTor", False),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "reports": data.get("reports", []),
        }
    
    def get_blacklist(self, confidence_minimum: int = 90, limit: int = 10000) -> List[Dict[str, Any]]:
        result = self._make_request("blacklist", {
            "confidenceMinimum": confidence_minimum,
            "limit": limit
        })
        
        return [
            {
                "ip": item.get("ipAddress"),
                "abuse_confidence_score": item.get("abuseConfidenceScore"),
                "last_reported_at": item.get("lastReportedAt"),
            }
            for item in result.get("data", [])
        ]


class ThreatIntelligenceAggregator:
    def __init__(self):
        self.virustotal = VirusTotalClient() if VIRUSTOTAL_API_KEY else None
        self.shodan = ShodanClient() if SHODAN_API_KEY else None
        self.otx = AlienVaultOTXClient() if ALIENVAULT_OTX_API_KEY else None
        self.misp = MISPClient() if MISP_URL and MISP_API_KEY else None
        self.hibp = HaveIBeenPwnedClient() if HIBP_API_KEY else None
        self.abuseipdb = AbuseIPDBClient() if ABUSEIPDB_API_KEY else None
        self._executor = ThreadPoolExecutor(max_workers=10)
    
    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        results = {
            "ip": ip,
            "sources": {},
            "risk_score": 0,
            "is_malicious": False,
            "tags": [],
            "summary": ""
        }
        
        risk_factors = []
        
        if self.virustotal:
            try:
                vt_result = self.virustotal.get_ip_report(ip)
                results["sources"]["virustotal"] = vt_result
                if vt_result.get("malicious", 0) > 0:
                    risk_factors.append(("virustotal_malicious", vt_result["malicious"] * 10))
            except Exception as e:
                logger.error(f"VirusTotal IP lookup failed: {e}")
        
        if self.shodan:
            try:
                shodan_result = self.shodan.get_host_info(ip)
                results["sources"]["shodan"] = shodan_result
                if shodan_result.get("vulns"):
                    risk_factors.append(("shodan_vulns", len(shodan_result["vulns"]) * 5))
            except Exception as e:
                logger.error(f"Shodan IP lookup failed: {e}")
        
        if self.otx:
            try:
                otx_result = self.otx.get_indicator_ipv4(ip)
                results["sources"]["alienvault_otx"] = otx_result
                if otx_result.get("pulse_count", 0) > 0:
                    risk_factors.append(("otx_pulses", otx_result["pulse_count"] * 3))
            except Exception as e:
                logger.error(f"AlienVault OTX IP lookup failed: {e}")
        
        if self.abuseipdb:
            try:
                abuse_result = self.abuseipdb.check_ip(ip)
                results["sources"]["abuseipdb"] = abuse_result
                if abuse_result.get("abuse_confidence_score", 0) > 0:
                    risk_factors.append(("abuseipdb_score", abuse_result["abuse_confidence_score"]))
            except Exception as e:
                logger.error(f"AbuseIPDB IP lookup failed: {e}")
        
        total_risk = sum(score for _, score in risk_factors)
        results["risk_score"] = min(100, total_risk)
        results["is_malicious"] = results["risk_score"] > 50
        
        return results
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        results = {
            "domain": domain,
            "sources": {},
            "risk_score": 0,
            "is_malicious": False,
            "tags": [],
            "summary": ""
        }
        
        risk_factors = []
        
        if self.virustotal:
            try:
                vt_result = self.virustotal.get_domain_report(domain)
                results["sources"]["virustotal"] = vt_result
                if vt_result.get("malicious", 0) > 0:
                    risk_factors.append(("virustotal_malicious", vt_result["malicious"] * 10))
            except Exception as e:
                logger.error(f"VirusTotal domain lookup failed: {e}")
        
        if self.otx:
            try:
                otx_result = self.otx.get_indicator_domain(domain)
                results["sources"]["alienvault_otx"] = otx_result
                if otx_result.get("pulse_count", 0) > 0:
                    risk_factors.append(("otx_pulses", otx_result["pulse_count"] * 3))
            except Exception as e:
                logger.error(f"AlienVault OTX domain lookup failed: {e}")
        
        total_risk = sum(score for _, score in risk_factors)
        results["risk_score"] = min(100, total_risk)
        results["is_malicious"] = results["risk_score"] > 50
        
        return results
    
    def analyze_hash(self, file_hash: str) -> Dict[str, Any]:
        results = {
            "hash": file_hash,
            "sources": {},
            "risk_score": 0,
            "is_malicious": False,
            "tags": [],
            "summary": ""
        }
        
        risk_factors = []
        
        if self.virustotal:
            try:
                vt_result = self.virustotal.get_file_report(file_hash)
                results["sources"]["virustotal"] = vt_result
                if vt_result.get("malicious", 0) > 0:
                    risk_factors.append(("virustotal_malicious", vt_result["malicious"] * 5))
            except Exception as e:
                logger.error(f"VirusTotal hash lookup failed: {e}")
        
        if self.otx:
            try:
                otx_result = self.otx.get_indicator_file(file_hash)
                results["sources"]["alienvault_otx"] = otx_result
                if otx_result.get("pulse_count", 0) > 0:
                    risk_factors.append(("otx_pulses", otx_result["pulse_count"] * 3))
            except Exception as e:
                logger.error(f"AlienVault OTX hash lookup failed: {e}")
        
        total_risk = sum(score for _, score in risk_factors)
        results["risk_score"] = min(100, total_risk)
        results["is_malicious"] = results["risk_score"] > 50
        
        return results
    
    def analyze_email(self, email: str) -> Dict[str, Any]:
        results = {
            "email": email,
            "sources": {},
            "breach_count": 0,
            "paste_count": 0,
            "is_compromised": False,
            "breaches": [],
            "pastes": []
        }
        
        if self.hibp:
            try:
                breaches = self.hibp.get_breaches_for_account(email)
                results["sources"]["haveibeenpwned"] = {"breaches": breaches}
                results["breaches"] = breaches
                results["breach_count"] = len(breaches)
                
                pastes = self.hibp.get_pastes_for_account(email)
                results["sources"]["haveibeenpwned"]["pastes"] = pastes
                results["pastes"] = pastes
                results["paste_count"] = len(pastes)
                
                results["is_compromised"] = len(breaches) > 0 or len(pastes) > 0
            except Exception as e:
                logger.error(f"HIBP email lookup failed: {e}")
        
        return results
    
    def get_threat_feeds(self, limit: int = 100) -> Dict[str, Any]:
        feeds = {
            "pulses": [],
            "events": [],
            "total_indicators": 0
        }
        
        if self.otx:
            try:
                pulses = self.otx.get_pulses_subscribed(limit=limit)
                feeds["pulses"] = pulses.get("pulses", [])
            except Exception as e:
                logger.error(f"OTX feed fetch failed: {e}")
        
        if self.misp:
            try:
                events = self.misp.get_events(limit=limit)
                feeds["events"] = events
            except Exception as e:
                logger.error(f"MISP feed fetch failed: {e}")
        
        return feeds


def get_threat_intelligence_aggregator() -> ThreatIntelligenceAggregator:
    return ThreatIntelligenceAggregator()
