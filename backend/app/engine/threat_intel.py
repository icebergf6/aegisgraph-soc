"""
Threat Intelligence and IOC Enrichment Engine
Provides threat actor attribution, IP reputation, ASN classification, and malware family intelligence.
"""
from typing import Dict, Any, Optional

KNOWN_THREAT_INTEL_DB: Dict[str, Dict[str, Any]] = {
    # Known Adversary C2 IPs
    "185.220.101.5": {
        "ioc_type": "ip",
        "verdict": "MALICIOUS",
        "threat_score": 98,
        "threat_actor": "APT29 (Cozy Bear / Nobelium)",
        "country": "Netherlands",
        "asn": "AS208323 (Zwiebelfreunde Tor Exit Node)",
        "category": "Command and Control (C2) / Tor Exit",
        "tags": ["apt29", "c2-beacon", "tor-exit", "high-confidence"]
    },
    "45.154.255.88": {
        "ioc_type": "ip",
        "verdict": "MALICIOUS",
        "threat_score": 95,
        "threat_actor": "FIN7 / Carbanak",
        "country": "Russia",
        "asn": "AS48282 (HostRoyale B.V.)",
        "category": "Bulletproof Hosting C2",
        "tags": ["fin7", "phishing-payload-delivery"]
    },
    "194.26.29.11": {
        "ioc_type": "ip",
        "verdict": "SUSPICIOUS",
        "threat_score": 82,
        "threat_actor": "LockBit 3.0 Affiliate Infrastructure",
        "country": "Bulgaria",
        "asn": "AS49981 (WorldStream B.V.)",
        "category": "Ransomware Data Exfiltration Relay",
        "tags": ["ransomware", "data-exfiltration"]
    },
    "10.0.0.1": {
        "ioc_type": "ip",
        "verdict": "INTERNAL_ASSET",
        "threat_score": 5,
        "threat_actor": "N/A",
        "country": "Internal Network (RFC 1918)",
        "asn": "Enterprise Active Directory Domain Controller",
        "category": "High-Value Asset / Tier 0 Asset",
        "tags": ["internal", "domain-controller", "tier-0"]
    }
}

class ThreatIntelEngine:
    @staticmethod
    def lookup_ioc(ioc: str) -> Dict[str, Any]:
        """
        Enriches an IP, domain, or hash with known threat intelligence signatures.
        """
        clean_ioc = ioc.strip().lower()
        # Direct lookup
        for key, info in KNOWN_THREAT_INTEL_DB.items():
            if key.lower() == clean_ioc or clean_ioc in key.lower():
                return info

        # Heuristic / RFC1918 classification for private subnets
        if clean_ioc.startswith(("10.", "192.168.", "172.16.", "127.")):
            return {
                "ioc_type": "ip",
                "verdict": "INTERNAL",
                "threat_score": 0,
                "threat_actor": "Internal Intranet",
                "country": "Private Enterprise LAN",
                "asn": "Local Intranet Subnet",
                "category": "Internal Endpoint",
                "tags": ["rfc1918", "internal-workstation"]
            }

        # Unknown / Unclassified External IP
        return {
            "ioc_type": "ip_or_hash",
            "verdict": "UNCLASSIFIED",
            "threat_score": 35,
            "threat_actor": "Unknown / Zero-Day Target",
            "country": "Global Network",
            "asn": "Public Transit Provider",
            "category": "External Infrastructure",
            "tags": ["unverified-traffic", "monitoring-required"]
        }
