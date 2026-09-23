"""
MITRE ATT&CK Knowledge Base and Threat Scoring Engine
Maps techniques, tactics, and computes kill-chain progression scores.
Includes robust base & subtechnique fallback resolution and case normalization.
"""
from typing import Dict, List, Any

MITRE_TACTICS_ORDER = [
    "TA0001: Initial Access",
    "TA0002: Execution",
    "TA0003: Persistence",
    "TA0004: Privilege Escalation",
    "TA0005: Defense Evasion",
    "TA0006: Credential Access",
    "TA0007: Discovery",
    "TA0008: Lateral Movement",
    "TA0009: Collection",
    "TA0011: Command and Control",
    "TA0010: Exfiltration",
    "TA0040: Impact"
]

TACTIC_WEIGHTS = {
    "Initial Access": 1.5,
    "Execution": 1.2,
    "Persistence": 1.8,
    "Privilege Escalation": 2.0,
    "Defense Evasion": 2.2,
    "Credential Access": 2.8,
    "Discovery": 1.1,
    "Lateral Movement": 3.0,
    "Collection": 2.5,
    "Command and Control": 3.2,
    "Exfiltration": 4.0,
    "Impact": 4.5
}

MITRE_TECHNIQUES_DB: Dict[str, Dict[str, Any]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "base_score": 6.5,
        "description": "Adversaries may abuse command and script interpreters to execute commands."
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "base_score": 7.0,
        "description": "Adversaries may abuse PowerShell commands and scripts for execution."
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "base_score": 5.5,
        "description": "Adversaries may abuse cmd.exe to execute utilities."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "base_score": 9.0,
        "description": "Adversaries may attempt to dump credentials to obtain account login information."
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "base_score": 9.5,
        "description": "Adversaries may attempt to access credential material stored in the process memory of LSASS."
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "base_score": 7.5,
        "description": "Adversaries may communicate using application layer protocols to avoid detection."
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "base_score": 8.0,
        "description": "Adversaries may communicate using HTTP/HTTPS to avoid detection."
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "base_score": 9.8,
        "description": "Adversaries may encrypt data on target systems to interrupt availability of resources (Ransomware)."
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "base_score": 9.0,
        "description": "Adversaries may delete or remove built-in data recovery mechanisms such as Volume Shadow Copies."
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "base_score": 8.5,
        "description": "Adversaries may inject code into processes in order to evade process-based defenses."
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "base_score": 4.0,
        "description": "Adversaries may attempt to get a listing of local system or domain accounts."
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "base_score": 8.0,
        "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections."
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "base_score": 8.8,
        "description": "Adversaries may use valid accounts to interact with remote SMB shares for lateral movement."
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "base_score": 7.0,
        "description": "Adversaries may send phishing messages to gain initial access."
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "base_score": 7.5,
        "description": "Adversaries may send spearphishing emails with a malicious attachment."
    }
}

class MitreMapper:
    @staticmethod
    def get_technique(technique_id: str) -> Dict[str, Any]:
        """
        Resolves technique with case-insensitivity, base technique fallback, or subtechnique mapping.
        """
        clean_id = technique_id.strip().upper()
        if clean_id in MITRE_TECHNIQUES_DB:
            return MITRE_TECHNIQUES_DB[clean_id]

        # Base technique fallback (e.g. if T1059.005 is queried, check T1059)
        if "." in clean_id:
            base_id = clean_id.split(".")[0]
            if base_id in MITRE_TECHNIQUES_DB:
                base_tech = MITRE_TECHNIQUES_DB[base_id]
                return {
                    "name": f"{base_tech['name']} (Subtechnique {clean_id})",
                    "tactic": base_tech["tactic"],
                    "base_score": base_tech["base_score"],
                    "description": base_tech["description"]
                }

        # Subtechnique match if base is queried
        for k, v in MITRE_TECHNIQUES_DB.items():
            if k.startswith(clean_id + "."):
                return v

        return {
            "name": f"Unclassified Technique ({clean_id})",
            "tactic": "Discovery",
            "base_score": 5.0,
            "description": "Generic adversary behavior observed."
        }

    @staticmethod
    def calculate_attack_path_score(techniques: List[str]) -> float:
        """
        Computes composite risk score based on multi-stage kill chain progression.
        """
        if not techniques:
            return 0.0

        tactics_seen = set()
        raw_score = 0.0

        for tech_id in techniques:
            tech = MitreMapper.get_technique(tech_id)
            tactic = tech["tactic"]
            tactics_seen.add(tactic)
            weight = TACTIC_WEIGHTS.get(tactic, 1.0)
            raw_score += tech["base_score"] * weight

        tactic_diversity_factor = 1.0 + (len(tactics_seen) * 0.2)
        composite_score = min(100.0, (raw_score / 1.5) * tactic_diversity_factor)
        return round(composite_score, 1)

    @staticmethod
    def get_tactics_order() -> List[str]:
        return MITRE_TACTICS_ORDER
