"""
Sigma-Style Rule Engine
Evaluates telemetry events against YAML detection signatures with condition trees.
"""
import re
import yaml
import os
from typing import List, Dict, Any, Optional
from backend.app.models.telemetry import (
    ProcessTelemetry, NetworkTelemetry, FileTelemetry, 
    DetectionAlert, Severity
)
from backend.app.engine.mitre_mapper import MitreMapper

class DetectionRule:
    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data.get("id", "UNKNOWN-001")
        self.title = rule_data.get("title", "Untitled Rule")
        self.status = rule_data.get("status", "experimental")
        self.description = rule_data.get("description", "")
        self.severity = Severity(rule_data.get("level", "MEDIUM").upper())
        self.tags = rule_data.get("tags", []) # e.g. ["attack.t1059.001", "attack.execution"]
        self.logsource = rule_data.get("logsource", {})
        self.detection = rule_data.get("detection", {})
        
        # Parse MITRE tags
        self.mitre_technique_id = "T1059"
        self.mitre_tactic = "Execution"
        for tag in self.tags:
            if tag.startswith("attack.t"):
                self.mitre_technique_id = tag.replace("attack.", "").upper()
            elif tag.startswith("attack."):
                self.mitre_tactic = tag.replace("attack.", "").replace("_", " ").title()

        tech_info = MitreMapper.get_technique(self.mitre_technique_id)
        self.mitre_technique_name = tech_info["name"]
        if self.mitre_tactic == "Execution" and tech_info["tactic"]:
            self.mitre_tactic = tech_info["tactic"]

    def matches(self, event_data: Dict[str, Any]) -> bool:
        """
        Evaluates event_data against detection conditions.
        Supports selection dictionaries and keywords.
        """
        selection = self.detection.get("selection", {})
        if not selection:
            return False

        for field, pattern in selection.items():
            value = str(event_data.get(field, "")).lower()
            if isinstance(pattern, list):
                # Any match in list (safely converting each item to string)
                matched = any(str(p).lower() in value for p in pattern)
                if not matched:
                    return False
            else:
                # Direct string or numeric comparison
                if str(pattern).lower() not in value:
                    return False
        return True

class DetectionEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[DetectionRule] = []
        if rules_dir and os.path.exists(rules_dir):
            self.load_rules_from_dir(rules_dir)

    def load_rules_from_dir(self, rules_dir: str):
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            rule_data = yaml.safe_load(f)
                            if rule_data and "detection" in rule_data:
                                self.rules.append(DetectionRule(rule_data))
                    except Exception as e:
                        print(f"Error loading rule {filepath}: {e}")

    def add_rule(self, rule_data: Dict[str, Any]):
        self.rules.append(DetectionRule(rule_data))

    def evaluate_process(self, event: ProcessTelemetry) -> List[DetectionAlert]:
        alerts = []
        event_dict = event.model_dump()
        for rule in self.rules:
            if rule.matches(event_dict):
                alert = DetectionAlert(
                    rule_id=rule.id,
                    rule_name=rule.title,
                    rule_description=rule.description,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique_id=rule.mitre_technique_id,
                    mitre_technique_name=rule.mitre_technique_name,
                    host_name=event.host_name,
                    host_ip=event.host_ip,
                    user_name=event.user_name,
                    process_guid=event.process_guid,
                    process_name=event.process_name,
                    matched_event_id=event.event_id,
                    details={
                        "command_line": event.command_line,
                        "parent_process": event.parent_process_name,
                        "hashes": event.hashes
                    }
                )
                alerts.append(alert)
        return alerts

    def evaluate_network(self, event: NetworkTelemetry) -> List[DetectionAlert]:
        alerts = []
        event_dict = event.model_dump()
        for rule in self.rules:
            if rule.matches(event_dict):
                alert = DetectionAlert(
                    rule_id=rule.id,
                    rule_name=rule.title,
                    rule_description=rule.description,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique_id=rule.mitre_technique_id,
                    mitre_technique_name=rule.mitre_technique_name,
                    host_name=event.host_name,
                    host_ip=event.source_ip,
                    user_name="SYSTEM",
                    process_guid=event.process_guid,
                    process_name=event.process_name,
                    matched_event_id=event.event_id,
                    details={
                        "dest_ip": event.dest_ip,
                        "dest_port": event.dest_port,
                        "domain": event.domain
                    }
                )
                alerts.append(alert)
        return alerts

    def evaluate_file(self, event: FileTelemetry) -> List[DetectionAlert]:
        alerts = []
        event_dict = event.model_dump()
        for rule in self.rules:
            if rule.matches(event_dict):
                alert = DetectionAlert(
                    rule_id=rule.id,
                    rule_name=rule.title,
                    rule_description=rule.description,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique_id=rule.mitre_technique_id,
                    mitre_technique_name=rule.mitre_technique_name,
                    host_name=event.host_name,
                    host_ip="127.0.0.1",
                    user_name="SYSTEM",
                    process_guid=event.process_guid,
                    process_name=event.process_name,
                    matched_event_id=event.event_id,
                    details={
                        "file_path": event.file_path,
                        "action": event.action,
                        "extension": event.file_extension
                    }
                )
                alerts.append(alert)
        return alerts
