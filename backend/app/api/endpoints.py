"""
FastAPI REST API Endpoints for AegisGraph-SOC
Provides incident retrieval, graph data, alert stream, SOAR execution, attack simulation,
telemetry timeline, incident report generation, Threat Intel lookups, Sigma Sandbox,
and STIX 2.1 IOC bundle exports.
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import os
import uuid
import yaml
from datetime import datetime, timezone

from backend.app.models.telemetry import (
    ProcessTelemetry, NetworkTelemetry, FileTelemetry,
    DetectionAlert, AttackPathGraph, SOARPlaybookAction
)
from backend.app.engine.detection import DetectionEngine, DetectionRule
from backend.app.engine.graph_correlator import GraphCorrelator
from backend.app.engine.mitre_mapper import MitreMapper, MITRE_TECHNIQUES_DB
from backend.app.engine.threat_intel import ThreatIntelEngine
from backend.app.soar.playbooks import SOAROrchestrator
from backend.app.soar.actions import ActionExecutor
from backend.app.simulator.adversary import AdversarySimulator

router = APIRouter()

class SOCState:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.rules_dir = os.path.join(self.base_dir, "rules")
        self.detector = DetectionEngine(self.rules_dir)
        self.correlator = GraphCorrelator()
        self.soar = SOAROrchestrator()
        self.all_alerts: List[DetectionAlert] = []
        self.all_events: List[Dict[str, Any]] = []
        self.incident_notes: Dict[str, List[Dict[str, Any]]] = {}
        self.telemetry_count: int = 0

soc_state = SOCState()

class SimulationRequest(BaseModel):
    scenario: str = "apt29" # "apt29", "ransomware", or "lateral"
    target_host: Optional[str] = "WORKSTATION-SEC-01"

class PlaybookExecuteRequest(BaseModel):
    incident_id: str
    playbook_name: str

class SingleActionRequest(BaseModel):
    incident_id: str
    action_type: str # "isolate_host", "terminate_process", "block_ip", "revoke_user"
    target_value: str
    host_name: Optional[str] = "WORKSTATION-01"

class IncidentStatusUpdateRequest(BaseModel):
    status: str # "ACTIVE", "INVESTIGATING", "CONTAINED", "CLOSED"

class IncidentNoteRequest(BaseModel):
    author: str = "SOC Analyst"
    note: str

class SigmaCompileRequest(BaseModel):
    yaml_content: str

class SigmaSaveRequest(BaseModel):
    filename: str
    yaml_content: str

class IngestCustomEventRequest(BaseModel):
    event_type: str = "process_creation" # "process_creation", "network_connection", "file_modification"
    host_name: str = "PROD-SERVER-01"
    host_ip: str = "192.168.10.25"
    user_name: str = "CORP\\admin"
    process_name: str = "powershell.exe"
    command_line: str = "powershell.exe -enc SQBFAFgA"
    dest_ip: Optional[str] = None
    file_path: Optional[str] = None

@router.get("/status")
def get_system_status():
    incidents = soc_state.correlator.get_all_incidents()
    critical_count = sum(1 for inc in incidents if inc.overall_severity == "CRITICAL")
    high_count = sum(1 for inc in incidents if inc.overall_severity == "HIGH")
    contained_count = sum(1 for inc in incidents if inc.containment_status == "CONTAINED")
    
    # Calculate global DEFCON threat posture (1=Critical active attack, 5=Peaceful/Normal)
    if critical_count > 0:
        defcon = 1
        defcon_label = "DEFCON 1 - CRITICAL ATTACK ACTIVE"
    elif high_count > 0:
        defcon = 2
        defcon_label = "DEFCON 2 - HIGH THREAT DETECTED"
    elif len(incidents) > 0:
        defcon = 3
        defcon_label = "DEFCON 3 - ELEVATED VIGILANCE"
    else:
        defcon = 5
        defcon_label = "DEFCON 5 - NORMAL / BASELINE"

    return {
        "status": "HEALTHY",
        "engine": "AegisGraph-SOC v1.0 Enterprise",
        "defcon": defcon,
        "defcon_label": defcon_label,
        "rules_loaded": len(soc_state.detector.rules),
        "total_telemetry_events": soc_state.telemetry_count,
        "total_alerts": len(soc_state.all_alerts),
        "total_incidents": len(incidents),
        "critical_incidents": critical_count,
        "high_incidents": high_count,
        "contained_incidents": contained_count
    }

@router.get("/incidents", response_model=List[AttackPathGraph])
def list_incidents():
    return soc_state.correlator.get_all_incidents()

@router.get("/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    inc = soc_state.correlator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@router.patch("/incidents/{incident_id}/status")
def update_incident_status(incident_id: str, req: IncidentStatusUpdateRequest):
    inc = soc_state.correlator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.containment_status = req.status
    return {"status": "SUCCESS", "incident_id": incident_id, "new_status": req.status}

@router.get("/incidents/{incident_id}/notes")
def get_incident_notes(incident_id: str):
    return soc_state.incident_notes.get(incident_id, [])

@router.post("/incidents/{incident_id}/notes")
def add_incident_note(incident_id: str, req: IncidentNoteRequest):
    inc = soc_state.correlator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident_id not in soc_state.incident_notes:
        soc_state.incident_notes[incident_id] = []

    note_entry = {
        "id": str(uuid.uuid4())[:8],
        "author": req.author,
        "note": req.note,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    soc_state.incident_notes[incident_id].append(note_entry)
    return {"status": "SUCCESS", "note": note_entry}

@router.get("/incidents/{incident_id}/report")
def generate_incident_report(incident_id: str):
    inc = soc_state.correlator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    report_md = f"""# INCIDENT TRIAGE & FORENSIC INVESTIGATION REPORT
**Reference ID:** `{inc.incident_id}`  
**Classification:** `{inc.overall_severity.value}` (Calculated Risk Score: {inc.overall_risk_score}/100)  
**Containment Status:** `{inc.containment_status}`  
**Threat Correlation:** {inc.threat_actor_hint}  
**Investigation Timestamp:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

---

## 1. Executive Summary
A multi-stage adversarial intrusion was detected and correlated by the **AegisGraph-SOC Engine**. 
The attack originated from root node `{inc.root_node_id}` and traversed across {len(inc.nodes)} entities 
(processes, network egress points, and filesystem modifications) before triggering high-fidelity behavioral signatures.

## 2. MITRE ATT&CK Framework Mapping
The adversary traversed the following MITRE tactics and techniques:
"""
    for t in inc.mitre_techniques:
        tech_info = MitreMapper.get_technique(t)
        report_md += f"- **[{t}] {tech_info['name']}** (Tactic: *{tech_info['tactic']}* | Base Weight: {tech_info['base_score']})\n"

    report_md += f"""
## 3. Forensic Blast Radius (Attack Graph Entities)
Total Correlated Entities: **{len(inc.nodes)}** nodes, **{len(inc.edges)}** relationship transitions.

### Key Nodes Involved:
"""
    for n in inc.nodes:
        report_md += f"- **[{n.type.upper()}] {n.label}** | Severity: `{n.severity}` | Risk: {n.risk_score}  \n"
        if n.properties.get("command_line"):
            report_md += f"  `Command: {n.properties['command_line']}`\n"
        if n.properties.get("dest_ip"):
            report_md += f"  `Remote Destination: {n.properties['dest_ip']}:{n.properties.get('dest_port', '')}`\n"

    notes = soc_state.incident_notes.get(incident_id, [])
    if notes:
        report_md += "\n## 4. SOC Analyst Investigation Log\n"
        for n in notes:
            report_md += f"- **[{n['timestamp']}] ({n['author']}):** {n['note']}\n"

    report_md += f"""
## 5. Remediation & SOAR Action Summary
- **Current Incident State:** `{inc.containment_status}`
- Recommended actions executed: Host network isolation, process tree neutralization, identity revocation, and perimeter firewall sinkholing.
"""
    return {
        "incident_id": inc.incident_id,
        "title": inc.title,
        "markdown_report": report_md
    }

@router.get("/incidents/{incident_id}/iocs")
def export_incident_iocs(incident_id: str, format: str = "json"):
    """
    Extracts all Indicators of Compromise (IPs, hashes, filenames) in standard JSON or STIX 2.1 format.
    """
    inc = soc_state.correlator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    ips = []
    files = []
    processes = []

    for n in inc.nodes:
        if n.type == "network" and n.properties.get("dest_ip"):
            ips.append(n.properties["dest_ip"])
        elif n.type == "file" and n.properties.get("path"):
            files.append(n.properties["path"])
        elif n.type == "process":
            processes.append({
                "process_name": n.label,
                "command_line": n.properties.get("command_line", ""),
                "guid": n.id
            })

    if format == "stix":
        # Generate STIX 2.1 JSON bundle
        stix_objects = []
        for ip in ips:
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "name": f"Malicious C2 IP {ip}",
                "indicator_types": ["malicious-activity"]
            })
        for f in files:
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "pattern": f"[file:name = '{f.split(chr(92))[-1]}']",
                "pattern_type": "stix",
                "name": f"Malicious Artifact {f}",
                "indicator_types": ["malware-artifact"]
            })
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects
        }

    return {
        "incident_id": inc.incident_id,
        "iocs": {
            "c2_ips": list(set(ips)),
            "suspicious_files": list(set(files)),
            "processes": processes
        }
    }

@router.get("/intel/lookup")
def lookup_threat_intel(ioc: str = Query(..., description="IP, hash, or domain to enrich")):
    """
    Returns threat reputation, attribution, ASN, and country for an IOC.
    """
    return ThreatIntelEngine.lookup_ioc(ioc)

@router.post("/rules/compile-test")
def compile_test_sigma_rule(req: SigmaCompileRequest):
    """
    Validates syntax and parses a Sigma YAML rule string.
    """
    try:
        rule_dict = yaml.safe_load(req.yaml_content)
        if not rule_dict or "detection" not in rule_dict:
            raise ValueError("YAML must contain a 'detection' block with selection criteria.")
        rule = DetectionRule(rule_dict)
        return {
            "valid": True,
            "rule_id": rule.id,
            "title": rule.title,
            "severity": rule.severity.value,
            "mitre_technique_id": rule.mitre_technique_id,
            "mitre_tactic": rule.mitre_tactic,
            "description": rule.description
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}

@router.post("/rules/save")
def save_custom_sigma_rule(req: SigmaSaveRequest):
    """
    Saves a verified Sigma YAML rule to disk and reloads the detection engine.
    """
    try:
        rule_dict = yaml.safe_load(req.yaml_content)
        if not rule_dict or "detection" not in rule_dict:
            raise ValueError("Invalid Sigma YAML rule.")

        filename = req.filename if req.filename.endswith((".yml", ".yaml")) else f"{req.filename}.yml"
        target_path = os.path.join(soc_state.rules_dir, filename)

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(req.yaml_content)

        # Reload engine rules
        soc_state.detector = DetectionEngine(soc_state.rules_dir)
        return {
            "status": "SUCCESS",
            "message": f"Rule saved to {filename}",
            "total_rules": len(soc_state.detector.rules)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/alerts", response_model=List[DetectionAlert])
def list_alerts():
    return list(reversed(soc_state.all_alerts))

@router.get("/telemetry/events")
def get_telemetry_events(limit: int = 50):
    return list(reversed(soc_state.all_events))[:limit]

@router.get("/rules")
def list_rules():
    return [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity.value,
            "mitre_tactic": r.mitre_tactic,
            "mitre_technique_id": r.mitre_technique_id,
            "mitre_technique_name": r.mitre_technique_name,
            "description": r.description
        }
        for r in soc_state.detector.rules
    ]

@router.get("/mitre/matrix")
def get_mitre_matrix():
    triggered_techniques = {}
    for a in soc_state.all_alerts:
        triggered_techniques[a.mitre_technique_id] = triggered_techniques.get(a.mitre_technique_id, 0) + 1

    matrix = []
    for tech_id, info in MITRE_TECHNIQUES_DB.items():
        matrix.append({
            "technique_id": tech_id,
            "technique_name": info["name"],
            "tactic": info["tactic"],
            "base_score": info["base_score"],
            "triggered_count": triggered_techniques.get(tech_id, 0),
            "status": "DETECTED" if tech_id in triggered_techniques else "MONITORED"
        })
    return matrix

@router.post("/telemetry/ingest")
def ingest_custom_event(req: IngestCustomEventRequest):
    soc_state.telemetry_count += 1
    now = datetime.now(timezone.utc).isoformat()
    guid = f"proc-{uuid.uuid4().hex[:12]}"
    alerts: List[DetectionAlert] = []

    if req.event_type == "network_connection" and req.dest_ip:
        ev = NetworkTelemetry(
            timestamp=now,
            host_name=req.host_name,
            process_id=4092,
            process_guid=guid,
            process_name=req.process_name,
            source_ip=req.host_ip,
            source_port=51000,
            dest_ip=req.dest_ip,
            dest_port=443
        )
        soc_state.correlator.add_network(ev)
        soc_state.all_events.append({"type": "NETWORK", "host": req.host_name, "detail": f"Outbound to {req.dest_ip}", "timestamp": now})
        alerts = soc_state.detector.evaluate_network(ev)
    elif req.event_type == "file_modification" and req.file_path:
        ev = FileTelemetry(
            timestamp=now,
            host_name=req.host_name,
            process_id=4092,
            process_guid=guid,
            process_name=req.process_name,
            file_path=req.file_path,
            action="created"
        )
        soc_state.correlator.add_file(ev)
        soc_state.all_events.append({"type": "FILE", "host": req.host_name, "detail": f"File create: {req.file_path}", "timestamp": now})
        alerts = soc_state.detector.evaluate_file(ev)
    else:
        ev = ProcessTelemetry(
            timestamp=now,
            host_name=req.host_name,
            host_ip=req.host_ip,
            user_name=req.user_name,
            process_id=4092,
            process_guid=guid,
            process_name=req.process_name,
            process_path=f"C:\\Windows\\System32\\{req.process_name}",
            command_line=req.command_line
        )
        soc_state.correlator.add_process(ev)
        soc_state.all_events.append({"type": "PROCESS", "host": req.host_name, "detail": f"Command: {req.command_line}", "timestamp": now})
        alerts = soc_state.detector.evaluate_process(ev)

    for a in alerts:
        soc_state.correlator.associate_alert(a)
        soc_state.all_alerts.append(a)

    incident = None
    if alerts:
        incident = soc_state.correlator.correlate_incident(alerts[0])

    return {
        "status": "SUCCESS",
        "alerts_triggered": len(alerts),
        "incident_created": incident
    }

@router.post("/simulator/launch")
def launch_simulation(req: SimulationRequest):
    if req.scenario == "ransomware":
        sim_data = AdversarySimulator.generate_ransomware_campaign_telemetry(host_name=req.target_host or "SRV-DATA-01")
    elif req.scenario == "lateral":
        sim_data = AdversarySimulator.generate_lateral_movement_campaign_telemetry(host_name=req.target_host or "OPS-WS-11")
    else:
        sim_data = AdversarySimulator.generate_apt_campaign_telemetry(host_name=req.target_host or "FIN-WKS-01")

    events = sim_data["events"]
    soc_state.telemetry_count += len(events)
    campaign_alerts: List[DetectionAlert] = []

    for ev in events:
        if isinstance(ev, ProcessTelemetry):
            soc_state.correlator.add_process(ev)
            soc_state.all_events.append({
                "type": "PROCESS",
                "host": ev.host_name,
                "user": ev.user_name,
                "label": ev.process_name,
                "detail": ev.command_line,
                "timestamp": ev.timestamp
            })
            alerts = soc_state.detector.evaluate_process(ev)
            for a in alerts:
                soc_state.correlator.associate_alert(a)
                soc_state.all_alerts.append(a)
                campaign_alerts.append(a)
        elif isinstance(ev, NetworkTelemetry):
            soc_state.correlator.add_network(ev)
            soc_state.all_events.append({
                "type": "NETWORK",
                "host": ev.host_name,
                "user": "SYSTEM",
                "label": f"{ev.dest_ip}:{ev.dest_port}",
                "detail": f"Outbound {ev.protocol} to {ev.dest_ip} ({ev.domain or 'No Domain'})",
                "timestamp": ev.timestamp
            })
            alerts = soc_state.detector.evaluate_network(ev)
            for a in alerts:
                soc_state.correlator.associate_alert(a)
                soc_state.all_alerts.append(a)
                campaign_alerts.append(a)
        elif isinstance(ev, FileTelemetry):
            soc_state.correlator.add_file(ev)
            soc_state.all_events.append({
                "type": "FILE",
                "host": ev.host_name,
                "user": "SYSTEM",
                "label": ev.file_path.split("\\")[-1],
                "detail": f"File {ev.action} at {ev.file_path}",
                "timestamp": ev.timestamp
            })
            alerts = soc_state.detector.evaluate_file(ev)
            for a in alerts:
                soc_state.correlator.associate_alert(a)
                soc_state.all_alerts.append(a)
                campaign_alerts.append(a)

    if campaign_alerts:
        primary_alert = max(campaign_alerts, key=lambda a: ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(a.severity.value))
        incident_graph = soc_state.correlator.correlate_incident(primary_alert)
        return {
            "message": f"Simulation '{sim_data['campaign_name']}' completed successfully.",
            "events_ingested": len(events),
            "alerts_triggered": len(campaign_alerts),
            "incident_created": incident_graph
        }

    return {
        "message": "Simulation ran but no alerts were triggered.",
        "events_ingested": len(events),
        "alerts_triggered": 0
    }

@router.post("/soar/playbooks/execute")
def execute_playbook(req: PlaybookExecuteRequest):
    incident = soc_state.correlator.get_incident(req.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if "ransomware" in req.playbook_name.lower():
        result = soc_state.soar.run_ransomware_containment(incident)
    else:
        result = soc_state.soar.run_c2_containment(incident)

    return {
        "status": "SUCCESS",
        "playbook_name": result.playbook_name,
        "incident_id": result.incident_id,
        "summary": result.summary,
        "actions": [a.model_dump() for a in result.actions],
        "incident_updated": incident
    }

@router.post("/soar/actions/execute-single")
def execute_single_action(req: SingleActionRequest):
    incident = soc_state.correlator.get_incident(req.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    action_obj: Optional[SOARPlaybookAction] = None
    if req.action_type == "isolate_host":
        action_obj = ActionExecutor.isolate_host(req.host_name or "TARGET-HOST", req.target_value)
    elif req.action_type == "terminate_process":
        action_obj = ActionExecutor.terminate_process(req.host_name or "TARGET-HOST", req.target_value, "Malicious Process")
    elif req.action_type == "block_ip":
        action_obj = ActionExecutor.block_c2_ip(req.target_value)
    elif req.action_type == "revoke_user":
        action_obj = ActionExecutor.revoke_credentials(req.target_value)

    if not action_obj:
        raise HTTPException(status_code=400, detail="Invalid action type")

    incident.containment_status = "CONTAINED"
    return {
        "status": "SUCCESS",
        "action": action_obj.model_dump(),
        "incident_id": incident.incident_id
    }

@router.get("/soar/history")
def get_soar_history():
    return soc_state.soar.get_playbook_history()
