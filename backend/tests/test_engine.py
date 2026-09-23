"""
Unit & Integration Tests for AegisGraph-SOC Engine
Validates rule engine, graph correlation, dynamic SOAR extraction, Threat Intel, and Lifecycle.
"""
import pytest
from backend.app.models.telemetry import ProcessTelemetry, NetworkTelemetry, EventType, Severity
from backend.app.engine.detection import DetectionEngine
from backend.app.engine.graph_correlator import GraphCorrelator
from backend.app.engine.mitre_mapper import MitreMapper
from backend.app.engine.threat_intel import ThreatIntelEngine
from backend.app.soar.playbooks import SOAROrchestrator
from backend.app.simulator.adversary import AdversarySimulator

def test_mitre_mapper_scoring():
    single_tech = ["T1059.001"]
    score1 = MitreMapper.calculate_attack_path_score(single_tech)
    assert score1 > 0

    multi_tech = ["T1566.001", "T1059.001", "T1071.001", "T1003.001"]
    score2 = MitreMapper.calculate_attack_path_score(multi_tech)
    assert score2 > score1
    assert score2 >= 70.0

def test_sigma_detection_rule_matching():
    import os
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
    engine = DetectionEngine(rules_dir)
    assert len(engine.rules) >= 5

    malicious_event = ProcessTelemetry(
        host_name="TEST-PC",
        host_ip="192.168.1.50",
        user_name="admin",
        process_id=1234,
        process_guid="guid-1234",
        process_name="powershell.exe",
        process_path="C:\\Windows\\System32\\powershell.exe",
        command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi..."
    )

    alerts = engine.evaluate_process(malicious_event)
    assert len(alerts) >= 1
    assert alerts[0].rule_id == "SIGMA-001"
    assert alerts[0].mitre_technique_id == "T1059.001"

def test_threat_intel_enrichment():
    # Known Tor / C2 IP
    c2_info = ThreatIntelEngine.lookup_ioc("185.220.101.5")
    assert c2_info["verdict"] == "MALICIOUS"
    assert "APT29" in c2_info["threat_actor"]
    assert c2_info["threat_score"] >= 90

    # Internal RFC1918 IP
    internal_info = ThreatIntelEngine.lookup_ioc("192.168.1.100")
    assert internal_info["verdict"] == "INTERNAL"
    assert internal_info["threat_score"] == 0

def test_graph_attack_path_correlation_and_deduplication():
    correlator = GraphCorrelator()
    sim_data = AdversarySimulator.generate_apt_campaign_telemetry()
    events = sim_data["events"]

    import os
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
    detector = DetectionEngine(rules_dir)

    all_alerts = []
    for ev in events:
        if isinstance(ev, ProcessTelemetry):
            correlator.add_process(ev)
            alerts = detector.evaluate_process(ev)
            for a in alerts:
                correlator.associate_alert(a)
                all_alerts.append(a)
        elif isinstance(ev, NetworkTelemetry):
            correlator.add_network(ev)

    assert len(all_alerts) > 0
    # First correlation
    inc1 = correlator.correlate_incident(all_alerts[0])
    first_id = inc1.incident_id

    # Second correlation on another alert in same chain should merge into SAME incident
    if len(all_alerts) > 1:
        inc2 = correlator.correlate_incident(all_alerts[1])
        assert inc2.incident_id == first_id # Verified deduplication & merging!

def test_dynamic_soar_execution():
    correlator = GraphCorrelator()
    sim_data = AdversarySimulator.generate_ransomware_campaign_telemetry(host_name="PROD-DB-09", host_ip="10.20.30.40")

    import os
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
    detector = DetectionEngine(rules_dir)

    all_alerts = []
    for ev in sim_data["events"]:
        if isinstance(ev, ProcessTelemetry):
            correlator.add_process(ev)
            for a in detector.evaluate_process(ev):
                correlator.associate_alert(a)
                all_alerts.append(a)

    incident = correlator.correlate_incident(all_alerts[0])
    soar = SOAROrchestrator()
    result = soar.run_ransomware_containment(incident)

    assert incident.containment_status == "CONTAINED"
    # Verify dynamic host extraction
    assert any("PROD-DB-09" in a.execution_log for a in result.actions)
