"""
Graph-Based Attack Path Correlator
Constructs stateful in-memory process-network-file provenance graphs and extracts multi-hop attack paths.
Includes Threat Intelligence enrichment and intelligent Incident Merging / Deduplication.
"""
import networkx as nx
from typing import Dict, List, Set, Any, Optional
from datetime import datetime, timezone
import uuid

from backend.app.models.telemetry import (
    ProcessTelemetry, NetworkTelemetry, FileTelemetry,
    DetectionAlert, GraphNode, GraphEdge, AttackPathGraph, Severity
)
from backend.app.engine.mitre_mapper import MitreMapper
from backend.app.engine.threat_intel import ThreatIntelEngine

class GraphCorrelator:
    def __init__(self):
        # Global Directed Multigraph holding all telemetry provenance
        self.graph = nx.MultiDiGraph()
        # Incident storage mapping incident_id -> AttackPathGraph
        self.incidents: Dict[str, AttackPathGraph] = {}
        # Mapping process_guid -> list of alerts
        self.node_alerts: Dict[str, List[DetectionAlert]] = {}

    def add_process(self, event: ProcessTelemetry):
        node_id = event.process_guid
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                label=event.process_name,
                type="process",
                host=event.host_name,
                host_ip=event.host_ip,
                user=event.user_name,
                pid=event.process_id,
                command_line=event.command_line,
                path=event.process_path,
                hashes=event.hashes,
                timestamp=event.timestamp,
                severity="INFORMATIONAL",
                risk_score=0.0
            )

        # Parent process edge
        if event.parent_process_guid:
            parent_id = event.parent_process_guid
            if not self.graph.has_node(parent_id):
                self.graph.add_node(
                    parent_id,
                    label=event.parent_process_name or "parent_proc",
                    type="process",
                    host=event.host_name,
                    host_ip=event.host_ip,
                    user=event.user_name,
                    pid=event.parent_process_id or 0,
                    command_line=event.parent_command_line or "",
                    timestamp=event.timestamp,
                    severity="INFORMATIONAL",
                    risk_score=0.0
                )
            self.graph.add_edge(
                parent_id,
                node_id,
                relationship="SPAWNED",
                timestamp=event.timestamp
            )

    def add_network(self, event: NetworkTelemetry):
        proc_node = event.process_guid
        if not self.graph.has_node(proc_node):
            self.graph.add_node(
                proc_node,
                label=event.process_name,
                type="process",
                host=event.host_name,
                pid=event.process_id,
                timestamp=event.timestamp,
                severity="INFORMATIONAL",
                risk_score=0.0
            )

        ip_node = f"ip:{event.dest_ip}"
        intel = ThreatIntelEngine.lookup_ioc(event.dest_ip)
        initial_sev = "INFORMATIONAL"
        initial_risk = 0.0
        if intel.get("verdict") == "MALICIOUS":
            initial_sev = "HIGH"
            initial_risk = float(intel.get("threat_score", 85))
        elif intel.get("verdict") == "SUSPICIOUS":
            initial_sev = "MEDIUM"
            initial_risk = float(intel.get("threat_score", 60))

        if not self.graph.has_node(ip_node):
            self.graph.add_node(
                ip_node,
                label=f"{event.dest_ip}:{event.dest_port}",
                type="network",
                dest_ip=event.dest_ip,
                dest_port=event.dest_port,
                protocol=event.protocol,
                domain=event.domain or "",
                threat_intel=intel,
                timestamp=event.timestamp,
                severity=initial_sev,
                risk_score=initial_risk
            )

        self.graph.add_edge(
            proc_node,
            ip_node,
            relationship="CONNECTED_TO",
            timestamp=event.timestamp,
            dest_port=event.dest_port,
            protocol=event.protocol
        )

    def add_file(self, event: FileTelemetry):
        proc_node = event.process_guid
        if not self.graph.has_node(proc_node):
            self.graph.add_node(
                proc_node,
                label=event.process_name,
                type="process",
                host=event.host_name,
                pid=event.process_id,
                timestamp=event.timestamp,
                severity="INFORMATIONAL",
                risk_score=0.0
            )

        file_node = f"file:{event.file_path}"
        sev = "HIGH" if ".locked" in event.file_path or ".crypt" in event.file_path or "lsass" in event.file_path else "INFORMATIONAL"
        if not self.graph.has_node(file_node):
            self.graph.add_node(
                file_node,
                label=event.file_path.split("\\")[-1].split("/")[-1] or event.file_path,
                type="file",
                path=event.file_path,
                action=event.action,
                extension=event.file_extension,
                timestamp=event.timestamp,
                severity=sev,
                risk_score=75.0 if sev == "HIGH" else 0.0
            )

        self.graph.add_edge(
            proc_node,
            file_node,
            relationship=f"MODIFIED_FILE ({event.action})",
            timestamp=event.timestamp
        )

    def associate_alert(self, alert: DetectionAlert):
        node_id = alert.process_guid
        if node_id not in self.node_alerts:
            self.node_alerts[node_id] = []
        self.node_alerts[node_id].append(alert)

        if self.graph.has_node(node_id):
            curr_sev = self.graph.nodes[node_id].get("severity", "INFORMATIONAL")
            sev_levels = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if sev_levels.index(alert.severity.value) > sev_levels.index(curr_sev):
                self.graph.nodes[node_id]["severity"] = alert.severity.value

            tech_info = MitreMapper.get_technique(alert.mitre_technique_id)
            self.graph.nodes[node_id]["risk_score"] = min(
                100.0, 
                self.graph.nodes[node_id].get("risk_score", 0.0) + (tech_info["base_score"] * 10)
            )

    def correlate_incident(self, trigger_alert: DetectionAlert) -> AttackPathGraph:
        """
        Reconstructs the full multi-hop attack path around a triggered alert.
        Traverses upstream (ancestors) to find Patient Zero, and downstream (children, network, files)
        to identify total blast radius.
        Merges automatically into existing incident if nodes overlap.
        """
        target_node = trigger_alert.process_guid
        if not self.graph.has_node(target_node):
            self.graph.add_node(
                target_node,
                label=trigger_alert.process_name,
                type="process",
                host=trigger_alert.host_name,
                host_ip=trigger_alert.host_ip,
                user=trigger_alert.user_name,
                severity=trigger_alert.severity.value,
                risk_score=75.0,
                timestamp=trigger_alert.timestamp
            )

        # 1. Discover Ancestors (Patient Zero / Root Process)
        ancestor_nodes = set()
        queue = [target_node]
        visited = set()
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            ancestor_nodes.add(curr)
            for predecessor in self.graph.predecessors(curr):
                if predecessor not in visited:
                    queue.append(predecessor)

        root_candidates = [n for n in ancestor_nodes if self.graph.in_degree(n) == 0]
        root_node_id = root_candidates[0] if root_candidates else target_node

        # 2. Discover Descendants (Blast Radius: Child procs, Network connections, File writes)
        descendant_nodes = set()
        queue = list(ancestor_nodes)
        visited_desc = set()
        while queue:
            curr = queue.pop(0)
            if curr in visited_desc:
                continue
            visited_desc.add(curr)
            descendant_nodes.add(curr)
            for successor in self.graph.successors(curr):
                if successor not in visited_desc:
                    queue.append(successor)

        all_incident_nodes = ancestor_nodes.union(descendant_nodes)
        subgraph = self.graph.subgraph(all_incident_nodes)

        # 3. Extract Nodes and Edges
        out_nodes: List[GraphNode] = []
        techniques_set: Set[str] = set()
        tactics_set: Set[str] = set()

        for n in subgraph.nodes():
            node_attrs = subgraph.nodes[n]
            alerts = self.node_alerts.get(n, [])
            for a in alerts:
                techniques_set.add(a.mitre_technique_id)
                tactics_set.add(a.mitre_tactic)

            out_nodes.append(GraphNode(
                id=n,
                label=node_attrs.get("label", n),
                type=node_attrs.get("type", "process"),
                severity=node_attrs.get("severity", "INFORMATIONAL"),
                risk_score=float(node_attrs.get("risk_score", 0.0)),
                properties={k: v for k, v in node_attrs.items() if k not in ["label", "type", "severity", "risk_score"]}
            ))

        out_edges: List[GraphEdge] = []
        for u, v, k, data in subgraph.edges(keys=True, data=True):
            out_edges.append(GraphEdge(
                source=u,
                target=v,
                relationship=data.get("relationship", "ASSOCIATED_WITH"),
                timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                properties={k: v for k, v in data.items() if k not in ["relationship", "timestamp"]}
            ))

        # 4. Calculate Composite Incident Risk Score
        techniques_set.add(trigger_alert.mitre_technique_id)
        tactics_set.add(trigger_alert.mitre_tactic)

        techniques_list = sorted(list(techniques_set))
        tactics_list = sorted(list(tactics_set))
        composite_score = MitreMapper.calculate_attack_path_score(techniques_list)

        if composite_score >= 80.0:
            overall_severity = Severity.CRITICAL
        elif composite_score >= 60.0:
            overall_severity = Severity.HIGH
        elif composite_score >= 35.0:
            overall_severity = Severity.MEDIUM
        else:
            overall_severity = Severity.LOW

        # 5. Incident Deduplication & Merging: Check if an existing incident already owns these nodes
        existing_incident_id = None
        for inc_id, existing in self.incidents.items():
            existing_node_ids = {n.id for n in existing.nodes}
            if root_node_id in existing_node_ids or target_node in existing_node_ids or existing.root_node_id == root_node_id:
                existing_incident_id = inc_id
                break

        if existing_incident_id:
            incident_id = existing_incident_id
            # Preserve or upgrade title
            if trigger_alert.severity.value in ["CRITICAL", "HIGH"]:
                title = f"Multi-Stage Attack: {trigger_alert.rule_name} on {trigger_alert.host_name}"
            else:
                title = self.incidents[incident_id].title
            containment_status = self.incidents[incident_id].containment_status
        else:
            incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
            title = f"Multi-Stage Attack: {trigger_alert.rule_name} on {trigger_alert.host_name}"
            containment_status = "ACTIVE"

        attack_graph = AttackPathGraph(
            incident_id=incident_id,
            title=title,
            root_node_id=root_node_id,
            threat_actor_hint="APT Simulation / Emulated Campaign",
            overall_severity=overall_severity,
            overall_risk_score=composite_score,
            mitre_tactics=tactics_list,
            mitre_techniques=techniques_list,
            nodes=out_nodes,
            edges=out_edges,
            containment_status=containment_status
        )

        self.incidents[incident_id] = attack_graph
        return attack_graph

    def get_incident(self, incident_id: str) -> Optional[AttackPathGraph]:
        return self.incidents.get(incident_id)

    def get_all_incidents(self) -> List[AttackPathGraph]:
        return sorted(self.incidents.values(), key=lambda x: x.overall_risk_score, reverse=True)
