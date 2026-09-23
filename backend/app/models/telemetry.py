"""
Telemetry and Data Models for AegisGraph-SOC
OCSF (Open Cybersecurity Schema Framework) / ECS Compliant Models
"""
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

class EventType(str, Enum):
    PROCESS_CREATION = "process_creation"
    PROCESS_TERMINATION = "process_termination"
    NETWORK_CONNECTION = "network_connection"
    FILE_MODIFICATION = "file_modification"
    REGISTRY_MODIFICATION = "registry_modification"
    AUTHENTICATION = "authentication"
    MEMORY_INJECTION = "memory_injection"

class Severity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ProcessTelemetry(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: EventType = EventType.PROCESS_CREATION
    host_name: str
    host_ip: str
    user_name: str
    process_id: int
    process_guid: str
    process_name: str
    process_path: str
    command_line: str
    parent_process_id: Optional[int] = None
    parent_process_guid: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_command_line: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict) # sha256, md5

class NetworkTelemetry(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: EventType = EventType.NETWORK_CONNECTION
    host_name: str
    process_id: int
    process_guid: str
    process_name: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str = "TCP"
    direction: str = "outbound"
    bytes_sent: Optional[int] = 0
    domain: Optional[str] = None

class FileTelemetry(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: EventType = EventType.FILE_MODIFICATION
    host_name: str
    process_id: int
    process_guid: str
    process_name: str
    file_path: str
    action: str = "created" # created, modified, deleted, encrypted
    file_extension: str = ""
    file_hash: Optional[str] = None

class DetectionAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    rule_id: str
    rule_name: str
    rule_description: str
    severity: Severity
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    host_name: str
    host_ip: str
    user_name: str
    process_guid: str
    process_name: str
    matched_event_id: str
    details: Dict[str, Any] = Field(default_factory=dict)

class GraphNode(BaseModel):
    id: str
    label: str # e.g. "powershell.exe", "185.220.101.5", "vssadmin.exe"
    type: str  # "process", "network", "file", "user", "host"
    severity: Optional[str] = "INFORMATIONAL"
    risk_score: float = 0.0
    properties: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str # SPAWNED, CONNECTED_TO, MODIFIED_FILE, INJECTED_INTO
    timestamp: str
    properties: Dict[str, Any] = Field(default_factory=dict)

class AttackPathGraph(BaseModel):
    incident_id: str
    title: str
    root_node_id: str
    threat_actor_hint: Optional[str] = None
    overall_severity: Severity
    overall_risk_score: float
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    containment_status: str = "ACTIVE" # ACTIVE, CONTAINED, REMEDIATED

class SOARPlaybookAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_name: str
    target_type: str # host, process, ip, user
    target_value: str
    status: str = "PENDING" # PENDING, APPROVED, EXECUTED, FAILED
    execution_log: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
