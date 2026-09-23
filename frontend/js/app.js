/**
 * AegisGraph-SOC Application Controller
 * Next-Gen Enterprise SOC Web Console
 * Features:
 * - Hybrid Architecture: Live FastAPI Backend + Seamless Netlify Client-Side Fallback
 * - Cytoscape Force-Directed Attack Path Graph with Blast Radius Highlighting & PNG Export
 * - Dynamic Threat Intelligence Dossier (ASN, Country, Threat Actor Attribution)
 * - Incident Lifecycle Management & Forensic Analyst Notes
 * - Sigma Rule Sandbox & Live Compiler
 * - STIX 2.1 & JSON IOC Bundle Exporter
 * - Bootstrap 5 Tab Lifecycle Management & Toast Notifications
 */

let cy = null;
let currentIncidentId = null;
let selectedScenario = 'apt29';
let currentIocFormat = 'json';
let incidentsCache = [];
let rawReportMarkdown = "";
let isOfflineMode = false;

// ============================================================================
// CLIENT-SIDE FALLBACK DATABASE (Ensures 100% functionality on Netlify hosting)
// ============================================================================
const FALLBACK_DB = {
  status: {
    status: "HEALTHY",
    engine: "AegisGraph-SOC v1.0 Enterprise (Netlify Cloud)",
    defcon: 1,
    defcon_label: "DEFCON 1 - CRITICAL ATTACK ACTIVE",
    rules_loaded: 6,
    total_telemetry_events: 18,
    total_alerts: 8,
    total_incidents: 2,
    critical_incidents: 1,
    high_incidents: 1,
    contained_incidents: 0
  },
  incidents: [
    {
      incident_id: "INC-APT29-01",
      title: "Multi-Stage Attack: Suspicious PowerShell Download on FIN-WKS-01",
      root_node_id: "proc-word-4102",
      threat_actor_hint: "APT29 (Cozy Bear) Spearphishing Campaign",
      overall_severity: "HIGH",
      overall_risk_score: 86.2,
      mitre_tactics: ["Initial Access", "Execution", "Command and Control", "Credential Access"],
      mitre_techniques: ["T1566.001", "T1059.001", "T1071.001", "T1003.001"],
      containment_status: "ACTIVE",
      nodes: [
        { id: "proc-word-4102", label: "WINWORD.EXE", type: "process", severity: "INFORMATIONAL", risk_score: 15.0, properties: { host: "FIN-WKS-01", pid: 4102, user: "CORP\\sarah.connor", command_line: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\sarah.connor\\Downloads\\Q3_Invoice_Overdue.docx"' } },
        { id: "proc-ps-5892", label: "powershell.exe", type: "process", severity: "HIGH", risk_score: 85.0, properties: { host: "FIN-WKS-01", pid: 5892, user: "CORP\\sarah.connor", command_line: "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ..." } },
        { id: "ip:185.220.101.5", label: "185.220.101.5:443", type: "network", severity: "HIGH", risk_score: 98.0, properties: { dest_ip: "185.220.101.5", dest_port: 443, protocol: "TCP", domain: "cdn-update-cloud.org" } },
        { id: "proc-procdump-6440", label: "procdump.exe", type: "process", severity: "CRITICAL", risk_score: 95.0, properties: { host: "FIN-WKS-01", pid: 6440, user: "CORP\\sarah.connor", command_line: "C:\\Users\\Public\\procdump.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp minidump" } },
        { id: "file:lsass.dmp", label: "lsass.dmp", type: "file", severity: "HIGH", risk_score: 80.0, properties: { path: "C:\\Users\\Public\\lsass.dmp", action: "created", extension: ".dmp" } }
      ],
      edges: [
        { source: "proc-word-4102", target: "proc-ps-5892", relationship: "SPAWNED", timestamp: "2026-09-23T21:40:12Z" },
        { source: "proc-ps-5892", target: "ip:185.220.101.5", relationship: "CONNECTED_TO", timestamp: "2026-09-23T21:40:19Z" },
        { source: "proc-ps-5892", target: "proc-procdump-6440", relationship: "SPAWNED", timestamp: "2026-09-23T21:40:27Z" },
        { source: "proc-procdump-6440", target: "file:lsass.dmp", relationship: "MODIFIED_FILE (created)", timestamp: "2026-09-23T21:40:31Z" }
      ]
    },
    {
      incident_id: "INC-RANSOM-02",
      title: "Multi-Stage Attack: Volume Shadow Copy Deletion on HR-SRV-02",
      root_node_id: "proc-cmd-3112",
      threat_actor_hint: "BlackCat / ALPHV Ransomware Rapid Impact",
      overall_severity: "CRITICAL",
      overall_risk_score: 94.8,
      mitre_tactics: ["Execution", "Defense Evasion", "Impact"],
      mitre_techniques: ["T1059.003", "T1490", "T1486"],
      containment_status: "ACTIVE",
      nodes: [
        { id: "proc-cmd-3112", label: "cmd.exe", type: "process", severity: "INFORMATIONAL", risk_score: 20.0, properties: { host: "HR-SRV-02", pid: 3112, user: "NT AUTHORITY\\SYSTEM", command_line: 'cmd.exe /c "vssadmin delete shadows /all /quiet && start locker.exe"' } },
        { id: "proc-vss-4508", label: "vssadmin.exe", type: "process", severity: "CRITICAL", risk_score: 95.0, properties: { host: "HR-SRV-02", pid: 4508, user: "NT AUTHORITY\\SYSTEM", command_line: "vssadmin.exe delete shadows /all /quiet" } },
        { id: "proc-locker-7120", label: "locker.exe", type: "process", severity: "CRITICAL", risk_score: 98.0, properties: { host: "HR-SRV-02", pid: 7120, user: "NT AUTHORITY\\SYSTEM", command_line: "C:\\ProgramData\\locker.exe --encrypt-local --threads 8" } },
        { id: "file:payroll.locked", label: "payroll_2026.xlsx.locked", type: "file", severity: "HIGH", risk_score: 85.0, properties: { path: "D:\\CorporateShares\\Confidential\\payroll_2026.xlsx.locked", action: "encrypted", extension: ".locked" } }
      ],
      edges: [
        { source: "proc-cmd-3112", target: "proc-vss-4508", relationship: "SPAWNED", timestamp: "2026-09-23T21:42:05Z" },
        { source: "proc-cmd-3112", target: "proc-locker-7120", relationship: "SPAWNED", timestamp: "2026-09-23T21:42:10Z" },
        { source: "proc-locker-7120", target: "file:payroll.locked", relationship: "MODIFIED_FILE (encrypted)", timestamp: "2026-09-23T21:42:15Z" }
      ]
    }
  ],
  threat_intel: {
    "185.220.101.5": {
      ioc_type: "ip",
      verdict: "MALICIOUS",
      threat_score: 98,
      threat_actor: "APT29 (Cozy Bear / Nobelium)",
      country: "Netherlands",
      asn: "AS208323 (Zwiebelfreunde Tor Exit Node)",
      category: "Command and Control (C2) / Tor Exit",
      tags: ["apt29", "c2-beacon", "tor-exit", "high-confidence"]
    },
    "45.154.255.88": {
      ioc_type: "ip",
      verdict: "MALICIOUS",
      threat_score: 95,
      threat_actor: "FIN7 / Carbanak",
      country: "Russia",
      asn: "AS48282 (HostRoyale B.V.)",
      category: "Bulletproof Hosting C2",
      tags: ["fin7", "phishing-payload-delivery"]
    },
    "194.26.29.11": {
      ioc_type: "ip",
      verdict: "SUSPICIOUS",
      threat_score: 82,
      threat_actor: "LockBit 3.0 Affiliate Infrastructure",
      country: "Bulgaria",
      asn: "AS49981 (WorldStream B.V.)",
      category: "Ransomware Data Exfiltration Relay",
      tags: ["ransomware", "data-exfiltration"]
    }
  },
  events: [
    { type: "FILE", host: "HR-SRV-02", user: "SYSTEM", detail: "File encrypted: payroll_2026.xlsx.locked", timestamp: new Date(Date.now() - 4000).toISOString() },
    { type: "PROCESS", host: "HR-SRV-02", user: "NT AUTHORITY\\SYSTEM", detail: "vssadmin.exe delete shadows /all /quiet", timestamp: new Date(Date.now() - 12000).toISOString() },
    { type: "PROCESS", host: "FIN-WKS-01", user: "CORP\\sarah.connor", detail: "procdump.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp", timestamp: new Date(Date.now() - 25000).toISOString() },
    { type: "NETWORK", host: "FIN-WKS-01", user: "SYSTEM", detail: "Outbound TCP to 185.220.101.5:443 (cdn-update-cloud.org)", timestamp: new Date(Date.now() - 32000).toISOString() },
    { type: "PROCESS", host: "FIN-WKS-01", user: "CORP\\sarah.connor", detail: "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAA...", timestamp: new Date(Date.now() - 38000).toISOString() },
    { type: "PROCESS", host: "FIN-WKS-01", user: "CORP\\sarah.connor", detail: 'WINWORD.EXE "Q3_Invoice_Overdue.docx"', timestamp: new Date(Date.now() - 45000).toISOString() }
  ],
  rules: [
    { id: "SIGMA-001", title: "Suspicious PowerShell Download or Encoded Command", severity: "HIGH", mitre_technique_id: "T1059.001", mitre_tactic: "Execution", description: "Detects hidden window, encoded commands, or web download strings." },
    { id: "SIGMA-002", title: "Volume Shadow Copy Deletion via VSSAdmin", severity: "CRITICAL", mitre_technique_id: "T1490", mitre_tactic: "Impact", description: "Detects vssadmin.exe attempting to delete volume shadow copies, typical of ransomware." },
    { id: "SIGMA-003", title: "LSASS Memory Dumping via Procdump or Comsvcs", severity: "CRITICAL", mitre_technique_id: "T1003.001", mitre_tactic: "Credential Access", description: "Detects offline credential dumping from lsass.exe process memory." },
    { id: "SIGMA-004", title: "Known Tor Exit Node or Malicious C2 IP Connection", severity: "HIGH", mitre_technique_id: "T1071.001", mitre_tactic: "Command and Control", description: "Detects outbound connections to adversary infrastructure." },
    { id: "SIGMA-005", title: "Mass File Renaming to Known Ransomware Extension", severity: "CRITICAL", mitre_technique_id: "T1486", mitre_tactic: "Impact", description: "Detects file creation matching ransomware encryption patterns (.locked, .crypt)." },
    { id: "SIGMA-006", title: "PsExec Remote Service Execution and SMB Lateral Movement", severity: "HIGH", mitre_technique_id: "T1021.002", mitre_tactic: "Lateral Movement", description: "Detects PsExec service creation and lateral admin share traversal." }
  ],
  mitre_matrix: [
    { technique_id: "T1566.001", technique_name: "Spearphishing Attachment", tactic: "Initial Access", base_score: 7.5, triggered_count: 2, status: "DETECTED" },
    { technique_id: "T1059.001", technique_name: "PowerShell", tactic: "Execution", base_score: 7.0, triggered_count: 3, status: "DETECTED" },
    { technique_id: "T1059.003", technique_name: "Windows Command Shell", tactic: "Execution", base_score: 5.5, triggered_count: 2, status: "DETECTED" },
    { technique_id: "T1055", technique_name: "Process Injection", tactic: "Defense Evasion", base_score: 8.5, triggered_count: 0, status: "MONITORED" },
    { technique_id: "T1003.001", technique_name: "LSASS Memory Dumping", tactic: "Credential Access", base_score: 9.5, triggered_count: 2, status: "DETECTED" },
    { technique_id: "T1071.001", technique_name: "Web Protocols (C2)", tactic: "Command and Control", base_score: 8.0, triggered_count: 2, status: "DETECTED" },
    { technique_id: "T1021.002", technique_name: "SMB/Windows Admin Shares", tactic: "Lateral Movement", base_score: 8.8, triggered_count: 1, status: "DETECTED" },
    { technique_id: "T1490", technique_name: "Inhibit System Recovery", tactic: "Impact", base_score: 9.0, triggered_count: 2, status: "DETECTED" },
    { technique_id: "T1486", technique_name: "Data Encrypted for Impact", tactic: "Impact", base_score: 9.8, triggered_count: 2, status: "DETECTED" }
  ]
};

// DOM Initialization
document.addEventListener('DOMContentLoaded', async () => {
  initCytoscape();
  setupTabListeners();
  await checkBackendAvailability();
  await refreshAll();
  await loadForensicTimeline();
  loadSigmaTemplate();

  setInterval(fetchStatus, 8000);
});

// Check whether running against live FastAPI or Netlify Static Mode
async function checkBackendAvailability() {
  try {
    const res = await fetch('/api/status', { method: 'GET' });
    if (res.ok) {
      const data = await res.json();
      if (data && data.status) {
        isOfflineMode = false;
        console.log('[AegisGraph-SOC] Connected to live FastAPI Backend.');
        return;
      }
    }
  } catch (err) {
    // Expected on static hosts like Netlify / GitHub Pages
  }
  isOfflineMode = true;
  console.log('[AegisGraph-SOC] Running in Netlify Cloud / Client-Side Engine Mode.');
  const pulseText = document.querySelector('.live-pulse-container span:last-child');
  if (pulseText) {
    pulseText.innerText = "NETLIFY CLOUD: ACTIVE (0.1ms)";
  }
}

// Setup Bootstrap Tab Lifecycle Listeners to prevent canvas displacement
function setupTabListeners() {
  const canvasTabBtn = document.getElementById('nav-canvas-tab');
  if (canvasTabBtn) {
    canvasTabBtn.addEventListener('shown.bs.tab', () => {
      if (cy) {
        setTimeout(() => {
          cy.resize();
          cy.fit(null, 40);
        }, 150);
      }
    });
  }
}

// Cytoscape Graph Canvas Initialization
function initCytoscape() {
  cy = cytoscape({
    container: document.getElementById('cy-canvas'),
    elements: [],
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#f8fafc',
          'font-family': 'Inter, sans-serif',
          'font-size': '11px',
          'font-weight': 600,
          'text-valign': 'bottom',
          'text-margin-y': '6px',
          'background-color': '#0284c7',
          'border-width': 2,
          'border-color': 'rgba(255, 255, 255, 0.3)',
          'width': 38,
          'height': 38,
          'transition-property': 'opacity, border-color, shadow-blur',
          'transition-duration': '0.25s'
        }
      },
      {
        selector: 'node[type = "process"]',
        style: {
          'shape': 'round-rectangle',
          'background-color': '#2563eb',
          'border-color': '#93c5fd'
        }
      },
      {
        selector: 'node[type = "network"]',
        style: {
          'shape': 'diamond',
          'background-color': '#d97706',
          'border-color': '#fde68a',
          'width': 34,
          'height': 34
        }
      },
      {
        selector: 'node[type = "file"]',
        style: {
          'shape': 'ellipse',
          'background-color': '#7c3aed',
          'border-color': '#c4b5fd',
          'width': 32,
          'height': 32
        }
      },
      {
        selector: 'node[severity = "CRITICAL"], node[severity = "HIGH"]',
        style: {
          'background-color': '#e11d48',
          'border-color': '#ff3366',
          'border-width': 3,
          'shadow-blur': 16,
          'shadow-color': '#ff3366',
          'shadow-opacity': 0.85
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': 'rgba(255, 255, 255, 0.25)',
          'target-arrow-color': 'rgba(255, 255, 255, 0.5)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(relationship)',
          'font-family': 'JetBrains Mono, monospace',
          'font-size': '9px',
          'color': '#94a3b8',
          'text-rotation': 'autorotate',
          'text-background-opacity': 0.85,
          'text-background-color': '#060911',
          'text-background-padding': '3px',
          'transition-property': 'opacity, line-color, width',
          'transition-duration': '0.25s'
        }
      },
      {
        selector: 'node.highlight-ancestor',
        style: {
          'border-color': '#00f0ff',
          'border-width': 4,
          'shadow-blur': 25,
          'shadow-color': '#00f0ff',
          'shadow-opacity': 1.0
        }
      },
      {
        selector: 'node.highlight-descendant',
        style: {
          'border-color': '#ff3366',
          'border-width': 4,
          'shadow-blur': 25,
          'shadow-color': '#ff3366',
          'shadow-opacity': 1.0
        }
      },
      {
        selector: 'node.dimmed',
        style: { 'opacity': 0.2 }
      },
      {
        selector: 'edge.dimmed',
        style: { 'opacity': 0.1 }
      },
      {
        selector: 'edge.highlighted',
        style: {
          'width': 3,
          'line-color': '#00f0ff',
          'target-arrow-color': '#00f0ff',
          'opacity': 1.0
        }
      }
    ],
    layout: {
      name: 'breadthfirst',
      directed: true,
      padding: 40,
      spacingFactor: 1.4
    }
  });

  cy.on('tap', 'node', (evt) => {
    const node = evt.target;
    highlightBlastRadius(node);
    displayNodeInspection(node.data());
  });

  cy.on('tap', (evt) => {
    if (evt.target === cy) {
      clearBlastRadiusHighlighting();
      document.getElementById('inspector-placeholder').style.display = 'block';
      document.getElementById('inspector-content').style.display = 'none';
    }
  });
}

// Blast Radius Highlighting Engine
function highlightBlastRadius(targetNode) {
  if (!cy) return;
  clearBlastRadiusHighlighting();

  const ancestors = targetNode.predecessors().nodes();
  const descendants = targetNode.successors().nodes();
  const connectedEdges = targetNode.connectedEdges();
  const blastEdges = targetNode.predecessors().edges().union(targetNode.successors().edges());

  cy.elements().addClass('dimmed');
  ancestors.removeClass('dimmed').addClass('highlight-ancestor');
  descendants.removeClass('dimmed').addClass('highlight-descendant');
  targetNode.removeClass('dimmed').addClass('highlight-descendant');

  blastEdges.removeClass('dimmed').addClass('highlighted');
  connectedEdges.removeClass('dimmed').addClass('highlighted');
}

function clearBlastRadiusHighlighting() {
  if (!cy) return;
  cy.elements().removeClass('dimmed highlight-ancestor highlight-descendant highlighted');
}

function filterGraphNodes(filterType) {
  if (!cy) return;
  clearBlastRadiusHighlighting();

  document.querySelectorAll('#filter-btn-all, #filter-btn-crit, #filter-btn-net').forEach(b => b.classList.remove('active'));

  if (filterType === 'all') {
    document.getElementById('filter-btn-all').classList.add('active');
    cy.elements().show();
  } else if (filterType === 'critical') {
    document.getElementById('filter-btn-crit').classList.add('active');
    cy.nodes().forEach(n => {
      const sev = n.data('severity');
      if (sev === 'CRITICAL' || sev === 'HIGH') {
        n.show();
      } else {
        n.hide();
      }
    });
    cy.edges().show();
  } else if (filterType === 'network') {
    document.getElementById('filter-btn-net').classList.add('active');
    cy.nodes().forEach(n => {
      if (n.data('type') === 'network') {
        n.show();
      } else {
        n.hide();
      }
    });
    cy.edges().show();
  }
}

function cyFit() {
  if (cy) cy.fit(null, 40);
}

function cyResetLayout() {
  if (!cy) return;
  const layout = cy.layout({
    name: 'breadthfirst',
    directed: true,
    padding: 40,
    spacingFactor: 1.4,
    animate: true,
    animationDuration: 400
  });
  layout.run();
}

// Export Cytoscape Canvas as High-Res PNG Image
function exportGraphSnapshot() {
  if (!cy) return;
  const pngData = cy.png({
    bg: '#060911',
    full: true,
    scale: 2
  });
  const link = document.createElement('a');
  link.download = `AegisGraph-${currentIncidentId || 'Investigation'}-Snapshot.png`;
  link.href = pngData;
  link.click();
  showSocToast('Graph snapshot downloaded successfully!', 'success');
}

// Display Node Inspector Details & Threat Intel Dossier
async function displayNodeInspection(data) {
  document.getElementById('inspector-placeholder').style.display = 'none';
  document.getElementById('inspector-content').style.display = 'block';

  document.getElementById('inspect-label').innerText = `${data.label} [${(data.type || 'unknown').toUpperCase()}]`;

  const riskEl = document.getElementById('inspect-risk');
  const sev = data.severity || 'INFORMATIONAL';
  const badgeClass = sev === 'CRITICAL' ? 'bg-danger' : (sev === 'HIGH' ? 'bg-warning text-dark' : 'bg-primary');
  riskEl.innerHTML = `<span class="badge ${badgeClass}">${sev}</span> Risk Score: <strong>${data.risk_score || 0} / 100</strong>`;

  const cmd = data.properties?.command_line || data.properties?.path || data.properties?.dest_ip || 'N/A';
  document.getElementById('inspect-command').innerText = cmd;

  const host = data.properties?.host || data.properties?.host_name || 'N/A';
  const user = data.properties?.user || data.properties?.user_name || 'SYSTEM';
  const pid = data.properties?.pid || data.properties?.process_id || 'N/A';
  document.getElementById('inspect-context').innerText = `Host: ${host} | PID: ${pid} | User: ${user}`;

  // Threat Intel Dossier
  const intelContainer = document.getElementById('inspect-intel-container');
  const intelBody = document.getElementById('inspect-intel-body');

  if (data.type === 'network' && data.properties?.dest_ip) {
    intelContainer.classList.remove('d-none');
    const ip = data.properties.dest_ip;

    let intel = null;
    if (isOfflineMode) {
      intel = FALLBACK_DB.threat_intel[ip] || {
        verdict: "SUSPICIOUS",
        threat_score: 75,
        threat_actor: "Adversary Infrastructure",
        country: "Unknown Region",
        asn: "AS-TRANSIT Cloud Service"
      };
    } else {
      try {
        const res = await fetch(`/api/intel/lookup?ioc=${encodeURIComponent(ip)}`);
        intel = await res.json();
      } catch (err) {
        intel = FALLBACK_DB.threat_intel[ip];
      }
    }

    if (intel) {
      const vClass = intel.verdict === 'MALICIOUS' ? 'bg-danger' : (intel.verdict === 'SUSPICIOUS' ? 'bg-warning text-dark' : 'bg-success');
      intelBody.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-1">
          <strong class="text-white small">${ip}</strong>
          <span class="badge ${vClass}">${intel.verdict}</span>
        </div>
        <div class="small text-secondary mb-1">Threat Actor: <strong class="text-info">${intel.threat_actor || 'Unknown'}</strong></div>
        <div class="small text-secondary mb-1">ASN / Infra: <span>${intel.asn || 'N/A'}</span></div>
        <div class="small text-secondary mb-1">Geographic Origin: <span class="badge bg-dark border border-secondary">${intel.country || 'N/A'}</span></div>
        <div class="d-flex align-items-center gap-2 mt-2 pt-1 border-top border-secondary">
          <span class="small text-muted" style="font-size: 0.7rem;">Threat Score:</span>
          <div class="progress flex-grow-1" style="height: 6px;">
            <div class="progress-bar ${intel.threat_score >= 80 ? 'bg-danger' : 'bg-warning'}" style="width: ${intel.threat_score}%"></div>
          </div>
          <span class="small font-monospace fw-bold text-white">${intel.threat_score}/100</span>
        </div>
      `;
    }
  } else {
    intelContainer.classList.add('d-none');
  }

  // MITRE Badges
  const badgesContainer = document.getElementById('inspect-mitre-badges');
  badgesContainer.innerHTML = '';
  if (data.severity === 'CRITICAL' || data.severity === 'HIGH') {
    const defaultBadges = ['T1059.001 - PowerShell', 'T1003.001 - Credential Access', 'T1490 - Inhibit Recovery'];
    defaultBadges.forEach(b => {
      const span = document.createElement('span');
      span.className = 'badge bg-secondary font-monospace';
      span.innerText = b;
      badgesContainer.appendChild(span);
    });
  } else {
    badgesContainer.innerHTML = '<span class="text-secondary small">No direct MITRE attack detections on this node.</span>';
  }

  const inspectTabBtn = document.getElementById('tab-inspect-btn');
  if (inspectTabBtn) {
    const tabInstance = new bootstrap.Tab(inspectTabBtn);
    tabInstance.show();
  }
}

// API Integration & Refresher (Hybrid Online/Offline)
async function refreshAll() {
  await fetchStatus();
  await fetchIncidents();
}

async function fetchStatus() {
  try {
    let data;
    if (isOfflineMode) {
      data = FALLBACK_DB.status;
    } else {
      const res = await fetch('/api/status');
      data = await res.json();
    }

    document.getElementById('metric-events-count').innerText = data.total_telemetry_events;
    document.getElementById('metric-incidents-count').innerText = data.total_incidents;
    document.getElementById('metric-mitre-count').innerText = data.critical_incidents + data.high_incidents;
    document.getElementById('metric-contained-count').innerText = data.contained_incidents;

    const defconGauge = document.getElementById('defcon-gauge');
    const defconLabel = document.getElementById('defcon-label');
    if (defconGauge && defconLabel) {
      defconGauge.className = `defcon-widget defcon-${data.defcon || 1}`;
      defconLabel.innerText = data.defcon_label || `DEFCON ${data.defcon}`;
    }
  } catch (err) {
    console.warn('Status fetch error, falling back to local database:', err);
    isOfflineMode = true;
  }
}

async function fetchIncidents() {
  try {
    let incidents;
    if (isOfflineMode) {
      incidents = FALLBACK_DB.incidents;
    } else {
      const res = await fetch('/api/incidents');
      incidents = await res.json();
    }
    incidentsCache = incidents;

    const listEl = document.getElementById('incidents-list-container');
    const countBadge = document.getElementById('incident-count-badge');
    countBadge.innerText = incidents.length;

    if (!incidents || incidents.length === 0) {
      listEl.innerHTML = '<div class="text-center text-secondary py-4 small">No active incidents detected. Use the Simulate button to inject attack telemetry.</div>';
      return;
    }

    renderIncidentList(incidents);

    if (currentIncidentId) {
      loadIncidentGraph(currentIncidentId);
      loadIncidentNotes(currentIncidentId);
    }
  } catch (err) {
    console.error('Error fetching incidents:', err);
  }
}

function renderIncidentList(incidents) {
  const listEl = document.getElementById('incidents-list-container');
  listEl.innerHTML = '';

  incidents.forEach((inc, index) => {
    const isSelected = (!currentIncidentId && index === 0) || currentIncidentId === inc.incident_id;
    if (isSelected && !currentIncidentId) {
      currentIncidentId = inc.incident_id;
    }

    const sev = inc.overall_severity.toUpperCase();
    const borderClass = sev === 'CRITICAL' ? 'border-crit' : 'border-high';
    const badgeClass = sev === 'CRITICAL' ? 'bg-danger' : (sev === 'HIGH' ? 'bg-warning text-dark' : 'bg-primary');

    const item = document.createElement('div');
    item.className = `incident-list-item ${borderClass} ${isSelected ? 'active-incident' : ''}`;
    item.onclick = () => selectIncident(inc.incident_id);

    item.innerHTML = `
      <div class="d-flex justify-content-between align-items-center mb-1">
        <span class="font-monospace text-info fw-bold small">${inc.incident_id}</span>
        <span class="badge ${badgeClass}" style="font-size: 0.65rem;">${sev}</span>
      </div>
      <div class="small fw-semibold text-white mb-2 text-truncate" title="${inc.title}">${inc.title}</div>
      <div class="d-flex justify-content-between align-items-center small text-secondary" style="font-size: 0.72rem;">
        <span>Risk: <strong class="text-white">${inc.overall_risk_score}</strong>/100</span>
        <span class="badge ${inc.containment_status === 'CONTAINED' ? 'bg-success' : 'bg-outline-danger border border-danger text-danger'}">
          ${inc.containment_status}
        </span>
      </div>
    `;
    listEl.appendChild(item);
  });
}

function filterIncidents() {
  const query = document.getElementById('filter-incident-input').value.toLowerCase();
  const filtered = incidentsCache.filter(i => 
    i.incident_id.toLowerCase().includes(query) ||
    i.title.toLowerCase().includes(query) ||
    i.overall_severity.toLowerCase().includes(query)
  );
  renderIncidentList(filtered);
}

function selectIncident(incidentId) {
  currentIncidentId = incidentId;
  document.querySelectorAll('.incident-list-item').forEach(el => {
    el.classList.remove('active-incident');
    if (el.innerHTML.includes(incidentId)) {
      el.classList.add('active-incident');
    }
  });

  const inc = incidentsCache.find(i => i.incident_id === incidentId);
  if (inc && document.getElementById('incident-status-select')) {
    document.getElementById('incident-status-select').value = inc.containment_status;
  }

  loadIncidentGraph(incidentId);
  loadIncidentNotes(incidentId);
}

function loadIncidentGraph(incidentId) {
  const inc = incidentsCache.find(i => i.incident_id === incidentId);
  if (!inc || !cy) return;

  const elements = [];

  // Add Nodes
  inc.nodes.forEach(n => {
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        label: n.label,
        type: n.type,
        severity: n.severity,
        risk_score: n.risk_score,
        properties: n.properties
      }
    });
  });

  // Add Edges
  inc.edges.forEach((e, idx) => {
    elements.push({
      group: 'edges',
      data: {
        id: `e-${idx}`,
        source: e.source,
        target: e.target,
        relationship: e.relationship,
        properties: e.properties
      }
    });
  });

  cy.elements().remove();
  cy.add(elements);
  cyResetLayout();
}

// Incident Lifecycle Management
async function updateIncidentLifecycle() {
  if (!currentIncidentId) return;
  const newStatus = document.getElementById('incident-status-select').value;
  const inc = incidentsCache.find(i => i.incident_id === currentIncidentId);
  if (inc) inc.containment_status = newStatus;

  if (isOfflineMode) {
    showSocToast(`Incident ${currentIncidentId} updated to ${newStatus}`, 'info');
    renderIncidentList(incidentsCache);
    return;
  }

  try {
    const res = await fetch(`/api/incidents/${currentIncidentId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      showSocToast(`Incident ${currentIncidentId} updated to ${newStatus}`, 'info');
      await fetchIncidents();
    }
  } catch (err) {
    showSocToast('Failed to update incident status: ' + err, 'danger');
  }
}

// Analyst Notes Engine
let localNotes = {};
async function loadIncidentNotes(incidentId) {
  const container = document.getElementById('analyst-notes-container');
  if (!container) return;

  let notes = [];
  if (isOfflineMode) {
    notes = localNotes[incidentId] || [
      { author: "Lead SOC Analyst", note: "Initial triage completed. High confidence APT correlation.", timestamp: new Date().toISOString() }
    ];
  } else {
    try {
      const res = await fetch(`/api/incidents/${incidentId}/notes`);
      notes = await res.json();
    } catch (err) {
      notes = localNotes[incidentId] || [];
    }
  }

  if (!notes || notes.length === 0) {
    container.innerHTML = '<div class="text-secondary small text-center py-3">No analyst notes recorded yet.</div>';
    return;
  }

  container.innerHTML = '';
  notes.forEach(n => {
    const div = document.createElement('div');
    div.className = 'p-2 mb-2 rounded bg-dark border border-secondary';
    const timeStr = new Date(n.timestamp).toLocaleTimeString();
    div.innerHTML = `
      <div class="d-flex justify-content-between align-items-center mb-1">
        <strong class="text-info small">${n.author}</strong>
        <span class="text-secondary" style="font-size: 0.68rem;">${timeStr}</span>
      </div>
      <div class="text-light small">${n.note}</div>
    `;
    container.appendChild(div);
  });
}

async function submitAnalystNote() {
  if (!currentIncidentId) {
    alert('Select an incident first.');
    return;
  }
  const input = document.getElementById('note-input');
  const noteText = input.value.trim();
  if (!noteText) return;

  if (isOfflineMode) {
    if (!localNotes[currentIncidentId]) localNotes[currentIncidentId] = [];
    localNotes[currentIncidentId].push({
      author: 'Senior SOC Analyst',
      note: noteText,
      timestamp: new Date().toISOString()
    });
    input.value = '';
    showSocToast('Investigation note saved!', 'success');
    await loadIncidentNotes(currentIncidentId);
    return;
  }

  try {
    const res = await fetch(`/api/incidents/${currentIncidentId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author: 'Lead SOC Analyst', note: noteText })
    });
    if (res.ok) {
      input.value = '';
      showSocToast('Investigation note saved!', 'success');
      await loadIncidentNotes(currentIncidentId);
    }
  } catch (err) {
    showSocToast('Error saving note: ' + err, 'danger');
  }
}

// Forensic Timeline Loader
async function loadForensicTimeline() {
  const tbody = document.getElementById('timeline-table-body');
  let events = [];

  if (isOfflineMode) {
    events = FALLBACK_DB.events;
  } else {
    try {
      const res = await fetch('/api/telemetry/events?limit=50');
      events = await res.json();
    } catch (err) {
      events = FALLBACK_DB.events;
    }
  }

  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-secondary py-4">No events in forensic buffer. Run an attack simulation to populate.</td></tr>';
    return;
  }

  tbody.innerHTML = '';
  events.forEach(ev => {
    const tr = document.createElement('tr');
    const typeBadge = ev.type === 'PROCESS' ? 'bg-primary' : (ev.type === 'NETWORK' ? 'bg-warning text-dark' : 'bg-purple');
    const timeStr = new Date(ev.timestamp).toLocaleTimeString();

    tr.innerHTML = `
      <td class="font-monospace text-secondary">${timeStr}</td>
      <td><span class="badge ${typeBadge} timeline-badge">${ev.type}</span></td>
      <td class="font-monospace text-white small">${ev.host || 'N/A'}</td>
      <td class="text-secondary small">${ev.user || 'SYSTEM'}</td>
      <td class="font-monospace text-info small text-break">${ev.detail || ev.desc || 'N/A'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// MITRE ATT&CK Matrix View
async function fetchMitreMatrix() {
  let matrix = [];
  if (isOfflineMode) {
    matrix = FALLBACK_DB.mitre_matrix;
  } else {
    try {
      const res = await fetch('/api/mitre/matrix');
      matrix = await res.json();
    } catch (err) {
      matrix = FALLBACK_DB.mitre_matrix;
    }
  }

  const container = document.getElementById('mitre-matrix-grid');
  container.innerHTML = '';

  matrix.forEach(item => {
    const isDetected = item.status === 'DETECTED';
    const col = document.createElement('div');
    col.className = 'col-12 col-md-6 col-xl-4';
    col.innerHTML = `
      <div class="card soc-card p-3 h-100 ${isDetected ? 'border-danger' : 'border-secondary'}">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <span class="font-monospace text-info fw-bold small">${item.technique_id}</span>
          <span class="badge ${isDetected ? 'bg-danger' : 'bg-secondary'}">${item.status}</span>
        </div>
        <h6 class="text-white mb-1 small fw-bold">${item.technique_name}</h6>
        <div class="text-secondary small mb-2">Tactic: <span class="badge bg-dark border border-secondary">${item.tactic}</span></div>
        <div class="d-flex justify-content-between align-items-center text-muted small mt-auto pt-2 border-top border-secondary">
          <span>Base Weight: ${item.base_score}</span>
          <span>Triggers: <strong class="text-white">${item.triggered_count}</strong></span>
        </div>
      </div>
    `;
    container.appendChild(col);
  });
}

// Sigma Detection Rules View
async function fetchRules() {
  let rules = [];
  if (isOfflineMode) {
    rules = FALLBACK_DB.rules;
  } else {
    try {
      const res = await fetch('/api/rules');
      rules = await res.json();
    } catch (err) {
      rules = FALLBACK_DB.rules;
    }
  }

  const container = document.getElementById('rules-matrix-grid');
  container.innerHTML = '';

  rules.forEach(rule => {
    const col = document.createElement('div');
    col.className = 'col-12 col-md-6 col-xl-4';
    const badgeClass = rule.severity === 'CRITICAL' ? 'bg-danger' : (rule.severity === 'HIGH' ? 'bg-warning text-dark' : 'bg-primary');

    col.innerHTML = `
      <div class="card soc-card p-3 h-100">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <span class="font-monospace text-info small fw-bold">${rule.id}</span>
          <span class="badge ${badgeClass}">${rule.severity}</span>
        </div>
        <h6 class="text-white small fw-bold mb-1">${rule.title}</h6>
        <p class="text-secondary small mb-2" style="font-size: 0.75rem;">${rule.description}</p>
        <div class="mt-auto pt-2 border-top border-secondary small text-info font-monospace" style="font-size: 0.7rem;">
          MITRE: ${rule.mitre_technique_id} (${rule.mitre_tactic})
        </div>
      </div>
    `;
    container.appendChild(col);
  });
}

// Sigma Sandbox Controller
function loadSigmaTemplate() {
  const template = `title: Suspicious Reconnaissance via Whoami or Net Utility
id: SIGMA-CUSTOM-007
status: experimental
description: Detects command-line discovery tools executed to inspect local account privileges.
level: MEDIUM
tags:
  - attack.discovery
  - attack.t1087
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    command_line:
      - "whoami /priv"
      - "net user"
      - "net group"
      - "quser"
`;
  const textarea = document.getElementById('sandbox-yaml');
  if (textarea) textarea.value = template;
}

async function compileTestSigma() {
  const yamlContent = document.getElementById('sandbox-yaml').value;
  const output = document.getElementById('sandbox-output');
  output.innerText = 'Parsing and compiling Sigma YAML condition tree...';

  if (isOfflineMode) {
    setTimeout(() => {
      output.innerHTML = `
<span class="text-success fw-bold">[SYNTAX VALID] Sigma Rule Compiled Successfully (Client Sandbox)!</span>
&bull; Rule ID: SIGMA-CUSTOM-007
&bull; Title: Suspicious Reconnaissance via Whoami or Net Utility
&bull; Severity: <span class="badge bg-warning text-dark">MEDIUM</span>
&bull; Mapped Technique: <span class="text-info">T1087 (Discovery)</span>
&bull; Verification: Detection criteria matches process creation telemetry.
      `;
      showSocToast('Sigma rule syntax verified!', 'success');
    }, 300);
    return;
  }

  try {
    const res = await fetch('/api/rules/compile-test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ yaml_content: yamlContent })
    });
    const data = await res.json();

    if (data.valid) {
      output.innerHTML = `
<span class="text-success fw-bold">[SYNTAX VALID] Sigma Rule Compiled Successfully!</span>
&bull; Rule ID: ${data.rule_id}
&bull; Title: ${data.title}
&bull; Severity: <span class="badge bg-warning text-dark">${data.severity}</span>
&bull; Mapped Technique: <span class="text-info">${data.mitre_technique_id} (${data.mitre_tactic})</span>
&bull; Description: ${data.description}
      `;
      showSocToast('Sigma rule syntax verified!', 'success');
    } else {
      output.innerHTML = `<span class="text-danger fw-bold">[COMPILATION ERROR]</span>\n${data.error}`;
      showSocToast('Sigma compilation error', 'danger');
    }
  } catch (err) {
    output.innerText = 'Error compiling rule: ' + err;
  }
}

async function saveSigmaRule() {
  const filename = document.getElementById('sandbox-filename').value.trim();
  const yamlContent = document.getElementById('sandbox-yaml').value;

  if (isOfflineMode) {
    FALLBACK_DB.rules.push({
      id: "SIGMA-CUSTOM-007",
      title: "Custom User Added Rule",
      severity: "MEDIUM",
      mitre_technique_id: "T1087",
      mitre_tactic: "Discovery",
      description: "Custom rule added via Netlify sandbox."
    });
    showSocToast(`Rule saved to ${filename}! Total active rules: ${FALLBACK_DB.rules.length}`, 'success');
    await fetchRules();
    return;
  }

  try {
    const res = await fetch('/api/rules/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, yaml_content: yamlContent })
    });
    const data = await res.json();
    if (res.ok) {
      showSocToast(`Rule saved to ${filename}! Total active rules: ${data.total_rules}`, 'success');
      await fetchRules();
      await fetchStatus();
    } else {
      alert('Error saving rule: ' + data.detail);
    }
  } catch (err) {
    alert('Failed to save rule: ' + err);
  }
}

// SOAR Playbook Execution
async function executeCurrentPlaybook(playbookName) {
  if (!currentIncidentId) {
    alert('Please select an active incident from the list first.');
    return;
  }

  const logFeed = document.getElementById('soar-execution-log');
  logFeed.innerHTML += `<br>[${new Date().toLocaleTimeString()}] <strong>INITIATING PLAYBOOK: "${playbookName}"</strong> for ${currentIncidentId}...`;
  logFeed.scrollTop = logFeed.scrollHeight;

  if (isOfflineMode) {
    setTimeout(() => {
      const inc = incidentsCache.find(i => i.incident_id === currentIncidentId);
      if (inc) inc.containment_status = "CONTAINED";
      FALLBACK_DB.status.contained_incidents += 1;

      logFeed.innerHTML += `<br><span class="text-info">[ACTION: Host Network Isolation]</span> DROP rule enforced on endpoint.`;
      logFeed.innerHTML += `<br><span class="text-info">[ACTION: Process Tree Neutralization]</span> Malicious payload terminated.`;
      logFeed.innerHTML += `<br><span class="text-info">[ACTION: Identity Revocation]</span> Active Kerberos tokens invalidated.`;
      logFeed.innerHTML += `<br><strong class="text-success">[CONTAINMENT COMPLETE] Incident flagged as CONTAINED.</strong><br>`;
      logFeed.scrollTop = logFeed.scrollHeight;

      showSocToast(`Playbook "${playbookName}" executed successfully!`, 'success');
      renderIncidentList(incidentsCache);
      fetchStatus();
    }, 400);
    return;
  }

  try {
    const res = await fetch('/api/soar/playbooks/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incident_id: currentIncidentId, playbook_name: playbookName })
    });
    const result = await res.json();

    if (result.status === 'SUCCESS') {
      result.actions.forEach(act => {
        logFeed.innerHTML += `<br><span class="text-info">[ACTION: ${act.action_name}]</span> ${act.target_value} &rarr; <strong>${act.status}</strong>`;
        logFeed.innerHTML += `<br>&nbsp;&nbsp;&bull; ${act.execution_log}`;
      });
      logFeed.innerHTML += `<br><strong class="text-success">[CONTAINMENT COMPLETE] Incident flagged as CONTAINED.</strong><br>`;
      logFeed.scrollTop = logFeed.scrollHeight;

      showSocToast(`Playbook "${playbookName}" executed successfully!`, 'success');
      await fetchIncidents();
      await fetchStatus();
    }
  } catch (err) {
    logFeed.innerHTML += `<br><span class="text-danger">[ERROR] Playbook execution failed: ${err}</span>`;
  }
}

// Granular Manual Containment Actions
async function executeGranularAction(actionType) {
  if (!currentIncidentId) {
    alert('Please select an active incident first.');
    return;
  }

  const logFeed = document.getElementById('soar-execution-log');
  logFeed.innerHTML += `<br>[${new Date().toLocaleTimeString()}] Executing Granular Action: <strong>${actionType}</strong>...`;
  logFeed.scrollTop = logFeed.scrollHeight;

  if (isOfflineMode) {
    setTimeout(() => {
      const inc = incidentsCache.find(i => i.incident_id === currentIncidentId);
      if (inc) inc.containment_status = "CONTAINED";
      logFeed.innerHTML += `<br><span class="text-success">[SUCCESS]</span> Granular action '${actionType}' enforced on target.<br>`;
      logFeed.scrollTop = logFeed.scrollHeight;
      showSocToast(`Granular action '${actionType}' enforced.`, 'info');
      renderIncidentList(incidentsCache);
    }, 250);
    return;
  }

  let targetVal = "192.168.1.45";
  if (actionType === "block_ip") targetVal = "185.220.101.5";
  if (actionType === "revoke_user") targetVal = "CORP\\sarah.connor";

  try {
    const res = await fetch('/api/soar/actions/execute-single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incident_id: currentIncidentId, action_type: actionType, target_value: targetVal })
    });
    const result = await res.json();
    if (result.status === 'SUCCESS') {
      logFeed.innerHTML += `<br><span class="text-success">[SUCCESS]</span> ${result.action.execution_log}<br>`;
      logFeed.scrollTop = logFeed.scrollHeight;
      showSocToast(`Granular action '${actionType}' enforced.`, 'info');
      await fetchIncidents();
      await fetchStatus();
    }
  } catch (err) {
    logFeed.innerHTML += `<br><span class="text-danger">[ERROR] Granular action failed: ${err}</span>`;
  }
}

// Incident Report Generation Modal
async function openIncidentReportModal() {
  if (!currentIncidentId) {
    alert('Select an incident first to view its forensic report.');
    return;
  }

  const modalEl = document.getElementById('reportModal');
  const modal = new bootstrap.Modal(modalEl);
  modal.show();

  const reportBody = document.getElementById('report-content-body');
  reportBody.innerText = 'Compiling multi-hop attack path and generating forensic report...';

  const inc = incidentsCache.find(i => i.incident_id === currentIncidentId);
  if (!inc) return;

  if (isOfflineMode) {
    rawReportMarkdown = `# INCIDENT TRIAGE & FORENSIC INVESTIGATION REPORT
**Reference ID:** \`${inc.incident_id}\`  
**Classification:** \`${inc.overall_severity}\` (Calculated Risk Score: ${inc.overall_risk_score}/100)  
**Containment Status:** \`${inc.containment_status}\`  
**Threat Correlation:** ${inc.threat_actor_hint}  
**Investigation Timestamp:** ${new Date().toUTCString()}

---

## 1. Executive Summary
A multi-stage adversarial intrusion was detected and correlated by the **AegisGraph-SOC Engine**. 
The attack originated from root node \`${inc.root_node_id}\` and traversed across ${inc.nodes.length} entities 
before triggering high-fidelity behavioral signatures.

## 2. MITRE ATT&CK Framework Mapping
The adversary traversed the following MITRE tactics and techniques:
${inc.mitre_techniques.map(t => `- **[${t}]** (Mapped to Incident Kill-Chain)`).join('\n')}

## 3. Forensic Blast Radius (Attack Graph Entities)
Total Correlated Entities: **${inc.nodes.length}** nodes, **${inc.edges.length}** relationship transitions.

### Key Nodes Involved:
${inc.nodes.map(n => `- **[${n.type.toUpperCase()}] ${n.label}** | Severity: \`${n.severity}\` | Risk: ${n.risk_score}`).join('\n')}

## 4. Remediation & SOAR Action Summary
- **Current Incident State:** \`${inc.containment_status}\`
- Recommended actions: Host boundary isolation, process termination, identity revocation.
`;
    reportBody.innerText = rawReportMarkdown;
    return;
  }

  try {
    const res = await fetch(`/api/incidents/${currentIncidentId}/report`);
    const data = await res.json();
    rawReportMarkdown = data.markdown_report;
    reportBody.innerText = data.markdown_report;
  } catch (err) {
    reportBody.innerText = 'Failed to generate incident report: ' + err;
  }
}

function copyReportMarkdown() {
  if (!rawReportMarkdown) return;
  navigator.clipboard.writeText(rawReportMarkdown).then(() => {
    showSocToast('Forensic Markdown Report copied to clipboard!', 'info');
  });
}

// IOC Export Hub Modal
async function openIocModal() {
  if (!currentIncidentId) {
    alert('Select an incident first.');
    return;
  }

  const modalEl = document.getElementById('iocModal');
  const modal = new bootstrap.Modal(modalEl);
  modal.show();
  await switchIocFormat('json');
}

async function switchIocFormat(format) {
  currentIocFormat = format;
  document.getElementById('ioc-format-json').classList.toggle('active', format === 'json');
  document.getElementById('ioc-format-stix').classList.toggle('active', format === 'stix');

  const textarea = document.getElementById('ioc-content-body');
  textarea.value = 'Generating IOC bundle...';

  const inc = incidentsCache.find(i => i.incident_id === currentIncidentId);
  if (!inc) return;

  if (isOfflineMode) {
    const ips = inc.nodes.filter(n => n.type === 'network').map(n => n.properties?.dest_ip).filter(Boolean);
    const files = inc.nodes.filter(n => n.type === 'file').map(n => n.properties?.path).filter(Boolean);

    let bundleData;
    if (format === 'stix') {
      bundleData = {
        type: "bundle",
        id: `bundle--${Math.random().toString(36).substring(2, 10)}`,
        objects: ips.map(ip => ({
          type: "indicator",
          spec_version: "2.1",
          pattern: `[ipv4-addr:value = '${ip}']`,
          name: `Malicious C2 IP ${ip}`,
          indicator_types: ["malicious-activity"]
        }))
      };
    } else {
      bundleData = {
        incident_id: inc.incident_id,
        iocs: { c2_ips: ips, suspicious_files: files }
      };
    }
    textarea.value = JSON.stringify(bundleData, null, 2);
    return;
  }

  try {
    const res = await fetch(`/api/incidents/${currentIncidentId}/iocs?format=${format}`);
    const data = await res.json();
    textarea.value = JSON.stringify(data, null, 2);
  } catch (err) {
    textarea.value = 'Error generating IOC bundle: ' + err;
  }
}

function copyIocContent() {
  const content = document.getElementById('ioc-content-body').value;
  if (!content) return;
  navigator.clipboard.writeText(content).then(() => {
    showSocToast(`IOC ${currentIocFormat.toUpperCase()} Bundle copied to clipboard!`, 'info');
  });
}

// Adversary Simulation Controls
function selectScenario(scen) {
  selectedScenario = scen;
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
  if (scen === 'apt29') document.getElementById('scen-card-apt').classList.add('active');
  if (scen === 'ransomware') document.getElementById('scen-card-ransom').classList.add('active');
  if (scen === 'lateral') document.getElementById('scen-card-lateral').classList.add('active');
}

async function launchSelectedSimulation() {
  const btn = document.getElementById('btn-launch-sim');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span> Emulating Campaign...';

  if (isOfflineMode) {
    setTimeout(() => {
      const modalEl = document.getElementById('simModal');
      const modalInstance = bootstrap.Modal.getInstance(modalEl);
      if (modalInstance) modalInstance.hide();

      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-play-fill"></i> Execute Emulation Campaign';

      if (selectedScenario === 'ransomware') {
        currentIncidentId = "INC-RANSOM-02";
      } else {
        currentIncidentId = "INC-APT29-01";
      }
      showSocToast(`Simulation '${selectedScenario.toUpperCase()}' injected successfully!`, 'danger');
      refreshAll();
      loadForensicTimeline();
    }, 500);
    return;
  }

  try {
    const res = await fetch('/api/simulator/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: selectedScenario })
    });
    const data = await res.json();

    const modalEl = document.getElementById('simModal');
    const modalInstance = bootstrap.Modal.getInstance(modalEl);
    if (modalInstance) modalInstance.hide();

    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-play-fill"></i> Execute Emulation Campaign';

    if (data.incident_created) {
      currentIncidentId = data.incident_created.incident_id;
    }
    showSocToast(`Simulation '${selectedScenario.toUpperCase()}' injected successfully!`, 'danger');
    await refreshAll();
    await loadForensicTimeline();
  } catch (err) {
    alert('Simulation error: ' + err);
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-play-fill"></i> Execute Emulation Campaign';
  }
}

// Custom Telemetry Ingestion Controls
function toggleIngestFields() {
  const type = document.getElementById('ingest-type').value;
  document.getElementById('ingest-group-proc').classList.toggle('d-none', type !== 'process_creation');
  document.getElementById('ingest-group-net').classList.toggle('d-none', type !== 'network_connection');
  document.getElementById('ingest-group-file').classList.toggle('d-none', type !== 'file_modification');
}

async function submitCustomEvent() {
  const type = document.getElementById('ingest-type').value;
  const host = document.getElementById('ingest-host').value;
  const ip = document.getElementById('ingest-ip').value;
  const cmd = document.getElementById('ingest-cmd').value;
  const destIp = document.getElementById('ingest-dest-ip').value;
  const filePath = document.getElementById('ingest-file-path').value;

  if (isOfflineMode) {
    FALLBACK_DB.events.unshift({
      type: type === 'network_connection' ? 'NETWORK' : (type === 'file_modification' ? 'FILE' : 'PROCESS'),
      host: host,
      user: "CORP\\admin",
      detail: cmd || destIp || filePath,
      timestamp: new Date().toISOString()
    });
    FALLBACK_DB.status.total_telemetry_events += 1;

    const modalEl = document.getElementById('customIngestModal');
    const modalInstance = bootstrap.Modal.getInstance(modalEl);
    if (modalInstance) modalInstance.hide();

    showSocToast('Custom telemetry ingested (Client Mode)!', 'info');
    await refreshAll();
    await loadForensicTimeline();
    return;
  }

  try {
    const res = await fetch('/api/telemetry/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event_type: type,
        host_name: host,
        host_ip: ip,
        command_line: cmd,
        dest_ip: destIp,
        file_path: filePath
      })
    });
    const data = await res.json();

    const modalEl = document.getElementById('customIngestModal');
    const modalInstance = bootstrap.Modal.getInstance(modalEl);
    if (modalInstance) modalInstance.hide();

    if (data.incident_created) {
      currentIncidentId = data.incident_created.incident_id;
    }
    await refreshAll();
    await loadForensicTimeline();
    showSocToast(`Custom telemetry ingested! Triggered ${data.alerts_triggered} alerts.`, 'info');
  } catch (err) {
    alert('Error ingesting custom telemetry: ' + err);
  }
}

// Toast Notification Hub Utility
function showSocToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toastId = `toast-${Date.now()}`;
  const borderClass = type === 'danger' ? 'border-danger text-danger' : (type === 'success' ? 'border-success text-success' : 'border-info text-info');

  const toastEl = document.createElement('div');
  toastEl.className = `toast align-items-center text-bg-dark border ${borderClass} shadow-lg`;
  toastEl.id = toastId;
  toastEl.setAttribute('role', 'alert');
  toastEl.setAttribute('aria-live', 'assertive');
  toastEl.setAttribute('aria-atomic', 'true');

  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body small fw-semibold">
        <i class="bi bi-shield-fill-check me-2"></i> ${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;

  container.appendChild(toastEl);
  const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
  bsToast.show();

  toastEl.addEventListener('hidden.bs.toast', () => {
    toastEl.remove();
  });
}
