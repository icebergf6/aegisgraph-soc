# AegisGraph-SOC: Enterprise Graph SIEM & Autonomous SOAR Engine

AegisGraph-SOC adalah platform **Security Operations Center (SOC) Generasi Baru** berbasis **Graph Correlation, Threat Intelligence, dan Autonomous SOAR Engine** yang dirancang untuk mendemonstrasikan keahlian tingkat lanjut dalam *Detection Engineering*, *Threat Hunting*, *Incident Response*, dan *Security Automation*.

Platform ini merekonstruksi rantai serangan multi-tahap (*multi-hop attack paths*) dari *Patient Zero* hingga *Blast Radius* secara otomatis, memetakan teknik ancaman ke **MITRE ATT&CK Enterprise Matrix**, dan menjalankan mitigasi insiden otomatis (*SOAR Playbooks*).

---

## 🌟 Fitur Utama & Keunggulan Portofolio

### 1. Graph-Based Attack Path Correlation & Blast Radius Highlighting
* **Cytoscape.js & NetworkX Engine:** Menghubungkan proses induk-anak, koneksi jaringan keluar (*C2 beaconing*), dan manipulasi berkas secara visual dan interaktif.
* **Blast Radius Highlighting:** Saat sebuah node diklik, sistem secara otomatis menyorot rantai asal (*Ancestors / Patient Zero*) dengan warna Cyan, rantai dampak (*Descendants / Blast Radius*) dengan warna Merah, dan meredupkan node yang tidak relevan.
* **1-Click High-Res PNG Snapshot:** Unduh visualisasi graf insiden langsung ke format gambar PNG berkualitas tinggi untuk lampiran laporan insiden.
* **Canvas Filter:** Filter cepat untuk menampilkan *All Nodes*, *Critical Only*, atau *C2 Egress Only*.

### 2. Threat Intelligence & IOC Enrichment Engine
* **Automated Enrichment:** Memeriksa IP, domain, dan hash secara otomatis terhadap basis data Threat Intelligence terintegrasi.
* **Threat Actor Attribution:** Menampilkan atribusi kelompok APT terkemuka (seperti *APT29 / Cozy Bear*, *FIN7*, *LockBit 3.0*).
* **Network Dossier:** Menampilkan skor reputasi ancaman (0-100), Autonomous System Number (ASN), dan negara asal infrastruktur musuh.
* **STIX 2.1 & JSON IOC Hub:** Ekspor seluruh Indicators of Compromise (IOC) dalam format standar industri **STIX 2.1 JSON Bundle** untuk integrasi dengan firewall edge atau platform MISP/OpenCTI.

### 3. Interactive Sigma Detection Rule Sandbox & Live Compiler
* **In-Browser YAML Editor:** SOC Detection Engineer dapat menulis, menyunting, dan memvalidasi aturan deteksi format **Sigma** langsung dari antarmuka web.
* **Live Syntax Validator:** Mengecek kondisi seleksi, pemetaan tag MITRE ATT&CK, dan hierarki field secara instan.
* **Hot-Reload Save:** Menyimpan aturan langsung ke direktori deteksi dan me-reload engine tanpa perlu me-restart server.

### 4. Enterprise Global Threat Posture (DEFCON Widget)
* **Real-time DEFCON Status Gauge:** Menghitung tingkat kesiagaan SOC secara otomatis (DEFCON 1: *Critical Attack Active*, DEFCON 2: *High Threat Detected*, DEFCON 5: *Normal Baseline*) berdasarkan skor risiko insiden tertinggi di jaringan.

### 5. Autonomous SOAR Playbooks & Granular Defense (100% Dynamic)
* **Playbook Otomatis:**
  * *Ransomware Rapid Containment:* Isolasi batas jaringan host, terminasi proses ransomware, dan pencabutan kredensial akun terkompromi.
  * *C2 Beaconing Containment:* Sinkholing IP C2 pada perimeter gateway dan terminasi proses beacon.
* **Granular Defense Actions:** Isolasi host mandiri, blacklist IP firewall, dan terminasi proses secara individual.
* **Live Terminal Audit Trail:** Pencatatan transparan seluruh aksi respon insiden dengan timestamp akurat.

### 6. Incident Lifecycle Management & Forensic Analyst Notes
* **Lifecycle State Tracking:** Pengelolaan status insiden dari `ACTIVE` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CONTAINED` $\rightarrow$ `CLOSED`.
* **Analyst Investigation Notes:** Buku catatan kronologis bagi analis untuk mencatat temuan forensik, hipotesis serangan, dan tindakan eskalasi.
* **Automated Triage Report:** Generator laporan investigasi forensik Markdown komprehensif dalam 1 klik.

### 7. Adversary Emulation Engine (Atomic Red Team Simulator)
Tiga skenario serangan multi-tahap realistis siap didemokan hanya dengan 1 klik:
1. **APT29 / CozyBear Campaign:** Spearphishing Outlook $\rightarrow$ Macro Word $\rightarrow$ Obfuscated PowerShell $\rightarrow$ C2 Outbound $\rightarrow$ LSASS Memory Dump via Procdump.
2. **BlackCat / ALPHV Ransomware:** Exploit $\rightarrow$ Volume Shadow Copy Deletion (`vssadmin delete shadows`) $\rightarrow$ Mass Encryption (`.locked`).
3. **Active Directory Lateral Movement:** Workstation Breach $\rightarrow$ PsExec Service Creation $\rightarrow$ SMB Port 445 $\rightarrow$ Domain Controller Privilege Escalation.

---

## 🏗️ Struktur Arsitektur Proyek

```
cyber_project/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── endpoints.py        # REST API (Status, Incidents, Reports, SOAR, Intel, Sandbox, IOCs)
│   │   ├── engine/
│   │   │   ├── detection.py        # Sigma signature evaluator & parser
│   │   │   ├── graph_correlator.py # Multi-hop provenance attack graph & deduplication
│   │   │   ├── mitre_mapper.py     # MITRE ATT&CK DB & Kill-Chain Risk Scorer
│   │   │   └── threat_intel.py     # IOC enrichment, ASN, Country, and APT attribution
│   │   ├── models/
│   │   │   └── telemetry.py        # OCSF/ECS Pydantic data schemas
│   │   ├── simulator/
│   │   │   └── adversary.py        # Atomic attack campaign telemetry generator
│   │   └── soar/
│   │       ├── actions.py          # Host isolation, IP block, Kill proc, Revoke identity
│   │       └── playbooks.py        # Dynamic autonomous response orchestrator
│   ├── rules/                      # Sigma detection signatures (YAML)
│   ├── tests/
│   │   └── test_engine.py          # Pytest automated test suite (5 passing test suites)
│   ├── main.py                     # FastAPI application entrypoint & static mounting
│   └── requirements.txt            # Python dependencies
└── frontend/
    ├── css/
    │   └── style.css               # Bootstrap 5 extension, DEFCON pulse, cyber dark-mode theme
    ├── js/
    │   └── app.js                  # Cytoscape graph renderer, Blast radius, Threat intel, SOAR controller
    └── index.html                  # Enterprise SOC Analyst Investigation Console
```

---

## 🚀 Panduan Menjalankan Aplikasi Secara Lokal

### 1. Prasyarat
* Python 3.10 atau lebih baru terinstal.

### 2. Aktivasi Virtual Environment & Dependensi
```powershell
# Buka PowerShell di direktori proyek
cd "c:\Users\LEO SYAFIQ\OneDrive\Documents\cyber_project"

# Aktifkan virtual environment
.\venv\Scripts\Activate.ps1

# Instal paket jika diperlukan
pip install -r backend/requirements.txt
```

### 3. Menjalankan Server AegisGraph-SOC
```powershell
$env:PYTHONPATH="."
.\venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### 4. Mengakses Dashboard di Browser
Buka browser favorit Anda dan kunjungi:
```
http://127.0.0.1:8000/
```

### 5. Menjalankan Pengujian Otomatis (Pytest)
```powershell
$env:PYTHONPATH="."
.\venv\Scripts\python -m pytest backend/tests/ -v
```
Semua 5 modul pengujian (*scoring*, *detection*, *threat intel*, *correlation & deduplication*, *dynamic SOAR*) diverifikasi lulus 100%.

---

## 🎯 Panduan Skenario Demo Portofolio (Interview Showcase)

1. **Tunjukkan Posture Global:** Tunjukkan widget **DEFCON Posture** di navigasi atas yang menunjukkan tingkat kesiagaan keamanan enterprise.
2. **Eksplorasi Attack Graph & Blast Radius:** Klik salah satu insiden di panel kiri. Klik node proses seperti `powershell.exe` atau `procdump.exe`: perhatikan bagaimana rantai infeksi (*Ancestors*) menyala Cyan dan rantai dampak (*Descendants*) menyala Merah sementara node lain meredup.
3. **Periksa Threat Intelligence:** Klik node jaringan (IP) untuk menunjukkan kartu **Threat Intelligence Dossier** lengkap dengan skor reputasi, ASN, negara asal, dan atribusi kelompok ancaman (*APT29*).
4. **Jalankan Simulasi Serangan Baru:** Klik tombol merah **"Simulate Adversary Attack"**, pilih *BlackCat Ransomware* atau *PsExec Lateral Movement*. Perhatikan sistem secara instan memproses event, memetakan teknik MITRE, dan memperbarui graf.
5. **Mitigasi Otomatis SOAR:** Masuk ke subtab **SOAR Defense**, jalankan protokol penanganan, dan perhatikan status insiden berubah menjadi `CONTAINED` dengan log audit terminal yang transparan.
6. **Ekspor Laporan Forensik & STIX 2.1:** Buka tombol **"Triage Report"** untuk mengekstrak laporan Markdown forensik, dan tombol **"IOCs"** untuk mendemonstrasikan bundel **STIX 2.1 JSON** siap pakai untuk integrasi MISP/Firewall.
7. **Demonstrasi Sigma Sandbox:** Pindah ke tab **Sigma Sandbox** untuk menunjukkan kemampuan Anda menulis atau memvalidasi aturan deteksi baru secara live di browser.
