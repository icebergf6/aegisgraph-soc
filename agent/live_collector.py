#!/usr/bin/env python3
"""
AegisGraph-SOC: Real-Time Host Telemetry Collector & Detection Agent
Author: AegisGraph-SOC Team
Description:
    Lightweight, high-performance host sensor that continuously monitors
    newly spawned OS processes, command-line arguments, and outbound network
    connections, shipping OCSF/ECS compliant telemetry to the AegisGraph-SOC
    FastAPI SIEM/SOAR engine in real-time.
"""

import os
import sys
import time
import uuid
import socket
import hashlib
import argparse
from datetime import datetime, timezone
from typing import Set, Dict, Any, Optional

try:
    import psutil
except ImportError:
    print("[!] Error: 'psutil' is not installed. Please run: pip install psutil")
    sys.exit(1)

try:
    import httpx
except ImportError:
    import urllib.request
    import json
    httpx = None


# ANSI Color Codes for Modern Cyber Terminal Display
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'


class LiveTelemetryCollector:
    def __init__(
        self,
        api_base: str = "http://127.0.0.1:8000/api/v1",
        host_name: Optional[str] = None,
        poll_interval: float = 1.5,
        quiet: bool = False
    ):
        self.api_base = api_base.rstrip("/")
        self.host_name = host_name or socket.gethostname().upper()
        self.host_ip = self._get_local_ip()
        self.poll_interval = poll_interval
        self.quiet = quiet

        self.seen_pids: Set[int] = set()
        self.seen_conns: Set[str] = set()

        self.events_shipped = 0
        self.alerts_triggered = 0

    def _get_local_ip(self) -> str:
        """Determines primary non-loopback host IPv4 address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _calculate_sha256(self, filepath: str) -> str:
        """Safely calculates SHA256 of target binary if accessible."""
        try:
            if not os.path.isfile(filepath):
                return ""
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _send_payload(self, endpoint: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Sends JSON payload to AegisGraph-SOC backend API."""
        url = f"{self.api_base}/{endpoint}"
        try:
            if httpx:
                with httpx.Client(timeout=3.0) as client:
                    resp = client.post(url, json=payload)
                    if resp.status_code == 200:
                        return resp.json()
            else:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            # Backend might be unreachable or restarting
            return None
        return None

    def initialize_baselines(self):
        """Populates baseline processes to prevent historical event spam on first run."""
        print(f"{Colors.CYAN}[*] Establishing baseline process snapshot...{Colors.RESET}")
        for p in psutil.process_iter(['pid']):
            try:
                self.seen_pids.add(p.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        print(f"{Colors.GREEN}[+] Baseline established with {len(self.seen_pids)} active processes.{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Monitoring for newly spawned processes and network sockets...{Colors.RESET}\n")

    def inspect_new_processes(self):
        """Scans for newly created processes since last polling cycle."""
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'exe', 'username']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)

                if pid not in self.seen_pids:
                    # New Process Detected!
                    self.seen_pids.add(pid)
                    p_name = proc.info.get('name') or "unknown.exe"
                    cmdline_list = proc.info.get('cmdline') or []
                    cmdline = " ".join(cmdline_list) if cmdline_list else p_name
                    ppid = proc.info.get('ppid')
                    username = proc.info.get('username') or os.getenv("USERNAME", "SYSTEM")
                    exe_path = proc.info.get('exe') or ""

                    # Parent process details
                    parent_name = "System"
                    if ppid:
                        try:
                            parent_proc = psutil.Process(ppid)
                            parent_name = parent_proc.name()
                        except Exception:
                            parent_name = f"PID:{ppid}"

                    # Calculate Hash for suspicious binaries
                    hashes = {}
                    if exe_path and os.path.exists(exe_path):
                        sha = self._calculate_sha256(exe_path)
                        if sha:
                            hashes["sha256"] = sha

                    telemetry = {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "process_creation",
                        "host_name": self.host_name,
                        "host_ip": self.host_ip,
                        "user_name": username,
                        "process_id": pid,
                        "process_guid": f"proc-{uuid.uuid4().hex[:12]}",
                        "process_name": p_name,
                        "process_path": exe_path or f"C:\\Windows\\System32\\{p_name}",
                        "command_line": cmdline,
                        "parent_process_id": ppid,
                        "parent_process_guid": f"proc-par-{uuid.uuid4().hex[:8]}",
                        "parent_process_name": parent_name,
                        "parent_command_line": parent_name,
                        "hashes": hashes
                    }

                    # Ship to SIEM backend
                    res = self._send_payload("telemetry/process", telemetry)
                    self.events_shipped += 1

                    if res:
                        alerts = res.get("alerts", [])
                        if alerts:
                            self.alerts_triggered += len(alerts)
                            for a in alerts:
                                print(f"\n{Colors.BG_RED}{Colors.BOLD} [!] 🚨 REALTIME SIGMA DETECTION TRIGGERED! {Colors.RESET}")
                                print(f"{Colors.RED}{Colors.BOLD} ├─ Rule:       {a.get('rule_title')}{Colors.RESET}")
                                print(f"{Colors.RED} ├─ Severity:   {a.get('severity')} | DEFCON Impact: HIGH{Colors.RESET}")
                                print(f"{Colors.RED} ├─ MITRE ATT&CK: [{a.get('mitre_technique_id')}] {a.get('mitre_technique_name')}{Colors.RESET}")
                                print(f"{Colors.RED} ├─ Process:    {p_name} (PID: {pid}){Colors.RESET}")
                                print(f"{Colors.RED} └─ Command:    {cmdline[:140]}{Colors.RESET}\n")
                        elif not self.quiet:
                            t_str = datetime.now().strftime("%H:%M:%S")
                            print(f"{Colors.GREEN}[{t_str}] [PROC] {p_name} (PID: {pid}) spawned by {parent_name} | {cmdline[:80]}{Colors.RESET}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Prune terminated PIDs to prevent unbounded memory growth
        self.seen_pids = self.seen_pids.intersection(current_pids)

    def inspect_network_connections(self):
        """Scans for active outbound network sockets."""
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, Exception):
            return

        for conn in connections:
            if conn.status in ('ESTABLISHED', 'SYN_SENT') and conn.raddr:
                r_ip = conn.raddr.ip
                r_port = conn.raddr.port

                # Skip localhost, link-local, and multicast
                if r_ip.startswith("127.") or r_ip.startswith("169.254.") or r_ip.startswith("224."):
                    continue

                conn_sig = f"{conn.pid}:{r_ip}:{r_port}"
                if conn_sig not in self.seen_conns:
                    self.seen_conns.add(conn_sig)
                    p_name = "network.exe"
                    if conn.pid:
                        try:
                            p_name = psutil.Process(conn.pid).name()
                        except Exception:
                            p_name = f"PID:{conn.pid}"

                    net_telemetry = {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "network_connection",
                        "host_name": self.host_name,
                        "process_id": conn.pid or 0,
                        "process_guid": f"proc-net-{uuid.uuid4().hex[:8]}",
                        "process_name": p_name,
                        "source_ip": self.host_ip,
                        "source_port": conn.laddr.port if conn.laddr else 0,
                        "dest_ip": r_ip,
                        "dest_port": r_port,
                        "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        "direction": "outbound",
                        "bytes_sent": 1024,
                        "domain": None
                    }

                    res = self._send_payload("telemetry/network", net_telemetry)
                    self.events_shipped += 1

                    if res and res.get("alerts"):
                        for a in res.get("alerts"):
                            self.alerts_triggered += 1
                            print(f"\n{Colors.BG_RED}{Colors.BOLD} [!] 🚨 MALICIOUS OUTBOUND CONNECTION DETECTED! {Colors.RESET}")
                            print(f"{Colors.RED}{Colors.BOLD} ├─ Rule:     {a.get('rule_title')}{Colors.RESET}")
                            print(f"{Colors.RED} ├─ C2 Dest:  {r_ip}:{r_port} ({p_name}){Colors.RESET}")
                            print(f"{Colors.RED} └─ MITRE:    [{a.get('mitre_technique_id')}] {a.get('mitre_technique_name')}{Colors.RESET}\n")
                    elif not self.quiet:
                        t_str = datetime.now().strftime("%H:%M:%S")
                        print(f"{Colors.YELLOW}[{t_str}] [NET]  {p_name} ➔ {r_ip}:{r_port} ({conn.status}){Colors.RESET}")

        # Limit cache size
        if len(self.seen_conns) > 2000:
            self.seen_conns.clear()

    def run(self):
        """Main real-time continuous monitoring loop."""
        self._print_banner()
        self.initialize_baselines()

        try:
            while True:
                self.inspect_new_processes()
                self.inspect_network_connections()
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[*] Shutting down AegisGraph-SOC Telemetry Agent...{Colors.RESET}")
            print(f"{Colors.CYAN}[*] Summary: {self.events_shipped} events shipped | {self.alerts_triggered} alerts triggered.{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Host sensor stopped cleanly.{Colors.RESET}")

    def _print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ___              _       ______                  __        _____ ____  ______
   /   | ___  ____ _(_)____ / ____/________ _____  / /_      / ___// __ \/ ____/
  / /| |/ _ \/ __ `/ / ___// / __/ ___/ __ `/ __ \/ __ \_____\__ \/ / / / /     
 / ___ /  __/ /_/ / (__  )/ /_/ / /  / /_/ / /_/ / / / /_____/__/ / /_/ / /___   
/_/  |_\___/\__, /_/____(_)____/_/   \__,_/ .___/_/ /_/     /____/\____/\____/   
           /____/                        /_/     LIVE TELEMETRY AGENT v1.0
{Colors.RESET}
{Colors.BOLD} 🛡️  Endpoint Host Sensor Active{Colors.RESET}
 ├─ Host Name:     {Colors.GREEN}{self.host_name}{Colors.RESET}
 ├─ Host IP:       {Colors.GREEN}{self.host_ip}{Colors.RESET}
 ├─ Ingestion API: {Colors.CYAN}{self.api_base}{Colors.RESET}
 ├─ Poll Cycle:    {self.poll_interval}s
 └─ Threat Posture: {Colors.BOLD}REAL-TIME DETECTION ARMED{Colors.RESET}
--------------------------------------------------------------------------------
"""
        print(banner)


def main():
    parser = argparse.ArgumentParser(description="AegisGraph-SOC Real-Time Host Telemetry Sensor")
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1", help="AegisGraph-SOC Backend API URL")
    parser.add_argument("--host-name", default=None, help="Custom hostname tag")
    parser.add_argument("--interval", type=float, default=1.2, help="Polling interval in seconds")
    parser.add_argument("--quiet", action="store_true", help="Only show high-severity alerts in terminal")
    args = parser.parse_args()

    agent = LiveTelemetryCollector(
        api_base=args.url,
        host_name=args.host_name,
        poll_interval=args.interval,
        quiet=args.quiet
    )
    agent.run()


if __name__ == "__main__":
    main()
