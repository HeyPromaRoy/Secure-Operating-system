A Cross-Platform Case Study of OS Telemetry Evasion and Kernel-Resident Detection on Windows 11 and Ubuntu
Course: CSC I0420 — Secure Operating Systems
Institution: The City College of New York, CUNY
Author: Proma Roy | Spring 2026
MITRE ATT&CK: T1562.006 — Impair Defenses: Disable or Modify Linux Audit System / ETW

Overview
This project empirically investigates whether ETW (Event Tracing for Windows) telemetry blind spots and Linux auditd suppression can be detected using independent kernel-level telemetry sources. The core question: if an attacker silences the OS's primary monitoring pipeline, can that silence be caught by a second path the attacker cannot reach without crashing the machine?
The answer demonstrated here is yes — on both platforms.

How It Works
The detection architecture maintains two independent telemetry views of the same system events and flags any divergence.
Windows path:

etw_baseline_monitor.py captures a process snapshot baseline using psutil + logman
projectTamper.cpp patches EtwEventWrite in ntdll.dll with a single 0xC3 (RET) byte, silently killing ETW for that process
PhantomGuard.sys runs a kernel callback via PsSetCreateProcessNotifyRoutineEx — completely outside the ETW pipeline
etw_correlator.py compares baseline vs tampered captures, flags missing processes as ghost processes, and writes a SIEM-compatible JSON alert

Linux path:

auditd monitors execve syscalls via a persistent phantom_exec audit rule
auditctl -e 0 disables audit enforcement system-wide with no visible disruption
phantom_guard.bt hooks the tracepoint:syscalls:sys_enter_execve kernel tracepoint via bpftrace eBPF — unaffected by auditctl
Side-by-side comparison of both streams shows the divergence


Key Findings
FindingValueDetection gap (ETW baseline vs tampered)1.13%Ghost processes identifiedAdobeARM.exe, DataExchangeHost.exeCPU during baseline23.32%CPU during tampering29.24% (+5.91 pp)Timing jitter baseline stdev0.0291 sTiming jitter tampered stdev0.0174 s (inverse finding)Undocumented side effectEventWrite returns 0x00000027 after patchLinux blind spot duration~90 secondsWindows validation tests12/12 PASS
The timing finding was unexpected: jitter decreased during tampering because the patched EtwEventWrite returns immediately, reducing the workload on the ETW code path.

Repository Structure
Secure-Operating-system/
│
├── KMDF Driver OS project/       # Phase 1 — Hello World kernel driver
│   └── Driver.c
│
├── projectphantom/               # Phase 2/5/6 — Baseline monitor, correlator, test suite
│   ├── etw_baseline_monitor.py
│   ├── etw_correlator.py
│   ├── etw_phase6.py
│   ├── etw_baseline_log.json     # Captured baseline (20 samples)
│   ├── etw_tampered_log.json     # Captured tampered run (20 samples)
│   ├── siem_alert.json           # Generated SIEM alert output
│   ├── phantom_analysis_report.txt
│   ├── phantom_test_report.txt
│   └── phantom_timing_report.txt
│
├── projectTamper/                # Phase 3 — ETW tamper tool (C++)
│   ├── projectTamper.cpp         # Core 0xC3 patch implementation
│   └── projectTamper2.cpp        # Version with Remcos RAT threat intel context
│
├── PhantomGuard/                 # Phase 4 — Kernel callback driver (C)
│   └── PhantomGuard/
│       ├── phantomguard.c
│       └── PhantomGuard.inf
│
└── Linux/                        # Linux extension (lives on Ubuntu VM)
    ├── audit_monitor.py          # auditd tail-based monitor v5
    ├── phantom_guard.bt          # bpftrace eBPF execve monitor
    └── phantom.rules             # Persistent audit rule for /etc/audit/rules.d/

Note: The Linux components (audit_monitor.py, phantom_guard.bt, phantom.rules) reside on the Ubuntu VM and are not part of the Windows VS solution. Upload them manually from the VM.


Environment
Windows
ComponentVersionHost OSWindows 11 Pro, Build 26200.7922IDEVisual Studio 2022 Community v17.14Windows SDK10.0.22621.0WDKWindows Driver Kit 11Kernel DebuggerWinDbg PreviewTarget VMWindows 11 Pro (VMware NAT)Python3.11 with psutil, pywin32
Linux
ComponentVersionVMUbuntu 24.04.4 LTS on VirtualBoxKernel6.17.0-19-genericbpftrace0.20.2auditd1:3.1.2-2.1build1.1

Running the Windows Implementation

Prerequisites: Run all commands as Administrator. WinDbg must be connected to the target VM before loading the driver.

Phase 2 — Baseline capture:
bashcd projectphantom
python etw_baseline_monitor.py
# Runs for 60 seconds, writes etw_baseline_log.json
Phase 3 — ETW tamper (run while Phase 2 is active in a second terminal):
projectTamper\x64\Release\projectTamper.exe
# Patches EtwEventWrite, prints 0xC3 byte confirmation and 0x00000027 return code
# Press Enter to restore
Phase 5 — Cross-correlation:
bashpython etw_correlator.py
# Compares baseline vs tampered logs, writes siem_alert.json
Phase 6 — Validation suite:
bashpython etw_phase6.py --test
# Runs 12 data validation tests, all should PASS
Phase 4 — PhantomGuard.sys (on target VM, requires test signing enabled):
cmdbcdedit /set testsigning on
# Reboot VM
sc create PhantomGuard type= kernel binPath= "C:\PhantomDriver\PhantomGuard.sys"
sc start PhantomGuard
# Output visible in WinDbg or DebugView

Running the Linux Extension

Prerequisites: Ubuntu 24.04+, bpftrace installed, auditd installed, run as root or with sudo.

Install and configure auditd:
bashsudo apt install auditd audispd-plugins
echo '-a always,exit -F arch=b64 -S execve -k phantom_exec' | \
    sudo tee /etc/audit/rules.d/phantom.rules
sudo augenrules --load
sudo auditctl -l   # confirm rule is loaded
Run both monitors simultaneously (two terminals):
bash# Terminal 1
sudo bpftrace ~/phantom-linux/ebpf/phantom_guard.bt

# Terminal 2
sudo python3 ~/phantom-linux/src/audit_monitor.py
Apply tamper (third terminal):
bashsudo auditctl -e 0
# Terminal 2 goes silent; Terminal 1 continues uninterrupted
# Restore:
sudo auditctl -e 1

SIEM Alert Sample
json{
    "alert_id": "PHANTOM-DETECT-001",
    "timestamp": "2026-04-08 23:27:53.381021",
    "severity": "CRITICAL",
    "mitre_technique": "T1562.006",
    "mitre_tactic": "Defense Evasion",
    "description": "ETW telemetry gap detected via Kernel Process Callback cross-correlation.",
    "threat_actor_associations": ["Remcos RAT", "Lazarus FudModule"],
    "ghost_processes": ["DataExchangeHost.exe", "AdobeARM.exe"]
}

Real-World Threat Context
Threat Actor / MalwareTechniqueRelevanceLazarus Group — FudModuleBYOVD kernel callback suppressionMotivated the choice of PsSetCreateProcessNotifyRoutineEx as the independent telemetry pathRemcos RATIn-memory EtwEventWrite 0xC3 patchIdentical to projectTamper.cpp implementationCVE-2021-21551Dell DBUtil driver privilege escalationIllustrates the escalation path that precedes this class of attack

Disclaimer
This project is for academic research only, completed as a final project for CSC I0420 at CCNY. All tools were run in isolated virtual machines. The tamper tools demonstrate documented attacker tradecraft for detection research purposes. Do not run on systems you do not own.

License
Academic use only. Not licensed for production or commercial deployment.
