# ============================================================
# Project Phantom - Phase 2: ETW Baseline Monitor
# Author: Proma Roy
# Course: CSC I0420 - Secure Operating Systems
# Description: Captures baseline ETW kernel telemetry
#              before tampering to establish normal behavior
# ============================================================

import subprocess
import datetime
import time
import os
import psutil
import json

# ── Configuration ────────────────────────────────────────────
LOG_FILE     = "etw_baseline_log.json"
DURATION_SEC = 60        # how long to monitor (seconds)
INTERVAL_SEC = 2         # sampling interval (seconds)
SESSION_NAME = "PhantomBaselineSession"
PROVIDER     = "Microsoft-Windows-Kernel-Process"

# ── Helper: get timestamp ────────────────────────────────────
def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

# ── Helper: start ETW trace session ─────────────────────────
def start_etw_session():
    print(f"[*] Starting ETW trace session: {SESSION_NAME}")
    cmd = [
        "logman", "start", SESSION_NAME,
        "-p", PROVIDER,
        "-o", "phantom_etw_trace.etl",
        "-ets"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if "successfully" in result.stdout.lower() or result.returncode == 0:
        print(f"[+] ETW session started successfully")
        return True
    else:
        print(f"[-] Failed to start ETW session: {result.stderr}")
        print(f"[*] Continuing with process monitoring only...")
        return False

# ── Helper: stop ETW trace session ───────────────────────────
def stop_etw_session():
    print(f"\n[*] Stopping ETW session...")
    cmd = ["logman", "stop", SESSION_NAME, "-ets"]
    subprocess.run(cmd, capture_output=True, text=True)
    print(f"[+] ETW session stopped")

# ── Helper: capture system snapshot ─────────────────────────
def capture_system_snapshot(sample_number):
    snapshot = {
        "sample"         : sample_number,
        "timestamp"      : get_timestamp(),
        "cpu_percent"    : psutil.cpu_percent(interval=1),
        "memory_percent" : psutil.virtual_memory().percent,
        "process_count"  : len(psutil.pids()),
        "processes"      : []
    }

    # capture all running processes
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            pinfo = proc.info
            snapshot["processes"].append({
                "pid"    : pinfo['pid'],
                "name"   : pinfo['name'],
                "cpu"    : pinfo['cpu_percent'],
                "memory" : pinfo['memory_info'].rss if pinfo['memory_info'] else 0
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return snapshot

# ── Helper: check ETW provider availability ──────────────────
def check_etw_providers():
    print("[*] Checking available ETW providers...")
    cmd = ["logman", "query", "providers", PROVIDER]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] Provider found: {PROVIDER}")
        return True
    else:
        print(f"[-] Provider not found: {PROVIDER}")
        return False

# ── Main monitoring loop ─────────────────────────────────────
def run_baseline_monitor():
    print("=" * 60)
    print("  Project Phantom - ETW Baseline Monitor")
    print("  Phase 2: Establishing Normal Telemetry Baseline")
    print("=" * 60)
    print(f"[*] Start time    : {get_timestamp()}")
    print(f"[*] Duration      : {DURATION_SEC} seconds")
    print(f"[*] Sample interval: {INTERVAL_SEC} seconds")
    print(f"[*] Log file      : {LOG_FILE}")
    print()

    # check provider
    check_etw_providers()

    # start ETW session
    etw_active = start_etw_session()

    # collect baseline data
    baseline_data = {
        "project"       : "Project Phantom",
        "phase"         : "2 - ETW Baseline Monitor",
        "author"        : "Proma Roy",
        "course"        : "CSC I0420",
        "start_time"    : get_timestamp(),
        "etw_active"    : etw_active,
        "provider"      : PROVIDER,
        "samples"       : []
    }

    print(f"\n[*] Collecting baseline samples...")
    print(f"[*] Press Ctrl+C to stop early\n")

    sample_count = 0
    start_time   = time.time()

    try:
        while (time.time() - start_time) < DURATION_SEC:
            sample_count += 1
            print(f"[{get_timestamp()}] Sample #{sample_count} - ", end="")

            snapshot = capture_system_snapshot(sample_count)
            baseline_data["samples"].append(snapshot)

            print(f"CPU: {snapshot['cpu_percent']}% | "
                  f"MEM: {snapshot['memory_percent']}% | "
                  f"Processes: {snapshot['process_count']}")

            time.sleep(INTERVAL_SEC)

    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user")

    # stop ETW session
    if etw_active:
        stop_etw_session()

    # save results
    baseline_data["end_time"]     = get_timestamp()
    baseline_data["total_samples"] = sample_count

    with open(LOG_FILE, 'w') as f:
        json.dump(baseline_data, f, indent=2)

    print(f"\n[+] Baseline collection complete!")
    print(f"[+] Total samples collected : {sample_count}")
    print(f"[+] Log saved to            : {LOG_FILE}")
    print(f"[+] ETW trace saved to      : phantom_etw_trace.etl")
    print("\n[*] This baseline will be compared against")
    print("[*] post-tampering data in Phase 3.")
    print("=" * 60)

# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    # must run as administrator for ETW access
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] ERROR: Please run as Administrator!")
        print("[-] Right-click PowerShell → Run as Administrator")
        exit(1)

    run_baseline_monitor()