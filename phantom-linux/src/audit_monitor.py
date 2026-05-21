#!/usr/bin/env python3
"""
Project Phantom - Linux Extension
Audit Baseline Monitor v5 - tail-based, no ausearch parsing issues
"""

import subprocess
import re
import json
import os
import sys
from datetime import datetime

LOG_FILE = os.path.expanduser("~/phantom-linux/logs/audit_events.log")
os.makedirs(os.path.expanduser("~/phantom-linux/logs"), exist_ok=True)

def parse_line(line):
    """Extract fields from a raw audit.log SYSCALL line."""
    if 'phantom_exec' not in line:
        return None
    if 'type=SYSCALL' not in line:
        return None
    if 'syscall=59' not in line and 'SYSCALL=execve' not in line:
        return None

    pid   = re.search(r'\bpid=(\d+)',   line)
    ppid  = re.search(r'\bppid=(\d+)',  line)
    comm  = re.search(r'comm="?([^"\s]+)"?', line)
    exe   = re.search(r'exe="?([^"\s]+)"?',  line)
    ts_raw = re.search(r'audit\((\d+\.\d+)', line)

    if not exe:
        return None

    ts_str = datetime.now().strftime('%m/%d/%Y %H:%M:%S.%f')[:25]
    if ts_raw:
        try:
            ts_str = datetime.fromtimestamp(
                float(ts_raw.group(1))).strftime('%m/%d/%Y %H:%M:%S.%f')[:25]
        except Exception:
            pass

    return {
        'timestamp': ts_str,
        'pid':  pid.group(1)  if pid  else '?',
        'ppid': ppid.group(1) if ppid else '?',
        'comm': comm.group(1)[:18] if comm else '?',
        'exe':  exe.group(1),
        'source': 'auditd'
    }

def main():
    print("[*] Phantom Linux - Audit Monitor v5")
    print("[*] Tailing /var/log/audit/audit.log directly")
    print("[*] Ctrl+C to stop\n")
    print(f"{'TIMESTAMP':<26} {'PID':<7} {'PPID':<7} {'COMM':<20} EXE")
    print("-" * 88)

    # tail -f -n 0 means: start from NOW, no old lines
    proc = subprocess.Popen(
        ['tail', '-f', '-n', '0', '/var/log/audit/audit.log'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    with open(LOG_FILE, 'a') as logf:
        try:
            for line in proc.stdout:
                ev = parse_line(line.strip())
                if not ev:
                    continue
                ts   = ev['timestamp']
                pid  = ev['pid']
                ppid = ev['ppid']
                comm = ev['comm']
                exe  = ev['exe']
                print(f"{ts:<26} {pid:<7} {ppid:<7} {comm:<20} {exe}")
                logf.write(json.dumps(ev) + '\n')
                logf.flush()
        except KeyboardInterrupt:
            print("\n[*] Monitor stopped.")
            proc.terminate()

if __name__ == '__main__':
    main()


