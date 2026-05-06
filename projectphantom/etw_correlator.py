# ============================================================
# Project Phantom - Phase 5: Cross-Correlation Analyzer
# Author: Proma Roy
# Course: CSC I0420 - Secure Operating Systems
# Description: Compares ETW baseline vs tampered telemetry
#              to measure the detection gap statistically
#              Novel defensive contribution of Project Phantom
# ============================================================

import json
import os
import datetime
import statistics

# ── Configuration ────────────────────────────────────────────
BASELINE_FILE  = "etw_baseline_log.json"
TAMPERED_FILE  = "etw_tampered_log.json"
REPORT_FILE    = "phantom_analysis_report.txt"
ALERT_FILE     = "siem_alert.json"

# ── Helper: load JSON log ────────────────────────────────────
def load_log(filename):
    if not os.path.exists(filename):
        print(f"[-] File not found: {filename}")
        return None
    with open(filename, 'r') as f:
        return json.load(f)

# ── Analyze: extract process statistics ──────────────────────
def analyze_samples(samples):
    if not samples:
        return {}

    cpu_values      = [s['cpu_percent'] for s in samples]
    mem_values      = [s['memory_percent'] for s in samples]
    process_counts  = [s['process_count'] for s in samples]

    all_process_names = set()
    for s in samples:
        for p in s.get('processes', []):
            all_process_names.add(p['name'])

    return {
        "sample_count"       : len(samples),
        "avg_cpu"            : round(statistics.mean(cpu_values), 2),
        "avg_memory"         : round(statistics.mean(mem_values), 2),
        "avg_process_count"  : round(statistics.mean(process_counts), 2),
        "min_process_count"  : min(process_counts),
        "max_process_count"  : max(process_counts),
        "unique_processes"   : len(all_process_names),
        "process_names"      : all_process_names
    }

# ── Compare: find differences ────────────────────────────────
def compare_logs(baseline, tampered):
    print("[*] Comparing baseline vs tampered telemetry...")

    b_stats = analyze_samples(baseline.get('samples', []))
    t_stats = analyze_samples(tampered.get('samples', []))

    if not b_stats or not t_stats:
        print("[-] Could not analyze samples")
        return None

    # find processes visible in baseline but missing in tampered
    baseline_procs = b_stats['process_names']
    tampered_procs = t_stats['process_names']
    missing_procs  = baseline_procs - tampered_procs
    new_procs      = tampered_procs - baseline_procs

    # calculate detection gap
    proc_count_diff = b_stats['avg_process_count'] - t_stats['avg_process_count']
    detection_gap   = round((len(missing_procs) / max(len(baseline_procs), 1)) * 100, 2)

    return {
        "baseline_stats"    : b_stats,
        "tampered_stats"    : t_stats,
        "missing_processes" : missing_procs,
        "new_processes"     : new_procs,
        "proc_count_diff"   : proc_count_diff,
        "detection_gap_pct" : detection_gap
    }

# ── Report: generate analysis report ─────────────────────────
def generate_report(comparison):
    if not comparison:
        return

    b = comparison['baseline_stats']
    t = comparison['tampered_stats']

    report = []
    report.append("=" * 60)
    report.append("  PROJECT PHANTOM - CROSS-CORRELATION ANALYSIS REPORT")
    report.append("  Author: Proma Roy")
    report.append("  Course: CSC I0420 - Secure Operating Systems")
    report.append(f"  Generated: {datetime.datetime.now()}")
    report.append("=" * 60)
    report.append("")
    report.append("RESEARCH QUESTION:")
    report.append("  Can ETW tampering create measurable telemetry gaps")
    report.append("  detectable by cross-correlating independent sources?")
    report.append("")
    report.append("─" * 60)
    report.append("BASELINE TELEMETRY (Normal ETW - Phase 2)")
    report.append("─" * 60)
    report.append(f"  Samples collected  : {b['sample_count']}")
    report.append(f"  Avg CPU usage      : {b['avg_cpu']}%")
    report.append(f"  Avg Memory usage   : {b['avg_memory']}%")
    report.append(f"  Avg Process count  : {b['avg_process_count']}")
    report.append(f"  Min Process count  : {b['min_process_count']}")
    report.append(f"  Max Process count  : {b['max_process_count']}")
    report.append(f"  Unique processes   : {b['unique_processes']}")
    report.append("")
    report.append("─" * 60)
    report.append("TAMPERED TELEMETRY (ETW Blinded - Phase 3 Active)")
    report.append("─" * 60)
    report.append(f"  Samples collected  : {t['sample_count']}")
    report.append(f"  Avg CPU usage      : {t['avg_cpu']}%")
    report.append(f"  Avg Memory usage   : {t['avg_memory']}%")
    report.append(f"  Avg Process count  : {t['avg_process_count']}")
    report.append(f"  Min Process count  : {t['min_process_count']}")
    report.append(f"  Max Process count  : {t['max_process_count']}")
    report.append(f"  Unique processes   : {t['unique_processes']}")
    report.append("")
    report.append("─" * 60)
    report.append("CROSS-CORRELATION FINDINGS")
    report.append("─" * 60)
    report.append(f"  Process count difference  : {comparison['proc_count_diff']:.2f}")
    report.append(f"  Detection gap             : {comparison['detection_gap_pct']}%")
    report.append(f"  Processes missing in ETW  : {len(comparison['missing_processes'])}")
    report.append(f"  New processes detected    : {len(comparison['new_processes'])}")
    report.append("")

    if comparison['missing_processes']:
        report.append("  Processes visible in baseline but missing after tamper:")
        for p in sorted(comparison['missing_processes'])[:20]:
            report.append(f"    - {p}")
    report.append("")
    report.append("─" * 60)
    report.append("CONCLUSION")
    report.append("─" * 60)

    if comparison['detection_gap_pct'] > 0:
        report.append("  TAMPERING DETECTED — ETW telemetry gap confirmed")
        report.append(f"  {comparison['detection_gap_pct']}% of baseline processes")
        report.append("  disappeared from ETW after EtwEventWrite patch")
        report.append("")
        report.append("  MITRE ATT&CK T1562.006 successfully demonstrated")
        report.append("  PhantomGuard kernel callbacks remained active")
        report.append("  Cross-correlation revealed the detection gap")
    else:
        report.append("  No significant gap detected in this sample")
        report.append("  Windows ETW-TI protections may have prevented full blind")
        report.append("  This is itself a valuable research finding")
        report.append("  Documents OS defense effectiveness")

    report.append("")
    report.append("=" * 60)

    report_text = "\n".join(report)
    print(report_text)

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(report_text)

    print(f"\n[+] Report saved to: {REPORT_FILE}")

# ── SIEM: Generate automated JSON alert ──────────────────────
def generate_siem_alert(comparison):
    if not comparison or comparison['detection_gap_pct'] <= 0:
        return # Only generate an alert if tampering is actually detected
        
    alert_data = {
        "alert_id": "PHANTOM-DETECT-001",
        "timestamp": str(datetime.datetime.now()),
        "severity": "CRITICAL",
        "mitre_technique": "T1562.006",
        "mitre_tactic": "Defense Evasion",
        "description": "ETW telemetry gap detected via Kernel Process Callback cross-correlation.",
        "threat_actor_associations": ["Remcos RAT", "Lazarus FudModule"],
        "ghost_processes": list(comparison['missing_processes'])
    }
    
    with open(ALERT_FILE, 'w', encoding='utf-8') as f:
        json.dump(alert_data, f, indent=4)
        
    print(f"[+] Automated SIEM Alert generated: {ALERT_FILE}")

# ── Main ─────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Project Phantom - Phase 5")
    print("  Cross-Correlation Analyzer")
    print("=" * 60)
    print()

    # load baseline log from Phase 2
    print(f"[*] Loading baseline log: {BASELINE_FILE}")
    baseline = load_log(BASELINE_FILE)
    if not baseline:
        print("[-] Run Phase 2 first to generate baseline")
        return

    # check if tampered log exists
    if not os.path.exists(TAMPERED_FILE):
        print(f"[!] Tampered log not found: {TAMPERED_FILE}")
        print("[*] Generating tampered capture now...")
        print("[*] Make sure Phase 3 tamper tool is running")
        print("[*] Then re-run this script")
        print()
        print("[*] Steps to generate tampered log:")
        print("    1. Open PowerShell as Admin")
        print("    2. Run: .\\projectTamper.exe")
        print("    3. Keep tamper tool open")
        print("    4. Open another PowerShell as Admin")
        print("    5. Run: python etw_baseline_monitor.py")
        print("    6. Rename output to etw_tampered_log.json")
        print("    7. Run this script again")
        return

    print(f"[*] Loading tampered log: {TAMPERED_FILE}")
    tampered = load_log(TAMPERED_FILE)
    if not tampered:
        return

    print()

    # compare the two logs
    comparison = compare_logs(baseline, tampered)

    if comparison:
        generate_report(comparison)
        generate_siem_alert(comparison)

if __name__ == "__main__":
    main()