#!/usr/bin/env python3
"""
Microsoft Defender for Identity (MDI/ATP) Sensor Log Analyser
=============================================================
Parses and analyses Microsoft.Tri.Sensor log files to surface:
  - Log level distribution & timeline
  - Top errors and warnings (deduplicated)
  - Authentication anomalies (wrong passwords, old password checks)
  - LDAP failures and referral errors
  - Kerberos/NTLM activity summary
  - Affected accounts and computers
  - Updater health & error summary
  - Timeline of error spikes

Usage:
    python3 analyse_mdi_logs.py [logs_directory]
    python3 analyse_mdi_logs.py                    # defaults to ./logs
    python3 analyse_mdi_logs.py /path/to/logs --html report.html
"""

import argparse
import glob
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Regex patterns for MDI log lines
# ---------------------------------------------------------------------------
# Main log line:  2026-04-10 15:42:02.0042 Warn  SamplerLogger ResolveAuth...
LOG_LINE_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+'  # timestamp
    r'(Error|Warn|Info|Debug|Fatal|Verbose)\s+'            # level
    r'(\S+)\s+'                                            # component
    r'(\S+)\s*'                                            # method/context
    r'(.*)',                                                # message
    re.IGNORECASE
)

# Key-value pairs inside [...] blocks
KV_RE = re.compile(r'(\w[\w.]*)\s*=\s*([^\s,\]]+(?:\s+[^\s=,\]]+)*?)(?=\s+\w[\w.]*=|[\],]|$)')

# DN extraction
DN_RE = re.compile(r'CN=([^,]+)')

# ---------------------------------------------------------------------------
# Colour helpers for terminal output
# ---------------------------------------------------------------------------
class C:
    """ANSI colour codes (disabled if not a tty)."""
    _enabled = sys.stdout.isatty()
    RED = '\033[91m' if _enabled else ''
    YELLOW = '\033[93m' if _enabled else ''
    GREEN = '\033[92m' if _enabled else ''
    CYAN = '\033[96m' if _enabled else ''
    BOLD = '\033[1m' if _enabled else ''
    DIM = '\033[2m' if _enabled else ''
    RESET = '\033[0m' if _enabled else ''


def coloured_level(level: str) -> str:
    level_upper = level.upper()
    if level_upper in ('ERROR', 'FATAL'):
        return f"{C.RED}{C.BOLD}{level_upper}{C.RESET}"
    elif level_upper == 'WARN':
        return f"{C.YELLOW}{level_upper}{C.RESET}"
    elif level_upper == 'INFO':
        return f"{C.GREEN}{level_upper}{C.RESET}"
    return f"{C.DIM}{level_upper}{C.RESET}"


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
class LogEntry:
    __slots__ = ('timestamp', 'level', 'component', 'method', 'message', 'raw')

    def __init__(self, timestamp, level, component, method, message, raw):
        self.timestamp = timestamp
        self.level = level.upper()
        self.component = component
        self.method = method
        self.message = message
        self.raw = raw


def parse_log_file(filepath: str):
    """Yield LogEntry objects from a single log file. Handles multiline stack traces."""
    entries = []
    current = None
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                m = LOG_LINE_RE.match(line)
                if m:
                    if current:
                        entries.append(current)
                    ts_str, level, component, method, message = m.groups()
                    try:
                        ts = datetime.strptime(ts_str[:23], '%Y-%m-%d %H:%M:%S.%f')
                    except ValueError:
                        ts = None
                    current = LogEntry(ts, level, component, method, message.strip(), line.rstrip())
                elif current:
                    # continuation line (stack trace etc)
                    current.message += '\n' + line.rstrip()
                    current.raw += '\n' + line.rstrip()
        if current:
            entries.append(current)
    except Exception as e:
        print(f"  {C.RED}Error reading {filepath}: {e}{C.RESET}", file=sys.stderr)
    return entries


def discover_log_files(log_dir: str) -> dict:
    """Return dict of category -> sorted list of file paths."""
    categories = {
        'sensor': [],
        'sensor_errors': [],
        'updater': [],
        'updater_errors': [],
    }
    for f in sorted(glob.glob(os.path.join(log_dir, 'Microsoft.Tri.Sensor*'))):
        basename = os.path.basename(f)
        if 'Updater-Errors' in basename:
            categories['updater_errors'].append(f)
        elif 'Updater' in basename:
            categories['updater'].append(f)
        elif 'Errors' in basename:
            categories['sensor_errors'].append(f)
        else:
            categories['sensor'].append(f)
    return categories


def extract_kv(message: str) -> dict:
    """Extract key=value pairs from a log message."""
    return dict(KV_RE.findall(message))


def extract_cn(dn_string: str) -> str:
    """Pull the CN= value from a distinguished name."""
    m = DN_RE.search(dn_string)
    return m.group(1) if m else dn_string


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------
def analyse_entries(entries: list[LogEntry]) -> dict:
    """Run all analyses on a list of log entries and return a results dict."""
    results = {}

    # --- Basic stats ---
    level_counts = Counter(e.level for e in entries)
    results['level_counts'] = level_counts
    results['total_lines'] = len(entries)

    if entries and entries[0].timestamp and entries[-1].timestamp:
        results['time_range'] = (entries[0].timestamp, entries[-1].timestamp)
    else:
        results['time_range'] = None

    # --- Component breakdown ---
    component_counts = Counter(e.component for e in entries)
    results['top_components'] = component_counts.most_common(20)

    # --- Error classification ---
    error_entries = [e for e in entries if e.level in ('ERROR', 'FATAL')]
    error_signatures = Counter()
    error_examples = {}
    for e in error_entries:
        # Normalise: strip timestamps, GUIDs, specific DNs for grouping
        sig = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<GUID>', e.message)
        sig = re.sub(r'DC=\w+', 'DC=*', sig)
        sig = re.sub(r'CN=\w+', 'CN=*', sig)
        # Truncate for grouping
        sig_key = sig[:200]
        error_signatures[sig_key] += 1
        if sig_key not in error_examples:
            error_examples[sig_key] = e

    results['error_signatures'] = error_signatures.most_common(15)
    results['error_examples'] = error_examples
    results['total_errors'] = len(error_entries)

    # --- Warning classification ---
    warn_entries = [e for e in entries if e.level == 'WARN']
    warn_signatures = Counter()
    warn_examples = {}
    for e in warn_entries:
        sig = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<GUID>', e.message)
        sig = re.sub(r'DC=\w+', 'DC=*', sig)
        sig = re.sub(r'CN=\w+', 'CN=*', sig)
        sig_key = sig[:200]
        warn_signatures[sig_key] += 1
        if sig_key not in warn_examples:
            warn_examples[sig_key] = e
    results['warn_signatures'] = warn_signatures.most_common(15)
    results['warn_examples'] = warn_examples
    results['total_warnings'] = len(warn_entries)

    # --- Authentication analysis ---
    auth_entries = [e for e in entries if 'ResolveAuthenticationActivityAsync' in e.message
                    or 'KerberosAs' in e.message or 'Ntlm' in e.message]
    wrong_password_entries = [e for e in auth_entries if 'IsWrongPassword=True' in e.message]
    old_password_entries = [e for e in auth_entries if 'Old password check' in e.message]

    # Extract affected accounts
    wrong_pw_accounts = Counter()
    wrong_pw_targets = Counter()
    for e in wrong_password_entries:
        kv = extract_kv(e.message)
        src_dn = kv.get('sourceAccount.DistinguishedName', '')
        dst_dn = kv.get('destinationComputer.DistinguishedName', '')
        if src_dn:
            wrong_pw_accounts[extract_cn(src_dn)] += 1
        if dst_dn:
            wrong_pw_targets[extract_cn(dst_dn)] += 1

    auth_types = Counter()
    for e in auth_entries:
        kv = extract_kv(e.message)
        auth_type = kv.get('Type', 'Unknown')
        auth_types[auth_type] += 1

    results['auth_total'] = len(auth_entries)
    results['wrong_password_total'] = len(wrong_password_entries)
    results['old_password_checks'] = len(old_password_entries)
    results['wrong_pw_accounts'] = wrong_pw_accounts.most_common(20)
    results['wrong_pw_targets'] = wrong_pw_targets.most_common(10)
    results['auth_types'] = auth_types.most_common(10)

    # --- LDAP failure analysis ---
    ldap_failures = [e for e in entries if 'LDAP search failed' in e.message]
    ldap_result_codes = Counter()
    ldap_target_dcs = Counter()
    ldap_target_dns = Counter()
    for e in ldap_failures:
        kv = extract_kv(e.message)
        rc_match = re.search(r'ResultCode=(\w+)', e.message)
        if rc_match:
            ldap_result_codes[rc_match.group(1)] += 1
        dc = kv.get('DomainControllerDnsName', 'Unknown')
        ldap_target_dcs[dc] += 1
        dn = kv.get('DistinguishedName', 'Unknown')
        ldap_target_dns[dn[:80]] += 1

    results['ldap_failures'] = len(ldap_failures)
    results['ldap_result_codes'] = ldap_result_codes.most_common(10)
    results['ldap_target_dcs'] = ldap_target_dcs.most_common(10)
    results['ldap_target_dns'] = ldap_target_dns.most_common(15)

    # --- Kerberos / NTLM network activity ---
    net_entries = [e for e in entries if e.component == 'NetworkActivityEntityResolver']
    kerberos_tgs = [e for e in net_entries if 'ResolveKerberosTgsAsync' in e.method]
    results['kerberos_tgs_total'] = len(kerberos_tgs)

    resource_names = Counter()
    source_accounts_net = Counter()
    for e in kerberos_tgs:
        kv = extract_kv(e.message)
        rn = kv.get('ResourceName', 'Unknown')
        resource_names[rn] += 1
        sa = kv.get('SourceAccountName', 'Unknown')
        source_accounts_net[sa] += 1

    results['kerberos_resource_names'] = resource_names.most_common(15)
    results['kerberos_source_accounts'] = source_accounts_net.most_common(15)

    # --- Connection / LDAP connectivity issues ---
    conn_failures = [e for e in entries if 'CreateLdapConnectionAsync' in e.message
                     or 'TryCreateLdapConnectionAsync failed' in e.message]
    failed_dcs = Counter()
    for e in conn_failures:
        dc_match = re.search(r'DomainControllerDnsName=(\S+?)[\]\s]', e.message)
        if dc_match:
            failed_dcs[dc_match.group(1)] += 1
    results['connection_failures'] = len(conn_failures)
    results['failed_dcs'] = failed_dcs.most_common(10)

    # --- Timeline: errors per hour ---
    error_timeline = defaultdict(int)
    warn_timeline = defaultdict(int)
    for e in entries:
        if e.timestamp:
            hour_key = e.timestamp.strftime('%Y-%m-%d %H:00')
            if e.level in ('ERROR', 'FATAL'):
                error_timeline[hour_key] += 1
            elif e.level == 'WARN':
                warn_timeline[hour_key] += 1

    results['error_timeline'] = dict(sorted(error_timeline.items()))
    results['warn_timeline'] = dict(sorted(warn_timeline.items()))

    # --- Sensor state transitions ---
    state_entries = [e for e in entries if 'SetState' in e.message]
    state_transitions = Counter()
    for e in state_entries:
        state_transitions[f"{e.component} -> {e.message}"] += 1
    results['state_transitions'] = state_transitions.most_common(20)

    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_section(title: str):
    width = 80
    print(f"\n{C.CYAN}{C.BOLD}{'=' * width}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  {title}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'=' * width}{C.RESET}")


def print_subsection(title: str):
    print(f"\n  {C.BOLD}{title}{C.RESET}")
    print(f"  {'-' * 60}")


def print_counter(items, max_items=15, indent=4):
    pad = ' ' * indent
    if not items:
        print(f"{pad}{C.DIM}(none){C.RESET}")
        return
    max_label_len = max(len(str(label)) for label, _ in items[:max_items])
    for label, count in items[:max_items]:
        bar_len = min(count // max(1, items[0][1] // 30), 30) if items else 0
        bar = '█' * bar_len
        print(f"{pad}{str(label):<{max_label_len}}  {count:>8,}  {C.DIM}{bar}{C.RESET}")


def print_report(all_results: dict, categories: dict):
    """Print the full analysis report to stdout."""

    print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║     Microsoft Defender for Identity (MDI) Sensor Log Analysis Report       ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{C.RESET}")

    # --- File inventory ---
    print_section("1. LOG FILE INVENTORY")
    total_size = 0
    for cat, files in categories.items():
        if files:
            cat_size = sum(os.path.getsize(f) for f in files)
            total_size += cat_size
            print(f"  {C.BOLD}{cat.replace('_', ' ').title()}{C.RESET}: {len(files)} file(s), {cat_size / 1024 / 1024:.1f} MB")
            for f in files:
                sz = os.path.getsize(f)
                print(f"    {C.DIM}{os.path.basename(f):60s} {sz / 1024 / 1024:>7.1f} MB{C.RESET}")
    print(f"\n  {C.BOLD}Total: {total_size / 1024 / 1024:.1f} MB across "
          f"{sum(len(v) for v in categories.values())} files{C.RESET}")

    # --- Per-category reports ---
    for cat_name, cat_label in [
        ('sensor', 'SENSOR LOG ANALYSIS'),
        ('sensor_errors', 'SENSOR ERROR LOG ANALYSIS'),
        ('updater', 'UPDATER LOG ANALYSIS'),
        ('updater_errors', 'UPDATER ERROR LOG ANALYSIS'),
    ]:
        if cat_name not in all_results:
            continue
        r = all_results[cat_name]

        print_section(f"2. {cat_label}")

        # Time range
        if r['time_range']:
            t0, t1 = r['time_range']
            duration = t1 - t0
            print(f"  Time range: {t0} -> {t1} ({duration})")
        print(f"  Total log entries: {r['total_lines']:,}")

        # Level breakdown
        print_subsection("Log Level Distribution")
        for level in ('FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'VERBOSE'):
            count = r['level_counts'].get(level, 0)
            if count > 0:
                pct = count / r['total_lines'] * 100 if r['total_lines'] else 0
                print(f"    {coloured_level(level):>20s}  {count:>10,}  ({pct:5.1f}%)")

        # Top components
        print_subsection("Top Components by Log Volume")
        print_counter(r['top_components'], indent=4)

        # --- Error analysis ---
        if r['total_errors'] > 0:
            print_subsection(f"Error Classification ({r['total_errors']:,} total errors)")
            for i, (sig, count) in enumerate(r['error_signatures'], 1):
                print(f"\n    {C.RED}[Error #{i}]{C.RESET} Count: {count:,}")
                # Show first 120 chars of signature
                display_sig = sig[:120] + ('...' if len(sig) > 120 else '')
                print(f"    {display_sig}")

        # --- Warning analysis ---
        if r['total_warnings'] > 0:
            print_subsection(f"Top Warning Types ({r['total_warnings']:,} total warnings)")
            for i, (sig, count) in enumerate(r['warn_signatures'][:10], 1):
                display_sig = sig[:120] + ('...' if len(sig) > 120 else '')
                print(f"    {C.YELLOW}[Warn #{i}]{C.RESET} Count: {count:,}")
                print(f"    {display_sig}")

        # --- Authentication analysis (sensor logs mainly) ---
        if r.get('auth_total', 0) > 0:
            print_subsection("Authentication Activity Analysis")
            print(f"    Total auth-related entries:    {r['auth_total']:,}")
            print(f"    Wrong password attempts:       {C.RED}{r['wrong_password_total']:,}{C.RESET}")
            print(f"    Old password checks:           {r['old_password_checks']:,}")

            if r['auth_types']:
                print(f"\n    {C.BOLD}Authentication Protocol Breakdown:{C.RESET}")
                print_counter(r['auth_types'], indent=6)

            if r['wrong_pw_accounts']:
                print(f"\n    {C.BOLD}Accounts with Wrong Passwords (potential brute-force):{C.RESET}")
                print_counter(r['wrong_pw_accounts'], indent=6)

            if r['wrong_pw_targets']:
                print(f"\n    {C.BOLD}Target Computers for Failed Auth:{C.RESET}")
                print_counter(r['wrong_pw_targets'], indent=6)

        # --- LDAP analysis ---
        if r.get('ldap_failures', 0) > 0:
            print_subsection(f"LDAP Failure Analysis ({r['ldap_failures']:,} failures)")

            if r['ldap_result_codes']:
                print(f"    {C.BOLD}LDAP Result Codes:{C.RESET}")
                print_counter(r['ldap_result_codes'], indent=6)

            if r['ldap_target_dcs']:
                print(f"\n    {C.BOLD}Affected Domain Controllers:{C.RESET}")
                print_counter(r['ldap_target_dcs'], indent=6)

            if r['ldap_target_dns']:
                print(f"\n    {C.BOLD}Affected Distinguished Names (top targets):{C.RESET}")
                print_counter(r['ldap_target_dns'], indent=6)

        # --- Connection failures ---
        if r.get('connection_failures', 0) > 0:
            print_subsection(f"LDAP Connection Failures ({r['connection_failures']:,} total)")
            if r['failed_dcs']:
                print(f"    {C.BOLD}Failed Domain Controllers:{C.RESET}")
                print_counter(r['failed_dcs'], indent=6)

        # --- Kerberos network activity ---
        if r.get('kerberos_tgs_total', 0) > 0:
            print_subsection(f"Kerberos TGS Activity ({r['kerberos_tgs_total']:,} entries)")
            if r['kerberos_resource_names']:
                print(f"    {C.BOLD}Requested Resources:{C.RESET}")
                print_counter(r['kerberos_resource_names'], indent=6)
            if r['kerberos_source_accounts']:
                print(f"\n    {C.BOLD}Source Accounts:{C.RESET}")
                print_counter(r['kerberos_source_accounts'], indent=6)

        # --- State transitions ---
        if r.get('state_transitions'):
            print_subsection("Sensor Component State Transitions")
            for label, count in r['state_transitions'][:15]:
                print(f"    {label:60s} x{count}")

        # --- Error timeline ---
        if r.get('error_timeline'):
            print_subsection("Error Timeline (per hour)")
            timeline = r['error_timeline']
            if timeline:
                max_val = max(timeline.values()) if timeline else 1
                for hour, count in list(timeline.items())[-24:]:  # last 24 hours
                    bar_len = int(count / max_val * 40) if max_val else 0
                    bar = '█' * bar_len
                    colour = C.RED if count > max_val * 0.7 else C.YELLOW if count > max_val * 0.3 else C.DIM
                    print(f"    {hour}  {colour}{count:>6,}  {bar}{C.RESET}")

    # --- Security-focused summary ---
    print_section("3. SECURITY-RELEVANT FINDINGS SUMMARY")

    sensor_r = all_results.get('sensor', {})
    sensor_err_r = all_results.get('sensor_errors', {})

    findings = []

    # Wrong passwords
    total_wrong_pw = sensor_r.get('wrong_password_total', 0) + sensor_err_r.get('wrong_password_total', 0)
    if total_wrong_pw > 0:
        accts = sensor_r.get('wrong_pw_accounts', []) or sensor_err_r.get('wrong_pw_accounts', [])
        acct_str = ', '.join(a for a, _ in accts[:5]) if accts else 'unknown'
        severity = 'HIGH' if total_wrong_pw > 100 else 'MEDIUM' if total_wrong_pw > 10 else 'LOW'
        findings.append((severity, f"Wrong password attempts: {total_wrong_pw:,} "
                         f"(accounts: {acct_str})"))

    # LDAP referrals
    total_ldap = sensor_r.get('ldap_failures', 0) + sensor_err_r.get('ldap_failures', 0)
    if total_ldap > 0:
        findings.append(('MEDIUM', f"LDAP search failures: {total_ldap:,} "
                         f"(mostly Referral errors - cross-domain resolution issues)"))

    # Connection failures
    total_conn = sensor_r.get('connection_failures', 0)
    if total_conn > 0:
        dcs = sensor_r.get('failed_dcs', [])
        dc_str = ', '.join(d for d, _ in dcs[:3]) if dcs else 'unknown'
        findings.append(('MEDIUM', f"LDAP connection failures: {total_conn:,} "
                         f"(DCs: {dc_str})"))

    # High error rate
    total_errors = sensor_r.get('total_errors', 0) + sensor_err_r.get('total_errors', 0)
    if total_errors > 1000:
        findings.append(('HIGH', f"Very high error count: {total_errors:,} across sensor logs"))
    elif total_errors > 100:
        findings.append(('MEDIUM', f"Elevated error count: {total_errors:,} across sensor logs"))

    if not findings:
        print(f"  {C.GREEN}No significant security findings.{C.RESET}")
    else:
        for severity, msg in sorted(findings, key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(x[0], 3)):
            if severity == 'HIGH':
                sev_col = f"{C.RED}{C.BOLD}[{severity}]{C.RESET}"
            elif severity == 'MEDIUM':
                sev_col = f"{C.YELLOW}[{severity}]{C.RESET}"
            else:
                sev_col = f"{C.DIM}[{severity}]{C.RESET}"
            print(f"  {sev_col} {msg}")

    # --- Recommendations ---
    print_section("4. RECOMMENDATIONS")
    rec_num = 1
    if total_wrong_pw > 50:
        print(f"  {rec_num}. {C.BOLD}Investigate repeated wrong password attempts{C.RESET}")
        print(f"     Accounts with high failure rates may indicate brute-force or credential stuffing.")
        print(f"     Check if the affected service accounts have been locked out or compromised.")
        rec_num += 1

    if total_ldap > 100:
        print(f"  {rec_num}. {C.BOLD}Resolve LDAP referral errors{C.RESET}")
        print(f"     The sensor is trying to resolve objects in child/remote domains via the local DC.")
        print(f"     Ensure the sensor can reach GC ports on all relevant DCs, or configure additional sensors.")
        rec_num += 1

    if total_conn > 0:
        print(f"  {rec_num}. {C.BOLD}Fix LDAP connectivity to failing DCs{C.RESET}")
        print(f"     Some domain controllers are unreachable. Check DNS, firewall rules (TCP 389/636/3268),")
        print(f"     and DC health for the failing targets.")
        rec_num += 1

    if total_errors > 500:
        print(f"  {rec_num}. {C.BOLD}Address high sensor error rate{C.RESET}")
        print(f"     A high error count can degrade detection coverage. Review the top error types above")
        print(f"     and address root causes (LDAP, connectivity, permissions).")
        rec_num += 1

    updater_err = all_results.get('updater_errors', {})
    if updater_err and updater_err.get('total_errors', 0) > 0:
        print(f"  {rec_num}. {C.BOLD}Review updater errors{C.RESET}")
        print(f"     The sensor updater has logged {updater_err.get('total_errors', 0):,} errors.")
        print(f"     Ensure the sensor can reach the MDI cloud service for updates.")
        rec_num += 1

    if rec_num == 1:
        print(f"  {C.GREEN}No specific recommendations - logs look healthy.{C.RESET}")

    print(f"\n{C.DIM}{'─' * 80}{C.RESET}")
    print(f"{C.DIM}Analysis complete. Run with --html <file> to export an HTML report.{C.RESET}\n")


# ---------------------------------------------------------------------------
# HTML report export
# ---------------------------------------------------------------------------
def generate_html_report(all_results: dict, categories: dict, output_path: str):
    """Generate an HTML report file."""
    html_parts = []
    html_parts.append("""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MDI Sensor Log Analysis</title>
<style>
body{font-family:'Segoe UI',Tahoma,sans-serif;margin:20px;background:#1e1e2e;color:#cdd6f4}
h1{color:#89b4fa;border-bottom:2px solid #89b4fa;padding-bottom:10px}
h2{color:#a6e3a1;margin-top:30px}
h3{color:#f9e2af}
table{border-collapse:collapse;margin:10px 0;width:auto}
th,td{padding:6px 14px;text-align:left;border:1px solid #45475a}
th{background:#313244;color:#cba6f7}
td{background:#1e1e2e}
.error{color:#f38ba8;font-weight:bold}
.warn{color:#f9e2af}
.info{color:#a6e3a1}
.high{color:#f38ba8;font-weight:bold}
.medium{color:#f9e2af}
.low{color:#a6adc8}
.bar{background:#89b4fa;height:14px;display:inline-block;border-radius:2px}
pre{background:#313244;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px}
.summary-box{background:#313244;border-left:4px solid #89b4fa;padding:15px;margin:10px 0;border-radius:4px}
</style></head><body>
<h1>Microsoft Defender for Identity - Sensor Log Analysis Report</h1>
<p>Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "</p>\n")

    # File inventory
    html_parts.append("<h2>Log File Inventory</h2><table><tr><th>Category</th><th>Files</th><th>Size</th></tr>")
    for cat, files in categories.items():
        if files:
            cat_size = sum(os.path.getsize(f) for f in files)
            html_parts.append(f"<tr><td>{cat.replace('_',' ').title()}</td>"
                              f"<td>{len(files)}</td><td>{cat_size/1024/1024:.1f} MB</td></tr>")
    html_parts.append("</table>")

    for cat_name, cat_label in [('sensor', 'Sensor Logs'), ('sensor_errors', 'Sensor Error Logs'),
                                 ('updater', 'Updater Logs'), ('updater_errors', 'Updater Error Logs')]:
        if cat_name not in all_results:
            continue
        r = all_results[cat_name]
        html_parts.append(f"<h2>{cat_label}</h2>")

        # Level distribution
        html_parts.append("<h3>Log Level Distribution</h3><table><tr><th>Level</th><th>Count</th><th>%</th></tr>")
        for level in ('FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG'):
            count = r['level_counts'].get(level, 0)
            if count:
                pct = count / r['total_lines'] * 100 if r['total_lines'] else 0
                css = 'error' if level in ('ERROR', 'FATAL') else 'warn' if level == 'WARN' else 'info'
                html_parts.append(f"<tr><td class='{css}'>{level}</td><td>{count:,}</td><td>{pct:.1f}%</td></tr>")
        html_parts.append("</table>")

        # Auth analysis
        if r.get('wrong_password_total', 0) > 0:
            html_parts.append("<h3>Authentication Anomalies</h3>")
            html_parts.append(f"<div class='summary-box'>Wrong password attempts: "
                              f"<span class='error'>{r['wrong_password_total']:,}</span></div>")
            if r['wrong_pw_accounts']:
                html_parts.append("<table><tr><th>Account</th><th>Failed Attempts</th></tr>")
                for acct, cnt in r['wrong_pw_accounts'][:15]:
                    html_parts.append(f"<tr><td>{acct}</td><td>{cnt:,}</td></tr>")
                html_parts.append("</table>")

        # LDAP
        if r.get('ldap_failures', 0) > 0:
            html_parts.append(f"<h3>LDAP Failures ({r['ldap_failures']:,})</h3>")
            if r['ldap_target_dcs']:
                html_parts.append("<table><tr><th>Domain Controller</th><th>Failures</th></tr>")
                for dc, cnt in r['ldap_target_dcs']:
                    html_parts.append(f"<tr><td>{dc}</td><td>{cnt:,}</td></tr>")
                html_parts.append("</table>")

        # Error timeline
        if r.get('error_timeline'):
            html_parts.append("<h3>Error Timeline (per hour)</h3><table><tr><th>Hour</th><th>Errors</th><th></th></tr>")
            max_val = max(r['error_timeline'].values()) if r['error_timeline'] else 1
            for hour, count in list(r['error_timeline'].items())[-48:]:
                bar_w = int(count / max_val * 200) if max_val else 0
                html_parts.append(f"<tr><td>{hour}</td><td>{count:,}</td>"
                                  f"<td><div class='bar' style='width:{bar_w}px'></div></td></tr>")
            html_parts.append("</table>")

    html_parts.append("</body></html>")

    with open(output_path, 'w') as f:
        f.write('\n'.join(html_parts))
    print(f"\n{C.GREEN}HTML report written to: {output_path}{C.RESET}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Analyse Microsoft Defender for Identity (MDI/ATP) sensor log files')
    parser.add_argument('log_dir', nargs='?', default='./logs',
                        help='Path to the logs directory (default: ./logs)')
    parser.add_argument('--html', metavar='FILE',
                        help='Export an HTML report to the specified file')
    parser.add_argument('--errors-only', action='store_true',
                        help='Only analyse error-level entries')
    args = parser.parse_args()

    log_dir = args.log_dir
    if not os.path.isdir(log_dir):
        print(f"{C.RED}Error: '{log_dir}' is not a directory{C.RESET}", file=sys.stderr)
        sys.exit(1)

    categories = discover_log_files(log_dir)
    if not any(categories.values()):
        print(f"{C.RED}Error: No MDI sensor log files found in '{log_dir}'{C.RESET}", file=sys.stderr)
        sys.exit(1)

    all_results = {}

    for cat_name, files in categories.items():
        if not files:
            continue
        print(f"\n{C.CYAN}Parsing {cat_name.replace('_', ' ')} ({len(files)} file(s))...{C.RESET}")
        all_entries = []
        for filepath in files:
            basename = os.path.basename(filepath)
            print(f"  Reading {basename}...", end=' ', flush=True)
            entries = parse_log_file(filepath)
            print(f"{len(entries):,} entries")
            all_entries.extend(entries)

        # Sort by timestamp
        all_entries.sort(key=lambda e: e.timestamp or datetime.min)

        if args.errors_only:
            all_entries = [e for e in all_entries if e.level in ('ERROR', 'FATAL')]

        print(f"  {C.BOLD}Total: {len(all_entries):,} entries{C.RESET}")
        all_results[cat_name] = analyse_entries(all_entries)

    print_report(all_results, categories)

    if args.html:
        generate_html_report(all_results, categories, args.html)


if __name__ == '__main__':
    main()
