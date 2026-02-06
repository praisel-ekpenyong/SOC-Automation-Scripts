#!/usr/bin/env python3
"""
Windows Security Log Analyzer - Parse and analyze Windows Security Event logs

Usage:
    python log_analyzer.py --input sample_log.json
    python log_analyzer.py --input security_events.csv --output flagged_events.csv

Features:
    - Parse JSON or CSV Windows Security/Sysmon logs
    - Flag suspicious events (failed logins, RDP, privilege escalation, suspicious processes)
    - Generate summary statistics
    - Output CSV report of flagged events
"""

import argparse
import json
import csv
import sys
from datetime import datetime
from typing import List, Dict, Tuple
from collections import defaultdict, Counter
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


# Suspicious process names to flag
SUSPICIOUS_PROCESSES = [
    'powershell.exe', 'cmd.exe', 'whoami.exe', 'net.exe', 
    'mimikatz.exe', 'psexec.exe', 'wmic.exe', 'netsh.exe',
    'reg.exe', 'sc.exe', 'taskkill.exe'
]


def load_log_file(file_path: str) -> List[Dict]:
    """Load log file (JSON or CSV format)."""
    try:
        # Try JSON first
        if file_path.endswith('.json'):
            with open(file_path, 'r') as f:
                data = json.load(f)
                # Handle both single object and array
                if isinstance(data, list):
                    return data
                else:
                    return [data]
        
        # Try CSV
        elif file_path.endswith('.csv'):
            with open(file_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                return list(reader)
        
        else:
            print(f"{Fore.RED}Error: Unsupported file format. Use .json or .csv")
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}Error: Invalid JSON format: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error loading file: {e}")
        sys.exit(1)


def normalize_event(event: Dict) -> Dict:
    """Normalize event structure for consistent access."""
    # Handle different JSON structures
    normalized = {}
    
    # Try to extract Event ID
    event_id = event.get('EventID') or event.get('event_id') or event.get('Event', {}).get('System', {}).get('EventID', 'Unknown')
    if isinstance(event_id, dict):
        event_id = event_id.get('#text', 'Unknown')
    normalized['EventID'] = str(event_id)
    
    # Extract other fields
    normalized['TimeCreated'] = (event.get('TimeCreated') or event.get('timestamp') or 
                                  event.get('Event', {}).get('System', {}).get('TimeCreated', {}).get('@SystemTime', 'Unknown'))
    
    normalized['Computer'] = event.get('Computer') or event.get('computer') or event.get('Event', {}).get('System', {}).get('Computer', 'Unknown')
    
    # Event data fields
    event_data = event.get('EventData') or event.get('event_data') or event.get('Event', {}).get('EventData', {})
    
    normalized['TargetUserName'] = event.get('TargetUserName') or event_data.get('TargetUserName', 'N/A')
    normalized['IpAddress'] = event.get('IpAddress') or event_data.get('IpAddress', 'N/A')
    normalized['SourceAddress'] = event.get('SourceAddress') or event_data.get('IpAddress', 'N/A')
    normalized['LogonType'] = event.get('LogonType') or event_data.get('LogonType', 'N/A')
    normalized['ProcessName'] = event.get('ProcessName') or event_data.get('NewProcessName', 'N/A')
    normalized['CommandLine'] = event.get('CommandLine') or event_data.get('CommandLine', 'N/A')
    normalized['SubjectUserName'] = event.get('SubjectUserName') or event_data.get('SubjectUserName', 'N/A')
    normalized['MemberSid'] = event.get('MemberSid') or event_data.get('MemberSid', 'N/A')
    
    # Keep original for reference
    normalized['_original'] = event
    
    return normalized


def analyze_event(event: Dict) -> Tuple[bool, str, str]:
    """
    Analyze single event for suspicious activity.
    Returns: (is_suspicious, severity, reason)
    """
    event = normalize_event(event)
    event_id = event['EventID']
    
    # Event ID 4625: Failed logon
    if event_id == '4625':
        return True, 'MEDIUM', f"Failed logon attempt for user {event['TargetUserName']} from {event['IpAddress']}"
    
    # Event ID 4624 with Logon Type 10: RDP logon
    elif event_id == '4624' and event['LogonType'] == '10':
        return True, 'MEDIUM', f"RDP logon by {event['TargetUserName']} from {event['SourceAddress']}"
    
    # Event ID 4720: User account created
    elif event_id == '4720':
        return True, 'HIGH', f"New user account created: {event['TargetUserName']} by {event['SubjectUserName']}"
    
    # Event ID 4728/4732: User added to privileged group
    elif event_id in ['4728', '4732']:
        group_name = "security-enabled global group" if event_id == '4728' else "security-enabled local group"
        return True, 'HIGH', f"User added to {group_name} (Possible privilege escalation)"
    
    # Event ID 4688: Process creation
    elif event_id == '4688':
        process_name = event['ProcessName'].lower() if event['ProcessName'] != 'N/A' else ''
        
        # Check for suspicious processes
        for sus_proc in SUSPICIOUS_PROCESSES:
            if sus_proc in process_name:
                return True, 'MEDIUM', f"Suspicious process created: {event['ProcessName']}"
        
        # Check for encoded commands
        cmdline = event['CommandLine']
        if cmdline != 'N/A' and ('-enc' in cmdline.lower() or '-e ' in cmdline.lower() or 'encodedcommand' in cmdline.lower()):
            return True, 'HIGH', f"Encoded PowerShell command detected: {cmdline[:100]}"
    
    # Event ID 1 (Sysmon): Process creation
    elif event_id == '1':
        cmdline = event['CommandLine']
        if cmdline != 'N/A' and ('-enc' in cmdline.lower() or 'encodedcommand' in cmdline.lower()):
            return True, 'HIGH', f"Encoded command in Sysmon event: {cmdline[:100]}"
    
    return False, 'INFO', 'Normal event'


def analyze_failed_logins(events: List[Dict]) -> Dict[str, int]:
    """Count failed login attempts by source."""
    failed_logins = defaultdict(int)
    
    for event in events:
        norm_event = normalize_event(event)
        if norm_event['EventID'] == '4625':
            source = norm_event['IpAddress']
            if source != 'N/A':
                failed_logins[source] += 1
    
    return dict(failed_logins)


def generate_summary(events: List[Dict], flagged: List[Dict]) -> Dict:
    """Generate summary statistics."""
    event_ids = Counter()
    severity_counts = Counter()
    source_ips = Counter()
    target_users = Counter()
    
    for event in events:
        norm_event = normalize_event(event)
        event_ids[norm_event['EventID']] += 1
    
    for flagged_event in flagged:
        severity_counts[flagged_event['severity']] += 1
        
        if flagged_event['source_ip'] != 'N/A':
            source_ips[flagged_event['source_ip']] += 1
        
        if flagged_event['target_user'] != 'N/A':
            target_users[flagged_event['target_user']] += 1
    
    return {
        'total_events': len(events),
        'flagged_events': len(flagged),
        'event_id_distribution': dict(event_ids.most_common(10)),
        'severity_counts': dict(severity_counts),
        'top_source_ips': dict(source_ips.most_common(10)),
        'top_target_users': dict(target_users.most_common(10))
    }


def save_csv_report(flagged_events: List[Dict], output_file: str):
    """Save flagged events to CSV file."""
    if not flagged_events:
        print(f"{Fore.YELLOW}No flagged events to save")
        return
    
    try:
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['timestamp', 'event_id', 'severity', 'reason', 
                         'computer', 'source_ip', 'target_user', 'process']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            writer.writerows(flagged_events)
        
        print(f"{Fore.GREEN}CSV report saved to: {output_file}")
    except Exception as e:
        print(f"{Fore.RED}Error saving CSV report: {e}")


def display_summary(summary: Dict, failed_logins: Dict[str, int]):
    """Display formatted summary."""
    print(f"\n{Style.BRIGHT}{'=' * 70}")
    print(f"WINDOWS SECURITY LOG ANALYSIS SUMMARY")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")
    
    print(f"{Style.BRIGHT}Overview:{Style.RESET_ALL}")
    print(f"  Total Events Analyzed: {summary['total_events']}")
    print(f"  Suspicious Events Flagged: {Fore.RED}{summary['flagged_events']}{Style.RESET_ALL}")
    
    # Severity breakdown
    if summary['severity_counts']:
        print(f"\n{Style.BRIGHT}Severity Distribution:{Style.RESET_ALL}")
        for severity, count in summary['severity_counts'].items():
            color = Fore.RED if severity == 'HIGH' else Fore.YELLOW if severity == 'MEDIUM' else Fore.GREEN
            print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
    
    # Failed logins with threshold
    high_fail_sources = {ip: count for ip, count in failed_logins.items() if count > 5}
    if high_fail_sources:
        print(f"\n{Style.BRIGHT}{Fore.RED}High Failed Login Sources (>5 attempts):{Style.RESET_ALL}")
        for ip, count in sorted(high_fail_sources.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} failed attempts")
    
    # Top source IPs
    if summary['top_source_ips']:
        print(f"\n{Style.BRIGHT}Top Source IPs:{Style.RESET_ALL}")
        for ip, count in list(summary['top_source_ips'].items())[:5]:
            print(f"  {ip}: {count} events")
    
    # Top targeted accounts
    if summary['top_target_users']:
        print(f"\n{Style.BRIGHT}Top Targeted Accounts:{Style.RESET_ALL}")
        for user, count in list(summary['top_target_users'].items())[:5]:
            print(f"  {user}: {count} events")
    
    # Event ID distribution
    if summary['event_id_distribution']:
        print(f"\n{Style.BRIGHT}Event ID Distribution:{Style.RESET_ALL}")
        for event_id, count in list(summary['event_id_distribution'].items())[:5]:
            print(f"  Event ID {event_id}: {count} events")
    
    print(f"\n{Style.BRIGHT}{'=' * 70}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Windows Security Log Analyzer - Detect suspicious events',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input sample_log.json
  %(prog)s --input security_events.csv --output flagged_events.csv
        """
    )
    
    parser.add_argument('--input', '-i', required=True, help='Input log file (JSON or CSV)')
    parser.add_argument('--output', '-o', default='flagged_events.csv', 
                       help='Output CSV file for flagged events (default: flagged_events.csv)')
    
    args = parser.parse_args()
    
    # Load log file
    print(f"{Fore.CYAN}Loading log file: {args.input}{Style.RESET_ALL}")
    events = load_log_file(args.input)
    print(f"{Fore.GREEN}Loaded {len(events)} events{Style.RESET_ALL}")
    
    # Analyze events
    print(f"{Fore.CYAN}Analyzing events for suspicious activity...{Style.RESET_ALL}")
    flagged_events = []
    
    for event in events:
        is_suspicious, severity, reason = analyze_event(event)
        
        if is_suspicious:
            norm_event = normalize_event(event)
            flagged_events.append({
                'timestamp': norm_event['TimeCreated'],
                'event_id': norm_event['EventID'],
                'severity': severity,
                'reason': reason,
                'computer': norm_event['Computer'],
                'source_ip': norm_event.get('IpAddress') or norm_event.get('SourceAddress', 'N/A'),
                'target_user': norm_event['TargetUserName'],
                'process': norm_event['ProcessName']
            })
    
    # Analyze failed logins
    failed_logins = analyze_failed_logins(events)
    
    # Generate summary
    summary = generate_summary(events, flagged_events)
    
    # Display results
    display_summary(summary, failed_logins)
    
    # Save CSV report
    if flagged_events:
        save_csv_report(flagged_events, args.output)
    
    print(f"{Fore.GREEN}Analysis complete!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
