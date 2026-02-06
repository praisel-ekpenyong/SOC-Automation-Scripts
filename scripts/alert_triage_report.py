#!/usr/bin/env python3
"""
Alert Triage Report Generator - Generate formatted incident triage reports

Usage:
    python alert_triage_report.py --input sample_alert.json
    python alert_triage_report.py --input brute_force_alert.json --analyst "John Doe"

Features:
    - Generate markdown incident triage reports
    - Support multiple alert types (brute force, malware, phishing, lateral movement)
    - Extract IOCs automatically
    - Map to MITRE ATT&CK framework
    - Provide recommended actions
    - Include analyst name and timestamp
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


# MITRE ATT&CK mappings
MITRE_MAPPINGS = {
    'brute_force': {
        'tactics': ['Credential Access'],
        'techniques': ['T1110 - Brute Force', 'T1110.001 - Password Guessing']
    },
    'malware': {
        'tactics': ['Execution', 'Persistence'],
        'techniques': ['T1204 - User Execution', 'T1547 - Boot or Logon Autostart Execution']
    },
    'phishing': {
        'tactics': ['Initial Access'],
        'techniques': ['T1566 - Phishing', 'T1566.001 - Spearphishing Attachment']
    },
    'lateral_movement': {
        'tactics': ['Lateral Movement'],
        'techniques': ['T1021 - Remote Services', 'T1021.001 - Remote Desktop Protocol']
    },
    'suspicious_process': {
        'tactics': ['Execution', 'Defense Evasion'],
        'techniques': ['T1059 - Command and Scripting Interpreter', 'T1027 - Obfuscated Files or Information']
    }
}


def load_alert_data(file_path: str) -> Dict:
    """Load alert data from JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}Error: Invalid JSON format: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error loading file: {e}")
        sys.exit(1)


def extract_iocs(alert_data: Dict) -> Dict[str, List[str]]:
    """Extract IOCs from alert data."""
    iocs = {
        'ip_addresses': [],
        'domains': [],
        'file_hashes': [],
        'file_names': [],
        'urls': [],
        'email_addresses': []
    }
    
    # Extract from various fields
    if 'source_ip' in alert_data:
        iocs['ip_addresses'].append(alert_data['source_ip'])
    
    if 'destination_ip' in alert_data:
        iocs['ip_addresses'].append(alert_data['destination_ip'])
    
    if 'domain' in alert_data:
        iocs['domains'].append(alert_data['domain'])
    
    if 'file_hash' in alert_data:
        iocs['file_hashes'].append(alert_data['file_hash'])
    
    if 'file_name' in alert_data:
        iocs['file_names'].append(alert_data['file_name'])
    
    if 'url' in alert_data:
        iocs['urls'].append(alert_data['url'])
    
    if 'sender_email' in alert_data:
        iocs['email_addresses'].append(alert_data['sender_email'])
    
    # Extract from nested IOCs field if present
    if 'iocs' in alert_data:
        for ioc_type, values in alert_data['iocs'].items():
            if ioc_type in iocs:
                if isinstance(values, list):
                    iocs[ioc_type].extend(values)
                else:
                    iocs[ioc_type].append(values)
    
    # Remove duplicates and empty values
    for key in iocs:
        iocs[key] = list(set([str(v) for v in iocs[key] if v]))
    
    return iocs


def assess_severity(alert_data: Dict) -> str:
    """Assess or use provided severity."""
    if 'severity' in alert_data:
        return alert_data['severity'].upper()
    
    # Default severity based on alert type
    alert_type = alert_data.get('alert_type', 'unknown')
    
    severity_map = {
        'malware': 'HIGH',
        'brute_force': 'MEDIUM',
        'phishing': 'HIGH',
        'lateral_movement': 'HIGH',
        'suspicious_process': 'MEDIUM'
    }
    
    return severity_map.get(alert_type, 'MEDIUM')


def get_mitre_mapping(alert_type: str) -> Dict:
    """Get MITRE ATT&CK mapping for alert type."""
    return MITRE_MAPPINGS.get(alert_type, {
        'tactics': ['Unknown'],
        'techniques': ['Unknown']
    })


def get_recommended_actions(alert_type: str, alert_data: Dict) -> List[str]:
    """Generate recommended actions based on alert type."""
    actions = []
    
    if alert_type == 'brute_force':
        actions = [
            "1. Verify if the account was successfully compromised",
            "2. Check for successful logins from the source IP after failed attempts",
            "3. Block source IP at firewall level",
            "4. Reset passwords for affected accounts",
            "5. Enable MFA if not already enabled",
            "6. Review logs for any suspicious activity from affected accounts"
        ]
    elif alert_type == 'malware':
        actions = [
            "1. Isolate the affected system from the network",
            "2. Run full antivirus/EDR scan",
            "3. Check for persistence mechanisms (scheduled tasks, registry keys)",
            "4. Review process execution history",
            "5. Collect forensic artifacts (memory dump, disk image)",
            "6. Check for lateral movement to other systems",
            "7. Submit file hash to VirusTotal for analysis"
        ]
    elif alert_type == 'phishing':
        actions = [
            "1. Quarantine the email across all mailboxes",
            "2. Check if any users clicked links or opened attachments",
            "3. Extract and analyze URLs/attachments",
            "4. Block sender domain at email gateway",
            "5. Search for similar emails in environment",
            "6. Notify affected users and provide security awareness training"
        ]
    elif alert_type == 'lateral_movement':
        actions = [
            "1. Identify compromised source account/system",
            "2. Check for unauthorized access to critical systems",
            "3. Review authentication logs for suspicious patterns",
            "4. Isolate affected systems",
            "5. Reset credentials for involved accounts",
            "6. Review and restrict lateral movement paths"
        ]
    else:
        actions = [
            "1. Gather additional context about the alert",
            "2. Review logs for related activity",
            "3. Determine if alert is true positive or false positive",
            "4. Document findings",
            "5. Escalate to Tier 2 if needed"
        ]
    
    return actions


def generate_markdown_report(alert_data: Dict, analyst_name: str) -> str:
    """Generate markdown incident triage report."""
    alert_type = alert_data.get('alert_type', 'unknown')
    alert_name = alert_data.get('alert_name', 'Unnamed Alert')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    severity = assess_severity(alert_data)
    iocs = extract_iocs(alert_data)
    mitre = get_mitre_mapping(alert_type)
    actions = get_recommended_actions(alert_type, alert_data)
    
    # Build report
    report = f"""# Incident Triage Report

## Alert Information
- **Alert Name:** {alert_name}
- **Alert Type:** {alert_type.replace('_', ' ').title()}
- **Severity:** {severity}
- **Date/Time:** {timestamp}
- **Analyst:** {analyst_name}

---

## Executive Summary
{alert_data.get('description', 'No description provided.')}

---

## Alert Details

### Source Information
- **Source IP:** {alert_data.get('source_ip', 'N/A')}
- **Source Host:** {alert_data.get('source_host', 'N/A')}
- **Source User:** {alert_data.get('source_user', 'N/A')}

### Destination Information
- **Destination IP:** {alert_data.get('destination_ip', 'N/A')}
- **Destination Host:** {alert_data.get('destination_host', 'N/A')}
- **Destination User:** {alert_data.get('target_user', 'N/A')}

### Additional Context
"""
    
    # Add additional fields
    for key, value in alert_data.items():
        if key not in ['alert_type', 'alert_name', 'severity', 'description', 
                       'source_ip', 'source_host', 'source_user', 
                       'destination_ip', 'destination_host', 'target_user', 'iocs']:
            report += f"- **{key.replace('_', ' ').title()}:** {value}\n"
    
    report += "\n---\n\n## Indicators of Compromise (IOCs)\n\n"
    
    # Add IOCs
    ioc_found = False
    for ioc_type, values in iocs.items():
        if values:
            ioc_found = True
            report += f"### {ioc_type.replace('_', ' ').title()}\n"
            for value in values:
                # Defang IOCs for safe display
                defanged = value.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
                defanged = defanged.replace('.', '[.]')
                report += f"- `{defanged}`\n"
            report += "\n"
    
    if not ioc_found:
        report += "*No IOCs extracted from this alert.*\n\n"
    
    report += "---\n\n## MITRE ATT&CK Mapping\n\n"
    report += f"### Tactics\n"
    for tactic in mitre.get('tactics', []):
        report += f"- {tactic}\n"
    
    report += f"\n### Techniques\n"
    for technique in mitre.get('techniques', []):
        report += f"- {technique}\n"
    
    report += "\n---\n\n## Recommended Actions\n\n"
    for action in actions:
        report += f"{action}\n"
    
    report += "\n---\n\n## Investigation Notes\n\n"
    report += "*[Add your investigation findings here]*\n\n"
    
    report += "---\n\n## Resolution\n\n"
    report += "- **Status:** Open\n"
    report += "- **Resolution:** *[To be filled after investigation]*\n"
    report += "- **Closed Date:** *[To be filled]*\n"
    report += "- **Closed By:** *[To be filled]*\n"
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description='Alert Triage Report Generator - Create formatted incident reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input sample_alert.json
  %(prog)s --input alert.json --analyst "Jane Smith"
  %(prog)s --input alert.json --output triage_report.md
        """
    )
    
    parser.add_argument('--input', '-i', required=True,
                       help='Input JSON file with alert data')
    parser.add_argument('--analyst', '-a', default='SOC Analyst',
                       help='Analyst name (default: SOC Analyst)')
    parser.add_argument('--output', '-o',
                       help='Output markdown file (default: auto-generated)')
    
    args = parser.parse_args()
    
    # Load alert data
    print(f"{Fore.CYAN}Loading alert data: {args.input}{Style.RESET_ALL}")
    alert_data = load_alert_data(args.input)
    
    # Generate report
    print(f"{Fore.CYAN}Generating triage report...{Style.RESET_ALL}")
    report = generate_markdown_report(alert_data, args.analyst)
    
    # Determine output filename
    if args.output:
        output_file = args.output
    else:
        alert_name = alert_data.get('alert_name', 'alert').replace(' ', '_').lower()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"triage_report_{alert_name}_{timestamp}.md"
    
    # Save report
    try:
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"{Fore.GREEN}✓ Triage report saved to: {output_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving report: {e}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Display preview
    print(f"\n{Style.BRIGHT}{'=' * 70}")
    print("REPORT PREVIEW")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")
    
    # Show first 20 lines
    lines = report.split('\n')[:20]
    for line in lines:
        print(line)
    
    print(f"\n{Style.DIM}... (truncated, see full report in {output_file}){Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}Report generation complete!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
