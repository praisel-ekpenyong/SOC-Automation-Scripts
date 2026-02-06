#!/usr/bin/env python3
"""
Bulk IP Reputation Checker - Query AbuseIPDB for multiple IPs

Usage:
    python bulk_ip_checker.py --input sample_ips.txt
    python bulk_ip_checker.py --input ip_list.txt --output ip_report.csv

Features:
    - Read IP addresses from text file (one per line)
    - Query AbuseIPDB API for each IP
    - Display abuse confidence score, country, ISP, report count
    - Generate CSV report with color-coded risk levels
    - Progress bar for batch processing
    - Rate limit handling
"""

import argparse
import os
import sys
import time
import csv
import requests
from typing import List, Dict, Optional
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)


def load_api_key() -> Optional[str]:
    """Load AbuseIPDB API key from environment variable."""
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        print(f"{Fore.RED}Error: ABUSEIPDB_API_KEY environment variable not set")
        print(f"{Fore.YELLOW}Please set your AbuseIPDB API key:")
        print("export ABUSEIPDB_API_KEY='your_api_key_here'")
        return None
    return api_key


def load_ip_list(file_path: str) -> List[str]:
    """Load IP addresses from text file."""
    try:
        with open(file_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return ips
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {e}")
        sys.exit(1)


def check_ip_reputation(ip: str, api_key: str) -> Optional[Dict]:
    """Query AbuseIPDB API for IP reputation."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': ''
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            print(f"\n{Fore.YELLOW}Rate limit hit. Waiting 60 seconds...")
            time.sleep(60)
            return check_ip_reputation(ip, api_key)  # Retry
        elif response.status_code == 401:
            print(f"\n{Fore.RED}Authentication failed. Check your API key.")
            return None
        else:
            print(f"\n{Fore.YELLOW}API Error for {ip}: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"\n{Fore.YELLOW}Request failed for {ip}: {e}")
        return None


def get_risk_level(score: int) -> tuple:
    """Get risk level and color based on abuse confidence score."""
    if score >= 75:
        return 'HIGH', Fore.RED
    elif score >= 25:
        return 'MEDIUM', Fore.YELLOW
    else:
        return 'LOW', Fore.GREEN


def format_date(date_str: Optional[str]) -> str:
    """Format date string."""
    if not date_str:
        return 'Never'
    try:
        # Parse ISO date and return short format
        from datetime import datetime
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d')
    except Exception:
        return date_str


def process_ips(ips: List[str], api_key: str) -> List[Dict]:
    """Process all IPs and collect results."""
    results = []
    
    print(f"{Fore.CYAN}Checking {len(ips)} IP addresses...{Style.RESET_ALL}\n")
    
    for ip in tqdm(ips, desc="Progress", unit="IP"):
        data = check_ip_reputation(ip, api_key)
        
        if data and 'data' in data:
            ip_data = data['data']
            
            abuse_score = ip_data.get('abuseConfidenceScore', 0)
            risk_level, color = get_risk_level(abuse_score)
            
            result = {
                'ip': ip,
                'abuse_score': abuse_score,
                'risk_level': risk_level,
                'country': ip_data.get('countryCode', 'Unknown'),
                'isp': ip_data.get('isp', 'Unknown'),
                'domain': ip_data.get('domain', 'N/A'),
                'total_reports': ip_data.get('totalReports', 0),
                'last_reported': format_date(ip_data.get('lastReportedAt')),
                'is_whitelisted': ip_data.get('isWhitelisted', False),
                'usage_type': ip_data.get('usageType', 'Unknown'),
                'color': color
            }
            
            results.append(result)
        else:
            # Add empty result for failed lookups
            results.append({
                'ip': ip,
                'abuse_score': -1,
                'risk_level': 'ERROR',
                'country': 'N/A',
                'isp': 'N/A',
                'domain': 'N/A',
                'total_reports': 0,
                'last_reported': 'N/A',
                'is_whitelisted': False,
                'usage_type': 'N/A',
                'color': Fore.YELLOW
            })
        
        # Small delay to respect rate limits (free tier: 1000/day, ~1 per second is safe)
        time.sleep(0.5)
    
    return results


def save_csv_report(results: List[Dict], output_file: str):
    """Save results to CSV file."""
    try:
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['ip', 'abuse_score', 'risk_level', 'country', 'isp', 
                         'domain', 'total_reports', 'last_reported', 'is_whitelisted', 'usage_type']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                # Remove color field before writing
                row = {k: v for k, v in result.items() if k != 'color'}
                writer.writerow(row)
        
        print(f"\n{Fore.GREEN}CSV report saved to: {output_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error saving CSV report: {e}{Style.RESET_ALL}")


def display_results(results: List[Dict]):
    """Display formatted results."""
    print(f"\n{Style.BRIGHT}{'=' * 100}")
    print(f"BULK IP REPUTATION CHECK RESULTS")
    print(f"{'=' * 100}{Style.RESET_ALL}\n")
    
    # Display each result
    for result in results:
        if result['abuse_score'] == -1:
            print(f"{result['color']}{result['ip']:<15} | ERROR - Lookup failed{Style.RESET_ALL}")
        else:
            score_color = result['color']
            whitelist = " [WHITELISTED]" if result['is_whitelisted'] else ""
            
            print(f"{score_color}{result['ip']:<15} | "
                  f"Score: {result['abuse_score']:>3} | "
                  f"Risk: {result['risk_level']:<6} | "
                  f"{result['country']:<3} | "
                  f"{result['isp']:<30}{whitelist}{Style.RESET_ALL}")
    
    print(f"\n{Style.BRIGHT}{'=' * 100}{Style.RESET_ALL}")


def display_summary(results: List[Dict]):
    """Display summary statistics."""
    valid_results = [r for r in results if r['abuse_score'] != -1]
    
    high_risk = sum(1 for r in valid_results if r['risk_level'] == 'HIGH')
    medium_risk = sum(1 for r in valid_results if r['risk_level'] == 'MEDIUM')
    low_risk = sum(1 for r in valid_results if r['risk_level'] == 'LOW')
    whitelisted = sum(1 for r in valid_results if r['is_whitelisted'])
    
    print(f"\n{Style.BRIGHT}Summary Statistics:{Style.RESET_ALL}")
    print(f"  Total IPs Checked: {len(results)}")
    print(f"  Successful Lookups: {len(valid_results)}")
    print(f"  Failed Lookups: {len(results) - len(valid_results)}")
    print(f"\n{Style.BRIGHT}Risk Distribution:{Style.RESET_ALL}")
    print(f"  {Fore.RED}HIGH Risk (≥75):   {high_risk}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}MEDIUM Risk (25-74): {medium_risk}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}LOW Risk (<25):    {low_risk}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Whitelisted:       {whitelisted}{Style.RESET_ALL}")
    
    # Show top malicious IPs
    malicious = sorted([r for r in valid_results if r['abuse_score'] >= 75], 
                       key=lambda x: x['abuse_score'], reverse=True)
    
    if malicious:
        print(f"\n{Style.BRIGHT}{Fore.RED}Top Malicious IPs:{Style.RESET_ALL}")
        for ip_data in malicious[:5]:
            print(f"  {ip_data['ip']:<15} | Score: {ip_data['abuse_score']} | "
                  f"Reports: {ip_data['total_reports']} | "
                  f"Last: {ip_data['last_reported']}")
    
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Bulk IP Reputation Checker - Query AbuseIPDB for multiple IPs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input sample_ips.txt
  %(prog)s --input ip_list.txt --output ip_report.csv
        """
    )
    
    parser.add_argument('--input', '-i', required=True, 
                       help='Input file with IP addresses (one per line)')
    parser.add_argument('--output', '-o', default='ip_report.csv',
                       help='Output CSV file (default: ip_report.csv)')
    
    args = parser.parse_args()
    
    # Load API key
    api_key = load_api_key()
    if not api_key:
        sys.exit(1)
    
    # Load IP list
    ips = load_ip_list(args.input)
    if not ips:
        print(f"{Fore.RED}No valid IP addresses found in file")
        sys.exit(1)
    
    print(f"{Fore.GREEN}Loaded {len(ips)} IP addresses{Style.RESET_ALL}")
    
    # Process IPs
    results = process_ips(ips, api_key)
    
    # Display results
    display_results(results)
    display_summary(results)
    
    # Save CSV report
    save_csv_report(results, args.output)
    
    print(f"{Fore.GREEN}Analysis complete!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
