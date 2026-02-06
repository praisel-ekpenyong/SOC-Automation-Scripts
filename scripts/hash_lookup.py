#!/usr/bin/env python3
"""
File Hash Reputation Lookup - Check file hashes against VirusTotal

Usage:
    python hash_lookup.py --hash 44d88612fea8a8f36de82e1278abb02f
    python hash_lookup.py --file sample_hashes.txt --output hash_report.csv

Features:
    - Support MD5, SHA1, SHA256 (auto-detect)
    - Query VirusTotal API v3
    - Display detection ratio, threat labels, first/last seen
    - Generate CSV report
    - Color-coded verdicts
"""

import argparse
import os
import sys
import csv
import requests
from typing import List, Dict, Optional
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def load_api_key() -> Optional[str]:
    """Load VirusTotal API key from environment variable."""
    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        print(f"{Fore.RED}Error: VT_API_KEY environment variable not set")
        print(f"{Fore.YELLOW}Please set your VirusTotal API key:")
        print("export VT_API_KEY='your_api_key_here'")
        return None
    return api_key


def detect_hash_type(hash_value: str) -> Optional[str]:
    """Auto-detect hash type based on length."""
    hash_len = len(hash_value)
    
    if hash_len == 32:
        return 'MD5'
    elif hash_len == 40:
        return 'SHA1'
    elif hash_len == 64:
        return 'SHA256'
    else:
        return None


def load_hash_file(file_path: str) -> List[str]:
    """Load hashes from text file."""
    try:
        with open(file_path, 'r') as f:
            hashes = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return hashes
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {e}")
        sys.exit(1)


def query_hash(hash_value: str, api_key: str) -> Optional[Dict]:
    """Query VirusTotal API for hash information."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    
    headers = {
        'x-apikey': api_key,
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {'error': 'not_found'}
        elif response.status_code == 429:
            print(f"{Fore.YELLOW}Rate limit exceeded. Please wait...")
            return {'error': 'rate_limit'}
        elif response.status_code == 401:
            print(f"{Fore.RED}Authentication failed. Check your API key.")
            return {'error': 'auth_failed'}
        else:
            print(f"{Fore.YELLOW}API Error: {response.status_code}")
            return {'error': f'api_error_{response.status_code}'}
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Request failed: {e}")
        return {'error': 'request_failed'}


def analyze_hash_result(data: Dict) -> Dict:
    """Analyze hash lookup result."""
    if 'error' in data:
        error_type = data['error']
        
        if error_type == 'not_found':
            return {
                'verdict': 'UNKNOWN',
                'color': Fore.YELLOW,
                'detection_ratio': '0/0',
                'malicious': 0,
                'suspicious': 0,
                'clean': 0,
                'threat_label': 'Not found in database',
                'file_name': 'N/A',
                'file_type': 'N/A',
                'size': 0,
                'first_seen': 'N/A',
                'last_seen': 'N/A'
            }
        else:
            return {
                'verdict': 'ERROR',
                'color': Fore.RED,
                'detection_ratio': 'Error',
                'malicious': 0,
                'suspicious': 0,
                'clean': 0,
                'threat_label': f'Error: {error_type}',
                'file_name': 'N/A',
                'file_type': 'N/A',
                'size': 0,
                'first_seen': 'N/A',
                'last_seen': 'N/A'
            }
    
    attributes = data.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    harmless = stats.get('harmless', 0)
    
    total_scanners = malicious + suspicious + undetected + harmless
    
    # Determine verdict
    if malicious > 0:
        verdict = 'MALICIOUS'
        color = Fore.RED
    elif suspicious > 0:
        verdict = 'SUSPICIOUS'
        color = Fore.YELLOW
    else:
        verdict = 'CLEAN'
        color = Fore.GREEN
    
    # Get threat labels
    threat_names = attributes.get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')
    if not threat_names:
        threat_names = 'Generic malware' if malicious > 0 else 'Clean'
    
    # Get file info
    file_names = attributes.get('names', ['Unknown'])
    file_name = file_names[0] if file_names else 'Unknown'
    file_type = attributes.get('type_description', 'Unknown')
    size = attributes.get('size', 0)
    
    # Get timestamps
    from datetime import datetime
    first_seen = attributes.get('first_submission_date')
    last_seen = attributes.get('last_analysis_date')
    
    first_seen_str = datetime.fromtimestamp(first_seen).strftime('%Y-%m-%d') if first_seen else 'N/A'
    last_seen_str = datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d') if last_seen else 'N/A'
    
    return {
        'verdict': verdict,
        'color': color,
        'detection_ratio': f'{malicious}/{total_scanners}',
        'malicious': malicious,
        'suspicious': suspicious,
        'clean': harmless + undetected,
        'threat_label': threat_names,
        'file_name': file_name,
        'file_type': file_type,
        'size': size,
        'first_seen': first_seen_str,
        'last_seen': last_seen_str
    }


def display_result(hash_value: str, hash_type: str, analysis: Dict):
    """Display formatted result for single hash."""
    color = analysis['color']
    
    print(f"\n{color}[{analysis['verdict']}] {hash_type}: {hash_value}{Style.RESET_ALL}")
    
    if analysis['verdict'] not in ['ERROR', 'UNKNOWN']:
        print(f"{Style.BRIGHT}Detection Ratio: {analysis['detection_ratio']}{Style.RESET_ALL}")
        print(f"Malicious: {Fore.RED}{analysis['malicious']}{Style.RESET_ALL} | "
              f"Suspicious: {Fore.YELLOW}{analysis['suspicious']}{Style.RESET_ALL} | "
              f"Clean: {Fore.GREEN}{analysis['clean']}{Style.RESET_ALL}")
        print(f"Threat Label: {analysis['threat_label']}")
        print(f"File Name: {analysis['file_name']}")
        print(f"File Type: {analysis['file_type']}")
        print(f"Size: {analysis['size']:,} bytes")
        print(f"First Seen: {analysis['first_seen']}")
        print(f"Last Seen: {analysis['last_seen']}")
    else:
        print(f"Status: {analysis['threat_label']}")


def save_csv_report(results: List[Dict], output_file: str):
    """Save results to CSV file."""
    try:
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['hash', 'hash_type', 'verdict', 'detection_ratio', 
                         'malicious', 'suspicious', 'clean', 'threat_label',
                         'file_name', 'file_type', 'size', 'first_seen', 'last_seen']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                # Remove color field
                row = {k: v for k, v in result.items() if k != 'color'}
                writer.writerow(row)
        
        print(f"\n{Fore.GREEN}CSV report saved to: {output_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error saving CSV report: {e}{Style.RESET_ALL}")


def display_summary(results: List[Dict]):
    """Display summary statistics."""
    print(f"\n{Style.BRIGHT}{'=' * 70}")
    print(f"HASH LOOKUP SUMMARY")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")
    
    malicious_count = sum(1 for r in results if r['verdict'] == 'MALICIOUS')
    suspicious_count = sum(1 for r in results if r['verdict'] == 'SUSPICIOUS')
    clean_count = sum(1 for r in results if r['verdict'] == 'CLEAN')
    unknown_count = sum(1 for r in results if r['verdict'] == 'UNKNOWN')
    error_count = sum(1 for r in results if r['verdict'] == 'ERROR')
    
    print(f"{Style.BRIGHT}Total Hashes Checked: {len(results)}{Style.RESET_ALL}")
    print(f"{Fore.RED}Malicious: {malicious_count}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Suspicious: {suspicious_count}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Clean: {clean_count}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Unknown: {unknown_count}{Style.RESET_ALL}")
    print(f"{Fore.RED}Errors: {error_count}{Style.RESET_ALL}")
    
    # Show malicious hashes
    malicious_hashes = [r for r in results if r['verdict'] == 'MALICIOUS']
    if malicious_hashes:
        print(f"\n{Style.BRIGHT}{Fore.RED}Malicious Hashes Detected:{Style.RESET_ALL}")
        for result in malicious_hashes[:5]:
            print(f"  {result['hash'][:16]}... | "
                  f"Detection: {result['detection_ratio']} | "
                  f"Threat: {result['threat_label']}")
    
    print(f"\n{Style.BRIGHT}{'=' * 70}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description='File Hash Reputation Lookup - Check hashes against VirusTotal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --hash 44d88612fea8a8f36de82e1278abb02f
  %(prog)s --file sample_hashes.txt --output hash_report.csv
        """
    )
    
    parser.add_argument('--hash', '-H', help='Single hash to check')
    parser.add_argument('--file', '-f', help='File with multiple hashes (one per line)')
    parser.add_argument('--output', '-o', default='hash_report.csv',
                       help='Output CSV file (default: hash_report.csv)')
    
    args = parser.parse_args()
    
    if not args.hash and not args.file:
        parser.error('Either --hash or --file must be specified')
    
    # Load API key
    api_key = load_api_key()
    if not api_key:
        sys.exit(1)
    
    # Get hash list
    if args.hash:
        hashes = [args.hash]
    else:
        hashes = load_hash_file(args.file)
    
    if not hashes:
        print(f"{Fore.RED}No valid hashes found")
        sys.exit(1)
    
    print(f"{Fore.CYAN}Checking {len(hashes)} hash(es)...{Style.RESET_ALL}")
    
    # Process hashes
    results = []
    
    for hash_value in hashes:
        hash_value = hash_value.strip().lower()
        hash_type = detect_hash_type(hash_value)
        
        if not hash_type:
            print(f"{Fore.RED}Invalid hash length: {hash_value}{Style.RESET_ALL}")
            continue
        
        # Query VirusTotal
        data = query_hash(hash_value, api_key)
        analysis = analyze_hash_result(data)
        
        # Display individual result
        display_result(hash_value, hash_type, analysis)
        
        # Store for CSV
        result = {
            'hash': hash_value,
            'hash_type': hash_type,
            **analysis
        }
        results.append(result)
        
        # Small delay between requests
        if len(hashes) > 1:
            import time
            time.sleep(0.5)
    
    # Display summary if multiple hashes
    if len(results) > 1:
        display_summary(results)
        save_csv_report(results, args.output)
    
    print(f"{Fore.GREEN}Hash lookup complete!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
