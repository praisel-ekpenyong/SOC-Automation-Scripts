#!/usr/bin/env python3
"""
IOC Enrichment Tool - Query VirusTotal API for IP/domain/hash reputation

Usage:
    python ioc_enrichment.py --type ip --value 8.8.8.8
    python ioc_enrichment.py --type domain --value google.com
    python ioc_enrichment.py --type hash --value 44d88612fea8a8f36de82e1278abb02f

Example Output:
    [CLEAN] IP: 8.8.8.8
    Detection Ratio: 0/94
    Malicious: 0 | Suspicious: 0 | Clean: 94
    Country: US
    Last Analysis: 2024-01-15 10:30:45
"""

import argparse
import os
import sys
import requests
from colorama import Fore, Style, init
from typing import Dict, Optional

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


def query_virustotal(ioc_type: str, value: str, api_key: str) -> Optional[Dict]:
    """Query VirusTotal API for IOC information."""
    base_url = "https://www.virustotal.com/api/v3"
    
    # Map type to API endpoint
    endpoints = {
        'ip': f"{base_url}/ip_addresses/{value}",
        'domain': f"{base_url}/domains/{value}",
        'hash': f"{base_url}/files/{value}"
    }
    
    if ioc_type not in endpoints:
        print(f"{Fore.RED}Error: Invalid type '{ioc_type}'. Must be 'ip', 'domain', or 'hash'")
        return None
    
    headers = {
        'x-apikey': api_key,
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(endpoints[ioc_type], headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"{Fore.YELLOW}Not found: {value} (not in VirusTotal database)")
            return None
        elif response.status_code == 429:
            print(f"{Fore.RED}Rate limit exceeded. Please wait and try again.")
            return None
        elif response.status_code == 401:
            print(f"{Fore.RED}Authentication failed. Please check your API key.")
            return None
        else:
            print(f"{Fore.RED}API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Request failed: {e}")
        return None


def display_results(ioc_type: str, value: str, data: Dict) -> None:
    """Display formatted results with color-coding."""
    if not data or 'data' not in data:
        return
    
    attributes = data['data'].get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    harmless = stats.get('harmless', 0)
    
    total_scanners = malicious + suspicious + undetected + harmless
    
    # Determine verdict color
    if malicious > 0:
        verdict_color = Fore.RED
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict_color = Fore.YELLOW
        verdict = "SUSPICIOUS"
    else:
        verdict_color = Fore.GREEN
        verdict = "CLEAN"
    
    print(f"\n{verdict_color}[{verdict}] {ioc_type.upper()}: {value}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}Detection Ratio: {malicious}/{total_scanners}{Style.RESET_ALL}")
    print(f"Malicious: {Fore.RED}{malicious}{Style.RESET_ALL} | "
          f"Suspicious: {Fore.YELLOW}{suspicious}{Style.RESET_ALL} | "
          f"Clean: {Fore.GREEN}{harmless + undetected}{Style.RESET_ALL}")
    
    # Type-specific information
    if ioc_type == 'ip':
        country = attributes.get('country', 'Unknown')
        asn = attributes.get('asn', 'Unknown')
        as_owner = attributes.get('as_owner', 'Unknown')
        print(f"Country: {country}")
        print(f"ASN: {asn} ({as_owner})")
    elif ioc_type == 'domain':
        categories = attributes.get('categories', {})
        if categories:
            print(f"Categories: {', '.join(list(categories.values())[:3])}")
        creation_date = attributes.get('creation_date')
        if creation_date:
            from datetime import datetime
            date_str = datetime.fromtimestamp(creation_date).strftime('%Y-%m-%d')
            print(f"Created: {date_str}")
    elif ioc_type == 'hash':
        names = attributes.get('meaningful_name') or attributes.get('names', ['Unknown'])[0] if attributes.get('names') else 'Unknown'
        file_type = attributes.get('type_description', 'Unknown')
        size = attributes.get('size', 0)
        print(f"File: {names}")
        print(f"Type: {file_type}")
        print(f"Size: {size:,} bytes")
    
    # Last analysis date
    last_analysis = attributes.get('last_analysis_date')
    if last_analysis:
        from datetime import datetime
        date_str = datetime.fromtimestamp(last_analysis).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Last Analysis: {date_str}")
    
    # Community votes
    votes = attributes.get('total_votes', {})
    if votes:
        harmless_votes = votes.get('harmless', 0)
        malicious_votes = votes.get('malicious', 0)
        if harmless_votes > 0 or malicious_votes > 0:
            print(f"Community Votes: {Fore.GREEN}+{harmless_votes}{Style.RESET_ALL} / "
                  f"{Fore.RED}-{malicious_votes}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='IOC Enrichment Tool - Query VirusTotal API for threat intelligence',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --type ip --value 8.8.8.8
  %(prog)s --type domain --value malicious-site.com
  %(prog)s --type hash --value 44d88612fea8a8f36de82e1278abb02f
        """
    )
    
    parser.add_argument('--type', '-t', required=True, choices=['ip', 'domain', 'hash'],
                        help='Type of IOC (ip, domain, or hash)')
    parser.add_argument('--value', '-v', required=True,
                        help='IOC value to check')
    
    args = parser.parse_args()
    
    # Load API key
    api_key = load_api_key()
    if not api_key:
        sys.exit(1)
    
    # Query VirusTotal
    print(f"{Fore.CYAN}Querying VirusTotal for {args.type}: {args.value}...{Style.RESET_ALL}")
    data = query_virustotal(args.type, args.value, api_key)
    
    if data:
        display_results(args.type, args.value, data)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
