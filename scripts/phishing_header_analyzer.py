#!/usr/bin/env python3
"""
Phishing Email Header Analyzer - Parse .eml files and analyze headers for phishing indicators

Usage:
    python phishing_header_analyzer.py sample_email.eml
    python phishing_header_analyzer.py /path/to/suspicious_email.eml

Features:
    - Extract and display key email headers
    - Check SPF, DKIM, DMARC authentication results
    - Flag sender mismatches (From vs Return-Path)
    - Trace email routing path via Received headers
    - Extract and defang URLs from body
    - Provide phishing verdict with confidence score
"""

import argparse
import email
import re
import sys
from email import policy
from email.parser import BytesParser
from typing import List, Tuple, Dict
from colorama import Fore, Style, init
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)


def parse_email_file(file_path: str) -> email.message.Message:
    """Parse .eml file and return email message object."""
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error parsing email file: {e}")
        sys.exit(1)


def extract_headers(msg: email.message.Message) -> Dict[str, str]:
    """Extract key headers from email message."""
    headers = {
        'From': msg.get('From', 'N/A'),
        'To': msg.get('To', 'N/A'),
        'Subject': msg.get('Subject', 'N/A'),
        'Date': msg.get('Date', 'N/A'),
        'Return-Path': msg.get('Return-Path', 'N/A'),
        'Message-ID': msg.get('Message-ID', 'N/A'),
        'Reply-To': msg.get('Reply-To', 'N/A'),
        'Authentication-Results': msg.get('Authentication-Results', 'N/A')
    }
    return headers


def extract_received_headers(msg: email.message.Message) -> List[str]:
    """Extract all Received headers to trace routing path."""
    received_headers = msg.get_all('Received', [])
    return received_headers


def check_auth_results(auth_header: str) -> Tuple[str, str, str]:
    """Parse Authentication-Results header for SPF, DKIM, DMARC."""
    spf = dkim = dmarc = 'none'
    
    if auth_header and auth_header != 'N/A':
        auth_lower = auth_header.lower()
        
        # Check SPF
        if 'spf=pass' in auth_lower:
            spf = 'pass'
        elif 'spf=fail' in auth_lower:
            spf = 'fail'
        elif 'spf=softfail' in auth_lower:
            spf = 'softfail'
        elif 'spf=neutral' in auth_lower:
            spf = 'neutral'
        
        # Check DKIM
        if 'dkim=pass' in auth_lower:
            dkim = 'pass'
        elif 'dkim=fail' in auth_lower:
            dkim = 'fail'
        elif 'dkim=none' in auth_lower:
            dkim = 'none'
        
        # Check DMARC
        if 'dmarc=pass' in auth_lower:
            dmarc = 'pass'
        elif 'dmarc=fail' in auth_lower:
            dmarc = 'fail'
        elif 'dmarc=none' in auth_lower:
            dmarc = 'none'
    
    return spf, dkim, dmarc


def extract_email_address(header_value: str) -> str:
    """Extract email address from header value (e.g., 'Name <email@domain.com>')."""
    match = re.search(r'<(.+?)>', header_value)
    if match:
        return match.group(1)
    # If no brackets, assume entire value is email
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
    if match:
        return match.group(0)
    return header_value


def check_sender_mismatch(from_header: str, return_path: str) -> bool:
    """Check if From and Return-Path addresses match."""
    from_email = extract_email_address(from_header)
    return_email = extract_email_address(return_path)
    
    if return_path == 'N/A':
        return False
    
    # Extract domains
    from_domain = from_email.split('@')[-1] if '@' in from_email else from_email
    return_domain = return_email.split('@')[-1] if '@' in return_email else return_email
    
    return from_domain.lower() != return_domain.lower()


def extract_urls(msg: email.message.Message) -> List[str]:
    """Extract URLs from email body."""
    urls = []
    
    # Get email body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except:
            pass
    
    # Find URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    found_urls = re.findall(url_pattern, body)
    urls.extend(found_urls)
    
    return urls


def defang_url(url: str) -> str:
    """Defang URL for safe sharing."""
    defanged = url.replace('http://', 'hxxp://')
    defanged = defanged.replace('https://', 'hxxps://')
    
    # Defang domain part
    parsed = urlparse(url)
    if parsed.netloc:
        defanged_domain = parsed.netloc.replace('.', '[.]')
        defanged = defanged.replace(parsed.netloc, defanged_domain)
    
    return defanged


def calculate_verdict(headers: Dict[str, str], spf: str, dkim: str, dmarc: str, 
                      sender_mismatch: bool) -> Tuple[str, int, List[str]]:
    """Calculate phishing verdict and confidence score."""
    suspicious_indicators = []
    score = 0
    
    # Authentication failures
    if spf == 'fail':
        suspicious_indicators.append("SPF authentication failed")
        score += 30
    elif spf == 'softfail':
        suspicious_indicators.append("SPF softfail")
        score += 15
    
    if dkim == 'fail':
        suspicious_indicators.append("DKIM authentication failed")
        score += 25
    
    if dmarc == 'fail':
        suspicious_indicators.append("DMARC authentication failed")
        score += 25
    
    # Sender mismatch
    if sender_mismatch:
        suspicious_indicators.append("From address doesn't match Return-Path")
        score += 20
    
    # Check for suspicious keywords in subject
    subject = headers.get('Subject', '').lower()
    suspicious_keywords = ['urgent', 'verify', 'suspended', 'unusual activity', 
                          'confirm', 'password', 'security alert', 'update payment']
    if any(keyword in subject for keyword in suspicious_keywords):
        suspicious_indicators.append("Suspicious keywords in subject")
        score += 10
    
    # Determine verdict
    if score >= 50:
        verdict = "SUSPICIOUS"
    elif score >= 25:
        verdict = "POTENTIALLY SUSPICIOUS"
    else:
        verdict = "CLEAN"
    
    confidence = min(score, 100)
    
    return verdict, confidence, suspicious_indicators


def display_analysis(headers: Dict[str, str], received: List[str], urls: List[str],
                     spf: str, dkim: str, dmarc: str, verdict: str, 
                     confidence: int, indicators: List[str]):
    """Display formatted analysis results."""
    print(f"\n{Style.BRIGHT}{'=' * 70}")
    print(f"PHISHING EMAIL HEADER ANALYSIS")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")
    
    # Key Headers
    print(f"{Style.BRIGHT}Key Headers:{Style.RESET_ALL}")
    print(f"  From:        {headers['From']}")
    print(f"  To:          {headers['To']}")
    print(f"  Subject:     {headers['Subject']}")
    print(f"  Date:        {headers['Date']}")
    print(f"  Return-Path: {headers['Return-Path']}")
    print(f"  Reply-To:    {headers['Reply-To']}")
    print(f"  Message-ID:  {headers['Message-ID']}")
    
    # Authentication Results
    print(f"\n{Style.BRIGHT}Authentication Results:{Style.RESET_ALL}")
    
    spf_color = Fore.GREEN if spf == 'pass' else Fore.RED if spf == 'fail' else Fore.YELLOW
    print(f"  SPF:   {spf_color}{spf.upper()}{Style.RESET_ALL}")
    
    dkim_color = Fore.GREEN if dkim == 'pass' else Fore.RED if dkim == 'fail' else Fore.YELLOW
    print(f"  DKIM:  {dkim_color}{dkim.upper()}{Style.RESET_ALL}")
    
    dmarc_color = Fore.GREEN if dmarc == 'pass' else Fore.RED if dmarc == 'fail' else Fore.YELLOW
    print(f"  DMARC: {dmarc_color}{dmarc.upper()}{Style.RESET_ALL}")
    
    # Routing Path
    if received:
        print(f"\n{Style.BRIGHT}Email Routing Path ({len(received)} hops):{Style.RESET_ALL}")
        for i, hop in enumerate(received[:3], 1):  # Show first 3 hops
            # Extract just the from/by parts
            hop_short = hop.split('\n')[0][:80] + '...' if len(hop) > 80 else hop.split('\n')[0]
            print(f"  {i}. {hop_short}")
    
    # URLs
    if urls:
        print(f"\n{Style.BRIGHT}Extracted URLs (defanged):{Style.RESET_ALL}")
        for url in urls[:5]:  # Show first 5 URLs
            defanged = defang_url(url)
            print(f"  • {defanged}")
    
    # Suspicious Indicators
    if indicators:
        print(f"\n{Style.BRIGHT}{Fore.RED}Suspicious Indicators:{Style.RESET_ALL}")
        for indicator in indicators:
            print(f"  ⚠ {indicator}")
    
    # Final Verdict
    print(f"\n{Style.BRIGHT}{'=' * 70}{Style.RESET_ALL}")
    verdict_color = Fore.RED if 'SUSPICIOUS' in verdict else Fore.GREEN
    print(f"{verdict_color}{Style.BRIGHT}VERDICT: {verdict}{Style.RESET_ALL}")
    print(f"Confidence Score: {confidence}%")
    print(f"{Style.BRIGHT}{'=' * 70}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Phishing Email Header Analyzer - Analyze email headers for phishing indicators',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sample_email.eml
  %(prog)s /path/to/suspicious_email.eml
        """
    )
    
    parser.add_argument('email_file', help='Path to .eml email file')
    
    args = parser.parse_args()
    
    # Parse email
    print(f"{Fore.CYAN}Parsing email file: {args.email_file}{Style.RESET_ALL}")
    msg = parse_email_file(args.email_file)
    
    # Extract information
    headers = extract_headers(msg)
    received = extract_received_headers(msg)
    urls = extract_urls(msg)
    
    # Check authentication
    spf, dkim, dmarc = check_auth_results(headers['Authentication-Results'])
    
    # Check sender mismatch
    sender_mismatch = check_sender_mismatch(headers['From'], headers['Return-Path'])
    
    # Calculate verdict
    verdict, confidence, indicators = calculate_verdict(
        headers, spf, dkim, dmarc, sender_mismatch
    )
    
    # Display results
    display_analysis(headers, received, urls, spf, dkim, dmarc, 
                    verdict, confidence, indicators)


if __name__ == "__main__":
    main()
