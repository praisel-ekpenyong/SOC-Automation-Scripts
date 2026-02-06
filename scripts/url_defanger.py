#!/usr/bin/env python3
"""
URL/IP Defanger & Refanger - Convert URLs/IPs to safe format for sharing

Usage:
    python url_defanger.py --url "http://malicious-site.com"
    python url_defanger.py --file sample_urls.txt
    python url_defanger.py --file defanged_urls.txt --refang
    python url_defanger.py --url "hxxp://malicious[.]site[.]com" --refang --output clean_urls.txt

Features:
    - Defang URLs and IPs for safe sharing in reports
    - Refang previously defanged URLs back to live format
    - Batch processing from file
    - Optional clipboard copy
    - Output to file
"""

import argparse
import re
import sys
from typing import List
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


def defang_url(url: str) -> str:
    """
    Defang a URL or IP to make it safe for sharing.
    
    Examples:
        http://example.com -> hxxp://example[.]com
        https://192.168.1.1 -> hxxps://192[.]168[.]1[.]1
        192.168.1.1 -> 192[.]168[.]1[.]1
    """
    defanged = url
    
    # Defang protocol
    defanged = defanged.replace('http://', 'hxxp://')
    defanged = defanged.replace('https://', 'hxxps://')
    defanged = defanged.replace('ftp://', 'fxp://')
    
    # Defang :// even if not preceded by protocol
    defanged = re.sub(r'(?<!x)://', '[://]', defanged)
    
    # Defang dots in domain/IP
    # Look for patterns like word.word or number.number
    # But preserve dots already in brackets
    parts = []
    in_brackets = False
    i = 0
    
    while i < len(defanged):
        if defanged[i] == '[':
            in_brackets = True
            parts.append(defanged[i])
        elif defanged[i] == ']':
            in_brackets = False
            parts.append(defanged[i])
        elif defanged[i] == '.' and not in_brackets:
            # Check if this dot is part of a domain or IP
            # Look ahead and behind for alphanumeric
            if i > 0 and i < len(defanged) - 1:
                before = defanged[i-1].isalnum() or defanged[i-1] == '-'
                after = defanged[i+1].isalnum() or defanged[i+1] == '-'
                if before and after:
                    parts.append('[.]')
                else:
                    parts.append('.')
            else:
                parts.append('.')
        else:
            parts.append(defanged[i])
        i += 1
    
    defanged = ''.join(parts)
    
    # Defang @ symbol
    defanged = defanged.replace('@', '[@]')
    
    return defanged


def refang_url(url: str) -> str:
    """
    Refang a previously defanged URL back to live format.
    
    Examples:
        hxxp://example[.]com -> http://example.com
        hxxps://192[.]168[.]1[.]1 -> https://192.168.1.1
    """
    refanged = url
    
    # Refang protocol
    refanged = refanged.replace('hxxp://', 'http://')
    refanged = refanged.replace('hxxps://', 'https://')
    refanged = refanged.replace('fxp://', 'ftp://')
    
    # Refang [://]
    refanged = refanged.replace('[://]', '://')
    
    # Refang dots
    refanged = refanged.replace('[.]', '.')
    
    # Refang @ symbol
    refanged = refanged.replace('[@]', '@')
    
    return refanged


def is_url_or_ip(text: str) -> bool:
    """Check if text looks like a URL or IP address."""
    # Check for URL patterns
    url_pattern = r'(?i)(hxxp|http|ftp)s?[:\[]?://|(?:[\w-]+\.)+[a-z]{2,}'
    # Check for IP patterns
    ip_pattern = r'\b(?:\d{1,3}[\.\[]){3}\d{1,3}\b'
    
    return bool(re.search(url_pattern, text) or re.search(ip_pattern, text))


def load_from_file(file_path: str) -> List[str]:
    """Load URLs/IPs from file."""
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return lines
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {e}")
        sys.exit(1)


def save_to_file(items: List[str], file_path: str):
    """Save processed items to file."""
    try:
        with open(file_path, 'w') as f:
            for item in items:
                f.write(item + '\n')
        print(f"{Fore.GREEN}Output saved to: {file_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving file: {e}{Style.RESET_ALL}")


def copy_to_clipboard(text: str):
    """Copy text to clipboard if available."""
    if CLIPBOARD_AVAILABLE:
        try:
            pyperclip.copy(text)
            print(f"{Fore.GREEN}✓ Copied to clipboard{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}Could not copy to clipboard: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Note: Install pyperclip for clipboard support{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='URL/IP Defanger & Refanger - Convert URLs/IPs to safe format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Defang a URL:
    %(prog)s --url "http://malicious-site.com"
  
  Defang URLs from file:
    %(prog)s --file sample_urls.txt
  
  Refang URLs:
    %(prog)s --url "hxxp://malicious[.]site[.]com" --refang
  
  Defang and save to file:
    %(prog)s --file urls.txt --output defanged_urls.txt
  
  Refang and copy to clipboard:
    %(prog)s --url "hxxp://example[.]com" --refang --copy
        """
    )
    
    parser.add_argument('--url', '-u', help='Single URL or IP to process')
    parser.add_argument('--file', '-f', help='File with URLs/IPs (one per line)')
    parser.add_argument('--refang', '-r', action='store_true',
                       help='Refang mode (convert defanged back to live)')
    parser.add_argument('--output', '-o', help='Output file to save results')
    parser.add_argument('--copy', '-c', action='store_true',
                       help='Copy result to clipboard (single URL only)')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.error('Either --url or --file must be specified')
    
    # Get input items
    if args.url:
        items = [args.url]
    else:
        items = load_from_file(args.file)
    
    if not items:
        print(f"{Fore.RED}No valid items to process")
        sys.exit(1)
    
    # Process items
    mode = "Refanging" if args.refang else "Defanging"
    print(f"{Fore.CYAN}{mode} {len(items)} item(s)...{Style.RESET_ALL}\n")
    
    processed = []
    
    for item in items:
        if args.refang:
            result = refang_url(item)
            color = Fore.GREEN
            arrow = "→"
        else:
            result = defang_url(item)
            color = Fore.YELLOW
            arrow = "→"
        
        processed.append(result)
        
        # Display transformation
        print(f"{color}{item}{Style.RESET_ALL}")
        print(f"  {arrow} {Fore.CYAN}{result}{Style.RESET_ALL}\n")
    
    # Save to file if requested
    if args.output:
        save_to_file(processed, args.output)
    
    # Copy to clipboard if requested and single item
    if args.copy and len(processed) == 1:
        copy_to_clipboard(processed[0])
    elif args.copy and len(processed) > 1:
        print(f"{Fore.YELLOW}Note: Clipboard copy only works with single item{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}Processing complete!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
