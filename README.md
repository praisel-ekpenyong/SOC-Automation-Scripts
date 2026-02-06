# SOC Automation Scripts

**Python scripts that automate common SOC analyst tasks — IOC enrichment, phishing analysis, log parsing, and threat intelligence lookups.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![VirusTotal](https://img.shields.io/badge/API-VirusTotal-brightgreen)](https://www.virustotal.com/)
[![AbuseIPDB](https://img.shields.io/badge/API-AbuseIPDB-orange)](https://www.abuseipdb.com/)
[![Email Analysis](https://img.shields.io/badge/Tool-Email%20Analysis-yellow)](https://github.com/praisel-ekpenyong/SOC-Automation-Scripts)
[![Log Parsing](https://img.shields.io/badge/Tool-Log%20Parsing-red)](https://github.com/praisel-ekpenyong/SOC-Automation-Scripts)

---

## 📋 Scripts Overview

| Script | Description | API Used |
|--------|-------------|----------|
| **ioc_enrichment.py** | Query VirusTotal for IP/domain/hash reputation with color-coded verdicts | VirusTotal API v3 |
| **phishing_header_analyzer.py** | Parse .eml files, analyze headers, check SPF/DKIM/DMARC, detect phishing | Built-in email library |
| **log_analyzer.py** | Parse Windows Security/Sysmon logs, flag suspicious events, generate reports | N/A |
| **bulk_ip_checker.py** | Bulk IP reputation lookup with progress tracking and CSV reports | AbuseIPDB API v2 |
| **hash_lookup.py** | Check file hashes (MD5/SHA1/SHA256) against VirusTotal database | VirusTotal API v3 |
| **url_defanger.py** | Defang/refang URLs and IPs for safe sharing in SOC reports | N/A |
| **alert_triage_report.py** | Generate formatted incident triage reports with MITRE ATT&CK mapping | N/A |

---

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/praisel-ekpenyong/SOC-Automation-Scripts.git
   cd SOC-Automation-Scripts
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up API keys:**
   
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your API keys:
   ```bash
   VT_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   ```
   
   Then load the environment variables:
   ```bash
   source .env
   # Or on Windows:
   # set VT_API_KEY=your_key
   # set ABUSEIPDB_API_KEY=your_key
   ```

   **Get your API keys:**
   - VirusTotal: [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
   - AbuseIPDB: [https://www.abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)

---

## 📖 Usage Examples

### 1. IOC Enrichment Tool

Query VirusTotal for threat intelligence on IPs, domains, or file hashes:

```bash
# Check IP reputation
python scripts/ioc_enrichment.py --type ip --value 8.8.8.8

# Check domain reputation
python scripts/ioc_enrichment.py --type domain --value malicious-site.com

# Check file hash
python scripts/ioc_enrichment.py --type hash --value 44d88612fea8a8f36de82e1278abb02f
```

**Sample Output:**
```
[CLEAN] IP: 8.8.8.8
Detection Ratio: 0/94
Malicious: 0 | Suspicious: 0 | Clean: 94
Country: US
ASN: 15169 (GOOGLE)
Last Analysis: 2024-02-05 10:30:45
```

---

### 2. Phishing Email Header Analyzer

Analyze email headers for phishing indicators:

```bash
python scripts/phishing_header_analyzer.py samples/sample_email.eml
```

**Features:**
- ✅ Extract key headers (From, To, Subject, Return-Path, etc.)
- ✅ Verify SPF, DKIM, DMARC authentication
- ✅ Detect sender mismatches and spoofing
- ✅ Trace email routing path
- ✅ Extract and defang URLs from body
- ✅ Provide phishing verdict with confidence score

**Sample Output:**
```
======================================================================
PHISHING EMAIL HEADER ANALYSIS
======================================================================

Key Headers:
  From:        "PayPal Security Team" <security@paypal.com>
  Return-Path: <noreply@paypa1-secure.com>
  Subject:     Urgent: Unusual Activity Detected on Your Account

Authentication Results:
  SPF:   FAIL
  DKIM:  NONE
  DMARC: FAIL

Suspicious Indicators:
  ⚠ SPF authentication failed
  ⚠ DMARC authentication failed
  ⚠ From address doesn't match Return-Path
  ⚠ Suspicious keywords in subject

VERDICT: SUSPICIOUS
Confidence Score: 75%
```

---

### 3. Windows Security Log Analyzer

Parse and analyze Windows Event logs for suspicious activity:

```bash
python scripts/log_analyzer.py --input samples/sample_log.json
python scripts/log_analyzer.py --input security_events.csv --output flagged_events.csv
```

**Flags:**
- 🔴 Event 4625: Failed logon attempts (brute force detection)
- 🔴 Event 4624 + Type 10: RDP logins
- 🔴 Event 4720: New user account creation
- 🔴 Event 4728/4732: User added to privileged group
- 🔴 Event 4688: Suspicious process creation (PowerShell, cmd.exe, encoded commands)
- 🔴 Sysmon Event 1: Process creation with obfuscation

**Sample Output:**
```
======================================================================
WINDOWS SECURITY LOG ANALYSIS SUMMARY
======================================================================

Overview:
  Total Events Analyzed: 20
  Suspicious Events Flagged: 8

Severity Distribution:
  HIGH: 4
  MEDIUM: 4

High Failed Login Sources (>5 attempts):
  192.168.1.50: 6 failed attempts

Top Source IPs:
  192.168.1.50: 6 events
  10.0.0.45: 1 events
```

---

### 4. Bulk IP Reputation Checker

Check multiple IPs against AbuseIPDB with progress tracking:

```bash
python scripts/bulk_ip_checker.py --input samples/sample_ips.txt
python scripts/bulk_ip_checker.py --input ip_list.txt --output ip_report.csv
```

**Features:**
- 📊 Batch processing with progress bar
- 🎨 Color-coded risk levels (Red: High, Yellow: Medium, Green: Low)
- 📝 CSV report generation
- ⏱️ Rate limit handling

**Sample Output:**
```
Checking 10 IP addresses...
Progress: 100%|████████████████████████| 10/10 [00:12<00:00,  1.2s/IP]

8.8.8.8         | Score:   0 | Risk: LOW    | US  | GOOGLE
185.220.101.1   | Score:  85 | Risk: HIGH   | DE  | Tor Exit Node
1.1.1.1         | Score:   0 | Risk: LOW    | AU  | CLOUDFLARE

Summary Statistics:
  Total IPs Checked: 10
  HIGH Risk (≥75):   2
  MEDIUM Risk (25-74): 1
  LOW Risk (<25):    7
```

---

### 5. File Hash Reputation Lookup

Check file hashes against VirusTotal:

```bash
# Single hash
python scripts/hash_lookup.py --hash 44d88612fea8a8f36de82e1278abb02f

# Multiple hashes from file
python scripts/hash_lookup.py --file samples/sample_hashes.txt --output hash_report.csv
```

**Supports:** MD5, SHA1, SHA256 (auto-detected)

**Sample Output:**
```
[MALICIOUS] MD5: 44d88612fea8a8f36de82e1278abb02f
Detection Ratio: 65/72
Malicious: 65 | Suspicious: 2 | Clean: 5
Threat Label: EICAR-Test-File
File Name: eicar.com
File Type: text
Size: 68 bytes
First Seen: 2005-01-01
Last Seen: 2024-02-05
```

---

### 6. URL/IP Defanger & Refanger

Convert URLs/IPs to safe format for sharing in reports:

```bash
# Defang a single URL
python scripts/url_defanger.py --url "http://malicious-site.com/payload.exe"

# Defang URLs from file
python scripts/url_defanger.py --file samples/sample_urls.txt --output defanged.txt

# Refang previously defanged URLs
python scripts/url_defanger.py --url "hxxp://malicious[.]site[.]com" --refang

# Copy result to clipboard
python scripts/url_defanger.py --url "http://evil.com" --copy
```

**Transformations:**
- `http://` → `hxxp://`
- `https://` → `hxxps://`
- `.` → `[.]` in domains
- `@` → `[@]`

**Sample Output:**
```
Defanging 1 item(s)...

http://malicious-site.com/payload.exe
  → hxxp://malicious[.]site[.]com/payload[.]exe

Processing complete!
```

---

### 7. Alert Triage Report Generator

Generate formatted incident triage reports from alert data:

```bash
python scripts/alert_triage_report.py --input samples/sample_alert.json
python scripts/alert_triage_report.py --input alert.json --analyst "Jane Smith" --output report.md
```

**Features:**
- 📄 Markdown report generation
- 🎯 MITRE ATT&CK technique mapping
- 🔍 Automatic IOC extraction and defanging
- ✅ Recommended action items
- 👤 Analyst attribution

**Sample Output:**
```
# Incident Triage Report

## Alert Information
- **Alert Name:** Brute Force Attack Detected
- **Alert Type:** Brute Force
- **Severity:** HIGH
- **Date/Time:** 2024-02-05 14:35:00 UTC
- **Analyst:** Jane Smith

## Executive Summary
Multiple failed login attempts detected from single source IP address...

## MITRE ATT&CK Mapping
### Tactics
- Credential Access

### Techniques
- T1110 - Brute Force
- T1110.001 - Password Guessing

## Recommended Actions
1. Verify if the account was successfully compromised
2. Check for successful logins from the source IP after failed attempts
3. Block source IP at firewall level
4. Reset passwords for affected accounts
5. Enable MFA if not already enabled
```

---

## 📁 Repository Structure

```
SOC-Automation-Scripts/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── .env.example                       # Example environment variables
├── scripts/
│   ├── ioc_enrichment.py             # VirusTotal IOC lookup
│   ├── phishing_header_analyzer.py   # Email phishing analysis
│   ├── log_analyzer.py               # Windows log parser
│   ├── bulk_ip_checker.py            # Bulk IP reputation checker
│   ├── hash_lookup.py                # File hash lookup
│   ├── url_defanger.py               # URL/IP defanger
│   └── alert_triage_report.py        # Incident report generator
└── samples/
    ├── sample_ips.txt                # Sample IP list
    ├── sample_log.json               # Sample Windows Security log
    ├── sample_email.eml              # Sample phishing email
    ├── sample_hashes.txt             # Sample file hashes
    ├── sample_urls.txt               # Sample URLs
    └── sample_alert.json             # Sample alert data
```

---

## 🔧 Requirements

- **Python:** 3.8 or higher
- **APIs:** VirusTotal API key (free tier available), AbuseIPDB API key (free tier available)
- **Dependencies:** See `requirements.txt`

---

## 🎯 Use Cases

These scripts are designed for:
- **SOC Analysts** performing initial triage and investigation
- **Incident Responders** gathering threat intelligence
- **Security Engineers** automating repetitive tasks
- **Blue Team Members** analyzing logs and alerts
- **Students** learning SOC analyst workflows

---

## 📚 Related Projects

See also: [**SOC Analyst Lab Portfolio**](https://github.com/praisel-ekpenyong/SOC-Analyst-Lab) — Detection rules, incident investigations, and phishing analysis

---

## 📞 Contact

**Praisel Ekpenyong**

- 🔗 LinkedIn: [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong)
- 📧 Email: ekpenyongpraisel@gmail.com
- 🐙 GitHub: [github.com/praisel-ekpenyong](https://github.com/praisel-ekpenyong)

---

## 📝 License

This project is open source and available for educational and professional use.

---

## ⚠️ Disclaimer

These tools are provided for educational and authorized security testing purposes only. Always ensure you have permission before testing on systems you do not own. The author is not responsible for misuse of these tools.

---

**⭐ If you find these scripts helpful, please consider starring the repository!**