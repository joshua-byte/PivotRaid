# PivotRaid

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Offensive Security](https://img.shields.io/badge/Focus-OffensiveSecurity-red)
![SMB](https://img.shields.io/badge/Protocol-SMB-green)
![FTP](https://img.shields.io/badge/Protocol-FTP-orange)
![Status](https://img.shields.io/badge/Status-Active-success)

PivotRaid is a lightweight, red-team-oriented automation tool designed to analyze exposed FTP and SMB services. It automates the repetitive process of service enumeration to identify weak configurations, exposed shares, sensitive-file leakage, and realistic lateral movement opportunities across network services.

Rather than treating services independently, PivotRaid correlates findings between FTP and SMB to model how attackers can chain exposures together during internal-network compromise scenarios.

The platform focuses on attack-surface analysis, credential exposure discovery, and offensive workflow automation for controlled VAPT and defensive-security assessment environments.

---

# Features

* FTP enumeration and exposure analysis
* SMB share enumeration and null-session validation
* Automated sensitive-file discovery
* Cross-service attack-path correlation
* Risk scoring and severity classification
* HTML report generation
* Offensive workflow automation
* Attack-surface prioritization
* Real-time terminal findings output
* Lightweight VAPT-oriented reconnaissance pipeline

---

# Why PivotRaid?

Traditional enumeration workflows across FTP and SMB services are often repetitive, fragmented, and manually intensive during internal-network assessments.

PivotRaid was designed to:

* automate cross-service reconnaissance,
* identify realistic attack-pivot opportunities,
* correlate exposed services,
* and model attacker workflows caused by weak legacy configurations.

Rather than simply enumerating open services, PivotRaid focuses on how attackers can leverage exposed resources to expand access and move laterally across a network environment.

---

# Security Focus Areas

PivotRaid focuses on:

* attack-surface mapping,
* service enumeration,
* credential exposure analysis,
* lateral movement simulation,
* offensive security automation,
* and VAPT-oriented reconnaissance workflows.

The platform is intended for internal-network security assessments and controlled penetration-testing environments.

---

# Tool Architecture & Data Flow

```text id="3zccsu"
                      [ Target IP ]
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
        [ FTP Module ]             [ SMB Module ]
         - Banner Grabbing          - Share Enumeration
         - Anonymous Login          - Null Sessions
         - Directory Enumeration    - Read/Write Checks
              │                           │
              └─────────────┬─────────────┘
                            ▼
               [ Sensitive File Finder ]
                - Credential Discovery
                - SSH / Config / DB Files
                            │
                            ▼
              [ Correlation & Path Engine ]
                - Cross-Service Pivot Mapping
                - Risk Scoring
                - Attack Path Analysis
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
       [ Terminal Output ]         [ HTML Report ]
       - Findings & Severity       - Executive Summary
       - Attack Paths              - Evidence Tables
       - Actionable Insights       - Remediation Guidance
```

---

# Example Assessment Workflow

PivotRaid was tested against intentionally vulnerable lab environments to simulate realistic internal-network enumeration scenarios.

Example findings included:

* vulnerable SMBv1 services,
* anonymous FTP access,
* accessible SMB shares,
* null-session exposure,
* and potential lateral movement pathways caused by weak service configurations.

The platform automatically correlates findings across services to identify realistic attack-pivot opportunities and prioritize remediation workflows.

---

# Sample Terminal Output

<img width="1423" height="992" alt="t_out_1" src="https://github.com/user-attachments/assets/114179b3-7275-4493-a91c-64b937157e23" />
<img width="1405" height="478" alt="t_out_2" src="https://github.com/user-attachments/assets/137462a8-a8b5-4abc-8484-16978e01e847" />


The terminal output provides:

* real-time service enumeration,
* vulnerability findings,
* severity classification,
* attack-path guidance,
* and attack-surface prioritization.

Example findings include:

* SMBv1 exposure
* Anonymous FTP login
* Null SMB sessions
* Accessible network shares
* Plaintext credential transmission
* Legacy protocol weaknesses

---

# HTML Report Preview

<img width="1475" height="821" alt="report" src="https://github.com/user-attachments/assets/991fe87f-4e69-40d0-b6b0-ae1363553180" />


The HTML reporting module generates structured offensive-security assessment reports including:

* executive summaries,
* evidence tables,
* vulnerability findings,
* impact analysis,
* remediation guidance,
* and attack-path recommendations.

The reporting system is designed to simulate lightweight internal-security assessment workflows.

---

# Example Findings

## SMB Findings

* SMB signing not required
* SMBv1 detected
* Null session allowed
* Accessible shares identified

## FTP Findings

* Anonymous login permitted
* Legacy FTP service detected
* Plaintext credential transmission
* Directory enumeration exposure

---

# Example Attack Path

```text id="dbq3g8"
Null SMB Session
        ↓
Enumerate SMB Shares
        ↓
Extract Sensitive Files
        ↓
Recover Credentials
        ↓
Authenticate Against FTP
        ↓
Expand Access
```

This workflow demonstrates how weak legacy configurations can be chained together during internal-network compromise scenarios.

---

# Risk Scoring

PivotRaid assigns confidence-based severity scores using factors including:

* service exposure,
* protocol insecurity,
* authentication weaknesses,
* accessible network shares,
* sensitive-file exposure,
* and cross-service attack-pivot opportunities.

Severity levels:

* INFO
* LOW
* MEDIUM
* HIGH
* CRITICAL

---

# MITRE ATT&CK Relevance

| Activity                | ATT&CK Technique |
| ----------------------- | ---------------- |
| SMB Share Enumeration   | T1135            |
| Credential Discovery    | T1552            |
| Valid Account Discovery | T1087            |
| Lateral Movement        | T1021            |
| Service Enumeration     | T1046            |

---

# Installation & Setup

Ensure Python 3.x is installed on your system.

## Clone Repository

```bash id="r3o3wp"
git clone https://github.com/joshua-byte/PivotRaid.git
cd PivotRaid
```

## Install Dependencies

```bash id="6yoj5k"
pip install -r requirements.txt
```

---

# Usage

Run the orchestrator by passing the target IP address:

```bash id="ezm8xm"
python3 main.py -t <target_ip>
```

Example:

```bash id="0kgbw7"
python3 main.py -t 192.168.1.10
```

---

# Example Lab Environment

PivotRaid was tested in controlled vulnerable-lab environments including:

* Metasploitable2
* Samba vulnerable containers
* Legacy FTP services
* Intentionally exposed SMB shares

The project should only be used in authorized and controlled environments.

---

# Project Structure

```text id="x89u4s"
PivotRaid/
│
├── main.py              # Main orchestrator and correlation engine
├── ftp.py               # FTP enumeration and exposure analysis
├── smb.py               # SMB share enumeration and validation
├── report.py            # HTML report generation module
├── report.html          # Sample generated report
├── requirements.txt     # Project dependencies
└── README.md
```

---

# Future Improvements

* Automated credential validation
* Recursive share crawling
* Multi-service correlation expansion
* LDAP and SSH integration
* Attack-path graph visualization
* ATT&CK-aligned reporting
* SIEM integration
* Parallelized scanning workflows
* Real-time alert streaming
* Expanded sensitive-file detection

---

# Recommended Remediation

Defensive recommendations include:

* Disable SMBv1
* Enforce SMB signing
* Restrict anonymous FTP access
* Harden share permissions
* Remove exposed sensitive files
* Disable legacy insecure services
* Monitor unusual internal enumeration activity

---

# Disclaimer

This project is intended solely for:

* cybersecurity education,
* authorized security assessments,
* offensive-security experimentation,
* and defensive hardening research.

Operating this tool against systems without explicit authorization is illegal. The author assumes no responsibility for misuse or damage caused by this software.

---

# Author

Joshua Jesuraj Sanctus

Cybersecurity • Detection Engineering • VAPT • Offensive Security Automation
