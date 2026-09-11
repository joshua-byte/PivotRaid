# PivotRaid

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Offensive Security](https://img.shields.io/badge/Focus-OffensiveSecurity-red)
![SMB](https://img.shields.io/badge/Protocol-SMB-green)
![FTP](https://img.shields.io/badge/Protocol-FTP-orange)
![SSH](https://img.shields.io/badge/Protocol-SSH-blue)
![Status](https://img.shields.io/badge/Status-Active-success)

PivotRaid is a lightweight, red-team-oriented security assessment automation tool designed to analyze exposed FTP, SMB, and SSH services. It automates repetitive service enumeration to identify weak configurations, exposed shares, sensitive-file leakage, SSH service fingerprints, vulnerability intelligence candidates, and potential lateral-movement relationships.

Rather than treating services independently, PivotRaid correlates findings between FTP, SMB, and SSH to model how multiple exposures could combine during an internal-network security assessment.

The project focuses on attack-surface analysis, credential exposure discovery, SSH fingerprinting, SearchSploit-based vulnerability intelligence, risk scoring, cross-service correlation, and lightweight HTML reporting for controlled VAPT and defensive-security assessment environments.

> **Important:** PivotRaid is intended for authorized security assessments and controlled lab environments only. Vulnerability intelligence candidates are not treated as confirmed vulnerabilities or evidence of successful exploitation.

---

# Features

- FTP enumeration and exposure analysis
- SMB share enumeration and null-session validation
- SSH banner fingerprinting and version identification
- SearchSploit-based vulnerability candidate enrichment
- Automated sensitive-file discovery
- Cross-service relationship and exposure-path correlation
- Confidence-aware risk scoring
- Severity classification
- Terminal findings and assessment summaries
- HTML security assessment reporting
- Interactive exposure-map visualization
- Lightweight VAPT-oriented reconnaissance pipeline

---

# Why PivotRaid?

Traditional enumeration workflows across FTP, SMB, and SSH services can be repetitive and fragmented during internal-network assessments.

PivotRaid was designed to:

- automate cross-service reconnaissance,
- identify realistic exposure relationships,
- correlate exposed services,
- fingerprint SSH implementations,
- identify potentially sensitive resources,
- prioritize security findings,
- and represent how multiple weaknesses may combine into a broader exposure path.

The goal is not simply to report that a port is open. PivotRaid attempts to provide context around **what was observed, how confident the observation is, and what other observations it may relate to**.

---

# Security Focus Areas

PivotRaid focuses on:

- attack-surface mapping,
- service enumeration,
- authentication and authorization weaknesses,
- credential exposure analysis,
- SSH service fingerprinting,
- vulnerability intelligence correlation,
- sensitive-file discovery,
- cross-service exposure analysis,
- risk prioritization,
- and VAPT-oriented reconnaissance workflows.

The platform is intended for internal-network security assessments and controlled penetration-testing environments.

---

# Tool Architecture & Data Flow

```text
                         [ Target IP ]
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
        [ FTP Module ]   [ SMB Module ]   [ SSH Module ]
         - Banner Grab    - Share Enum     - SSH Banner
         - Anonymous      - Null Sessions  - Version ID
           Login          - Read/Write     - Platform ID
         - Directory        Checks         - Fingerprint
           Enumeration
              |               |               |
              +---------------+---------------+
                              |
                              v
                   [ Sensitive File Finder ]
                     - Credential Discovery
                     - Config / DB / SSH Files
                              |
                              v
                  [ Vulnerability Enrichment ]
                    - SearchSploit Candidates
                    - Candidate Classification
                              |
                              v
                    [ Risk Engine ]
                     - Severity
                     - Confidence
                     - Risk Score
                              |
                              v
                  [ Correlation Engine ]
                    - Cross-Service Relationships
                    - Potential Exposure Paths
                              |
                 +------------+------------+
                 |                         |
                 v                         v
          [ Terminal Output ]       [ HTML Report ]
          - Findings               - Executive Summary
          - Severity               - Service Findings
          - Risk Score             - Evidence
          - Relationships          - Vulnerability Candidates
          - Exposure Paths         - Exposure Visualization
```

The architecture intentionally separates:

```text
Scanner Modules
      ↓
Observed Findings
      ↓
Vulnerability Intelligence
      ↓
Risk Assessment
      ↓
Cross-Service Correlation
      ↓
Reporting
```

This keeps vulnerability candidates separate from confirmed observations and keeps risk scoring separate from correlation logic.

---

# Example Assessment Workflow

PivotRaid can be used against intentionally vulnerable lab environments to simulate internal-network enumeration scenarios.

Example observations may include:

- vulnerable SMB protocol configurations,
- anonymous FTP access,
- accessible SMB shares,
- null-session exposure,
- legacy SSH services,
- SSH software/version fingerprints,
- SearchSploit vulnerability candidates,
- sensitive-file indicators,
- and potential cross-service exposure relationships.

The platform correlates these observations to help prioritize security review.

---

# Sample Terminal Output

The terminal interface provides:

- real-time service enumeration,
- structured security findings,
- confidence information,
- severity classification,
- risk scoring,
- cross-service relationships,
- potential exposure paths,
- and an executive assessment summary.

Example findings include:

- SMBv1 exposure
- Anonymous FTP login
- Null SMB sessions
- Accessible network shares
- Plaintext credential exposure
- Legacy protocol weaknesses
- SSH software and version fingerprinting
- SearchSploit vulnerability candidates

---

# HTML Security Report

PivotRaid generates an HTML security assessment report as `report.html`.

The report is currently being **actively improved** as part of the project's job-readiness and code-quality work.

The reporting module is being refined to provide a clearer distinction between:

- observed security findings,
- vulnerability intelligence candidates,
- confirmed vulnerabilities,
- potential relationships,
- and actual exploitation.

The current report includes or is being improved to include:

- executive assessment summary,
- target and service information,
- service-level risk information,
- structured security findings,
- confidence information,
- vulnerability intelligence candidates,
- evidence presentation,
- exposure impact,
- potential exposure progression,
- and an interactive exposure-map visualization.

SearchSploit records are explicitly presented as **vulnerability candidates**. A candidate match does not by itself prove that the target is vulnerable, exploitable, or compromised.

The `report.html` file in the repository can be used as a sample generated report.

> **Reporting status:** The HTML reporting layer is an active improvement area. The objective is to make the final report look and read like a lightweight professional security-assessment deliverable without turning PivotRaid into an overengineered reporting platform.

---

# Example Findings

## SMB Findings

- SMB signing posture
- SMBv1 detection
- Null-session exposure
- Accessible shares
- Share permission observations
- Sensitive-file indicators

## FTP Findings

- Anonymous login
- Legacy FTP service detection
- Plaintext credential exposure
- Directory enumeration exposure
- Writable-resource observations
- Sensitive-file indicators

## SSH Findings

- SSH service exposure
- SSH banner identification
- OpenSSH implementation fingerprinting
- OpenSSH version identification
- Platform information from service fingerprinting
- SearchSploit vulnerability candidates

---

# Example Exposure Path

A conceptual assessment path may look like:

```text
Null SMB Session
        ↓
Enumerate SMB Shares
        ↓
Identify Sensitive File Indicators
        ↓
Potential Credential Exposure
        ↓
Potential Cross-Service Relationship
        ↓
Expand Assessment Scope
```

These paths represent **potential security relationships**, not automated exploitation instructions.

PivotRaid does not claim that a discovered credential is valid against another service unless that has actually been established by the assessment logic.

---

# Risk Scoring

PivotRaid assigns risk scores using factors including:

- service exposure,
- protocol security,
- authentication weaknesses,
- accessible network shares,
- sensitive-file exposure,
- vulnerability intelligence candidates,
- confidence of observations,
- and cross-service relationships.

Severity levels:

- INFO
- LOW
- MEDIUM
- HIGH
- CRITICAL

The risk engine intentionally separates:

```text
Finding Severity
        +
Confidence
        +
Service Context
        ↓
Overall Risk Score
```

A HIGH individual finding does not automatically mean that the overall target assessment is HIGH or CRITICAL.

---

# Vulnerability Intelligence

PivotRaid can enrich SSH fingerprint information using SearchSploit/Exploit-DB vulnerability intelligence.

The important distinction is:

```text
SearchSploit Match
       ↓
Vulnerability Candidate
       ↓
Requires Validation
       ↓
Confirmed Vulnerability
```

A SearchSploit match is therefore not automatically treated as proof of:

- vulnerable target software,
- successful exploitation,
- remote code execution,
- credential compromise,
- or system compromise.

This distinction is maintained across the enrichment, risk, correlation, and reporting layers.

---

# MITRE ATT&CK Relevance

| Activity | ATT&CK Technique |
|---|---|
| SMB Share Enumeration | T1135 |
| Credential Discovery | T1552 |
| Valid Account Discovery | T1087 |
| Lateral Movement | T1021 |
| Network Service Scanning | T1046 |

These mappings provide contextual relevance for the assessment workflow; they are not intended to imply that every technique was successfully executed against a target.

---

# Installation & Setup

Ensure Python 3.x is installed.

## Clone Repository

```bash
git clone https://github.com/joshua-byte/PivotRaid.git
cd PivotRaid
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

Run the orchestrator by passing the target IP address:

```bash
python3 main.py -t <target_ip>
```

Example:

```bash
python3 main.py -t 192.168.1.10
```

PivotRaid performs the assessment across its supported service modules and then processes the results through vulnerability enrichment, risk assessment, correlation, and HTML report generation.

The generated report is written to:

```text
report.html
```

---

# Example Lab Environment

PivotRaid is intended to be tested against controlled environments such as:

- Metasploitable2
- vulnerable Samba environments
- legacy FTP services
- intentionally exposed SMB shares
- Ubuntu SSH servers
- legacy OpenSSH services

The project should only be used where explicit authorization has been obtained.

---

# Project Structure

```text
PivotRaid/
│
├── main.py                       # Main orchestrator
├── ftp.py                        # FTP enumeration and exposure analysis
├── smb.py                        # SMB enumeration and validation
├── ssh.py                        # SSH fingerprinting and analysis
├── vulnerabilities.py            # Vulnerability intelligence/search logic
├── vulnerability_enrichment.py   # Vulnerability candidate enrichment
├── risk_engine.py                # Risk scoring and severity assessment
├── correlation_engine.py         # Cross-service correlation and paths
├── report.py                     # HTML security report generation
├── report.html                   # Sample/generated HTML report
├── requirements.txt              # Project dependencies
└── README.md
```

---

# Development Direction

The current development focus is **quality and job readiness rather than feature expansion**.

The project is being improved incrementally, with emphasis on:

- cleaner module boundaries,
- reliable state handling,
- defensive input handling,
- clear security semantics,
- accurate reporting language,
- maintainable code,
- and a small but meaningful test suite.

The objective is to make the existing PivotRaid capabilities more credible and maintainable rather than turning the project into a large security framework.

---

# Future Improvements

Potential future improvements include:

- expanded sensitive-file detection,
- additional cross-service correlation rules,
- ATT&CK-aligned reporting,
- improved test coverage,
- richer evidence handling,
- improved HTML report presentation,
- and additional controlled assessment workflows.

More complex features such as LDAP integration, SIEM integration, real-time alerting, or broader protocol coverage are intentionally lower priority until the core assessment pipeline is mature.

---

# Recommended Remediation

Defensive recommendations may include:

- disable SMBv1,
- enforce SMB signing where appropriate,
- restrict anonymous FTP access,
- harden SMB share permissions,
- remove exposed sensitive files,
- disable unnecessary legacy services,
- keep SSH implementations updated,
- review credential reuse risks,
- and monitor unusual internal service-enumeration activity.

---

# Disclaimer

This project is intended solely for:

- cybersecurity education,
- authorized security assessments,
- offensive-security experimentation,
- defensive hardening research,
- and controlled laboratory environments.

Operating this tool against systems without explicit authorization may be illegal. The author assumes no responsibility for misuse or damage caused by this software.

---

# Author

Joshua Jesuraj Sanctus

Cybersecurity • Detection Engineering • VAPT • Offensive Security Automation
