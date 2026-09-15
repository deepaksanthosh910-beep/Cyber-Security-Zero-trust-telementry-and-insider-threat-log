# 🔐 Zero-Trust Telemetry & Insider Threat Detection

## Overview

A cybersecurity system that analyzes identity, authentication, network, and endpoint telemetry to identify suspicious user behavior and support Zero-Trust security decisions.

The system combines multiple security telemetry sources to calculate user-level security risk and recommend appropriate security actions.

## 🎯 Project Objective

The objective of this project is to continuously evaluate security activity instead of automatically trusting users or devices.

The system analyzes:

- IAM audit logs
- Firewall telemetry
- Endpoint security alerts
- Identity and asset information

and combines these signals to identify anomalous and potentially malicious user behavior.

## 🏗️ System Architecture

```text
Raw Security Telemetry
        ↓
Data Cleaning
        ↓
Telemetry Normalization
        ↓
Security Correlation
        ↓
Insider Threat Detection
        ↓
Risk Scoring
        ↓
Zero-Trust Decision
        ↓
Security Dashboard
```

## 🚨 Zero-Trust Actions

| Risk Level | Action |
|------------|--------|
| LOW | ALLOW |
| MEDIUM | VERIFY |
| HIGH | RESTRICT |
| CRITICAL | BLOCK |

## 🔍 Security Signals

The detection system considers multiple security signals, including:

- Failed login attempts
- Successful login activity
- MFA failures
- IAM risk scores
- Firewall DENY events
- Firewall threat events
- Network activity
- Endpoint alerts
- Critical endpoint alerts
- High-severity endpoint alerts
- Invalid endpoint resolution timestamps
- Combined user and device activity

## 🛡️ Insider Threat Detection

The project uses rule-based security analytics to calculate an insider-threat score for each user.

Users can be classified as:

- NORMAL
- ANOMALOUS
- SUSPICIOUS
- LIKELY INSIDER THREAT

The system also generates:

- Threat score
- Risk level
- Recommended Zero-Trust action
- Threat confidence
- Human-readable threat explanation
- Investigation priority

## 🖥️ Security Dashboard

The Streamlit dashboard provides:

- Overall security statistics
- Risk distribution
- Zero-Trust action distribution
- Threat classification
- High-risk user identification
- Department filtering
- Risk-level filtering
- Threat filtering
- Individual user investigation
- Security signal details
- Threat explanations
- Zero-Trust decision recommendations

## 🛠️ Technologies Used

- Python
- Pandas
- Streamlit
- JSON
- CSV
- Excel
- Rule-based security analytics

## 📁 Project Structure

```text
CyberSecurity_Hackathone/
│
├── data/
│   └── Raw security telemetry datasets
│
├── output/
│   └── Generated security analysis results
│
├── src/
│   ├── clean_data.py
│   ├── clean_telemetry.py
│   ├── correlate_security.py
│   ├── insider_threat_detector.py
│   ├── dashboard.py
│   ├── inspect_data.py
│   └── main.py
│
├── .gitignore
└── README.md
```

## ⚙️ Processing Pipeline

### 1. Data Cleaning

The project cleans identity and IAM information, including user IDs and department names.

### 2. Telemetry Normalization

Security telemetry is normalized across IAM, firewall, endpoint, and identity sources.

The cleaning process handles fields such as:

- Timestamps
- User IDs
- Departments
- IP addresses
- Ports
- Network bytes
- Risk scores
- MFA values
- Event types
- Firewall actions
- Threat flags
- Endpoint severity and status

### 3. Security Correlation

Telemetry from different sources is correlated using identifiers such as:

- `user_id`
- `hostname`
- `session_id`
- Timestamp relationships

This produces a unified user-level security dataset.

### 4. Insider Threat Detection

Security signals are combined to calculate an insider-threat score and determine the user's risk level and recommended security action.

### 5. Dashboard

The final results are visualized through an interactive Streamlit security dashboard.

## ▶️ How to Run

Install the required Python packages:

```bash
pip install pandas streamlit openpyxl
```

Run the processing pipeline:

```bash
python src/clean_data.py
python src/clean_telemetry.py
python src/correlate_security.py
python src/insider_threat_detector.py
```

Start the dashboard:

```bash
streamlit run src/dashboard.py
```

The dashboard will open in your browser.

## 🔐 Zero-Trust Principle

> **Never trust automatically. Always verify.**

The system uses security telemetry and risk signals to determine whether a user should be allowed, verified, restricted, or blocked.

## 📌 Project Status

Core components of the project are implemented:

- ✅ Data cleaning
- ✅ Telemetry normalization
- ✅ Multi-source security correlation
- ✅ Insider-threat detection
- ✅ Risk scoring
- ✅ Zero-Trust decision engine
- ✅ Interactive Streamlit dashboard

## ⚠️ Dataset Security

Raw security telemetry and generated output files should not be uploaded to a public GitHub repository unless redistribution is explicitly permitted by the hackathon or dataset owner.

The project's `.gitignore` excludes:

- Virtual environments
- PyCharm files
- Raw datasets
- Generated output files
- Environment variables and secrets
- Streamlit secrets

