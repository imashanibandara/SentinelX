# SentinelX 🛡️

### Security Monitoring & Incident Response Platform

SentinelX is a lightweight Security Operations Center (SOC)-style platform designed to monitor security events, detect suspicious activity, assess security risks, and support incident investigation and response.

The project simulates a practical security monitoring workflow where security logs are processed through a detection and risk assessment pipeline before being presented through a live monitoring dashboard.

---

## 🚀 Features

* 🔍 **Security Log Monitoring**

  * Monitors security events from structured JSON logs.
  * Detects newly added events automatically.

* 🚨 **Threat Detection**

  * Brute-force login detection
  * Suspicious IP activity detection
  * Login-after-multiple-failures detection
  * Account-based login attack detection

* 📋 **Alert Management**

  * Automatically generates security alerts.
  * Prevents duplicate alerts.
  * Assigns unique alert IDs and timestamps.

* 🎯 **Risk Assessment**

  * Calculates risk scores from 0–100.
  * Considers severity, attack type, attempt count, and threat intelligence.
  * Classifies incidents as LOW, MEDIUM, HIGH, or CRITICAL.

* 🌐 **Threat Intelligence**

  * Maintains IP reputation information.
  * Supports malicious/suspicious IP classification.
  * Includes confidence and blacklist/watchlist information.

* 🔎 **Incident Management**

  * Investigate security alerts.
  * Update incident status.
  * Add analyst notes.
  * Maintain an incident timeline.

* 🛑 **Simulated Response**

  * Block suspicious IP addresses.
  * Unblock previously blocked IPs.
  * Maintain response audit logs.

* 📊 **Security Dashboard**

  * Alert statistics
  * Risk distribution
  * Threat intelligence
  * Security activity
  * Incident investigation
  * IP response controls

* 🔄 **Live Monitoring**

  * Automatically checks for new security events every 30 seconds.
  * Processes only newly detected events.

---

## 🏗️ System Architecture

```text
Security Logs
      ↓
Detection Engine
      ↓
Alert Manager
      ↓
Risk Engine
      ↓
Threat Intelligence
      ↓
IP Investigation
      ↓
Incident Management
      ↓
Automated Response
      ↓
Audit Logs
      ↓
Security Reports
```

---

## 🛠️ Technologies

### Backend

* Python
* Flask
* Flask-CORS

### Frontend

* HTML5
* CSS3
* JavaScript

### Data Storage

* JSON

### Security Concepts

* Security Event Monitoring
* Threat Detection
* Brute-Force Detection
* IP Reputation
* Risk Scoring
* Incident Response
* Audit Logging

---

## 📁 Project Structure

```text
SentinelX/
│
├── data/
│   ├── security_logs.json
│   ├── alerts.json
│   ├── risk_assessments.json
│   ├── threat_intelligence.json
│   ├── incident_status.json
│   ├── incident_timeline.json
│   ├── blocked_ips.json
│   ├── audit_logs.json
│   └── monitor_state.json
│
├── backend/
│   └── app/
│       ├── app.py
│       │
│       ├── api/
│       ├── detectors/
│       ├── models/
│       │
│       └── services/
│           ├── log_parser.py
│           ├── detection_engine.py
│           ├── alert_manager.py
│           ├── risk_engine.py
│           ├── event_simulator.py
│           ├── pipeline.py
│           ├── monitor.py
│           ├── threat_intelligence.py
│           ├── incident_manager.py
│           └── response_manager.py
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/imashanibandara/SentinelX.git
cd SentinelX
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running SentinelX

### 1. Start the Flask Backend

From the SentinelX root directory:

```bash
python backend/app/app.py
```

The backend will run at:

```text
http://127.0.0.1:5000
```

### 2. Start the Frontend

Open another terminal from the SentinelX root directory:

```bash
python -m http.server 5500 --directory frontend
```

Then open:

```text
http://127.0.0.1:5500/
```

---

## 🧪 Testing the Detection System

SentinelX includes an event simulator for testing security detection.

Run:

```bash
python backend/app/services/event_simulator.py
```

The simulator generates failed login events that can trigger the detection pipeline.

The monitoring service can then detect newly added events and process them automatically.

---

## 🔄 Monitoring Workflow

```text
New Security Event
        ↓
Monitor detects new event
        ↓
Detection Engine analyzes event
        ↓
Alert generated
        ↓
Duplicate check
        ↓
Risk score calculated
        ↓
Threat Intelligence checked
        ↓
Incident created/updated
        ↓
Analyst investigation
        ↓
Response action
        ↓
Audit log recorded
```

---

## 🎯 Project Objectives

The main objectives of SentinelX are to:

1. Demonstrate security event monitoring.
2. Detect common authentication-related attacks.
3. Prioritize alerts using risk scoring.
4. Integrate basic threat intelligence.
5. Provide an incident investigation workflow.
6. Simulate automated security response.
7. Present security information through a SOC-style dashboard.

---

## 🔐 Security Note

SentinelX is an educational and portfolio project designed to simulate a security monitoring and incident response environment.

IP blocking is simulated within the application and does **not** modify the operating system firewall.

The project should not be considered a production SOC or enterprise security platform.

---

## 📌 Future Improvements

Possible future enhancements include:

* Database-backed event storage
* Authentication and role-based access control
* External threat intelligence APIs
* Advanced correlation rules
* Email/notification integration
* Machine-learning-assisted anomaly detection
* Real firewall integration
* Deployment using Docker

---

## 👩‍💻 Author

**Imashani Bandara**

Cybersecurity-focused undergraduate interested in Security Operations, Threat Detection, Incident Response, and Defensive Security.

---

⭐ If you find this project useful, feel free to explore the repository and connect with me.
