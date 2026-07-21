# 🛡️ SOC Home Lab

> A fully operational Security Operations Center home lab built from the ground up —  
> centralized SIEM, endpoint detection, network monitoring, and vulnerability management.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      HOME LAB NETWORK                   │
│                                                         │
│  ┌─────────────────┐        ┌─────────────────────┐    │
│  │  Ubuntu Server  │        │    Windows 10        │    │
│  │─────────────────│        │─────────────────────│    │
│  │ • Wazuh Manager │◄───────│ • Wazuh Agent        │    │
│  │ • Suricata IDS  │        │ • Sysmon             │    │
│  │ • OpenVAS       │        └─────────────────────┘    │
│  └────────┬────────┘                                    │
│           │         ┌─────────────────────┐            │
│           └────────►│     Kali Linux       │            │
│                     │─────────────────────│            │
│                     │ • Nessus Essentials  │            │
│                     │ • OpenVAS Client     │            │
│                     │ • Attack Simulation  │            │
│                     └─────────────────────┘            │
└─────────────────────────────────────────────────────────┘
```

---

## ⚙️ Components

| Host | Role | Tools |
|------|------|-------|
| Ubuntu Server | SIEM + IDS + Scanner | Wazuh Manager, Suricata, OpenVAS |
| Windows 10 | Monitored Endpoint | Wazuh Agent, Sysmon |
| Kali Linux | Attacker / Scanner | Nessus Essentials, OpenVAS |

---

## 🎯 Objectives

- Centralized log collection from all endpoints into Wazuh
- Deep endpoint visibility via Sysmon event logging on Windows
- Real-time network threat detection with Suricata IDS
- Vulnerability scanning and reporting with Nessus and OpenVAS
- End-to-end alert triage and incident investigation workflow
- Detection engineering — writing and tuning custom rules

---

## 📂 Repository Structure

```
SOC-Home-Lab/
│
├── architecture/
│   └── network-diagram.png
│
├── wazuh/
│   ├── setup-notes.md
│   ├── custom-rules/
│   └── screenshots/
│
├── suricata/
│   ├── setup-notes.md
│   ├── custom-rules/
│   └── screenshots/
│
├── sysmon/
│   ├── config.xml
│   ├── setup-notes.md
│   └── screenshots/
│
├── vulnerability-management/
│   ├── nessus/
│   │   └── screenshots/
│   └── openvas/
│       └── screenshots/
│
└── detections/
    └── [Detection use cases documented here]
```

---

## 🔍 Detection Use Cases

| # | Use Case | Tool | Status |
|---|----------|------|--------|
| 01 | [Port Scan Detection](detections/01-port-scan-detection.md) | Suricata | ✅ Complete |
| 02 | [Brute Force Login Attempt](detections/02-brute-force-login-attempt.md) | Hydra / Medusa + Wazuh | ✅ Complete |
| 03 | [Suspicious Process Creation — Encoded PowerShell Download Cradle](detections/03-suspicious-process-creation-encoded-powershell.md) | Sysmon + Wazuh | ✅ Complete |
| 04 | [Vulnerability Discovery](Detections/04-vulnerability-discovery/vulnerability-discovery.md) | Nessus | ✅ Complete |

---

## 🚧 Roadmap

**Phase 1 — Infrastructure** ✅ Complete

**Phase 2 — Detection Engineering** ✅ Complete
*(Future enhancement: custom correlation rule chaining 60122→60115→60200 into a single composite alert)*

**Phase 3 — Incident Response Playbooks** 📅 Planned

---

**This lab is continuously updated. New detections and documentation added regularly.*
