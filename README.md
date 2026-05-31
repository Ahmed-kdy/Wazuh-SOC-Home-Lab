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
| 01 | Port Scan Detection | Suricata | 🔄 In Progress |
| 02 | Brute Force Login Attempt | Wazuh | 🔄 In Progress |
| 03 | Suspicious Process Creation | Sysmon + Wazuh | 🔄 In Progress |
| 04 | Vulnerability Discovery | Nessus + OpenVAS | 🔄 In Progress |

---

## 🚧 Roadmap

**Phase 1 — Infrastructure** ✅ Complete

**Phase 2 — Detection Engineering** 🔄 In Progress

**Phase 3 — Threat Hunting** 📅 Planned

**Phase 4 — Incident Response Playbooks** 📅 Planned

---

*This lab is continuously updated. New detections and documentation added regularly.*
