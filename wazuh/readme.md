# Wazuh SIEM — Setup & Detection Notes

## Environment
- **Host:** Ubuntu Server (VMware Virtual Platform)
- **Wazuh Version:** 4.x
  - `DESKTOP-A966884` — Windows 10 (Agent ID: 001)
  - `ubuntu-VMware-Virtual-Platform` — Ubuntu Server (Agent ID: 000)
- **Log Sources:** Suricata eve.json, Windows Event Channel, Sysmon

---

## Integration Overview

| Component | Integration Method |
|-----------|-------------------|
| Suricata | eve.json log file monitored by Wazuh |
| Windows 10 | Wazuh Agent + Sysmon event forwarding |
| Ubuntu Server | Wazuh Agent (local) |

---

## 🔍 Use Case 01 — False Positive Detection & Rule Tuning (WPAD DNS Timeout)

### Objective
Identify and suppress a recurring Windows DNS false positive alert that generates noise in the Wazuh dashboard, using a custom local rule targeting the specific Event ID and query name.

---

### 📊 Step 1 — Alert Identified

Wazuh rule `61109` fired **169 times** against agent `DESKTOP-A966884`, all flagged as level 5 warnings.

**Alert details:**
- **Rule ID:** 61109
- **Description:** Name resolution for the name wpad timed out
- **Agent:** DESKTOP-A966884 (Windows 10)
- **Agent IP:** 192.168.235.139
- **Event ID:** 1014
- **Provider:** Microsoft-Windows-DNS-Client
- **Channel:** System
- **Severity:** WARNING (level 3 Windows, level 5 Wazuh)
- **Fired times:** 7+ per session

**Raw alert message:**
```
"Name resolution for the name wpad timed out after none of the
configured DNS servers responded."
```

> 📸 `02-total hits.jpg` — Wazuh dashboard filtered on rule.id: 61109 showing 169 total hits

---

### 🔎 Step 2 — Root Cause Analysis

**What is WPAD?**
WPAD (Web Proxy Auto-Discovery) is a Windows protocol that automatically discovers web proxy settings by querying DNS for the hostname `wpad`. When no DNS server responds to this query, Windows logs Event ID 1014 repeatedly as a warning.

**Why is this a false positive?**
- No proxy server exists in this lab network
- Windows generates this event automatically and continuously
- It is not triggered by any user action or threat activity
- It creates alert fatigue by generating high-volume, low-value noise

> 📸 `01-fp.wazuh alert.jpg` — Expanded alert showing full event details including queryName: wpad and Event ID: 1014

---

### 🔧 Step 3 — Tune the Rule

A custom suppression rule was added to `/var/ossec/etc/rules/local_rules.xml` targeting the specific combination of Event ID `1014` and query name `wpad`:

```xml
<rule id="100050" level="0">
    <decoded_as>json</decoded_as>
    <field name="win.system.eventID">^1014$</field>
    <field name="win.eventdata.queryName">^wpad$</field>
    <description>Silence benign WPAD DNS client resolution timeouts</description>
</rule>
```

**Rule logic:**
- `decoded_as: json` — targets Windows Event Channel logs decoded as JSON
- `win.system.eventID: 1014` — specifically targets DNS timeout events
- `win.eventdata.queryName: wpad` — only matches WPAD queries, not other DNS timeouts
- `level: 0` — suppresses the alert from dashboard
- Regex anchors `^` and `$` ensure exact match — prevents unintended suppression

> 📸 `03-dns wazuh rule.jpg` — local_rules.xml showing the suppression rule added

---

### 🧠 Key Takeaways

| Item | Detail |
|------|--------|
| Alert type | Windows DNS timeout — Event ID 1014 |
| Root cause | WPAD auto-discovery with no proxy in the network |
| Volume | 169 alerts generated |
| Tuning method | Custom Wazuh local rule targeting Event ID + query name |
| Precision | Regex anchors used to avoid over-suppression |
| Result | Benign noise suppressed, real DNS alerts remain active |

---

## 📁 Screenshots

| File | Description |
|------|-------------|
| `01-fp.wazuh alert.jpg` | Expanded alert showing WPAD DNS timeout event details |
| `02-total hits.jpg` | Wazuh dashboard filtered on rule 61109 — 169 total hits |
| `03-dns wazuh rule.jpg` | local_rules.xml with suppression rule 100050 |
