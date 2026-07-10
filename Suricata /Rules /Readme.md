# Suricata IDS — Setup & Detection Notes

## Environment
- **Host:** Ubuntu Server (VMware Virtual Platform)
- **Mode:** IDS (Intrusion Detection System)
- **Ruleset:** ET Open (Emerging Threats)
- **Integration:** Wazuh Manager — Suricata alerts forwarded via `eve.json`

---

## Integration with Wazuh

Suricata logs are forwarded to Wazuh by configuring the `eve.json` log file as a monitored log source. All Suricata alerts appear in the Wazuh Security Events dashboard under the agent `ubuntu-VMware-Virtual-Platform`.

---

## 🔍 Use Case 01 — False Positive Detection & Rule Tuning

### Objective
Review Suricata alerts, identify false positives, and suppress them using a custom Wazuh local rule — without disabling the underlying Suricata signature.

---

### 📊 Step 1 — Review Total Alerts

After deploying Suricata and letting it run, a total of **1,050 alerts** were generated.

> 📸 `01-Suricata Hits.jpg` — Total alert count in Wazuh dashboard

---

### 🔎 Step 2 — Identify False Positives

During alert review, **17 alerts** were identified with the signature:

```
ET INFO Microsoft Connection Test
Signature ID: 2031071
Category: Misc Activity
Severity: 3 (Informational)
```

**Alert details:**
- Source IP: `192.168.235.139` (internal Windows host)
- Destination: `www.msftconnecttest.com` → `/connecttest.txt`
- HTTP User-Agent: `Microsoft NCSI`
- Protocol: TCP

**Analysis:** This is Windows Network Connectivity Status Indicator (NCSI) — a legitimate OS process that periodically checks internet connectivity by reaching `www.msftconnecttest.com`. This is **not a threat**, it is normal Windows behavior generating noise in Suricata.

> 📸 `02-num of MS connection test.jpg` — 17 hits visible in Wazuh  
> 📸 `03-suricata-FP-MS connection test role tuning.jpg` — Alert expanded view showing full event details

---

### 🔧 Step 3 — Tune the Rule (Suppress False Positive)

Instead of disabling the Suricata signature (which would reduce detection coverage), a **custom suppression rule** was written in Wazuh's `local_rules.xml` to set the alert level to 0, effectively muting it in the dashboard while keeping the signature active.

**Custom rule added to `/var/ossec/etc/rules/local_rules.xml`:**

```xml
<rule id="100025" level="0">
    <if_sid>86601</if_sid>
    <field name="data.alert.signature_id">2031071</field>
    <description>Mute Suricata ET INFO Microsoft Connection Test alerts</description>
</rule>
```

**Rule logic:**
- `if_sid: 86601` — targets Wazuh's Suricata alert rule
- `signature_id: 2031071` — specifically targets the Microsoft Connection Test signature
- `level: 0` — suppresses the alert from appearing in the dashboard
- Keeps the Suricata signature active — not disabled, just filtered at SIEM level

> 📸 `04-Suricata rule tuning in Wazuh.jpg` — local_rules.xml before adding suppression rule  
> 📸 `05-rule before tuning.jpg` — Rule file before the suppression rule was added  
> 📸 `06-rule after tuning.jpg` — Rule file after suppression rule was added

---

### ✅ Step 4 — Validate the Rule

The custom rule was validated using **Wazuh's built-in Ruleset Tester** by replaying the original alert JSON and confirming:

- Rule `100025` fires correctly
- Alert level set to `0` (suppressed)
- Description: `Mute Suricata ET INFO Microsoft Connection Test alerts`
- `firedtimes: 1` — rule matched successfully

```json
{
  "timestamp": "2026-06-04T12:46:16.173741+0200",
  "event_type": "alert",
  "src_ip": "192.168.235.139",
  "dest_ip": "104.103.72.81",
  "proto": "TCP",
  "alert": {
    "signature": "ET INFO Microsoft Connection Test",
    "signature_id": 2031071,
    "severity": 3
  },
  "http": {
    "hostname": "www.msftconnecttest.com",
    "url": "/connecttest.txt",
    "http_user_agent": "Microsoft NCSI"
  }
}
```

**Ruleset Tester Result:**
```
Phase 3: Completed filtering (rules)
  id: '100025'
  level: '0'
  description: 'Mute Suricata ET INFO Microsoft Connection Test alerts'
  firedtimes: '1'
  mail: 'false'
```

> 📸 `07-ruleset test.jpg` — Wazuh Ruleset Tester confirming rule fires correctly at level 0

---

## 🧠 Key Takeaways

| Item | Detail |
|------|--------|
| Alert type | Suricata ET INFO — informational, not a threat |
| Root cause | Windows NCSI connectivity check to `msftconnecttest.com` |
| Tuning method | Custom Wazuh local rule targeting specific signature ID |
| Result | FP suppressed at SIEM level, Suricata signature remains active |
| Benefit | Reduces alert fatigue without losing detection coverage |

---

## 📁 Screenshots

| File | Description |
|------|-------------|
| `01-Suricata Hits.jpg` | Total Suricata alert count in Wazuh |
| `02-num of MS connection test.jpg` | 17 false positive hits identified |
| `03-suricata-FP-MS connection test role tuning.jpg` | Expanded alert details |
| `04-Suricata rule tuning in Wazuh.jpg` | Wazuh local rules file |
| `05-rule before tuning.jpg` | Rules file before suppression |
| `06-rule after tuning.jpg` | Rules file after suppression rule added |
| `07-ruleset test.jpg` | Ruleset Tester validation result |

