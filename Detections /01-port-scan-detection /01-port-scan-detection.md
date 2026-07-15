
# Detection Use Case 01: Nmap NSE HTTP Reconnaissance Scan

**Tool:** Suricata IDS
**MITRE ATT&CK:** T1595 – Active Scanning (Discovery)
**Status:** ✅ Validated

## Scenario
From the Kali attacker VM (`192.168.235.140`), an Nmap NSE HTTP script scan was run against the Ubuntu SIEM host (`192.168.235.138`) on port 443. The scan sent an HTTP GET request attempting to access `/etc/passwd`, consistent with an NSE script probing for path traversal or file exposure vulnerabilities.

## Detection
Suricata, monitoring interface `ens33`, flagged the traffic using the ET Open rule **"ET SCAN Possible Nmap User-Agent Observed"** (SID 2024364). The rule matches on the HTTP User-Agent string Nmap's scripting engine sends by default:

Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)


This is signature-based detection: the tool identified itself in the request header, and the IDS caught it immediately — no behavioral analysis required.

| Field | Value |
|---|---|
| Source | 192.168.235.140:53452 (Kali) |
| Destination | 192.168.235.138:443 (Ubuntu) |
| Request | `GET //etc/passwd` |
| Signature | ET SCAN Possible Nmap User-Agent Observed (SID 2024364) |
| Wazuh Rule | 86601 (Level 3) |

## Pipeline Validated
`Suricata (eve.json) → ossec → alerts.json → Filebeat → Wazuh Indexer → Wazuh Dashboard`

## Response / Takeaway
Severity is informational, but in a production environment this alert would trigger a check for follow-on activity from the source IP, since reconnaissance typically precedes exploitation attempts. No further malicious activity followed in this lab session.


## Detection Evidence

![Wazuh alert - Nmap NSE scan detected](screenshots/01-nmap-nse-alert.png)

<details>
<summary>Raw alert JSON</summary>

```json
{
  "data": {
    "src_ip": "192.168.235.140",
    "dest_ip": "192.168.235.138",
    "dest_port": "443",
    "alert": {
      "signature": "ET SCAN Possible Nmap User-Agent Observed",
      "signature_id": "2024364"
    },
    "http": {
      "url": "%2F%2Fetc%2Fpasswd",
      "http_user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
    }
  },
  "rule": {
    "id": "86601",
    "level": 3
  }
}
</details>
```
