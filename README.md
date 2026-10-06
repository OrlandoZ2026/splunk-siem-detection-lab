# Splunk SIEM Detection Lab

A home SIEM built on Splunk Enterprise that ingests Windows Security and Sysmon telemetry from a monitored endpoint, with three detections mapped to MITRE ATT&CK, a scheduled brute-force alert, and a Tier-1 triage dashboard. Attacks are simulated on the endpoint, forwarded to Splunk, and surfaced through SPL detections written and tuned by hand.

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Detection |
| --- | --- | --- | --- |
| Brute Force: Password Guessing | T1110.001 | Credential Access | Failed logon (4625) clustering, 5+ failures in 5 minutes |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution | Encoded PowerShell via Sysmon process creation |
| Application Layer Protocol | T1071 | Command and Control | Anomalous outbound connections via Sysmon network events |

## Lab Environment

| Component | Details |
| --- | --- |
| SIEM | Splunk Enterprise (host PC) |
| Log collection | Splunk Universal Forwarder (Windows 11 VM) |
| Endpoint telemetry | Sysmon with SwiftOnSecurity config |
| Field extraction | Splunk Add-on for Sysmon |
| Hypervisor | VirtualBox |
| Forwarding | Security + Sysmon Operational logs over TCP 9997 to the `wineventlog` index |

## Architecture

```
[ Windows 11 VM ]                         [ Host PC ]
  Sysmon  ───┐
             ├──► Universal Forwarder ──TCP 9997──► Splunk Enterprise
  Security ──┘        (inputs.conf)                   index=wineventlog
                                                            │
                                              SPL detections + Tier-1 dashboard
```

The forwarder is the only agent on the endpoint; all parsing and detection logic runs on the Splunk instance. This mirrors a real deployment where lightweight forwarders ship raw logs to a central indexer.

## Setup Overview

1. Created the `wineventlog` index and enabled a receiving port on TCP 9997.
2. Installed the Universal Forwarder on the VM and pointed it at the indexer.
3. Configured `inputs.conf` to forward both the Security and Sysmon Operational channels:

   ```
   [WinEventLog://Security]
   disabled = 0
   index = wineventlog

   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   disabled = 0
   index = wineventlog
   ```

4. Installed the Splunk Add-on for Sysmon on the indexer for CIM-compliant field extraction (`Image`, `CommandLine`, `ParentImage`, `DestinationIp`, etc.).

## Detection 1: Brute Force (T1110.001)

Simulated a password-guessing attack against a local account, then detected the failed-logon burst.

**Simulation (on the endpoint):**
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
net user labuser Lab!Pass2026 /add
1..15 | ForEach-Object { net use \\127.0.0.1\IPC$ /user:labuser "Wrong$_" 2>$null }
```

**Detection (SPL):**
```
index=wineventlog EventCode=4625
| eval target_user=mvindex(Account_Name,1)
| bin _time span=5m
| stats count AS failed_logons values(Logon_Type) AS logon_type values(Source_Network_Address) AS src_ip values(Failure_Reason) AS reason by _time host target_user
| where failed_logons >= 5
```

**Detection logic:** Event ID 4625 is a failed logon. The `Account_Name` field is multi-valued — index 0 is the subject account, index 1 is the account that actually failed authentication — so `mvindex(Account_Name,1)` is required to attribute failures to the correct target. Failures are bucketed into 5-minute windows; any account with 5+ failures in a window is flagged. This is the classic brute-force signature: many failures, fast, against one account.

**Alerting:** Saved as a scheduled alert on a `*/5 * * * *` cron schedule (every 5 minutes), triggering when results are greater than 0, with the "Add to Triggered Alerts" action so firings are logged for review.

## Detection 2: Encoded PowerShell (T1059.001)

**Simulation (on the endpoint):**
```powershell
$cmd = "Write-Host 'phase5-test'"
powershell.exe -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)))
```

**Detection (SPL):**
```
index=wineventlog source="*Sysmon*" EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| table _time host User ParentImage CommandLine
```

**Detection logic:** Attackers use PowerShell's `-EncodedCommand` flag to pass base64-encoded payloads, hiding the actual command from casual inspection and simple signature detection. Sysmon Event ID 1 (process creation) captures the full command line including the encoded blob, so filtering on `-enc` in the command line catches the technique regardless of payload. The detection surfaces who ran it, the parent process, and the encoded string for decoding during investigation.

## Detection 3: Anomalous Outbound Connections (T1071)

**Simulation (on the endpoint):**
```powershell
Invoke-WebRequest https://example.com -UseBasicParsing
```

**Detection (SPL):**
```
index=wineventlog source="*Sysmon*" EventCode=3 NOT DestinationIp IN ("10.*","192.168.*","172.16.*","127.*")
| stats count dc(DestinationIp) AS unique_dests values(DestinationPort) AS ports by Image
```

**Detection logic:** Sysmon Event ID 3 logs network connections. Excluding private (RFC 1918) and loopback ranges isolates genuinely external traffic, grouped by the process making the connection. The simulated `powershell.exe` connection to port 443 appears alongside legitimate traffic (OneDrive sync, Windows update) and living-off-the-land binaries (`msiexec.exe`, `rundll32.exe`) making external connections — the exact signal-versus-noise separation a Tier-1 analyst performs. LOLBins reaching out to unknown destinations are a standing investigation trigger in production.

## Tier-1 Triage Dashboard

A single dashboard combining the detections for at-a-glance monitoring:

- **Failed Logons Over Time** — timechart of 4625 events; the two spikes correspond to the simulated brute-force bursts.
- **Brute Force Detection** — the clustered-failure table.
- **Encoded PowerShell** — the T1059.001 catch.
- **Anomalous Outbound Connections** — external connections by process.

## Troubleshooting Highlight: Sysmon Forwarding Failure (errorCode=5)

After configuring the Sysmon input, Security logs forwarded normally but no Sysmon events reached the index. Root-cause investigation:

1. Confirmed Sysmon was running and logging locally on the endpoint (`Get-WinEvent` returned events).
2. Confirmed the forwarder had loaded the Sysmon input (`splunk cmd btool inputs list` showed the stanza active).
3. Confirmed only `WinEventLog:Security` was arriving in the index (`index=wineventlog | stats count by source`).
4. Read `splunkd.log`, which revealed the cause:
   `Could not subscribe to Windows Event Log channel 'Microsoft-Windows-Sysmon/Operational': errorCode=5`

errorCode=5 is "Access Denied." The Sysmon Operational channel has a restrictive ACL that the forwarder's default service account could not read, while the Security log's broader default access let the same account through — which is why one channel worked and the other failed silently.

**Fix:** Reconfigured the SplunkForwarder service to run as LocalSystem, which can read all event channels:
```powershell
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
  Invoke-CimMethod -MethodName Change -Arguments @{ StartName = "LocalSystem"; StartPassword = $null }
```
After restarting the forwarder, the Sysmon source appeared and all three detections fired on live data.

## Lab Notes

- **`User` field shows `NOT_TRANSLATED`** — the endpoint is a standalone VM with no domain, so Sysmon logs the raw SID instead of a resolved account name. Expected behavior in a non-domain lab.
- **Host/guest clock skew** — the VM clock drifted from the host, placing events outside narrow search windows. Diagnosed by comparing event timestamps to host time; worked around by searching over All time while validating detections.

## Defensive Takeaways

- Centralizing endpoint telemetry in a SIEM turns isolated host events into correlatable, searchable detections.
- Behavioral detection beats signatures: encoded PowerShell and brute-force clustering have no fixed signature but are clearly observable in process and authentication metadata.
- Multi-valued fields (like `Account_Name` on 4625) must be handled explicitly or detections silently miscount.
- Separating malicious from benign outbound traffic — including legitimate LOLBin activity — is the core of Tier-1 triage.

## Skills Demonstrated

Splunk Enterprise administration · Universal Forwarder deployment · SPL detection engineering · Windows Security and Sysmon log analysis · MITRE ATT&CK mapping · scheduled alerting · dashboard design · root-cause troubleshooting of a log-forwarding permissions failure
