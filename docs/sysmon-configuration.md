# Sysmon Configuration

This document explains how Sysmon was installed in the laboratory and how it was used as complementary endpoint telemetry for the Wazuh detection chain.

Sysmon was not used as the only source of detection. The core detections rely mainly on Windows Security events and Wazuh rules. Sysmon adds process-level context and can help validate post-access activity.

## 1. Purpose of Sysmon in This Lab

Sysmon was used to improve visibility over endpoint behavior, especially process creation.

| Sysmon Event | Use in the lab |
|---|---|
| Sysmon Event ID `1` — Process Creation | Provides process execution context, parent process and command-line information when available |
| Sysmon Event ID `10` — Process Access | Useful as additional context in endpoint analysis, but not the main basis of the final detection chain |

The most relevant use case in this project is process creation after remote access.

Examples:

```text
whoami.exe
hostname.exe
ipconfig.exe
cmd.exe
```

These events are useful in the RDP scenario because an RDP logon alone is ambiguous. Post-access commands make the scenario more meaningful for an analyst.

## 2. Installation Directory

Create a working directory:

```powershell
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force
Set-Location C:\Tools\Sysmon
```

## 3. Download Sysmon

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon\Sysmon.zip"
Expand-Archive "C:\Tools\Sysmon\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
```

## 4. Download Sysmon Configuration

The lab used the public SwiftOnSecurity Sysmon configuration as a practical baseline:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig-export.xml"
```

## 5. Install Sysmon

```powershell
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

## 6. Verify Sysmon Service and Event Channel

```powershell
Get-Service Sysmon*
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Expected result:

- The Sysmon service exists and is running.
- The event channel `Microsoft-Windows-Sysmon/Operational` contains recent events.
- Process creation events appear after command execution.

## 7. Sysmon vs Windows Security 4688

Both Windows Security Event ID `4688` and Sysmon Event ID `1` can provide process creation telemetry.

They overlap, but they are not identical.

| Source | Event | Strength | Limitation |
|---|---|---|---|
| Windows Security | `4688` | Native Windows telemetry, useful for SIEM correlation | Requires audit policy and command-line logging configuration |
| Sysmon | Event ID `1` | Rich process context and parent-child process relationships | Requires Sysmon installation, configuration and Wazuh collection |

<details>
<summary>Explanation: why Sysmon can be redundant but still useful</summary>

If Windows Security `4688` is correctly configured with command-line logging, some process execution evidence may already be visible without Sysmon.

However, Sysmon remains useful because it can provide richer endpoint context, especially for parent process relationships and process metadata.

In this lab, Sysmon should be understood as complementary telemetry. The detection chain should not collapse if a single process source is unavailable, but the analysis becomes stronger when both Windows Security and Sysmon are available.
</details>

## 8. Events Used by Scenario

| Scenario | Sysmon Value |
|---|---|
| RDP | Helps validate post-access process execution after the remote session |
| SMB / PsExec-like | Helps review processes created by remote service activity |
| Pass-the-Hash | Provides additional endpoint context; the main chain uses Windows Security telemetry |
| Kerberoasting | Optional Sysmon Event ID `3` context when a monitored Windows process connects to `DC01:88` |
| AS-REP Roasting | No Sysmon event was supplied or required; the validated detection uses Event ID `4768` on `DC01` |

AS-REP Roasting must not be represented as a Sysmon-based detection in this repository.

## 9. Operational Notes

After installing or changing Sysmon configuration:

1. Restart Sysmon if needed.
2. Confirm new events are written to `Microsoft-Windows-Sysmon/Operational`.
3. Confirm the Wazuh agent collects that channel.
4. Search in Wazuh for Sysmon events from `DC01` and `WS01`.

Example Wazuh query:

```kql
data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

## 10. Key Takeaway

Sysmon improves endpoint visibility, but it does not replace correct Windows audit policy.

For this project, Sysmon is valuable because it helps explain what happened after access was obtained. It supports analyst interpretation rather than acting as the only detection source.
