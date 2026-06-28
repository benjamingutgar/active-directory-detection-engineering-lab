# Windows Audit Policy

This document describes the Windows audit policy required to generate the events used by the Wazuh lateral movement detection laboratory.

The detections in this repository depend on Windows telemetry. If the required audit categories are not enabled, Wazuh may be correctly installed but still lack the events needed to detect the scenarios.

## 1. Purpose

The goal of this configuration is to enable the Windows Security events required for the three simulated scenarios:

| Scenario | Technique | Required Events |
|---|---|---|
| RDP lateral movement | `T1021.001` | `4624`, `4634`, `4647`, `4688` |
| SMB/PsExec-like execution | `T1021.002` | `4624`, `4672`, `5145`, `7045`, `4688` |
| Pass-the-Hash / DCSync correlation | `T1550.002`, `T1003.006` | `4624`, `4672`, `4662`, `7045`, `4688` |

## 2. Audit Policy Commands

Run the following commands in an elevated PowerShell or Command Prompt session on the monitored Windows systems.

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

## 3. Command-by-Command Explanation

| Command | Main Events | Why it matters |
|---|---|---|
| `Logon` | `4624`, `4625` | Required to observe successful and failed authentication activity. This is the base for RDP, SMB and Pass-the-Hash analysis. |
| `Special Logon` | `4672` | Required to identify when a logon session receives special privileges. This is essential for rules such as `100021` and correlation rule `100033`. |
| `Process Creation` | `4688` | Required to observe post-access command execution such as `whoami.exe`, `hostname.exe`, `ipconfig.exe` or `cmd.exe`. |
| `File Share` | `5140` and related share activity | Useful for general share access visibility. |
| `Detailed File Share` | `5145` | Required to observe detailed access to administrative shares such as `ADMIN$`, `C$` or `IPC$`. |

<details>
<summary>Explanation: why Detailed File Share is critical</summary>

Without the `Detailed File Share` audit policy, Windows may not generate Event ID `5145`.

Without Event ID `5145`, the lab loses the main telemetry needed to support hypothesis H4: access to administrative shares such as `ADMIN$`, `C$` or `IPC$`.

That does not mean SMB activity disappears completely. It means the detection chain becomes weaker because Wazuh sees authentication but loses detailed evidence of what resource was accessed.
</details>

## 4. Process Command Line Logging

To include command-line arguments in process creation events, enable the following registry value:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

This improves the value of Event ID `4688`.

Without command-line logging, Windows may show that a process was created, but not enough context about how it was executed.

Example:

```text
cmd.exe /Q /c whoami
```

is much more useful than only:

```text
cmd.exe
```

## 5. Remote Administration Support on DC01

The SMB/PsExec-like and Pass-the-Hash scenarios require remote administrative behavior against `DC01`.

On `DC01`, enable the following firewall rule groups when required:

```powershell
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=Yes
```

These rules allow the lab to generate the remote activity required for SMB, WMI and PsExec-like behavior.

## 6. Local Account Token Filter Policy

When local administrative accounts are used in a controlled lab, remote administration can be affected by User Account Control remote restrictions.

When necessary, the lab used:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord
```

This setting should be treated carefully.

<details>
<summary>Production warning</summary>

This setting is useful in a controlled laboratory, but it should not be blindly applied in production.

Changing `LocalAccountTokenFilterPolicy` can increase exposure by allowing local administrator accounts to receive a full remote token. In a real environment, this should be evaluated according to hardening policy, administrative model and compensating controls.
</details>

## 7. Restarting the Wazuh Agent

After changing telemetry configuration, restart the Wazuh agent:

```powershell
Restart-Service WazuhSvc
```

## 8. Validation Commands

Use these commands to verify the audit policy:

```powershell
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Special Logon"
auditpol /get /subcategory:"Process Creation"
auditpol /get /subcategory:"File Share"
auditpol /get /subcategory:"Detailed File Share"
```

Check recent Security events:

```powershell
Get-WinEvent -LogName Security -MaxEvents 20
```

For process creation events:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 5
```

For detailed file share events:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -MaxEvents 5
```

## 9. Detection Dependency Matrix

| Detection Hypothesis | Required Audit Configuration | Main Event |
|---|---|---|
| H1 — RDP access from known attacker origin | `Logon` | `4624` |
| H2 — Post-access command execution after RDP | `Process Creation` + command line logging | `4688` |
| H3 — SMB authentication from Kali to DC01 | `Logon` | `4624` |
| H4 — Administrative share access | `Detailed File Share` | `5145` |
| H5 — SMB + remote service execution | Service Control Manager logging + process visibility | `7045`, `4688` |
| H6 — NTLM privileged access | `Logon` + `Special Logon` | `4624`, `4672` |
| H7 — Pass-the-Hash + DCSync correlation | Directory Service Access auditing + `Special Logon` | `4662`, `4672` |

## 10. Key Takeaway

A SIEM does not create telemetry by itself.

Wazuh can only normalize, correlate and alert on events that Windows actually generates and forwards. The audit policy is therefore not a secondary configuration step; it is a prerequisite for the detection logic.
