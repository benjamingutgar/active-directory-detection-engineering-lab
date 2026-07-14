# Windows Audit Policy

This document describes the Windows audit policy required to generate the events used by the Wazuh Active Directory security laboratory.

The detections in this repository depend on Windows telemetry. If the required audit categories are not enabled, Wazuh may be correctly installed but still lack the events needed to detect the scenarios.

## 1. Purpose

The goal of this configuration is to enable the Windows Security events required for the four simulated scenarios:

| Scenario | Technique | Required Events |
|---|---|---|
| RDP lateral movement | `T1021.001` | `4624`, `4634`, `4647`, `4688` |
| SMB/PsExec-like execution | `T1021.002`, `T1569.002` | `4624`, `4672`, `5145`, `7045`, `4688` |
| Pass-the-Hash / DCSync correlation | `T1550.002`, `T1003.006` | `4624`, `4672`, `4662`, `7045`, `4688` |
| Kerberoasting | `T1558.003` | `4769`, optional Sysmon Event ID `3` |

Kerberoasting extends the project from lateral movement into credential access.

Its main Windows telemetry is generated on `DC01`, because the Domain Controller hosts the Kerberos Key Distribution Center and processes service-ticket requests.

---

## 2. Audit Policy Commands

Run the following commands in an elevated PowerShell or Command Prompt session on the monitored Windows systems:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

On `DC01`, also enable Kerberos service-ticket auditing:

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

The DCSync-related scenario additionally requires Directory Service Access auditing and an appropriate System Access Control List on the Active Directory object being monitored.

---

## 3. Command-by-Command Explanation

| Command | Main Events | Why it matters |
|---|---|---|
| `Logon` | `4624`, `4625` | Required to observe successful and failed authentication activity. This is the base for RDP, SMB and Pass-the-Hash analysis. |
| `Special Logon` | `4672` | Required to identify when a logon session receives special privileges. This is essential for rules such as `100021` and correlation rule `100033`. |
| `Process Creation` | `4688` | Required to observe post-access command execution such as `whoami.exe`, `hostname.exe`, `ipconfig.exe` or `cmd.exe`. |
| `File Share` | `5140` and related share activity | Useful for general share-access visibility. |
| `Detailed File Share` | `5145` | Required to observe detailed access to administrative shares such as `ADMIN$`, `C$` or `IPC$`. |
| `Kerberos Service Ticket Operations` | `4769` | Required to observe Kerberos service-ticket requests processed by the Domain Controller. This is the principal event for hypotheses H8 and H9. |
| `Directory Service Access` | `4662` | Required for DCSync-like visibility when the appropriate Active Directory auditing configuration is present. |

<details>
<summary>Explanation: why Detailed File Share is critical</summary>

Without the `Detailed File Share` audit policy, Windows may not generate Event ID `5145`.

Without Event ID `5145`, the lab loses the main telemetry needed to support hypothesis H4: access to administrative shares such as `ADMIN$`, `C$` or `IPC$`.

That does not mean SMB activity disappears completely. It means the detection chain becomes weaker because Wazuh sees authentication but loses detailed evidence of the resource that was accessed.
</details>

<details>
<summary>Explanation: why Kerberos Service Ticket Operations is critical</summary>

Without the `Kerberos Service Ticket Operations` audit subcategory, `DC01` may not generate the Event ID `4769` records required by the Kerberoasting scenario.

The ticket request can still occur successfully, but Wazuh will not have the principal Domain Controller telemetry needed to apply rules `100040` and `100041`.

The auditing must be enabled on `DC01`, because the KDC processes the request and issues the service ticket.
</details>

---

## 4. Process Command-Line Logging

To include command-line arguments in process creation events, enable the following registry value:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

This improves the value of Event ID `4688`.

Without command-line logging, Windows may show that a process was created, but not enough context about how it was executed.

For example:

```text
cmd.exe /Q /c whoami
```

is more useful than only:

```text
cmd.exe
```

Command-line logging supports the RDP, SMB/PsExec-like and Pass-the-Hash scenarios.

The main Kerberoasting detection does not depend on Event ID `4688`, because it is based on the service-ticket request recorded as Event ID `4769`.

---

## 5. Kerberos Service-Ticket Auditing

Run the following command on `DC01`:

```powershell
auditpol.exe `
    /set `
    /subcategory:"Kerberos Service Ticket Operations" `
    /success:enable `
    /failure:enable
```

Verify it:

```powershell
auditpol.exe `
    /get `
    /subcategory:"Kerberos Service Ticket Operations"
```

Expected result:

```text
Kerberos Service Ticket Operations    Success and Failure
```

The principal event is:

```text
4769 — A Kerberos service ticket was requested
```

### Relevant Event ID 4769 Fields

| Field | Detection Use |
|---|---|
| Requesting account | Identifies the domain identity that requested the ticket |
| Service name | Identifies the account associated with the requested SPN |
| Client address | Identifies the source of the ticket request |
| Ticket encryption type | Distinguishes RC4 from AES |
| Ticket options | Provides additional information about the Kerberos request |
| Status or failure code | Indicates whether the request succeeded |
| Event record ID | Allows the event to be traced in Windows and Wazuh |
| System time | Allows ingestion and detection latency to be calculated |

### Kerberos Encryption Values

| Windows Value | Kerberos Etype | Meaning |
|---|---:|---|
| `0x17` | 23 | RC4-HMAC |
| `0x11` | 17 | AES128-CTS-HMAC-SHA1-96 |
| `0x12` | 18 | AES256-CTS-HMAC-SHA1-96 |

The custom rule `100040` focuses on:

```text
ticketEncryptionType = 0x17
```

This identifies RC4-HMAC service tickets.

RC4 is relevant because it is a legacy encryption type and generally provides a more efficient target for offline password testing than AES-based Kerberos formats.

AES increases the computational cost, but it does not make a weak password safe.

### Client Address Representation

Windows may represent an IPv4 client address in normal form:

```text
192.168.56.40
```

or as an IPv4-mapped IPv6 value:

```text
::ffff:192.168.56.40
```

Detection rules and analyst searches must account for both representations.

---

## 6. Directory Service Access for DCSync Visibility

The Pass-the-Hash / DCSync scenario relies on Event ID `4662`.

Enable Directory Service Access auditing on `DC01`:

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

Verify it:

```powershell
auditpol /get /subcategory:"Directory Service Access"
```

Enabling the audit subcategory alone may not be sufficient.

Windows generates Event ID `4662` only when the relevant Active Directory object also has an appropriate auditing entry in its System Access Control List.

The project uses Event ID `4662` to identify replication-related permissions associated with DCSync-like activity.

Relevant values include:

```text
AccessMask = 0x100
```

and replication-related GUIDs such as:

```text
1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
89e95b76-444d-4c62-991a-0facbeda640c
```

---

## 7. Remote Administration Support on DC01

The SMB/PsExec-like and Pass-the-Hash scenarios require remote administrative behavior against `DC01`.

On `DC01`, enable the following firewall rule groups when required:

```powershell
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=Yes
```

These rules allow the laboratory to generate the remote activity required for SMB, WMI and PsExec-like behavior.

The Kerberoasting scenario additionally requires network access to services used by Active Directory, including:

```text
TCP/UDP 88 — Kerberos
TCP/UDP 389 — LDAP
TCP 445 — SMB, depending on the tool and authentication flow
TCP 53 / UDP 53 — DNS when domain-name resolution is used
```

Only the services required by the isolated laboratory should be exposed.

---

## 8. Local Account Token Filter Policy

When local administrative accounts are used in a controlled laboratory, remote administration can be affected by User Account Control remote restrictions.

When necessary, the lab used:

```powershell
Set-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LocalAccountTokenFilterPolicy" `
    -Value 1 `
    -Type DWord
```

This setting should be treated carefully.

<details>
<summary>Production warning</summary>

This setting is useful in a controlled laboratory, but it should not be blindly applied in production.

Changing `LocalAccountTokenFilterPolicy` can increase exposure by allowing local administrator accounts to receive a full remote token.

In a real environment, this should be evaluated according to the hardening policy, administrative model and compensating controls.
</details>

This configuration is not required for the main Kerberoasting ticket-request detection.

---

## 9. Wazuh Event-Channel Collection

The Wazuh agent must collect the Windows Security channel.

The agent configuration should contain an entry equivalent to:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

This channel provides the principal events used by the project:

```text
4624
4625
4662
4672
4688
4769
5145
```

The Windows `System` channel is also required for Service Control Manager events such as `7045`.

Example:

```xml
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
</localfile>
```

For optional Sysmon telemetry, the agent must collect:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## 10. Optional Sysmon Network Telemetry

Hypothesis H10 and rule `100042` depend on Sysmon Event ID `3`.

Sysmon network-connection logging must be enabled for this event to exist.

The supporting Kerberoasting rule looks for:

```text
source host = WS01
destination IP = 192.168.56.20
destination port = 88
process image is not lsass.exe
```

This telemetry can add process-level context when Kerberos activity originates from a monitored Windows workstation.

It is not required for the principal Kali-based Kerberoasting validation.

The main validated chain is based on:

```text
Event ID 4769
        ↓
rule 100040
        ↓
rule 100041
```

A process that triggers Kerberos activity may also communicate through LSASS.

In that case, Sysmon can show:

```text
C:\Windows\System32\lsass.exe
```

even when another application initiated the ticket request.

For this reason, rule `100042` is complementary and environment-dependent.

---

## 11. Restarting the Wazuh Agent

After changing telemetry configuration, restart the Wazuh agent:

```powershell
Restart-Service WazuhSvc
```

Verify its state:

```powershell
Get-Service WazuhSvc |
    Format-Table Name,Status,StartType
```

Expected status:

```text
Running
```

---

## 12. Validation Commands

Use these commands to verify the audit policy:

```powershell
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Special Logon"
auditpol /get /subcategory:"Process Creation"
auditpol /get /subcategory:"File Share"
auditpol /get /subcategory:"Detailed File Share"
auditpol /get /subcategory:"Directory Service Access"
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

Check recent Security events:

```powershell
Get-WinEvent -LogName Security -MaxEvents 20
```

For process creation events:

```powershell
Get-WinEvent `
    -FilterHashtable @{
        LogName = 'Security'
        Id = 4688
    } `
    -MaxEvents 5
```

For detailed file-share events:

```powershell
Get-WinEvent `
    -FilterHashtable @{
        LogName = 'Security'
        Id = 5145
    } `
    -MaxEvents 5
```

For DCSync-related events:

```powershell
Get-WinEvent `
    -FilterHashtable @{
        LogName = 'Security'
        Id = 4662
    } `
    -MaxEvents 5
```

For Kerberos service-ticket requests:

```powershell
Get-WinEvent `
    -FilterHashtable @{
        LogName = 'Security'
        Id = 4769
        StartTime = (Get-Date).AddMinutes(-30)
    } |
Select-Object `
    TimeCreated,
    RecordId,
    Message |
Format-List
```

To filter the controlled Kerberoasting scenario without exposing credentials:

```powershell
Get-WinEvent `
    -FilterHashtable @{
        LogName = 'Security'
        Id = 4769
        StartTime = (Get-Date).AddMinutes(-30)
    } |
Where-Object {
    $_.Message -match '<SERVICE_ACCOUNT>|192\.168\.56\.40'
} |
Select-Object `
    TimeCreated,
    RecordId,
    Message |
Format-List
```

Replace `<SERVICE_ACCOUNT>` locally before running the command.

Do not publish the private account password or the complete exported Kerberos ticket.

---

## 13. Detection Dependency Matrix

| Detection Hypothesis | Required Audit Configuration | Main Event |
|---|---|---|
| H1 — RDP access from known attacker origin | `Logon` | `4624` |
| H2 — Post-access command execution after RDP | `Process Creation` + command-line logging | `4688` |
| H3 — SMB authentication from Kali to DC01 | `Logon` | `4624` |
| H4 — Administrative share access | `Detailed File Share` | `5145` |
| H5 — SMB + remote service execution | Service Control Manager logging + process visibility | `7045`, `4688` |
| H6 — NTLM privileged access | `Logon` + `Special Logon` | `4624`, `4672` |
| H7 — Pass-the-Hash + DCSync correlation | `Directory Service Access` + appropriate AD SACL + `Special Logon` | `4662`, `4672` |
| H8 — RC4 service-ticket request from unexpected source | `Kerberos Service Ticket Operations` | `4769` |
| H9 — Repeated suspicious RC4 ticket requests | `Kerberos Service Ticket Operations` + Wazuh frequency correlation | `4769`, rules `100040` and `100041` |
| H10 — Unusual process connecting to Kerberos | Sysmon network connections + Sysmon channel collection | Sysmon Event ID `3` |

---

## 14. Scenario Telemetry Summary

### RDP

```text
4624
   ↓
4688
   ↓
RDP access and post-access process activity
```

### SMB / PsExec-like

```text
4624
   ↓
4672
   ↓
5145
   ↓
7045
   ↓
4688
```

### Pass-the-Hash / DCSync

```text
4662
   ↓
4624 / 4672
   ↓
correlation
```

### Kerberoasting

```text
4769
   ↓
ticketEncryptionType = 0x17
   ↓
unexpected source
   ↓
100040
   ↓
three matching requests
   ↓
100041
```

Optional endpoint context:

```text
Sysmon Event ID 3
        ↓
connection to DC01:88
        ↓
process other than lsass.exe
        ↓
100042
```

---

## 15. Detection Limitations

Enabling an audit category does not automatically make a detection conclusive.

Examples:

- Event ID `4624` does not prove lateral movement.
- Event ID `4672` does not prove malicious privilege use.
- Event ID `5145` does not prove administrative-share abuse.
- Event ID `7045` does not prove PsExec.
- Event ID `4662` requires interpretation of the requested rights and account context.
- Event ID `4769` does not prove Kerberoasting.
- Sysmon Event ID `3` does not prove malicious network activity.

The analyst must combine:

```text
event
+
field values
+
source and destination
+
identity
+
timing
+
related alerts
+
environment baseline
```

For Kerberoasting, Wazuh can observe the service-ticket request.

It cannot directly observe each offline password candidate tested after the ticket has been exported.

---

## 16. Key Takeaway

A SIEM does not create telemetry by itself.

Wazuh can only normalize, correlate and alert on events that Windows and Sysmon actually generate and forward.

The audit policy is therefore not a secondary configuration step. It is a prerequisite for the detection logic.

The Kerberoasting extension reinforces the same principle:

```text
no Event ID 4769
        ↓
no visibility into the TGS request
        ↓
rules 100040 and 100041 cannot operate
```

Correct telemetry configuration is the foundation of every detection in the repository.
