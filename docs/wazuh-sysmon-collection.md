# Wazuh Sysmon Collection

This document explains how the Windows Wazuh agent was configured to collect Sysmon events from the `Microsoft-Windows-Sysmon/Operational` channel.

## 1. Purpose

Installing Sysmon is not enough.

Sysmon writes events to a specific Windows Event Channel. Wazuh must be explicitly configured to read that channel.

The relevant channel is:

```text
Microsoft-Windows-Sysmon/Operational
```

## 2. Wazuh Agent Configuration

On the Windows agent, edit:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Add the following block:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## 3. Why This Channel?

Sysmon does not write its main telemetry to the standard `Security` log.

It writes to:

```text
Microsoft-Windows-Sysmon/Operational
```

That is why Wazuh must be pointed to that exact channel.

| Field | Value |
|---|---|
| `location` | `Microsoft-Windows-Sysmon/Operational` |
| `log_format` | `eventchannel` |
| Host scope | Windows agents where Sysmon is installed |
| Detection value | Process and endpoint telemetry |

<details>
<summary>Explanation: why not use only the Security channel?</summary>

The Windows Security channel contains events such as `4624`, `4672`, `4688` and `5145`.

Sysmon events are stored in a different channel. If Wazuh only collects the Security channel, Sysmon may be correctly installed but invisible to Wazuh.

This distinction matters because a SIEM can only alert on telemetry that it actually receives.
</details>

## 4. Validate XML Before Restarting

Before restarting the agent, validate the XML structure:

```powershell
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
[xml]$xml = Get-Content $conf -Raw
```

If PowerShell returns no XML parsing error, the file is structurally valid.

## 5. Restart Wazuh Agent

```powershell
Restart-Service WazuhSvc
```

## 6. Local Windows Validation

Check whether Sysmon has recent events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

## 7. Wazuh Validation

In Wazuh Discover or Security Events, search for:

```kql
data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

Alternative query:

```kql
agent.name:WS01 AND data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

or:

```kql
agent.name:DC01 AND data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

## 8. Troubleshooting

| Problem | Likely Cause | Check |
|---|---|---|
| Sysmon events exist locally but not in Wazuh | `ossec.conf` does not include the Sysmon channel | Review `<localfile>` block |
| Wazuh agent fails to start | XML syntax error | Validate with `[xml]$xml = Get-Content $conf -Raw` |
| No Sysmon events locally | Sysmon not installed or not running | `Get-Service Sysmon*` |
| Events appear from one host but not another | Agent configuration differs between hosts | Compare `ossec.conf` on DC01 and WS01 |

## 9. Scenario Scope

Sysmon collection is complementary and is not required equally by every scenario.

| Scenario | Sysmon Dependency |
|---|---|
| RDP | Useful for process context |
| SMB / PsExec-like | Useful for process context |
| Pass-the-Hash / DCSync | Supporting telemetry only |
| Kerberoasting | Optional for rule `100042` |
| AS-REP Roasting | Not required by the validated `4768` detection chain |

The AS-REP Roasting rules operate on the Windows Security channel:

```text
Security → Event ID 4768 → rules 100050, 100051 and 100052
```

They do not depend on `Microsoft-Windows-Sysmon/Operational`.

## 10. Key Takeaway

Sysmon collection requires three things:

1. Sysmon installed.
2. Sysmon generating events locally.
3. Wazuh agent configured to collect `Microsoft-Windows-Sysmon/Operational`.

If any of these three steps is missing, Sysmon telemetry will not be available for detection or analysis in Wazuh.
