# Custom Wazuh Rules

This document explains the custom Wazuh rules developed for the lateral movement detection laboratory.

The rules are designed to enrich native Wazuh detections with project-specific context, MITRE ATT&CK mapping and correlation logic. They focus on three controlled laboratory scenarios:

* RDP-based lateral movement.
* SMB / PsExec-like remote execution.
* Pass-the-Hash activity with DCSync-related evidence.

The full XML rule file is available at:

```text
wazuh/rules/local_rules.xml
```

---

## Rule 100001 — RDP Session Context

Rule `100001` contextualizes RDP activity associated with the observed laboratory user.

The initial RDP access is covered by the native Wazuh rule `92653`. Rule `100001` extends this detection chain by filtering the authenticated user involved in the RDP session. The `if_sid` dependency ensures that this rule only fires when the native RDP-related rule has already matched.

This rule is mapped to MITRE ATT&CK technique `T1021.001 — Remote Services: Remote Desktop Protocol`.

### Detection value

This rule helps isolate RDP activity that belongs to the controlled lateral movement scenario and separates it from generic RDP-related noise.

### Main fields

| Field                          | Purpose                                    |
| ------------------------------ | ------------------------------------------ |
| `if_sid`                       | Requires native rule `92653` to have fired |
| `win.eventdata.targetUserName` | Filters the observed laboratory user       |
| `mitre.id`                     | Maps the alert to `T1021.001`              |

### Notes

In the public repository, the real username is replaced with `standard_user`. In a private deployment, this value should be replaced with the actual laboratory account.

---

## Rule 100010 — Remote Service Creation Compatible with PsExec-like Activity

Rule `100010` detects remote service creation compatible with PsExec-like or smbexec-style activity.

It builds on the native Wazuh rule `61138`, associated with Windows Event ID `7045`, and adds additional filters to ensure that the event comes from the Service Control Manager and that the service is executed as `LocalSystem`.

Although native rules such as `92307` and `92650` may also detect suspicious payload patterns, rule `100010` explicitly tags the event as part of the TFM lateral movement detection chain.

This rule is mapped to:

* `T1021.002 — Remote Services: SMB/Windows Admin Shares`
* `T1569.002 — System Services: Service Execution`

### Detection value

Remote service creation is one of the strongest indicators in the SMB/PsExec-like scenario because it reflects a concrete execution mechanism on the target system.

### Main fields

| Field                       | Purpose                             |
| --------------------------- | ----------------------------------- |
| `if_sid`                    | Requires native rule `61138`        |
| `win.system.eventID`        | Confirms Event ID `7045`            |
| `win.system.providerName`   | Confirms Service Control Manager    |
| `win.eventdata.accountName` | Confirms execution as `LocalSystem` |

---

## Rule 100011 — NTLM Network Logon Shared Indicator

Rule `100011` detects network authentication through NTLM by observing Windows Event ID `4624` with Logon Type `3` and authentication package `NTLM`.

This rule is a shared indicator. It may fire in both the SMB/PsExec-like scenario and the Pass-the-Hash scenario. By itself, it does not distinguish between those two techniques. Its value is that it opens the correlation chain and provides an early signal of NTLM-based remote access.

This rule is mapped to:

* `T1021.002 — Remote Services: SMB/Windows Admin Shares`
* `T1550.002 — Use Alternate Authentication Material: Pass the Hash`

### Detection value

NTLM network authentication is not necessarily malicious. However, when combined with privileged access, administrative share access, service creation or DCSync-like activity, it becomes a relevant lateral movement signal.

### Main fields

| Field                                     | Purpose                                                      |
| ----------------------------------------- | ------------------------------------------------------------ |
| `if_sid`                                  | Requires native rule `92652`                                 |
| `win.eventdata.authenticationPackageName` | Confirms NTLM authentication                                 |
| `mitre.id`                                | Maps the event to SMB/PsExec-like and Pass-the-Hash contexts |

---

## Rule 100021 — Special Privileges Assigned to a Remote Privileged Session

Rule `100021` detects Windows Event ID `4672` when special privileges are assigned to a non-system account.

The rule excludes common internal Windows accounts such as `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE` and machine accounts ending in `$`. This reduces noise and keeps visible the assignment of privileges to real user accounts.

This rule acts as a shared indicator between the SMB/PsExec-like and Pass-the-Hash scenarios. It also works as a parent signal for rule `100033`.

This rule is mapped to:

* `T1078 — Valid Accounts`
* `T1550.002 — Pass the Hash`

### Detection value

Special privileges alone do not prove malicious activity. However, when a privileged session appears close in time to NTLM network authentication, remote service creation or DCSync-like activity, it becomes a strong supporting signal.

### Main fields

| Field                           | Purpose                                           |
| ------------------------------- | ------------------------------------------------- |
| `if_sid`                        | Requires native rule `67028`                      |
| `win.eventdata.subjectUserName` | Excludes system and machine accounts              |
| `mitre.id`                      | Maps the event to credential-based access context |

---

## Rule 100022 — Defender Disabled Followed by Privileged Access

Rule `100022` correlates Windows Defender being disabled with a later privileged session within a 300-second window.

This is not a universal Pass-the-Hash detection. It is a controlled laboratory chain that represents a specific preparation sequence: reduction of endpoint protection followed by administrative access.

This rule is mapped to:

* `T1550.002 — Pass the Hash`
* `T1562.001 — Impair Defenses: Disable or Modify Tools`

### Detection value

This rule is useful for documenting the controlled attack chain in the laboratory. In a production environment, this logic would require additional tuning to avoid false positives caused by legitimate administrative actions.

### Main fields

| Field            | Purpose                                         |
| ---------------- | ----------------------------------------------- |
| `if_matched_sid` | Requires previous Defender-related rule `92008` |
| `if_sid`         | Requires privileged access rule `100021`        |
| `timeframe`      | Correlates both signals within 300 seconds      |

---

## Rule 100030 — DCSync / secretsdump-like Activity

Rule `100030` detects behavior compatible with DCSync or secretsdump-style activity by observing the use of Active Directory replication rights by a non-machine account.

The rule is based on Windows Event ID `4662`, filtering for `accessMask` value `0x100` and replication-related GUIDs associated with directory replication permissions.

The rule excludes machine accounts ending in `$`, since these accounts may legitimately request replication rights during normal domain controller replication.

This rule is mapped to:

* `T1003.006 — OS Credential Dumping: DCSync`

### Detection value

This is one of the strongest detections in the project because DCSync-like behavior is closely related to credential access against Active Directory. When this signal is later correlated with privileged NTLM access, the confidence level increases significantly.

### Main fields

| Field                           | Purpose                                |
| ------------------------------- | -------------------------------------- |
| `if_sid`                        | Requires native rule `60103`           |
| `win.system.eventID`            | Confirms Event ID `4662`               |
| `win.eventdata.accessMask`      | Filters Control Access events          |
| `win.eventdata.properties`      | Searches for replication-related GUIDs |
| `win.eventdata.subjectUserName` | Excludes machine accounts              |

---

## Rule 100033 — Critical Pass-the-Hash Correlation

Rule `100033` correlates two high-value signals within a 300-second window:

1. DCSync/secretsdump-like activity detected by rule `100030`.
2. Special privileges assigned to a non-system account detected by rule `100021`.

The `if_matched_sid` condition requires rule `100030` to have fired previously, while `if_sid` requires the current event to match rule `100021`.

This rule is the strongest Pass-the-Hash-related correlation in the laboratory because it connects credential access evidence with privileged NTLM-based lateral movement.

This rule is mapped to:

* `T1550.002 — Pass the Hash`
* `T1003.006 — DCSync`

### Detection value

This rule provides a high-confidence alert in the controlled laboratory scenario. It does not observe the NTLM hash directly, but it correlates the observable effects of the attack chain from Wazuh telemetry.

### Main fields

| Field            | Purpose                                      |
| ---------------- | -------------------------------------------- |
| `if_matched_sid` | Requires previous DCSync-like alert `100030` |
| `if_sid`         | Requires privileged session alert `100021`   |
| `timeframe`      | Correlates both signals within 300 seconds   |
| `level`          | Raises the alert to critical severity        |

---

## Summary Matrix

|  Rule ID | Main Purpose                           | Technique Mapping        | Scenario                 |
| -------: | -------------------------------------- | ------------------------ | ------------------------ |
| `100001` | RDP session context                    | `T1021.001`              | RDP                      |
| `100010` | Remote service creation                | `T1021.002`, `T1569.002` | SMB / PsExec-like        |
| `100011` | NTLM network logon                     | `T1021.002`, `T1550.002` | SMB / PtH                |
| `100021` | Privileged user session                | `T1078`, `T1550.002`     | SMB / PtH                |
| `100022` | Defender disabled + privileged access  | `T1550.002`, `T1562.001` | Controlled PtH chain     |
| `100030` | DCSync-like activity                   | `T1003.006`              | Pass-the-Hash / DCSync   |
| `100033` | DCSync + privileged access correlation | `T1550.002`, `T1003.006` | Critical PtH correlation |
