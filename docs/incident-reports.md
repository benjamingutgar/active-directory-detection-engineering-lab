# Incident Reports

This document converts the laboratory detections into incident-style reports.

The goal is to make the Wazuh alerts useful for defensive response. Each report explains:

- what was detected,
- which asset was affected,
- what weakness was abused,
- what evidence supports the interpretation,
- what response actions should be prioritized,
- what limitations must be considered.

The scenarios do not exploit a classic CVE. They abuse legitimate Windows mechanisms such as RDP, SMB, NTLM, administrative shares, privileged accounts and remote service creation.

## 1. Severity Criteria

The severity assessment considers:

| Criterion | Impact |
|---|---|
| Affected asset | Activity on `DC01` is more critical than activity on `WS01` |
| Privilege level | Administrative accounts increase severity |
| MITRE ATT&CK technique | Lateral Movement and Credential Access increase severity |
| Remote execution | Service creation or execution under `LocalSystem` increases severity |
| Temporal correlation | Several related signals in the same timeframe reduce ambiguity |
| False-positive possibility | Legitimate administration requires contextual review |

## 2. Report — RDP Lateral Movement

| Field | Value |
|---|---|
| MITRE Tactic | Lateral Movement |
| Technique | `T1021.001 — Remote Services: Remote Desktop Protocol` |
| Affected System | `WS01` |
| Source | `Kali-ATK01 / 192.168.56.40` |
| User | `LAB\<standard_user>` |
| Severity | High |
| Main Rules | `92653`, `100001`, `67027`, `92052` |
| Main Events | `4624`, `4688`, optional Sysmon Event ID `1` |

### Weakness Abused

The scenario abuses the availability of RDP, valid domain credentials and remote logon permissions on the target workstation.

The weakness is not a software vulnerability. It is the combination of:

```text
RDP enabled + valid account + remote logon rights + insufficient contextual restriction
```

### Main Evidence

The main evidence is a remote RDP-related authentication from the attacker IP to `WS01`, followed by command execution inside the remote session.

Observed evidence includes:

- source IP `192.168.56.40`,
- target host `WS01`,
- domain user authentication,
- RDP-related logon context,
- post-access commands,
- process creation events.

### Potential Impact

A successful RDP session may allow an attacker to:

- interactively access the workstation,
- run reconnaissance commands,
- inspect local configuration,
- prepare lateral movement,
- access resources available to the authenticated user,
- use the endpoint as a pivot point.

### Defensive Response

Recommended response actions:

1. Confirm whether the RDP access was authorized.
2. Identify the source IP and whether it belongs to an approved administrative origin.
3. Review the authenticated user.
4. Review commands executed after login.
5. Check for persistence or configuration changes.
6. Isolate `WS01` if the session was unauthorized.
7. Reset or rotate the affected account credentials if compromise is suspected.

### Future Mitigation

Recommended mitigation actions:

- restrict RDP to approved administrative hosts,
- limit membership of Remote Desktop Users,
- enforce MFA where possible,
- monitor RDP from unusual sources,
- baseline normal RDP administration,
- audit command execution after remote logon,
- consider jump-server based administration.

### Attribution Limitation

RDP is a legitimate protocol. The alert should not be interpreted in isolation.

The attribution becomes stronger when the analyst correlates:

```text
source IP + user + target host + time + post-access activity
```

## 3. Report — SMB / PsExec-like Remote Execution

| Field | Value |
|---|---|
| MITRE Tactic | Lateral Movement / Execution |
| Technique | `T1021.002 — SMB/Windows Admin Shares`, `T1569.002 — Service Execution` |
| Affected System | `DC01` |
| Source | `Kali-ATK01 / 192.168.56.40` |
| User | `LAB\<privileged_user>` |
| Severity | High / Critical |
| Main Rules | `100011`, `100010`, `100021`, `92218`, `92307`, `92650`, `92052` |
| Main Events | `4624`, `4672`, `5145`, `7045`, `4688` |

### Weakness Abused

The scenario abuses SMB availability, valid administrative credentials, administrative shares and the ability to remotely create services through the Service Control Manager.

The weakness is the combination of:

```text
SMB exposed + privileged account + ADMIN$/IPC$ access + remote service creation
```

### Main Evidence

Observed evidence includes:

- NTLM network authentication from `192.168.56.40`,
- Logon Type `3`,
- special privileges assigned to the session,
- access to administrative shares,
- Service Control Manager activity,
- creation of a new service,
- process execution after remote service creation.

### Potential Impact

A successful SMB/PsExec-like chain may allow an attacker to:

- execute commands remotely on `DC01`,
- abuse legitimate administration mechanisms,
- run code under a privileged context,
- create temporary services,
- expand control over the Active Directory environment,
- prepare credential access or further lateral movement.

### Defensive Response

Recommended response actions:

1. Review the service created on `DC01`.
2. Inspect the service `ImagePath`.
3. Determine whether the service name is random, tool-generated or known.
4. Check administrative share access, especially `ADMIN$`, `C$` and `IPC$`.
5. Identify the account used.
6. Review whether the account should have administrative rights on `DC01`.
7. Search for process execution after the service creation.
8. Contain the source host if unauthorized.
9. Rotate credentials if account compromise is suspected.

### Future Mitigation

Recommended mitigation actions:

- apply tiered administration,
- restrict SMB access between segments,
- limit administrative share usage,
- monitor remote service creation,
- prevent workstation-originated administration of domain controllers,
- reduce local administrator reuse,
- enforce privileged access workstations for domain administration.

### Attribution Limitation

SMB, administrative shares and service creation can be legitimate in Windows administration.

The attribution becomes stronger because the scenario correlates:

```text
NTLM network logon + privileged session + admin share access + service creation + process execution
```

A single SMB logon alone should not be treated as proof of malicious activity.

## 4. Report — Pass-the-Hash / DCSync Correlation

| Field | Value |
|---|---|
| MITRE Tactic | Lateral Movement / Credential Access |
| Technique | `T1550.002 — Pass the Hash`, related `T1003.006 — DCSync` |
| Affected System | `DC01` |
| Source | `Kali-ATK01 / 192.168.56.40` |
| User | `LAB\<privileged_user>` |
| Severity | Critical |
| Main Rules | `100030`, `100021`, `100033`, `100011`, `92650`, `92052` |
| Main Events | `4662`, `4624`, `4672`, `5145`, `7045`, `4688` |

### Weakness Abused

The scenario abuses reusable NTLM authentication material, NTLM availability, privileged access and the exposure of the domain controller to privileged remote authentication.

The weakness is the combination of:

```text
NTLM enabled + privileged account + hash reuse + domain controller exposure + replication rights
```

### Main Evidence

Observed evidence includes:

- DCSync-like activity detected through Event ID `4662`,
- use of replication-related permissions by a non-machine account,
- NTLM network authentication,
- privileged session creation,
- correlation through rule `100033`,
- additional remote activity against `DC01`.

### Potential Impact

A successful Pass-the-Hash / DCSync-related chain may allow an attacker to:

- authenticate without knowing the plaintext password,
- reuse administrative NTLM material,
- access the domain controller,
- extract or attempt to extract credential material,
- compromise additional accounts,
- expand lateral movement across Active Directory.

### Defensive Response

Recommended response actions:

1. Isolate or investigate the source host.
2. Review directory replication events.
3. Identify the account that requested replication-related permissions.
4. Rotate privileged credentials.
5. Check whether the account was used on other systems.
6. Search for NTLM logons from the same source.
7. Review remote service creation and command execution around the same timeframe.
8. Investigate whether credential dumping occurred.

### Future Mitigation

Recommended mitigation actions:

- reduce dependency on NTLM,
- restrict privileged account usage,
- apply tiered administration,
- protect domain administrator accounts,
- audit replication permissions,
- restrict remote access to domain controllers,
- monitor DCSync-like activity,
- use privileged access workstations,
- avoid using domain administrator accounts on lower-trust systems.

### Attribution Limitation

Wazuh does not directly observe the NTLM hash.

The attribution to Pass-the-Hash is built from correlation between:

```text
credential access evidence + NTLM privileged authentication + remote activity
```

This means the alert should be described as:

```text
behavior compatible with Pass-the-Hash
```

rather than:

```text
direct proof that a hash was used
```

## 5. Report Summary

| Scenario | Affected Host | Severity | Strongest Evidence | Main Limitation |
|---|---|---|---|---|
| RDP | `WS01` | High | RDP access followed by process execution | RDP can be legitimate |
| SMB / PsExec-like | `DC01` | High / Critical | NTLM, privileges, admin shares, service creation | Remote administration can be legitimate |
| Pass-the-Hash / DCSync | `DC01` | Critical | DCSync-like activity correlated with privileged NTLM access | Wazuh does not observe the hash directly |

## 6. Key Takeaway

The incident reports transform raw alerts into response-oriented information.

The strongest reports are not based on a single event. They combine:

```text
asset criticality + source + account + privileges + telemetry chain + MITRE mapping + known limitations
```
