# Project Summary

This project presents the design and implementation of a SIEM laboratory using Wazuh to detect lateral movement and credential-access techniques in a Windows Active Directory environment.

The laboratory was built on a single physical host using several virtual machines. Its purpose is to create a controlled, reproducible and defensive environment in which Windows telemetry can be collected, analyzed and correlated.

The project combines:

- Windows Event Logs;
- Sysmon telemetry;
- Wazuh agents and manager;
- custom Wazuh detection rules;
- temporal and frequency correlation;
- MITRE ATT&CK mapping;
- sanitized technical evidence;
- analyst-oriented documentation;
- false-positive and detection-limit analysis.

---

## Laboratory Components

| System | Role | IP Address |
|---|---|---:|
| `Wazuh-Manager` | Central SIEM, indexer and dashboard | `192.168.56.10` |
| `DC01` | Active Directory Domain Controller, DNS and Kerberos KDC | `192.168.56.20` |
| `WS01` | Domain-joined Windows workstation | `192.168.56.30` |
| `Kali-ATK01` | Controlled attack-simulation host | `192.168.56.40` |

The main laboratory network uses the range:

```text
192.168.56.0/24
```

These addresses belong to an isolated virtual network.

Passwords, complete Kerberos tickets, reusable hashes, Wazuh agent keys and other private credentials are excluded from the public repository.

---

## Detection Scenarios

The project covers five controlled scenarios.

### 1. RDP Lateral Movement

MITRE ATT&CK technique:

```text
T1021.001 — Remote Services: Remote Desktop Protocol
```

The scenario reproduces remote interactive access from `Kali-ATK01` to `WS01`.

The main observable chain is:

```text
RDP authentication
        ↓
Windows Event ID 4624
        ↓
post-access process creation
        ↓
Windows Event ID 4688
```

Detection hypotheses:

```text
H1 — RDP access from the controlled attacker host
H2 — post-access command execution after the RDP session
```

Main rules:

```text
92653
100001
67027
92052
```

Full write-up:

- [`../detections/T1021.001-rdp.md`](../detections/T1021.001-rdp.md)

---

### 2. SMB / PsExec-Like Remote Execution

MITRE ATT&CK techniques:

```text
T1021.002 — Remote Services: SMB/Windows Admin Shares
T1569.002 — System Services: Service Execution
```

The scenario reproduces remote execution against `DC01` using NTLM authentication, administrative shares and the Windows Service Control Manager.

The main observable chain is:

```text
NTLM network authentication
        ↓
special privileges
        ↓
administrative-share access
        ↓
remote service creation
        ↓
process execution
```

Detection hypotheses:

```text
H3 — NTLM network authentication from Kali to DC01
H4 — access to administrative shares
H5 — remote service creation compatible with PsExec-like execution
```

Main events:

```text
4624
4672
5145
7045
4688
```

Main rules:

```text
100011
100021
92218
100010
92307
92650
92052
```

Full write-up:

- [`../detections/T1021.002-smb-psexec-like.md`](../detections/T1021.002-smb-psexec-like.md)

---

### 3. Pass-the-Hash / DCSync

MITRE ATT&CK techniques:

```text
T1550.002 — Use Alternate Authentication Material: Pass the Hash
T1003.006 — OS Credential Dumping: DCSync
```

The scenario reproduces a controlled chain involving NTLM authentication, privileged access and DCSync-related activity.

The main observable chain is:

```text
DCSync-like activity
        ↓
privileged NTLM network authentication
        ↓
remote administrative activity
        ↓
critical Wazuh correlation
```

Detection hypotheses:

```text
H6 — privileged NTLM authentication compatible with credential reuse
H7 — DCSync-like activity correlated with privileged access
```

Main events:

```text
4662
4624
4672
5145
7045
4688
```

Main rules:

```text
100030
100011
100021
100033
92650
92052
```

Wazuh does not directly observe the NTLM hash.

It observes authentication, privileges, directory-replication activity and remote behavior that are compatible with the controlled Pass-the-Hash scenario.

Full write-up:

- [`../detections/T1550.002-pass-the-hash.md`](../detections/T1550.002-pass-the-hash.md)

---

### 4. Kerberoasting

MITRE ATT&CK technique:

```text
T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
```

The Kerberoasting scenario extends the original lateral-movement laboratory with credential-access detection.

A controlled non-privileged service account is associated with a Service Principal Name. A valid domain user requests a Kerberos service ticket for that account.

The main observable chain is:

```text
service account associated with an SPN
        ↓
Kerberos TGS request
        ↓
Windows Security Event ID 4769
        ↓
RC4-HMAC ticket encryption
        ↓
request from an unexpected source
        ↓
rule 100040
        ↓
three matching requests from the same source
        ↓
rule 100041
```

Detection hypotheses:

```text
H8 — RC4 Kerberos service ticket from an unexpected source
H9 — repeated RC4 service-ticket requests from the same source
H10 — optional unusual process connection to the Kerberos service
```

Main telemetry:

```text
Windows Security Event ID 4769
optional Sysmon Event ID 3
```

Main custom rules:

```text
100040
100041
100042
```

The principal validated detection chain is:

```text
4769
    ↓
100040
    ↓
100041
```

Rule `100042` provides optional endpoint context when Kerberos activity originates from a monitored Windows workstation.

Wazuh observes the Kerberos service-ticket request, encryption type, source and frequency.

It does not directly observe every password candidate tested offline after the ticket has been exported.

Full write-up:

- [`../detections/T1558.003-kerberoasting.md`](../detections/T1558.003-kerberoasting.md)

---

### 5. AS-REP Roasting

Technique:

```text
T1558.004 — AS-REP Roasting
```

The scenario validates whether Wazuh can detect a successful Kerberos TGT request for an account that does not require pre-authentication.

Main telemetry:

```text
Windows Security Event ID 4768
```

Relevant observed fields:

```text
targetUserName = svc_asrep_lab
serviceName = krbtgt
preAuthType = 0
status = 0x0
ticketEncryptionType = 0x17
ipAddress = ::ffff:192.168.56.40
```

Detection chain:

```text
4768
  ↓
100050
  ↓
100051
  ↓
100052
```

Direct alert evidence exists for all three custom rules. The evidence was collected across 18 and 28 August 2026 rather than one single continuous run.

Wazuh observes the Kerberos request and correlation context. It does not observe or prove successful offline password recovery.

Full write-up:

- [`../detections/T1558.004-as-rep-roasting.md`](../detections/T1558.004-as-rep-roasting.md)

---

## Detection Hypotheses

The project is organized around thirteen detection hypotheses.

| Hypothesis | Scenario | Main Purpose |
|---|---|---|
| `H1` | RDP | Detect RDP access from the controlled attacker host |
| `H2` | RDP | Detect post-access process execution |
| `H3` | SMB / PsExec-like | Detect NTLM network authentication to `DC01` |
| `H4` | SMB / PsExec-like | Detect administrative-share access |
| `H5` | SMB / PsExec-like | Detect remote service creation |
| `H6` | Pass-the-Hash | Detect privileged NTLM authentication compatible with credential reuse |
| `H7` | Pass-the-Hash / DCSync | Correlate DCSync-like activity with privileged access |
| `H8` | Kerberoasting | Detect an RC4 service-ticket request from an unexpected source |
| `H9` | Kerberoasting | Correlate repeated suspicious RC4 ticket requests |
| `H10` | Kerberoasting | Add optional process-level Kerberos context |
| `H11` | AS-REP Roasting | Detect a successful TGT request without Kerberos pre-authentication |
| `H12` | AS-REP Roasting | Add RC4-HMAC context to the no-pre-authentication request |
| `H13` | AS-REP Roasting | Correlate three qualifying requests from one source within 60 seconds |

Full hypothesis documentation:

- [`../detections/detection-hypotheses.md`](../detections/detection-hypotheses.md)
- [`../detections/detection-matrix.md`](../detections/detection-matrix.md)

---

## Main Telemetry

The project relies primarily on the following Windows events:

| Event ID | Purpose |
|---:|---|
| `4624` | Successful logon |
| `4625` | Failed logon |
| `4662` | Directory Service access and DCSync-related evidence |
| `4672` | Special privileges assigned to a new logon |
| `4688` | Process creation |
| `4768` | Kerberos authentication ticket or TGT request used by AS-REP Roasting detection |
| `4769` | Kerberos service-ticket request |
| `5145` | Detailed network-share access |
| `7045` | New Windows service installed |

Complementary Sysmon telemetry includes:

| Sysmon Event ID | Purpose |
|---:|---|
| `1` | Detailed process creation |
| `3` | Network connection context |
| `10` | Process access telemetry |

Detection quality depends on correct Windows audit-policy configuration and Wazuh event-channel collection.

---

## Custom Wazuh Rules

The main custom rules are:

| Rule ID | Purpose |
|---:|---|
| `100001` | RDP post-access context |
| `100010` | Remote service creation compatible with PsExec-like activity |
| `100011` | NTLM network authentication |
| `100021` | Special privileges assigned to a non-system account |
| `100022` | Defender disabled followed by privileged access |
| `100030` | DCSync-like activity |
| `100033` | DCSync and privileged-access correlation |
| `100040` | RC4 Kerberos service-ticket request from an unexpected source |
| `100041` | Three suspicious RC4 ticket requests from the same source |
| `100042` | Unusual process connecting to the Kerberos service |
| `100050` | Successful TGT request without Kerberos pre-authentication |
| `100051` | AS-REP request using RC4-HMAC |
| `100052` | Three qualifying AS-REP requests from one source in 60 seconds |

Rule files:

- [`../wazuh/rules/local_rules.xml`](../wazuh/rules/local_rules.xml)
- [`../wazuh/rules/rules-explanation.md`](../wazuh/rules/rules-explanation.md)

---

## Correlation Logic

The project contains three principal custom correlations.

### Pass-the-Hash / DCSync

```text
rule 100030
        ↓
privileged-access rule 100021
        ↓
rule 100033
```

Correlation window:

```text
300 seconds
```

### Kerberoasting

```text
rule 100040
        ↓
three matches from the same source
        ↓
rule 100041
```

Correlation parameters:

```text
frequency = 3
timeframe = 120 seconds
same_field = source IP address
```

---

### AS-REP Roasting

```text
successful Event ID 4768
        ↓
preAuthType = 0
        ↓
rule 100050
        ↓
ticketEncryptionType = 0x17
        ↓
rule 100051
        ↓
three qualifying requests from one source
        ↓
rule 100052
```

Correlation parameters:

```text
frequency = 3
timeframe = 60 seconds
same_field = source IP address
```

## Evidence Model

Each scenario includes defensive evidence such as:

- selected Wazuh JSON alerts;
- filtered CSV summaries;
- reconstructed timelines;
- Wazuh KQL filters;
- relevant Windows event fields;
- rule IDs and severity levels;
- MITRE ATT&CK mappings;
- false-positive and limitation analysis.

Evidence directories:

```text
evidence/rdp/
evidence/smb-psexec-like/
evidence/pass-the-hash/
evidence/kerberoasting/
evidence/as-rep-roasting/
```

Sensitive information is excluded from the public repository.

For Kerberoasting, this includes:

- service-account passwords;
- domain credentials;
- complete Kerberos tickets;
- complete `$krb5tgs$` strings;
- Hashcat potfiles;
- private wordlists;
- recovered passwords;
- reusable credential material.

For AS-REP Roasting, this additionally includes:

- complete `$krb5asrep$` output;
- passwords and recovered passwords;
- reusable Kerberos material;
- credential-output files;
- dictionaries and potfiles.

---

## Detection Philosophy

The project distinguishes between three analytical levels.

| Level | Meaning |
|---|---|
| Event | Raw telemetry generated by Windows or Sysmon |
| Alert | Wazuh output after applying a detection rule |
| Attribution | Analyst interpretation that maps evidence to MITRE ATT&CK |

This distinction prevents overclaiming.

For example:

```text
Event ID 4624 using NTLM
```

does not directly prove Pass-the-Hash.

Similarly:

```text
Event ID 4769 using RC4
```

does not directly prove successful Kerberoasting or password recovery.

Likewise:

```text
Event ID 4768 with preAuthType = 0
```

does not directly prove successful AS-REP password recovery.

The correct interpretation is:

```text
behavior compatible with the technique in the controlled laboratory context
```

---

## Main Results

The laboratory demonstrated that:

1. RDP access can be reconstructed through authentication and post-access process events.
2. SMB/PsExec-like execution can be identified through NTLM authentication, privileges, administrative shares and service creation.
3. Pass-the-Hash cannot be proven through a single NTLM event, but confidence increases through DCSync and privileged-access correlation.
4. Kerberoasting can be detected at the service-ticket request stage through Event ID `4769`, RC4 context, source analysis and frequency correlation.
5. AS-REP Roasting can be detected at the TGT-request stage through Event ID `4768`, pre-authentication type, result status, encryption context and source-frequency correlation.
6. Offline password testing or recovery remains outside the direct visibility of the Domain Controller for the Kerberoasting and AS-REP Roasting scenarios.
7. Detection quality depends on telemetry configuration, field parsing and correlation design.
8. Laboratory detections require baselining and tuning before production use.

---

## Limitations

The project was validated in a small controlled environment.

It does not reproduce:

- normal enterprise event volume;
- multiple Domain Controllers;
- large numbers of service accounts and SPNs;
- complex trust relationships;
- hybrid identity infrastructure;
- production endpoint-management platforms;
- long-term false-positive measurements;
- realistic administrative activity at scale;
- complete EDR telemetry.

The rules should therefore be considered:

```text
validated laboratory detections
```

not:

```text
production-ready detections without tuning
```

---

## Production Improvements

A production implementation should add:

- environment-specific allowlists;
- normal source and account baselines;
- service-account and SPN inventories;
- inventory of accounts without Kerberos pre-authentication;
- RC4 dependency analysis;
- distinct-SPN counting;
- privileged service-account prioritization;
- password-age monitoring;
- gMSA adoption;
- maintenance-window context;
- ticketing integration;
- analyst playbooks;
- false-positive tracking;
- long-term detection metrics.

---

## Defensive Value

The main value of the repository is not only the Wazuh rule XML.

It documents the relationship between:

```text
attack behavior
        ↓
required telemetry
        ↓
detection hypothesis
        ↓
Wazuh rule
        ↓
alert or correlation
        ↓
sanitized evidence
        ↓
analyst interpretation
        ↓
MITRE ATT&CK mapping
        ↓
limitations and tuning
```

This structure makes the repository useful as:

- a technical portfolio project;
- a reproducible Active Directory security laboratory;
- a Blue Team learning resource;
- an introductory detection-engineering project;
- a foundation for future Wazuh and SIEM detections.

---

## Final Conclusion

The project demonstrates that a lightweight local Wazuh deployment can provide useful visibility into controlled Active Directory attack behavior.

The five scenarios cover different detection challenges:

```text
RDP:
access and process activity are directly observable

SMB / PsExec-like:
authentication, shares, services and execution are observable

Pass-the-Hash:
the authentication material is hidden, but its surrounding effects can be correlated

Kerberoasting:
the ticket request is observable, while offline password testing remains outside SIEM visibility

AS-REP Roasting:
the no-pre-authentication TGT request is observable, while offline password recovery remains outside SIEM visibility
```

The principal lesson is that detection engineering requires more than generating alerts.

It requires understanding:

```text
what the event proves
what it does not prove
how it relates to other signals
how it maps to attacker behavior
how it should be investigated
how it must be tuned before production
```

That analytical discipline is the central result of the laboratory.
