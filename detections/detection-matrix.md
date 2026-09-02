# Detection Matrix

This matrix summarizes the relationship between the controlled Active Directory scenarios, telemetry prerequisites, Wazuh rules, evidence quality, false-positive risk and production readiness.

---

## 1. Main Detection Matrix

| Technique | Scenario | Main Events | Wazuh Rules | Prerequisite Telemetry | False-Positive Risk | Evidence Quality | Production Readiness |
|---|---|---|---|---|---|---|---|
| `T1021.001` | RDP lateral movement | `4624`, `4688`, `4634`, `4647`, optional Sysmon Event ID `1` | `92653`, `100001`, `92052`, `67027` | Logon auditing, process creation auditing and Wazuh agent on `WS01` | Medium | Medium / High | Needs tuning |
| `T1021.002`, `T1569.002` | SMB / PsExec-like execution | `4624`, `4672`, `5145`, `7045`, `4688` | `100011`, `100021`, `100010`, `92218`, `92307`, `92650`, `92052` | Logon, special logon, detailed file share, service and process telemetry on `DC01` | Medium / High | High | Needs tuning |
| `T1550.002`, `T1003.006` | Pass-the-Hash / DCSync | `4624`, `4672`, `4662`, `5145`, `7045`, `4688` | `100011`, `100021`, `100030`, `100033`, `92650`, `92052` | Logon auditing, Directory Service Access, suitable AD auditing and Wazuh agent on `DC01` | Medium | High correlated | Prototype / needs tuning |
| `T1558.003` | Kerberoasting | `4769`, optional Sysmon Event ID `3` | `100040`, `100041`, optional `100042` | Kerberos Service Ticket Operations auditing and Windows Security collection on `DC01` | Medium | High for the validated correlation | Prototype / needs tuning |
| `T1558.004` | AS-REP Roasting | `4768` | `100050`, `100051`, `100052` | Kerberos Authentication Service auditing and Windows Security collection on `DC01` | Medium | High for rule-ID validation; collected across two dates | Prototype / needs tuning |

---

## 2. Hypothesis Coverage

| Hypothesis | Technique | Scenario | Main Rules | Evidence |
|---|---|---|---|---|
| H1 | `T1021.001` | RDP access | `92653`, `100001` | Remote RDP access to `WS01` |
| H2 | `T1021.001` | RDP post-access | `67027`, `92052`, `100001` | Post-access process execution |
| H3 | `T1021.002` | SMB authentication | `100011` | Logon Type 3 using NTLM |
| H4 | `T1021.002` | Administrative shares | `92218`, Event ID `5145` | Access to administrative SMB resources |
| H5 | `T1021.002`, `T1569.002` | PsExec-like execution | `100010`, `92307`, `92650` | Remote service creation |
| H6 | `T1550.002` | Pass-the-Hash authentication effect | `100011`, `100021` | Privileged NTLM network authentication |
| H7 | `T1550.002`, `T1003.006` | Pass-the-Hash / DCSync | `100030`, `100033` | DCSync-like and privileged-access correlation |
| H8 | `T1558.003` | Kerberoasting initial signal | `100040` | RC4 service-ticket request from an unexpected source |
| H9 | `T1558.003` | Kerberoasting correlation | `100041` | Three suspicious requests from one source |
| H10 | `T1558.003` | Kerberoasting process context | `100042` | Optional Sysmon connection to `DC01:88` |
| H11 | `T1558.004` | AS-REP initial signal | `100050` | Successful Event ID `4768` with `preAuthType=0` |
| H12 | `T1558.004` | AS-REP RC4 context | `100051` | No-pre-authentication request using `0x17` |
| H13 | `T1558.004` | AS-REP correlation | `100052` | Three qualifying requests from one source in 60 seconds |

---

## 3. Rule-Level Matrix

| Rule ID | Purpose | Event Basis | MITRE Mapping | Detection Value | Limitation |
|---:|---|---|---|---|---|
| `60103` | Native Windows event-channel rule dependency | Decoded Windows event | Supporting dependency | Allows custom Windows rules to evaluate decoded fields | No standalone `60103` alert was supplied |
| `92653` | Native RDP-related detection | `4624` / RDP context | `T1021.001` | Identifies RDP access | RDP can be legitimate |
| `100001` | RDP post-access context | Process telemetry | `T1021.001` | Links process execution to the controlled RDP scenario | Requires username tuning |
| `100010` | Remote service creation | `7045` | `T1021.002`, `T1569.002` | Strong PsExec-like indicator | Administrative tools may create services |
| `100011` | NTLM network logon | `4624`, Logon Type `3`, NTLM | `T1021.002`, `T1550.002` | Early SMB and credential-use signal | High false-positive risk when isolated |
| `100021` | Special privileges | `4672` | `T1078`, `T1550.002` | Adds privileged-session context | Administrative logons are common |
| `100030` | DCSync-like activity | `4662` and replication permissions | `T1003.006` | High-value credential-access signal | Requires Directory Service Access visibility |
| `100033` | DCSync and privileged-access correlation | `100030` followed by `100021` | `T1550.002`, `T1003.006` | Highest-confidence Pass-the-Hash chain in the lab | Does not expose the NTLM hash |
| `100040` | RC4 TGS request from an unexpected source | `4769`, `0x17` | `T1558.003` | Main observable Kerberoasting signal | One request can be legitimate |
| `100041` | Kerberoasting frequency correlation | Three `100040` matches in 120 seconds | `T1558.003` | Strong repeated-ticket-request evidence | Requires environment-specific threshold tuning |
| `100042` | Unusual process connecting to Kerberos | Sysmon Event ID `3` | `T1558.003` | Optional process context | Not applicable to the Kali execution |
| `100050` | Successful TGT request without pre-authentication | `4768`, `preAuthType=0` | `T1558.004` | Main AS-REP Roasting-compatible signal | A deliberately configured legacy account can generate it |
| `100051` | RC4 context for no-pre-authentication request | `100050`, `ticketEncryptionType=0x17` | `T1558.004` | Raises confidence with encryption context | Validated on a separate collection date |
| `100052` | Repeated AS-REP request correlation | Three `100051` matches in 60 seconds by source IP | `T1558.004` | Strongest AS-REP correlation in the lab | Source-IP grouping requires baseline and tuning |

---

## 4. Evidence Quality

| Scenario | Evidence Quality | Reason |
|---|---|---|
| RDP | Medium / High | Remote access and post-access execution were observed, but RDP is a legitimate protocol |
| SMB / PsExec-like | High | Authentication, privileges, share activity and service creation form a rich chain |
| Pass-the-Hash / DCSync | High correlated | DCSync-like telemetry and privileged access are correlated |
| Kerberoasting | High for the validated correlation | Event ID `4769`, RC4, source context and frequency are preserved |
| AS-REP Roasting | High for rule-ID validation | Direct evidence exists for `100050`, `100051` and `100052`, but across two dates |

---

## 5. False-Positive Risk

| Scenario | Risk | Main Considerations |
|---|---|---|
| RDP | Medium | Helpdesk, administrators, jump hosts and remote support |
| SMB / PsExec-like | Medium / High | Management, backup and software-deployment systems |
| Pass-the-Hash / DCSync | Medium | Legitimate privileged NTLM activity; replication rights require careful review |
| Kerberoasting | Medium | Legacy RC4 use and expected service-ticket requests |
| AS-REP Roasting | Medium | Known accounts without pre-authentication, authorized assessments and shared source addresses |

AS-REP investigations should review:

- target account;
- whether pre-authentication is intentionally disabled;
- source host;
- request result;
- encryption type;
- request frequency;
- account privilege level;
- subsequent use of the account.

---

## 6. Production Readiness

| Scenario | Readiness |
|---|---|
| RDP | Needs tuning |
| SMB / PsExec-like | Needs tuning |
| Pass-the-Hash / DCSync | Prototype / needs tuning |
| Kerberoasting | Prototype / needs tuning |
| AS-REP Roasting | Prototype / needs tuning |

AS-REP production tuning requires:

- an inventory of accounts without Kerberos pre-authentication;
- approved-source baselines;
- IPv4 and IPv4-mapped IPv6 normalization;
- account criticality;
- event-volume baselines;
- documented correlation thresholds;
- handling of shared or translated source addresses.

---

## 7. Operational Detection Chains

### RDP

```text
RDP logon → post-access process execution
```

### SMB / PsExec-like

```text
NTLM logon → privileges → administrative share → service creation
```

### Pass-the-Hash / DCSync

```text
DCSync-like activity → privileged NTLM access → correlation
```

### Kerberoasting

```text
4769 → RC4-HMAC → unexpected source → 100040 → frequency → 100041
```

### AS-REP Roasting

```text
4768
  ↓
preAuthType = 0
  ↓
status = 0x0
  ↓
100050
  ↓
ticketEncryptionType = 0x17
  ↓
100051
  ↓
three matches from the same source in 60 seconds
  ↓
100052
```

---

## 8. Detection Boundaries

Wazuh does not directly observe:

- the NTLM hash used during Pass-the-Hash;
- every password candidate tested after a Kerberoasting ticket request;
- every password candidate tested after an AS-REP response;
- successful password recovery unless later activity creates additional telemetry.

The correct attribution is:

```text
behavior compatible with the technique in the controlled laboratory context
```

not direct proof of hidden credential material or offline password recovery.

---

## 9. Key Takeaway

The reusable value of the repository comes from documenting:

```text
telemetry prerequisite
        ↓
detection hypothesis
        ↓
Wazuh rule
        ↓
evidence
        ↓
analyst interpretation
        ↓
limitations
        ↓
MITRE ATT&CK mapping
```
