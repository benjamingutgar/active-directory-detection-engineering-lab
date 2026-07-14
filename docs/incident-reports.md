# Incident Reports

This document converts the laboratory detections into incident-style reports.

The goal is to make the Wazuh alerts useful for defensive response. Each report explains:

- what was detected;
- which asset was affected;
- what weakness was abused;
- what evidence supports the interpretation;
- what response actions should be prioritized;
- what limitations must be considered.

The scenarios do not exploit a classic CVE.

They abuse legitimate Windows and Active Directory mechanisms such as:

- RDP;
- SMB;
- NTLM;
- administrative shares;
- privileged accounts;
- remote service creation;
- Kerberos service-ticket requests;
- weak service-account credentials;
- legacy RC4 encryption.

---

## 1. Severity Criteria

The severity assessment considers:

| Criterion | Impact |
|---|---|
| Affected asset | Activity on `DC01` is more critical than activity on `WS01` |
| Privilege level | Administrative or high-value service accounts increase severity |
| MITRE ATT&CK technique | Lateral Movement and Credential Access increase severity |
| Remote execution | Service creation or execution under `LocalSystem` increases severity |
| Credential access | DCSync-like behavior or Kerberos ticket targeting increases severity |
| Temporal correlation | Several related signals in the same timeframe reduce ambiguity |
| Source baseline | Activity from an unexpected source increases relevance |
| Encryption type | RC4 Kerberos tickets increase credential exposure risk |
| False-positive possibility | Legitimate administration and application activity require contextual review |

---

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

The weakness is not a software vulnerability.

It is the combination of:

```text
RDP enabled
+
valid account
+
remote logon rights
+
insufficient contextual restriction
```

### Main Evidence

The main evidence is a remote RDP-related authentication from the attacker IP to `WS01`, followed by command execution inside the remote session.

Observed evidence includes:

- source IP `192.168.56.40`;
- target host `WS01`;
- domain-user authentication;
- RDP-related logon context;
- post-access commands;
- process-creation events.

### Potential Impact

A successful RDP session may allow an attacker to:

- interactively access the workstation;
- run reconnaissance commands;
- inspect local configuration;
- prepare lateral movement;
- access resources available to the authenticated user;
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

- restrict RDP to approved administrative hosts;
- limit membership of Remote Desktop Users;
- enforce MFA where possible;
- monitor RDP from unusual sources;
- baseline normal RDP administration;
- audit command execution after remote logon;
- consider jump-server-based administration.

### Attribution Limitation

RDP is a legitimate protocol.

The alert should not be interpreted in isolation.

The attribution becomes stronger when the analyst correlates:

```text
source IP
+
user
+
target host
+
time
+
post-access activity
```

---

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
SMB exposed
+
privileged account
+
ADMIN$ / IPC$ access
+
remote service creation
```

### Main Evidence

Observed evidence includes:

- NTLM network authentication from `192.168.56.40`;
- Logon Type `3`;
- special privileges assigned to the session;
- access to administrative shares;
- Service Control Manager activity;
- creation of a new service;
- process execution after remote service creation.

### Potential Impact

A successful SMB/PsExec-like chain may allow an attacker to:

- execute commands remotely on `DC01`;
- abuse legitimate administration mechanisms;
- run code under a privileged context;
- create temporary services;
- expand control over the Active Directory environment;
- prepare credential access or further lateral movement.

### Defensive Response

Recommended response actions:

1. Review the service created on `DC01`.
2. Inspect the service `ImagePath`.
3. Determine whether the service name is random, tool-generated or known.
4. Check administrative-share access, especially `ADMIN$`, `C$` and `IPC$`.
5. Identify the account used.
6. Review whether the account should have administrative rights on `DC01`.
7. Search for process execution after the service creation.
8. Contain the source host if unauthorized.
9. Rotate credentials if account compromise is suspected.

### Future Mitigation

Recommended mitigation actions:

- apply tiered administration;
- restrict SMB access between segments;
- limit administrative-share usage;
- monitor remote service creation;
- prevent workstation-originated administration of domain controllers;
- reduce local administrator reuse;
- enforce privileged access workstations for domain administration.

### Attribution Limitation

SMB, administrative shares and service creation can be legitimate in Windows administration.

The attribution becomes stronger because the scenario correlates:

```text
NTLM network logon
+
privileged session
+
administrative-share access
+
service creation
+
process execution
```

A single SMB logon alone should not be treated as proof of malicious activity.

---

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
NTLM enabled
+
privileged account
+
hash reuse
+
domain controller exposure
+
replication rights
```

### Main Evidence

Observed evidence includes:

- DCSync-like activity detected through Event ID `4662`;
- use of replication-related permissions by a non-machine account;
- NTLM network authentication;
- privileged-session creation;
- correlation through rule `100033`;
- additional remote activity against `DC01`.

### Potential Impact

A successful Pass-the-Hash / DCSync-related chain may allow an attacker to:

- authenticate without knowing the plaintext password;
- reuse administrative NTLM material;
- access the domain controller;
- extract or attempt to extract credential material;
- compromise additional accounts;
- expand lateral movement across Active Directory.

### Defensive Response

Recommended response actions:

1. Isolate or investigate the source host.
2. Review directory-replication events.
3. Identify the account that requested replication-related permissions.
4. Rotate privileged credentials.
5. Check whether the account was used on other systems.
6. Search for NTLM logons from the same source.
7. Review remote service creation and command execution around the same timeframe.
8. Investigate whether credential dumping occurred.

### Future Mitigation

Recommended mitigation actions:

- reduce dependency on NTLM;
- restrict privileged-account usage;
- apply tiered administration;
- protect domain administrator accounts;
- audit replication permissions;
- restrict remote access to domain controllers;
- monitor DCSync-like activity;
- use privileged access workstations;
- avoid using domain administrator accounts on lower-trust systems.

### Attribution Limitation

Wazuh does not directly observe the NTLM hash.

The attribution to Pass-the-Hash is built from correlation between:

```text
credential-access evidence
+
NTLM privileged authentication
+
remote activity
```

The alert should therefore be described as:

```text
behavior compatible with Pass-the-Hash
```

rather than:

```text
direct proof that a hash was used
```

---

## 5. Report — Kerberoasting-Compatible Activity

| Field | Value |
|---|---|
| MITRE Tactic | Credential Access |
| Technique | `T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting` |
| Affected System | `DC01` |
| Source | `Kali-ATK01 / 192.168.56.40` |
| Requesting User | `LAB\<domain_user>` |
| Target Identity | `LAB\<service_account>` |
| Severity | High / Critical |
| Main Rules | `100040`, `100041` |
| Supporting Rule | `100042` |
| Main Event | `4769` |
| Encryption Type | `0x17 — RC4-HMAC` |

### Weakness Abused

The scenario abuses normal Kerberos service-ticket functionality together with a service account configured with:

- a registered Service Principal Name;
- a weak password used only for the controlled laboratory;
- static password behavior;
- temporary RC4 support.

The weakness is the combination of:

```text
valid domain account
+
service account with SPN
+
weak service-account password
+
RC4-HMAC support
+
offline password testing
```

Kerberoasting does not require exploitation of a Kerberos software vulnerability.

A domain-authenticated user can normally request service tickets for available SPNs.

The risk appears when the encrypted ticket material can be tested offline against weak password candidates.

### Main Evidence

Observed evidence includes:

- Windows Security Event ID `4769` on `DC01`;
- a Kerberos service-ticket request;
- the controlled service identity;
- the requesting domain account;
- source address `192.168.56.40` or its IPv4-mapped IPv6 form;
- ticket encryption type `0x17`;
- Wazuh rule `100040`;
- repeated requests from the same source;
- Wazuh correlation rule `100041`;
- three requests inside the 120-second window.

The main validated chain is:

```text
Kerberos TGS request
        ↓
Event ID 4769
        ↓
RC4-HMAC 0x17
        ↓
unexpected source
        ↓
rule 100040
        ↓
three matching requests
        ↓
rule 100041
```

### Potential Impact

If the service-account password is recovered offline, an attacker may gain the permissions assigned to that account.

Potential impact includes:

- access to the service associated with the SPN;
- access to application data;
- credential reuse on other systems;
- movement to systems where the account can authenticate;
- persistence while the password remains unchanged;
- privilege escalation if the account has excessive rights;
- access to secondary secrets used by the application.

The impact depends on the real privileges and logon rights of the targeted service account.

In this laboratory, the controlled account should remain non-privileged.

### Defensive Response

Recommended response actions:

1. Identify the requesting account.
2. Identify the source host and client address.
3. Review the requested service identity and SPN.
4. Confirm whether the source normally requests this ticket.
5. Determine whether RC4 is still required.
6. Review the number of ticket requests from the same source.
7. Review the number of distinct SPNs requested.
8. Review the service account's password age.
9. Review privileged-group membership.
10. Review allowed logon locations and rights.
11. Search for later authentication using the service account.
12. Rotate the service-account password if compromise is suspected.
13. Preserve the related Windows and Wazuh evidence.

### Containment and Mitigation

Recommended mitigation actions:

- rotate the service-account password;
- use a long random password;
- remove `PasswordNeverExpires` where possible;
- enable AES128 and AES256;
- retire RC4 after validating application compatibility;
- prefer a Group Managed Service Account when supported;
- apply minimum privilege;
- deny interactive and RDP logon when unnecessary;
- restrict the systems where the account can authenticate;
- remove unused or duplicate SPNs;
- maintain an inventory of service accounts and SPNs;
- prioritize monitoring of privileged service identities.

A safer final state is:

```text
RC4 removed
+
AES enabled
+
password rotated
+
minimum privilege verified
+
interactive logon restricted
```

### Offline Visibility Limitation

Wazuh can observe the ticket request.

Wazuh cannot directly observe every password candidate tested after the ticket has been exported.

The offline phase occurs locally on the attacker system.

Consequently:

- the Domain Controller does not receive one request per password candidate;
- the service account is not locked by the offline test;
- Windows does not generate thousands of failed-logon events;
- Wazuh does not prove that Hashcat was executed;
- Wazuh does not prove that the password was recovered.

### Attribution Limitation

A single Event ID `4769` does not prove Kerberoasting.

A legitimate application may request an RC4 ticket because of:

- legacy compatibility;
- old account configuration;
- missing AES keys;
- application-server behavior;
- monitoring or administration activity.

The attribution becomes stronger because the controlled scenario combines:

```text
service account with SPN
+
RC4 ticket
+
unexpected source
+
repeated requests
+
known laboratory execution
```

The correct incident statement is:

> Wazuh detected repeated RC4 Kerberos service-ticket requests from an unexpected source, producing activity compatible with Kerberoasting.

The incorrect statement is:

> Wazuh detected the service-account password being cracked.

### Supporting Rule 100042

Rule `100042` can add process-level context when equivalent Kerberos activity originates from `WS01`.

It looks for:

```text
Sysmon Event ID 3
+
destination DC01:88
+
process other than lsass.exe
```

This rule is complementary.

It is not part of the principal Kali-based validation because Kali Linux does not generate Windows Sysmon telemetry.

---

## 6. Report Summary

| Scenario | Affected Host | Severity | Strongest Evidence | Main Limitation |
|---|---|---|---|---|
| RDP | `WS01` | High | RDP access followed by process execution | RDP can be legitimate |
| SMB / PsExec-like | `DC01` | High / Critical | NTLM, privileges, admin shares, service creation | Remote administration can be legitimate |
| Pass-the-Hash / DCSync | `DC01` | Critical | DCSync-like activity correlated with privileged NTLM access | Wazuh does not observe the hash directly |
| Kerberoasting | `DC01` | High / Critical | Event ID `4769`, RC4, unexpected source and rule `100041` correlation | Wazuh does not observe offline password testing |

---

## 7. Shared Response Priorities

Across the four scenarios, the analyst should prioritize:

1. Source identification.
2. User and service-account identification.
3. Asset criticality.
4. Privilege review.
5. Timeline reconstruction.
6. Related event correlation.
7. Credential rotation where compromise is suspected.
8. Source-host containment when unauthorized.
9. Evidence preservation.
10. Tuning and false-positive documentation.

---

## 8. Key Takeaway

The incident reports transform raw alerts into response-oriented information.

The strongest reports are not based on a single event.

They combine:

```text
asset criticality
+
source
+
account
+
privileges
+
telemetry chain
+
temporal correlation
+
MITRE mapping
+
known limitations
```

The four scenarios also demonstrate different visibility boundaries:

```text
RDP:
access and process activity are observable

SMB / PsExec-like:
authentication, shares, services and execution are observable

Pass-the-Hash:
the hash is hidden, but surrounding behavior can be correlated

Kerberoasting:
the ticket request is observable, while offline password testing is hidden
```

This distinction should remain explicit in every incident conclusion.
