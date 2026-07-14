# Custom Wazuh Rules

This document explains the custom Wazuh rules developed for the Active Directory security laboratory.

The rules enrich native Wazuh detections with project-specific context, MITRE ATT&CK mapping and correlation logic.

They cover four controlled scenarios:

- RDP-based lateral movement.
- SMB / PsExec-like remote execution.
- Pass-the-Hash activity with DCSync-related evidence.
- Kerberoasting activity against a controlled service account.

The full XML rule file is available at:

```text
wazuh/rules/local_rules.xml
```

---

## Rule 100001 — RDP Session Context

Rule `100001` contextualizes RDP activity associated with the observed laboratory user.

The initial RDP access is covered by the native Wazuh rule `92653`. Rule `100001` extends this detection chain by filtering the authenticated user involved in the RDP session.

The `if_sid` dependency ensures that this rule only fires when the native RDP-related rule has already matched.

This rule is mapped to:

```text
T1021.001 — Remote Services: Remote Desktop Protocol
```

### Detection value

This rule helps isolate RDP activity that belongs to the controlled lateral movement scenario and separates it from generic RDP-related noise.

### Main fields

| Field | Purpose |
|---|---|
| `if_sid` | Requires native rule `92653` to have fired |
| `win.eventdata.targetUserName` | Filters the observed laboratory user |
| `mitre.id` | Maps the alert to `T1021.001` |

### Limitations

RDP is a legitimate administration protocol.

The rule provides laboratory context but does not prove malicious intent by itself.

In the public repository, the real username is replaced with a placeholder such as:

```text
<standard_user>
```

In a private deployment, this value must be replaced with the actual laboratory account.

---

## Rule 100010 — Remote Service Creation Compatible with PsExec-like Activity

Rule `100010` detects remote service creation compatible with PsExec-like or smbexec-style activity.

It builds on the native Wazuh rule `61138`, associated with Windows Event ID `7045`, and adds filters to confirm that:

- the event comes from the Service Control Manager;
- the service executes as `LocalSystem`.

Native rules such as `92307` and `92650` may also detect suspicious service or payload patterns.

Rule `100010` explicitly tags the activity as part of the project detection chain.

This rule is mapped to:

- `T1021.002 — Remote Services: SMB/Windows Admin Shares`
- `T1569.002 — System Services: Service Execution`

### Detection value

Remote service creation is one of the strongest indicators in the SMB/PsExec-like scenario because it reflects a concrete execution mechanism on the target system.

### Main fields

| Field | Purpose |
|---|---|
| `if_sid` | Requires native rule `61138` |
| `win.system.eventID` | Confirms Event ID `7045` |
| `win.system.providerName` | Confirms Service Control Manager |
| `win.eventdata.accountName` | Confirms execution as `LocalSystem` |
| `mitre.id` | Maps the alert to SMB and service-execution techniques |

### Limitations

Legitimate administration and endpoint-management tools can also create services remotely.

The analyst must review:

- service name;
- service path;
- source system;
- account used;
- maintenance window;
- related authentication and share-access events.

---

## Rule 100011 — NTLM Network Logon Shared Indicator

Rule `100011` detects network authentication through NTLM by observing Windows Event ID `4624` with:

```text
Logon Type 3
Authentication Package NTLM
```

This rule is a shared indicator.

It may fire in both:

- the SMB/PsExec-like scenario;
- the Pass-the-Hash scenario.

By itself, it does not distinguish between those techniques.

Its value is that it opens the correlation chain and provides an early signal of NTLM-based remote access.

This rule is mapped to:

- `T1021.002 — Remote Services: SMB/Windows Admin Shares`
- `T1550.002 — Use Alternate Authentication Material: Pass the Hash`

### Detection value

NTLM network authentication is not necessarily malicious.

It becomes more relevant when combined with:

- privileged access;
- administrative-share access;
- service creation;
- DCSync-like activity;
- unusual source systems;
- unexpected user accounts.

### Main fields

| Field | Purpose |
|---|---|
| `if_sid` | Requires native rule `92652` |
| `win.eventdata.authenticationPackageName` | Confirms NTLM authentication |
| `win.eventdata.logonType` | Identifies a network logon |
| `win.eventdata.ipAddress` | Identifies the source system |
| `mitre.id` | Maps the event to SMB and Pass-the-Hash contexts |

### Limitations

A normal NTLM authentication using a password can generate telemetry similar to authentication using a hash.

Therefore, this rule must not be described as direct proof of Pass-the-Hash.

The correct interpretation is:

```text
NTLM network authentication compatible with remote credential use.
```

---

## Rule 100021 — Special Privileges Assigned to a Remote Privileged Session

Rule `100021` detects Windows Event ID `4672` when special privileges are assigned to a non-system account.

The rule excludes common internal Windows identities such as:

```text
SYSTEM
LOCAL SERVICE
NETWORK SERVICE
machine accounts ending in $
```

This reduces noise and keeps visible the assignment of privileges to real user accounts.

Rule `100021` acts as a shared indicator between:

- SMB/PsExec-like activity;
- Pass-the-Hash activity.

It also works as a parent signal for correlation rule `100033`.

This rule is mapped to:

- `T1078 — Valid Accounts`
- `T1550.002 — Pass the Hash`

### Detection value

Special privileges alone do not prove malicious activity.

The signal becomes stronger when it occurs close in time to:

- NTLM network authentication;
- remote service creation;
- administrative-share access;
- DCSync-like activity;
- Defender modification.

### Main fields

| Field | Purpose |
|---|---|
| `if_sid` | Requires native rule `67028` |
| `win.eventdata.subjectUserName` | Excludes system and machine accounts |
| `win.eventdata.privilegeList` | Shows assigned privileges |
| `mitre.id` | Maps the event to credential-based access context |

### Limitations

Administrative users can legitimately receive special privileges.

The event requires identity, source, timing and activity context.

---

## Rule 100022 — Defender Disabled Followed by Privileged Access

Rule `100022` correlates Windows Defender being disabled with a later privileged session within a 300-second window.

This is not a universal Pass-the-Hash detection.

It represents a specific controlled laboratory preparation sequence:

```text
Defender disabled
        ↓
privileged access
```

This rule is mapped to:

- `T1550.002 — Pass the Hash`
- `T1562.001 — Impair Defenses: Disable or Modify Tools`

### Detection value

The rule documents a high-risk sequence in which endpoint protection is reduced shortly before administrative activity.

### Main fields

| Field | Purpose |
|---|---|
| `if_matched_sid` | Requires previous Defender-related rule `92008` |
| `if_sid` | Requires privileged-access rule `100021` |
| `timeframe` | Correlates both signals within 300 seconds |
| `mitre.id` | Maps the correlation to credential use and defense impairment |

### Limitations

Legitimate administrators can temporarily modify Defender settings.

A production deployment requires:

- administrator allowlists;
- change-window awareness;
- endpoint-management context;
- confirmation of the commands used;
- review of subsequent remote activity.

---

## Rule 100030 — DCSync / secretsdump-like Activity

Rule `100030` detects behavior compatible with DCSync or secretsdump-style activity by observing the use of Active Directory replication rights by a non-machine account.

The rule is based on Windows Event ID `4662`.

It filters for:

```text
accessMask = 0x100
```

and replication-related permissions or GUIDs associated with directory replication.

The rule excludes machine accounts ending in `$`, because domain controllers may legitimately use replication rights.

This rule is mapped to:

```text
T1003.006 — OS Credential Dumping: DCSync
```

### Detection value

This is one of the strongest detections in the project because DCSync-like behavior is closely related to credential access against Active Directory.

When correlated with privileged access, confidence increases significantly.

### Main fields

| Field | Purpose |
|---|---|
| `if_sid` | Requires native rule `60103` |
| `win.system.eventID` | Confirms Event ID `4662` |
| `win.eventdata.accessMask` | Filters Control Access events |
| `win.eventdata.properties` | Searches for replication-related GUIDs or rights |
| `win.eventdata.subjectUserName` | Excludes machine accounts |
| `mitre.id` | Maps the alert to `T1003.006` |

### Limitations

Event ID `4662` can be noisy and depends on correct Directory Service Access auditing and SACL configuration.

The analyst must confirm:

- requesting account;
- replication rights;
- target object;
- whether the requester is a domain controller;
- nearby privileged logons;
- related network activity.

---

## Rule 100033 — Critical Pass-the-Hash / DCSync Correlation

Rule `100033` correlates two high-value signals within a 300-second window:

1. DCSync/secretsdump-like activity detected by rule `100030`.
2. Special privileges assigned to a non-system account detected by rule `100021`.

The `if_matched_sid` condition requires rule `100030` to have fired previously.

The `if_sid` condition requires the current event to match rule `100021`.

This rule is mapped to:

- `T1550.002 — Pass the Hash`
- `T1003.006 — DCSync`

### Detection value

Rule `100033` is the strongest Pass-the-Hash-related correlation in the laboratory.

It connects:

```text
credential-access activity
+
privileged session activity
```

The rule does not observe the NTLM hash itself.

It correlates the observable effects of the controlled attack chain.

### Main fields

| Field | Purpose |
|---|---|
| `if_matched_sid` | Requires previous DCSync-like alert `100030` |
| `if_sid` | Requires privileged-session alert `100021` |
| `timeframe` | Correlates both signals within 300 seconds |
| `level` | Raises the alert to critical severity |
| `mitre.id` | Maps the correlation to Pass-the-Hash and DCSync |

### Limitations

The rule does not prove that a hash was used.

The correct interpretation is:

```text
Wazuh detected behavior compatible with Pass-the-Hash by correlating DCSync-like activity and privileged access.
```

---

## Rule 100040 — RC4 Kerberos Service Ticket from an Unexpected Source

Rule `100040` detects a Kerberos service-ticket request using RC4-HMAC from a source outside the approved laboratory list.

The rule is based on Windows Security Event ID:

```text
4769 — A Kerberos service ticket was requested
```

It requires:

```text
ticketEncryptionType = 0x17
```

The value `0x17` represents:

```text
RC4-HMAC
Kerberos etype 23
```

The rule also checks the source address and excludes the systems considered expected in the laboratory.

A request from `Kali-ATK01` therefore generates the initial Kerberoasting-compatible alert.

This rule is mapped to:

```text
T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
```

### Detection hypothesis

```text
H8 — RC4 Kerberos service ticket from an unexpected source
```

### Detection logic

```text
Windows Security Event ID 4769
+
ticketEncryptionType = 0x17
+
source address outside the approved list
=
rule 100040
```

### Main fields

| Field | Purpose |
|---|---|
| `if_sid` | Requires the Windows Security parent rule `60103` |
| `win.system.eventID` | Confirms Event ID `4769` |
| `win.eventdata.ticketEncryptionType` | Confirms RC4-HMAC through `0x17` |
| `win.eventdata.ipAddress` | Identifies and filters the request source |
| `win.eventdata.targetUserName` | Identifies the requesting domain account |
| `win.eventdata.serviceName` | Identifies the requested service identity |
| `win.eventdata.ticketOptions` | Adds Kerberos request context |
| `mitre.id` | Maps the event to `T1558.003` |

### IPv4 and IPv4-mapped IPv6

Windows may represent the source address as:

```text
192.168.56.40
```

or:

```text
::ffff:192.168.56.40
```

The rule accounts for the optional IPv4-mapped IPv6 prefix.

### Detection value

Rule `100040` combines three useful elements:

```text
service-ticket request
+
legacy RC4 encryption
+
unexpected source
```

This is more useful than alerting on every Event ID `4769`, because service-ticket requests are normal in Active Directory.

### What the rule proves

The rule proves that:

- the Domain Controller processed a TGS request;
- the ticket used RC4-HMAC;
- the request originated outside the approved laboratory source list.

### What the rule does not prove

The rule does not prove that:

- the complete ticket was exported;
- the ticket was tested offline;
- the service-account password was recovered;
- the requesting user had malicious intent;
- the recovered credential was reused.

### False-positive considerations

Possible legitimate causes include:

- legacy applications;
- old service accounts;
- monitoring platforms;
- administration systems;
- application servers;
- incomplete RC4 remediation;
- systems missing from the expected-source list.

### Analyst interpretation

The correct interpretation is:

> `DC01` issued an RC4 Kerberos service ticket to an unexpected source. The activity is compatible with the initial observable phase of Kerberoasting and requires contextual review.

The incorrect interpretation is:

> Wazuh detected the service-account password being cracked.

---

## Rule 100041 — Kerberoasting Frequency Correlation

Rule `100041` correlates three alerts from rule `100040` generated by the same source within 120 seconds.

The rule uses:

```text
if_matched_sid = 100040
frequency = 3
timeframe = 120
same_field = win.eventdata.ipAddress
```

It is mapped to:

```text
T1558.003 — Kerberoasting
```

### Detection hypothesis

```text
H9 — Repeated RC4 service-ticket requests from the same source
```

### Detection logic

```text
three matches of rule 100040
+
same source address
+
within 120 seconds
=
rule 100041
```

### Expected alert sequence

```text
first suspicious request  → 100040
second suspicious request → 100040
third suspicious request  → 100041
```

On the third matching event, Wazuh may display the higher-level correlation rule instead of another visible `100040`.

This does not mean that the third event failed the original rule conditions.

It means the correlation rule became the principal alert.

### Main fields

| Field | Purpose |
|---|---|
| `if_matched_sid` | Requires previous matches of rule `100040` |
| `frequency` | Requires three matching alerts |
| `timeframe` | Limits the sequence to 120 seconds |
| `same_field` | Requires the same source address |
| `ignore` | Prevents repeated critical alerts for the configured period |
| `level` | Raises the alert to critical severity |
| `mitre.id` | Maps the correlation to `T1558.003` |

### Detection value

A single TGS request may be legitimate.

Repeated suspicious RC4 requests from the same source can indicate:

- automated ticket collection;
- scripted Kerberoasting activity;
- repeated requests for a vulnerable service identity;
- rapid testing of the attack workflow;
- requests targeting several service accounts.

### What the rule proves

Rule `100041` proves that several suspicious requests satisfying rule `100040` originated from the same source inside the configured window.

### What the rule does not prove

The rule does not prove that:

- Hashcat was executed;
- offline password recovery succeeded;
- the service-account password was weak;
- the account was later abused.

### Evasion and limitations

The correlation can be bypassed by an attacker who:

- requests only one high-value ticket;
- introduces delays between requests;
- distributes requests across several systems;
- uses an allowlisted source;
- requests AES tickets instead of RC4.

Legitimate applications can also request several tickets in a short period.

The production threshold must be tuned against normal Kerberos traffic.

---

## Rule 100042 — Unusual Process Connecting to Kerberos

Rule `100042` provides optional endpoint context for Kerberos activity originating from `WS01`.

It is based on Sysmon Event ID:

```text
3 — Network connection
```

The rule looks for:

```text
source host = WS01
destination IP = DC01
destination port = 88
process image is not lsass.exe
```

It is mapped to:

```text
T1558.003 — Kerberoasting
```

### Detection hypothesis

```text
H10 — Unusual process connecting directly to the Kerberos service
```

### Detection logic

```text
Sysmon Event ID 3
+
WS01 connects to DC01:88
+
process image does not end in lsass.exe
=
rule 100042
```

### Main fields

| Field | Purpose |
|---|---|
| `if_sid` | Requires the Sysmon network-connection parent rule `61605` |
| `win.system.computer` | Restricts the source system to `WS01` |
| `win.eventdata.destinationIp` | Identifies `DC01` |
| `win.eventdata.destinationPort` | Identifies the Kerberos service on port `88` |
| `win.eventdata.image` | Excludes the expected Windows process `lsass.exe` |
| `mitre.id` | Maps the alert to `T1558.003` |

### Detection value

The rule adds process-level context that Event ID `4769` does not provide directly.

It can identify:

- unusual executables;
- scripts;
- custom Kerberos tools;
- direct process connections to the KDC;
- activity from a workstation that normally uses LSASS-mediated authentication.

### Limitations

Rule `100042` is complementary coverage.

It was not required for the main Kali-based validation because Kali Linux does not generate Windows Sysmon telemetry.

Some Windows applications also request Kerberos tickets through LSASS.

In those cases, Sysmon may show:

```text
C:\Windows\System32\lsass.exe
```

even when another application triggered the request.

Therefore, the absence of rule `100042` does not mean that Kerberoasting did not occur.

The principal validated chain remains:

```text
Event ID 4769
        ↓
rule 100040
        ↓
rule 100041
```

---

## Summary Matrix

| Rule ID | Main Purpose | Technique Mapping | Scenario |
|---:|---|---|---|
| `100001` | RDP session context | `T1021.001` | RDP |
| `100010` | Remote service creation | `T1021.002`, `T1569.002` | SMB / PsExec-like |
| `100011` | NTLM network logon | `T1021.002`, `T1550.002` | SMB / Pass-the-Hash |
| `100021` | Privileged user session | `T1078`, `T1550.002` | SMB / Pass-the-Hash |
| `100022` | Defender disabled followed by privileged access | `T1550.002`, `T1562.001` | Controlled Pass-the-Hash chain |
| `100030` | DCSync-like activity | `T1003.006` | Pass-the-Hash / DCSync |
| `100033` | DCSync and privileged-access correlation | `T1550.002`, `T1003.006` | Critical Pass-the-Hash correlation |
| `100040` | RC4 TGS request from an unexpected source | `T1558.003` | Kerberoasting |
| `100041` | Three suspicious RC4 TGS requests from the same source | `T1558.003` | Critical Kerberoasting correlation |
| `100042` | Unusual process connecting to Kerberos | `T1558.003` | Kerberoasting supporting context |

---

## Scenario Detection Chains

### RDP

```text
native RDP alert
        ↓
rule 100001
        ↓
post-access process events
```

### SMB / PsExec-like

```text
rule 100011
        ↓
rule 100021
        ↓
administrative-share activity
        ↓
rule 100010 / native service rules
```

### Pass-the-Hash / DCSync

```text
rule 100030
        ↓
rule 100021
        ↓
rule 100033
```

### Kerberoasting

```text
Windows Event ID 4769
        ↓
RC4-HMAC 0x17
        ↓
unexpected source
        ↓
rule 100040
        ↓
three matches from the same source in 120 seconds
        ↓
rule 100041
```

Optional supporting context:

```text
Sysmon Event ID 3
        ↓
WS01 connects to DC01:88
        ↓
process other than lsass.exe
        ↓
rule 100042
```

---

## Detection Boundaries

The rules detect observable events and relationships.

They do not directly expose hidden credential material.

### Pass-the-Hash

Wazuh does not see the NTLM hash itself.

It sees:

```text
NTLM network authentication
+
privileged access
+
DCSync-like activity
+
remote execution context
```

### Kerberoasting

Wazuh does not see every offline password attempt.

It sees:

```text
Kerberos service-ticket request
+
RC4 encryption
+
source context
+
request frequency
```

The analyst must distinguish between:

```text
event
```

```text
alert
```

and:

```text
MITRE ATT&CK attribution
```

The correct wording is:

```text
behavior compatible with the technique in the controlled laboratory context
```

not:

```text
direct proof that the hidden password or hash was used or recovered
```

---

## Key Takeaway

The value of these rules is not only that they generate alerts.

Their value comes from the documented relationship between:

```text
Windows or Sysmon telemetry
        ↓
detection hypothesis
        ↓
custom Wazuh rule
        ↓
correlation
        ↓
analyst interpretation
        ↓
MITRE ATT&CK mapping
        ↓
documented limitations
```

That relationship makes the detections understandable, reproducible and suitable for later tuning in a real environment.
