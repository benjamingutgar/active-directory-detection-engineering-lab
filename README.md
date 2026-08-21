# Wazuh Lateral Movement Detection Lab

A **Blue Team / Detection Engineering laboratory** for analyzing Windows lateral movement and credential-access techniques with **Wazuh**, **Windows Event Logs**, **Sysmon**, **Windows / Active Directory internals** and **MITRE ATT&CK**.

The lab reproduces four controlled scenarios:

* **RDP lateral movement** — `T1021.001`
* **SMB / PsExec-like remote execution** — `T1021.002` / `T1569.002`
* **Pass-the-Hash with DCSync-related evidence** — `T1550.002` / `T1003.006`
* **Kerberoasting** — `T1558.003`

The repository is focused on understanding and detecting the behavior, not simply reproducing the offensive technique.

The project follows the complete chain:

```text
MITRE technique
      ↓
Windows / Active Directory internals
      ↓
controlled execution
      ↓
Windows telemetry
      ↓
Wazuh processing
      ↓
custom detection
      ↓
correlation
      ↓
evidence
      ↓
analyst interpretation
      ↓
hardening / mitigation
```

The objective is not only to answer:

```text
Which event was generated?
```

but also:

```text
Why did Windows generate it?

Which Windows component performed the action?

Which authentication or authorization decision occurred before it?

How does the protocol work internally?

What can Wazuh actually observe?

What can Wazuh not prove?

How can the underlying Windows configuration be hardened?
```

---

## Overview

This project documents a small Active Directory laboratory used to validate Wazuh detections for lateral movement and credential-access activity.

The environment includes:

| Host | Role | IP Address |
| --- | --- | ---: |
| `Wazuh-Manager` | SIEM / monitoring server | `192.168.56.10` |
| `DC01` | Domain Controller and Kerberos KDC | `192.168.56.20` |
| `WS01` | Domain workstation | `192.168.56.30` |
| `Kali-ATK01` | Controlled attack simulation host | `192.168.56.40` |

Full architecture:

* [`docs/lab-architecture.md`](docs/lab-architecture.md)

---

## Detection Engineering Approach

The repository separates several layers that are often incorrectly treated as the same thing:

```text
Offensive action
      ↓
Windows internal mechanism
      ↓
Windows Event / Sysmon telemetry
      ↓
Wazuh native processing
      ↓
Wazuh custom rule
      ↓
Wazuh correlation
      ↓
Analyst interpretation
      ↓
MITRE ATT&CK attribution
```

For example:

```text
Remote SMB request
      ↓
SMB
      ↓
IPC$
      ↓
Named Pipe
      ↓
DCE/RPC
      ↓
Service Control Manager
      ↓
services.exe
      ↓
process creation
      ↓
Windows Event IDs
      ↓
Wazuh alerts
```

The Windows event is not the attack itself.

The event is telemetry generated because a Windows component performed a specific operation.

Likewise, a Wazuh alert is not automatically proof of a MITRE ATT&CK technique.

Attribution is built from:

```text
telemetry
+
context
+
sequence
+
correlation
+
analyst interpretation
```

This distinction is one of the main design principles of the project.

---

## Windows and Active Directory Internals

In addition to the detection write-ups, the repository contains a dedicated **Windows Internals** layer.

These documents explain what happens inside Windows before, during and after each controlled scenario.

They are located in:

* [`docs/windows-internals/`](docs/windows-internals/)

The purpose is to connect:

```text
what the attacker requests
```

with:

```text
what Windows actually does internally
```

and finally with:

```text
what the SIEM is able to observe
```

Current internals documentation includes:

| Technique | Internal mechanisms |
| --- | --- |
| [`T1021.001 — RDP`](docs/windows-internals/T1021.001-rdp-internals.md) | RDP, `TermService`, NLA, CredSSP, SSPI, Kerberos/NTLM, LSASS, Logon Type 10, access tokens, RDP sessions, `WinSta0`, desktop creation and process execution |
| [`T1021.002 — SMB / Admin Shares`](docs/windows-internals/T1021.002-smb-admin-shares-internals.md) | SMB negotiation, `SESSION_SETUP`, NTLM, Logon Type 3, access tokens, `ADMIN$`, `C$`, `IPC$`, Named Pipes, DCE/RPC, SCMR, Service Control Manager and SYSTEM execution |
| [`T1550.002 — Pass-the-Hash`](docs/windows-internals/T1550.002-pass-the-hash-internals.md) | NT hashes, NTLM challenge-response, NTLMv2 key derivation, logon sessions, tokens, SMB authorization, PsExec service execution and PtH detection limitations |
| [`T1558.003 — Kerberoasting`](docs/windows-internals/T1558.003-kerberoasting-internals.md) | Kerberos, KDC, AS/TGS exchanges, TGTs, SPNs, service-account keys, TGS encryption, offline password testing, `4769`, detection limitations and service-account hardening |

The internals documentation follows a common model:

```text
Protocol
   ↓
Windows component
   ↓
Authentication
   ↓
Security context
   ↓
Authorization
   ↓
Operating-system action
   ↓
Telemetry
   ↓
Detection
```

This makes it possible to understand the causal relationship between a Windows mechanism and the resulting detection instead of memorizing isolated Event IDs.

---

## Why Windows Internals Matter

A detection such as:

```text
4624
```

has limited meaning without understanding:

```text
which Logon Type was created
why Windows created that logon
which authentication mechanism was involved
where the request originated
what happened afterwards
```

Likewise:

```text
7045
```

becomes much more meaningful when the analyst understands the preceding chain:

```text
SMB authentication
      ↓
network logon
      ↓
administrative authorization
      ↓
IPC$
      ↓
\pipe\svcctl
      ↓
DCE/RPC
      ↓
Service Control Manager
      ↓
CreateService
      ↓
7045
```

The repository therefore tries to document both:

```text
Detection Engineering
```

and:

```text
the Windows architecture that makes
the detection possible
```

---

## What This Repository Contains

| Folder | Content |
| --- | --- |
| [`docs/`](docs/) | Architecture, deployment notes, telemetry configuration, Windows internals, detection methodology, latencies and incident reports |
| [`docs/windows-internals/`](docs/windows-internals/) | Detailed Windows / Active Directory architecture and internal protocol flows behind each technique |
| [`detections/`](detections/) | Detection hypotheses, detection matrix and MITRE technique write-ups |
| [`scenarios/`](scenarios/) | Controlled scenario execution notes, timelines and Wazuh KQL filters |
| [`evidence/`](evidence/) | Anonymized JSON alerts and CSV summaries |
| [`wazuh/rules/`](wazuh/rules/) | Wazuh custom rules and rule explanations |

The repository deliberately separates:

```text
scenarios/
```

which describes:

```text
what was executed
```

from:

```text
windows-internals/
```

which explains:

```text
what Windows did internally
```

and from:

```text
detections/
```

which explains:

```text
how that behavior can be detected
```

---

## Detection Scenarios

| Scenario | Technique | Main Detection Chain | Detection Write-up | Windows Internals |
| --- | --- | --- | --- | --- |
| RDP | `T1021.001` | RDP logon → post-access process execution | [`T1021.001-rdp.md`](detections/T1021.001-rdp.md) | [`RDP Internals`](docs/windows-internals/T1021.001-rdp-internals.md) |
| SMB / PsExec-like | `T1021.002`, `T1569.002` | NTLM logon → privileges → admin shares → service creation → execution | [`T1021.002-smb-psexec-like.md`](detections/T1021.002-smb-psexec-like.md) | [`SMB Internals`](docs/windows-internals/T1021.002-smb-admin-shares-internals.md) |
| Pass-the-Hash / DCSync | `T1550.002`, `T1003.006` | DCSync-like activity → privileged NTLM access → remote execution → correlation | [`T1550.002-pass-the-hash.md`](detections/T1550.002-pass-the-hash.md) | [`Pass-the-Hash Internals`](docs/windows-internals/T1550.002-pass-the-hash-internals.md) |
| Kerberoasting | `T1558.003` | RC4 TGS request → unexpected source → frequency correlation → offline limitation | [`T1558.003-kerberoasting.md`](detections/T1558.003-kerberoasting.md) | [`Kerberoasting Internals`](docs/windows-internals/T1558.003-kerberoasting-internals.md) |

---

## RDP Internal Model

The RDP scenario is not treated simply as:

```text
TCP/3389
      ↓
4624
```

The internal Windows path is closer to:

```text
RDP client
      ↓
TCP/3389
      ↓
Remote Desktop Services / TermService
      ↓
NLA / CredSSP
      ↓
SSPI / Negotiate
      ↓
Kerberos or NTLM
      ↓
LSA / LSASS
      ↓
RemoteInteractive authorization
      ↓
Windows logon session
      ↓
access token
      ↓
4624 / Logon Type 10
      ↓
RDP Session ID
      ↓
WinSta0 / interactive desktop
      ↓
user shell
      ↓
cmd.exe
      ↓
post-access processes
      ↓
4688 / Sysmon
      ↓
Wazuh
```

This explains why processes launched through RDP execute on the destination Windows system rather than on the RDP client.

---

## SMB / PsExec-like Internal Model

The SMB scenario is similarly decomposed into the Windows components involved:

```text
remote SMB client
      ↓
TCP/445
      ↓
SMB NEGOTIATE
      ↓
SESSION_SETUP
      ↓
NTLM authentication
      ↓
4624 / Logon Type 3
      ↓
access token
      ↓
administrative authorization
      ↓
ADMIN$ / IPC$
      ↓
Named Pipe
      ↓
\pipe\svcctl
      ↓
DCE/RPC
      ↓
SCMR
      ↓
Service Control Manager
      ↓
services.exe
      ↓
temporary service
      ↓
SYSTEM process execution
```

This explains why the remote attacker is not directly the parent of the resulting Windows process.

The remote system requests the operation, but:

```text
Windows itself performs the local execution
```

through legitimate service-management infrastructure.

---

## Pass-the-Hash Internal Model

Pass-the-Hash is documented at the authentication level rather than described simply as:

```text
use hash instead of password
```

The relevant internal model is:

```text
password
   ↓
NT hash
   ↓
NTLM key derivation
   ↓
challenge-response
```

In Pass-the-Hash:

```text
NT hash already possessed
      ↓
NTLM key derivation
      ↓
valid challenge-response
      ↓
Windows accepts authentication
```

The NT hash itself is not simply transmitted as a password field.

The client uses it as cryptographic secret material to produce valid NTLM authentication structures.

Once authentication succeeds:

```text
Windows receives
an authenticated identity
```

not:

```text
PassTheHash = True
```

This explains why:

```text
4624 + NTLM
```

does not independently prove Pass-the-Hash.

The laboratory therefore relies on contextual correlation between:

```text
credential-access evidence
      ↓
privileged NTLM authentication
      ↓
administrative-share activity
      ↓
service creation
      ↓
process execution
```

---

## Kerberoasting: Detection and Prevention

Kerberoasting requires a different defensive approach from many remote-execution techniques.

A normal Kerberos user legitimately performs:

```text
TGS-REQ
      ↓
KDC
      ↓
TGS-REP
      ↓
service ticket
```

A Kerberoasting workflow can perform the same protocol operation:

```text
valid user
      ↓
valid TGT
      ↓
TGS-REQ
      ↓
valid service ticket
```

The difference appears after the ticket is returned.

Instead of using it only to authenticate to the service, the encrypted ticket material can be retained and tested against password candidates offline.

Conceptually:

```text
DC01
 ↓
service ticket
 ↓
client
 ↓
offline password testing
```

The Domain Controller sees:

```text
the TGS request
```

but does not see:

```text
candidate password 1
candidate password 2
candidate password 3
...
```

This means that:

```text
Event ID 4769
```

is evidence of a Kerberos service-ticket request.

It is **not** proof that Kerberoasting occurred.

---

## Why Kerberoasting Is Difficult to Detect

In a large Active Directory environment, legitimate users continuously request service tickets.

Normal sources can include:

```text
workstations
application servers
database clients
file servers
RDP sessions
VPN users
VDI sessions
scheduled workloads
monitoring platforms
management systems
```

Therefore:

```text
alert on every 4769
```

is not a viable detection model.

Even the source IP may not directly identify the original remote user.

For example:

```text
Internet user
      ↓
VPN
      ↓
RDP
      ↓
WS01
      ↓
Kerberos TGS request
      ↓
DC01
```

The KDC can observe the ticket request as originating from:

```text
WS01
```

rather than from the user's original public Internet address.

Production Kerberoasting detection therefore requires context such as:

```text
requesting account
+
requesting host
+
requested SPN
+
ticket encryption
+
number of requests
+
number of distinct SPNs
+
historical user behavior
+
historical host behavior
+
service-account risk
+
VPN / RDP / VDI context
```

---

## Kerberoasting Hardening

Because the offline password-testing stage is not visible to the Domain Controller, Kerberoasting cannot be addressed only by improving SIEM rules.

The defensive objective should also be:

```text
Even if the attacker obtains the ticket,
make the service credential impractical to recover.
```

The preferred model is:

```text
gMSA where supported
      +
high-entropy credentials
      +
automatic / controlled rotation
      +
AES
      +
remove RC4 dependencies
      +
least privilege
      +
restricted service-account use
      +
no unnecessary interactive logon
      +
SPN hygiene
```

Traditional service accounts are particularly risky when they combine:

```text
SPN
+
human-generated password
+
PasswordNeverExpires
+
RC4
+
high privileges
```

Where manually managed service accounts remain necessary, credentials should be:

```text
long
random
unique
machine-generated
```

rather than merely satisfying traditional password-complexity requirements.

Managed service identities such as:

```text
gMSA
```

provide a significantly stronger model because Active Directory manages high-entropy credentials and their rotation automatically.

---

## Hardening Improves Detection

Hardening also improves detection quality.

For example, if legitimate applications continuously generate:

```text
RC4 Kerberos tickets
```

then an RC4 alert has limited value.

If legitimate RC4 dependencies are removed:

```text
normal RC4 activity
      ↓
approaches zero
```

then:

```text
unexpected RC4 TGS request
```

becomes much more meaningful.

Therefore:

```text
hardening
      ↓
reduces legitimate noise
      ↓
improves SIEM signal quality
```

This relationship between prevention and detection is particularly important for Kerberoasting.

---

## Detection Hypotheses

The project is built around ten detection hypotheses:

| Hypothesis | Scenario | Purpose |
| --- | --- | --- |
| `H1` | RDP | Detect RDP access from the controlled attacker host to `WS01` |
| `H2` | RDP | Detect post-access command execution after RDP |
| `H3` | SMB / PsExec-like | Detect NTLM network authentication to `DC01` |
| `H4` | SMB / PsExec-like | Detect administrative share access |
| `H5` | SMB / PsExec-like | Detect remote service creation |
| `H6` | Pass-the-Hash | Detect privileged NTLM authentication compatible with credential reuse |
| `H7` | Pass-the-Hash / DCSync | Correlate DCSync-like activity with privileged access |
| `H8` | Kerberoasting | Detect an RC4 service-ticket request from an unexpected source |
| `H9` | Kerberoasting | Correlate repeated suspicious RC4 service-ticket requests |
| `H10` | Kerberoasting | Add optional process-level Kerberos network context |

Full model:

* [`detections/detection-hypotheses.md`](detections/detection-hypotheses.md)
* [`detections/detection-matrix.md`](detections/detection-matrix.md)

---

## Wazuh Rules

Custom Wazuh rules are located in:

* [`wazuh/rules/local_rules.xml`](wazuh/rules/local_rules.xml)

Rule explanation:

* [`wazuh/rules/rules-explanation.md`](wazuh/rules/rules-explanation.md)

Main custom rules:

| Rule ID | Purpose |
| ---: | --- |
| `100001` | RDP logon context |
| `100010` | Remote service creation |
| `100011` | NTLM network logon |
| `100021` | Special privileges assigned |
| `100022` | Defender-related activity followed by privileged access |
| `100030` | DCSync / replication-related activity |
| `100033` | Pass-the-Hash / DCSync correlation |
| `100040` | RC4 Kerberos service ticket from an unexpected source |
| `100041` | Repeated Kerberoasting-compatible request correlation |
| `100042` | Unusual process connecting to the Kerberos service |

The rules intentionally distinguish:

```text
single-event detection
```

from:

```text
correlation
```

For example:

```text
4769
      ↓
100040
      ↓
repeated matches
      ↓
100041
```

Rule `100041` is therefore a correlation layer built on the suspicious request detection performed by `100040`.

Rule `100042` belongs to a separate supporting endpoint/network detection branch.

---

## Telemetry Requirements

The detections require Windows and Wazuh telemetry to be correctly configured.

Main documentation:

* [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md)
* [`docs/sysmon-configuration.md`](docs/sysmon-configuration.md)
* [`docs/wazuh-sysmon-collection.md`](docs/wazuh-sysmon-collection.md)

Relevant Windows events include:

```text
4624
4625
4662
4672
4688
4769
5145
7045
```

These events represent different internal Windows mechanisms.

For example:

```text
4624
→ successful Windows logon

4662
→ operation on an Active Directory object when
  the corresponding auditing is configured

4672
→ special privileges assigned to a new logon

4688
→ process creation

4769
→ Kerberos service-ticket request

5145
→ network-share access check

7045
→ service installation
```

No individual Event ID should automatically be interpreted as proof of a MITRE ATT&CK technique.

---

## Kerberoasting Telemetry

Event ID:

```text
4769
```

provides the main Domain Controller telemetry for the Kerberoasting scenario.

Important analytical context includes:

```text
requesting account
service name / SPN
client address
ticket encryption type
ticket options
status
request frequency
```

For the controlled RC4 laboratory scenario:

```text
TicketEncryptionType = 0x17
```

represents:

```text
RC4-HMAC
```

The repository deliberately distinguishes this from:

```text
msDS-SupportedEncryptionTypes
```

which is an Active Directory capability bitmask.

These values belong to different layers and should not be confused.

---

## Evidence

The repository includes anonymized evidence for each scenario:

| Scenario | Evidence |
| --- | --- |
| RDP | [`evidence/rdp/`](evidence/rdp/) |
| SMB / PsExec-like | [`evidence/smb-psexec-like/`](evidence/smb-psexec-like/) |
| Pass-the-Hash / DCSync | [`evidence/pass-the-hash/`](evidence/pass-the-hash/) |
| Kerberoasting | [`evidence/kerberoasting/`](evidence/kerberoasting/) |

Evidence includes:

* selected Wazuh JSON alerts;
* filtered CSV summaries;
* scenario timelines.

Sensitive material is deliberately excluded, including:

```text
real passwords
complete reusable credential material
complete Kerberos tickets
private cracking artifacts
```

Public examples use placeholders where appropriate.

---

## Evidence vs Architecture

The repository explicitly distinguishes between:

```text
validated laboratory evidence
```

and:

```text
supplementary Windows behavior
```

The Windows Internals documentation may describe mechanisms or telemetry that Windows can provide even when those specific events were not collected during the original laboratory execution.

Such information is identified as:

```text
supplementary telemetry
```

rather than presented as experimentally validated evidence.

The scenario and evidence directories remain the authoritative source for:

```text
what was actually executed and observed
```

while the internals documentation explains:

```text
why Windows produced those observations
```

---

## Quick Navigation

| Purpose | File |
| --- | --- |
| Project summary | [`docs/project-summary.md`](docs/project-summary.md) |
| Lab architecture | [`docs/lab-architecture.md`](docs/lab-architecture.md) |
| Windows internals | [`docs/windows-internals/`](docs/windows-internals/) |
| RDP internals | [`docs/windows-internals/T1021.001-rdp-internals.md`](docs/windows-internals/T1021.001-rdp-internals.md) |
| SMB internals | [`docs/windows-internals/T1021.002-smb-admin-shares-internals.md`](docs/windows-internals/T1021.002-smb-admin-shares-internals.md) |
| Pass-the-Hash internals | [`docs/windows-internals/T1550.002-pass-the-hash-internals.md`](docs/windows-internals/T1550.002-pass-the-hash-internals.md) |
| Kerberoasting internals | [`docs/windows-internals/T1558.003-kerberoasting-internals.md`](docs/windows-internals/T1558.003-kerberoasting-internals.md) |
| Deployment notes | [`docs/deployment-notes.md`](docs/deployment-notes.md) |
| Detection methodology | [`docs/detection-methodology.md`](docs/detection-methodology.md) |
| Detection hypotheses | [`detections/detection-hypotheses.md`](detections/detection-hypotheses.md) |
| Detection matrix | [`detections/detection-matrix.md`](detections/detection-matrix.md) |
| Detection latencies | [`docs/detection-latencies.md`](docs/detection-latencies.md) |
| Incident reports | [`docs/incident-reports.md`](docs/incident-reports.md) |
| Wazuh rules | [`wazuh/rules/local_rules.xml`](wazuh/rules/local_rules.xml) |
| Rule explanations | [`wazuh/rules/rules-explanation.md`](wazuh/rules/rules-explanation.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |

---

## Scenario Filters

Wazuh KQL filters are available for each scenario:

* [`scenarios/rdp/wazuh-filter.kql`](scenarios/rdp/wazuh-filter.kql)
* [`scenarios/smb-psexec-like/wazuh-filter.kql`](scenarios/smb-psexec-like/wazuh-filter.kql)
* [`scenarios/pass-the-hash/wazuh-filter.kql`](scenarios/pass-the-hash/wazuh-filter.kql)
* [`scenarios/kerberoasting/wazuh-filter.kql`](scenarios/kerberoasting/wazuh-filter.kql)

---

## Project Scope

This repository is a **controlled Detection Engineering laboratory**.

The offensive actions exist only to generate reproducible Windows telemetry.

The project does not treat successful execution of a technique as the final result.

The expected workflow is:

```text
controlled test
      ↓
Windows / Active Directory behavior
      ↓
telemetry
      ↓
Wazuh detection
      ↓
correlation
      ↓
validation
      ↓
analyst interpretation
      ↓
limitations
      ↓
hardening
```

The main objective is to understand how legitimate Windows mechanisms can be abused and how defenders can distinguish that abuse from normal administration.

---

## Main Lessons

The four scenarios illustrate different detection challenges.

### RDP

```text
legitimate remote interactive access
      ↓
potential lateral movement
```

The challenge is distinguishing authorized remote administration from suspicious remote access and subsequent execution.

### SMB / PsExec-like

```text
legitimate SMB
+
legitimate administrative shares
+
legitimate Service Control Manager
      ↓
remote SYSTEM execution
```

The value comes from correlating several individually legitimate Windows operations.

### Pass-the-Hash

```text
valid NTLM response
      ↓
Windows authentication succeeds
```

The target cannot directly determine whether the response was generated from a legitimately entered password or from previously obtained NT-hash material.

Detection therefore relies heavily on context and correlation.

### Kerberoasting

```text
legitimate TGS request
      ↓
legitimate ticket
      ↓
offline password testing
```

The Domain Controller cannot directly observe the attacker's offline password-testing loop.

Therefore the strongest defensive model combines:

```text
detection
+
service-account hardening
```

rather than depending on Event ID `4769` alone.

---

## Project Status

Current repository evolution:

```text
1.4.0 — Windows / Active Directory internals documentation
```

This extension adds deep technical documentation connecting the controlled techniques with the Windows components, authentication protocols, authorization mechanisms and telemetry that make the detections possible.

It also extends the Kerberoasting scenario with a defensive model covering:

```text
Kerberos internals
service-account credential strength
gMSA
AES migration
RC4 reduction
least privilege
SPN hygiene
behavioral baselining
offline-cracking visibility limitations
```

See:

* [`CHANGELOG.md`](CHANGELOG.md)

---

## Author

**Benjamín Gerardo Gutiérrez García**
