# Wazuh Detection Lab

A **Blue Team detection laboratory** for analyzing Windows lateral movement and credential-access techniques with **Wazuh**, **Windows Event Logs**, **Sysmon** and **MITRE ATT&CK**.

The lab reproduces four controlled scenarios:

* **RDP lateral movement** — `T1021.001`
* **SMB / PsExec-like remote execution** — `T1021.002` / `T1569.002`
* **Pass-the-Hash with DCSync-related evidence** — `T1550.002` / `T1003.006`
* **Kerberoasting** — `T1558.003`

The repository focuses on detection engineering, not on offensive tooling.

It also includes a dedicated **Windows / Active Directory Internals** section explaining what happens inside Windows during each technique and how those internal mechanisms produce the telemetry later analyzed by Wazuh.

```text
MITRE technique → Windows internals → detection hypothesis → telemetry → Wazuh rule → evidence → analyst interpretation
```

---

## Overview

This project documents a small Active Directory laboratory used to validate Wazuh detections for lateral movement and credential-access activity.

The environment includes:

| Host            | Role                               |      IP Address |
| --------------- | ---------------------------------- | --------------: |
| `Wazuh-Manager` | SIEM / monitoring server           | `192.168.56.10` |
| `DC01`          | Domain Controller and Kerberos KDC | `192.168.56.20` |
| `WS01`          | Domain workstation                 | `192.168.56.30` |
| `Kali-ATK01`    | Controlled attack simulation host  | `192.168.56.40` |

Full architecture:

* [`docs/lab-architecture.md`](docs/lab-architecture.md)

---

## What This Repository Contains

| Folder                                           | Content                                                                                  |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| [`docs/`](docs/)                                 | Architecture, deployment notes, telemetry configuration, latencies and incident reports |
| [`docs/windows-internals/`](docs/windows-internals/) | Windows / Active Directory internals behind the reproduced techniques                 |
| [`detections/`](detections/)                     | Detection hypotheses, detection matrix and MITRE technique write-ups                    |
| [`scenarios/`](scenarios/)                       | Scenario execution notes, timelines and Wazuh KQL filters                               |
| [`evidence/`](evidence/)                         | Anonymized JSON alerts and CSV summaries                                                 |
| [`wazuh/rules/`](wazuh/rules/)                   | Wazuh custom rules and rule explanations                                                 |

---

## Windows / Active Directory Internals

The repository includes a dedicated technical section explaining **what happens inside Windows before and during each controlled scenario**.

The objective is to connect:

```text
controlled action
      ↓
Windows protocol / component
      ↓
authentication and authorization
      ↓
Windows operation
      ↓
Windows telemetry
      ↓
Wazuh detection
```

These documents explain the internal mechanisms behind the events used by the detections instead of treating Event IDs as isolated indicators.

| Technique | Main concepts | Documentation |
| --------- | ------------- | ------------- |
| RDP — `T1021.001` | `TermService`, RDP, NLA, CredSSP, Kerberos/NTLM, LSASS, Logon Type 10, access tokens, RDP sessions and process execution | [`RDP Internals`](docs/windows-internals/T1021.001-rdp-internals.md) |
| SMB / Admin Shares — `T1021.002` | SMB negotiation, NTLM, Logon Type 3, `ADMIN$`, `IPC$`, Named Pipes, DCE/RPC, SCMR, Service Control Manager and SYSTEM execution | [`SMB Internals`](docs/windows-internals/T1021.002-smb-admin-shares-internals.md) |
| Pass-the-Hash — `T1550.002` | NT hashes, NTLM challenge-response, authentication, logon sessions, access tokens, PsExec execution and detection limitations | [`Pass-the-Hash Internals`](docs/windows-internals/T1550.002-pass-the-hash-internals.md) |
| Kerberoasting — `T1558.003` | Kerberos, KDC, TGT/TGS, SPNs, service-account keys, `4769`, offline password testing, detection limitations and hardening | [`Kerberoasting Internals`](docs/windows-internals/T1558.003-kerberoasting-internals.md) |

The Kerberoasting internals document also covers the defensive implications of offline password testing and service-account hardening, including strong credentials, gMSA, AES, RC4 reduction, least privilege and SPN hygiene.

---

## Detection Scenarios

| Scenario               | Technique                | Main Detection Chain                                              | Write-up                                                                  |
| ---------------------- | ------------------------ | ----------------------------------------------------------------- | ------------------------------------------------------------------------- |
| RDP                    | `T1021.001`              | RDP logon → post-access process execution                         | [`T1021.001-rdp.md`](detections/T1021.001-rdp.md)                         |
| SMB / PsExec-like      | `T1021.002`, `T1569.002` | NTLM logon → privileges → admin shares → service creation         | [`T1021.002-smb-psexec-like.md`](detections/T1021.002-smb-psexec-like.md) |
| Pass-the-Hash / DCSync | `T1550.002`, `T1003.006` | DCSync-like activity → privileged NTLM access → correlation alert | [`T1550.002-pass-the-hash.md`](detections/T1550.002-pass-the-hash.md)     |
| Kerberoasting          | `T1558.003`              | RC4 TGS request → unexpected source → frequency correlation       | [`T1558.003-kerberoasting.md`](detections/T1558.003-kerberoasting.md)     |

---

## Detection Hypotheses

The project is built around ten detection hypotheses:

| Hypothesis | Scenario               | Purpose                                                                |
| ---------- | ---------------------- | ---------------------------------------------------------------------- |
| `H1`       | RDP                    | Detect RDP access from the controlled attacker host to `WS01`          |
| `H2`       | RDP                    | Detect post-access command execution after RDP                         |
| `H3`       | SMB / PsExec-like      | Detect NTLM network authentication to `DC01`                           |
| `H4`       | SMB / PsExec-like      | Detect administrative share access                                    |
| `H5`       | SMB / PsExec-like      | Detect remote service creation                                        |
| `H6`       | Pass-the-Hash          | Detect privileged NTLM authentication compatible with credential reuse |
| `H7`       | Pass-the-Hash / DCSync | Correlate DCSync-like activity with privileged access                  |
| `H8`       | Kerberoasting          | Detect an RC4 service-ticket request from an unexpected source         |
| `H9`       | Kerberoasting          | Correlate repeated suspicious RC4 service-ticket requests              |
| `H10`      | Kerberoasting          | Add optional process-level Kerberos network context                    |

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

|  Rule ID | Purpose                                                  |
| -------: | -------------------------------------------------------- |
| `100001` | RDP logon context                                        |
| `100010` | Remote service creation                                  |
| `100011` | NTLM network logon                                       |
| `100021` | Special privileges assigned                              |
| `100022` | Defender-related activity followed by privileged access  |
| `100030` | DCSync / secretsdump-like activity                       |
| `100033` | Pass-the-Hash / DCSync correlation                       |
| `100040` | RC4 Kerberos service ticket from an unexpected source    |
| `100041` | Repeated Kerberoasting-compatible request correlation    |
| `100042` | Unusual process connecting to the Kerberos service       |

---

## Telemetry Requirements

The detections require Windows and Wazuh telemetry to be correctly configured.

Main documentation:

* [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md)
* [`docs/sysmon-configuration.md`](docs/sysmon-configuration.md)
* [`docs/wazuh-sysmon-collection.md`](docs/wazuh-sysmon-collection.md)

Relevant Windows events include:

```text
4624, 4625, 4662, 4672, 4688, 4769, 5145, 7045
```

Event ID `4769` provides the main Domain Controller telemetry for the Kerberoasting scenario.

---

## Evidence

The repository includes anonymized evidence for each scenario:

| Scenario               | Evidence                                                 |
| ---------------------- | -------------------------------------------------------- |
| RDP                    | [`evidence/rdp/`](evidence/rdp/)                         |
| SMB / PsExec-like      | [`evidence/smb-psexec-like/`](evidence/smb-psexec-like/) |
| Pass-the-Hash / DCSync | [`evidence/pass-the-hash/`](evidence/pass-the-hash/)     |
| Kerberoasting          | [`evidence/kerberoasting/`](evidence/kerberoasting/)     |

Evidence includes:

* selected Wazuh JSON alerts;
* filtered CSV summaries;
* scenario timelines.

Sensitive passwords, complete Kerberos tickets and reusable credential material are excluded.

---

## Quick Navigation

| Purpose               | File                                                                       |
| --------------------- | -------------------------------------------------------------------------- |
| Project summary       | [`docs/project-summary.md`](docs/project-summary.md)                       |
| Lab architecture      | [`docs/lab-architecture.md`](docs/lab-architecture.md)                     |
| Windows internals     | [`docs/windows-internals/`](docs/windows-internals/)                       |
| Deployment notes      | [`docs/deployment-notes.md`](docs/deployment-notes.md)                     |
| Detection methodology | [`docs/detection-methodology.md`](docs/detection-methodology.md)           |
| Detection hypotheses  | [`detections/detection-hypotheses.md`](detections/detection-hypotheses.md) |
| Detection matrix      | [`detections/detection-matrix.md`](detections/detection-matrix.md)         |
| Detection latencies   | [`docs/detection-latencies.md`](docs/detection-latencies.md)               |
| Incident reports      | [`docs/incident-reports.md`](docs/incident-reports.md)                     |
| Changelog             | [`CHANGELOG.md`](CHANGELOG.md)                                             |

---

## Scenario Filters

Wazuh KQL filters are available for each scenario:

* [`scenarios/rdp/wazuh-filter.kql`](scenarios/rdp/wazuh-filter.kql)
* [`scenarios/smb-psexec-like/wazuh-filter.kql`](scenarios/smb-psexec-like/wazuh-filter.kql)
* [`scenarios/pass-the-hash/wazuh-filter.kql`](scenarios/pass-the-hash/wazuh-filter.kql)
* [`scenarios/kerberoasting/wazuh-filter.kql`](scenarios/kerberoasting/wazuh-filter.kql)

---

## Project Status

Current public version:

```text
1.3.0 — Kerberoasting detection extension
```

See:

* [`CHANGELOG.md`](CHANGELOG.md)

---

## Author

**Benjamín Gerardo Gutiérrez García**
