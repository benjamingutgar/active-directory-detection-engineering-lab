# Wazuh Lateral Movement Detection Lab

A reproducible **Blue Team detection laboratory** for identifying Windows lateral movement techniques using **Wazuh**, **Windows Event Logs**, **Sysmon** and **MITRE ATT&CK**.

This repository documents a controlled Active Directory laboratory designed to detect and analyze three lateral movement scenarios:

- **RDP-based lateral movement**.
- **SMB / PsExec-like remote execution**.
- **Pass-the-Hash with DCSync-related evidence**.

The goal of the project is not only to provide Wazuh rules, but to explain the full detection reasoning behind them:

```text
MITRE technique → detection hypothesis → telemetry prerequisite → Wazuh rule → evidence → analyst interpretation
```

---

## Table of Contents

- [Project Overview](#project-overview)
- [Main Objectives](#main-objectives)
- [Detected Techniques](#detected-techniques)
- [Laboratory Architecture](#laboratory-architecture)
- [Repository Structure](#repository-structure)
- [Recommended Reading Order](#recommended-reading-order)
- [Detection Hypotheses](#detection-hypotheses)
- [Detection Logic by Scenario](#detection-logic-by-scenario)
- [Wazuh Rules](#wazuh-rules)
- [Telemetry Requirements](#telemetry-requirements)
- [Evidence Included](#evidence-included)
- [Detection Latencies](#detection-latencies)
- [How to Use This Repository](#how-to-use-this-repository)
- [Project Status](#project-status)
- [Author](#author)

---

## Project Overview

This project presents the design, deployment and validation of a Wazuh-based SIEM laboratory for detecting lateral movement in a Windows Active Directory environment.

The laboratory is intentionally small and reproducible. It is composed of:

- one Wazuh server;
- one Windows Server domain controller;
- one Windows workstation joined to the domain;
- one Kali Linux host used as the controlled attack simulation machine.

The project focuses on **observable defensive telemetry** rather than offensive tooling.

The main idea is that lateral movement is difficult to detect from a single event. Many Windows events are legitimate when analyzed in isolation. The detection value comes from correlating several signals:

```text
authentication → privileges → administrative access → service creation → process execution → correlation
```

---

## Main Objectives

| Objective | Description |
|---|---|
| **Design a controlled lab** | Build a small Windows Active Directory environment suitable for lateral movement simulation |
| **Deploy Wazuh** | Use Wazuh as the central SIEM for log collection, normalization, rule processing and alert review |
| **Collect relevant telemetry** | Enable Windows Security, Sysmon and Wazuh agent collection |
| **Simulate lateral movement** | Execute controlled RDP, SMB/PsExec-like and Pass-the-Hash scenarios |
| **Build detection logic** | Create and document Wazuh rules mapped to MITRE ATT&CK |
| **Validate alerts** | Review generated alerts, JSON evidence and filtered CSV summaries |
| **Explain analyst reasoning** | Document hypotheses, telemetry, evidence, interpretation and response context |

---

## Detected Techniques

| Scenario | MITRE ATT&CK Technique | Description | Main Target |
|---|---|---|---|
| **RDP lateral movement** | `T1021.001 — Remote Desktop Protocol` | Remote interactive access to a workstation using RDP | `WS01` |
| **SMB / PsExec-like execution** | `T1021.002 — SMB/Windows Admin Shares` and `T1569.002 — Service Execution` | Remote execution through SMB, administrative shares and service creation | `DC01` |
| **Pass-the-Hash / DCSync correlation** | `T1550.002 — Pass the Hash` and `T1003.006 — DCSync` | NTLM hash reuse effects combined with DCSync-like credential access telemetry | `DC01` |

---

## Laboratory Architecture

The laboratory uses a Host-only VirtualBox network with static IP addresses.

| Host | Role | Operating System | IP Address |
|---|---|---|---|
| `Wazuh-Manager` | SIEM / monitoring server | Ubuntu Server 24.04 LTS | `192.168.56.10` |
| `DC01` | Domain Controller | Windows Server 2022 Standard | `192.168.56.20` |
| `WS01` | Domain workstation | Windows 10 Enterprise | `192.168.56.30` |
| `Kali-ATK01` | Attack simulation host | Kali Linux | `192.168.56.40` |

Main flows:

| Flow | Source | Destination | Purpose |
|---|---|---|---|
| RDP | `Kali-ATK01` | `WS01` | RDP lateral movement scenario |
| SMB | `Kali-ATK01` | `DC01` | SMB/PsExec-like and Pass-the-Hash scenarios |
| Domain services | `WS01` | `DC01` | Domain authentication and AD membership |
| Wazuh telemetry | `DC01`, `WS01` | `Wazuh-Manager` | Event forwarding and alert generation |

Full architecture documentation:

- [`docs/lab-architecture.md`](docs/lab-architecture.md)

---

## Repository Structure

```text
.
├── README.md
├── CHANGELOG.md
├── .gitignore
│
├── docs/
│   ├── lab-architecture.md
│   ├── deployment-notes.md
│   ├── windows-audit-policy.md
│   ├── sysmon-configuration.md
│   ├── wazuh-sysmon-collection.md
│   ├── detection-methodology.md
│   ├── detection-latencies.md
│   ├── incident-reports.md
│   └── project-summary.md
│
├── detections/
│   ├── detection-hypotheses.md
│   ├── detection-matrix.md
│   ├── T1021.001-rdp.md
│   ├── T1021.002-smb-psexec-like.md
│   └── T1550.002-pass-the-hash.md
│
├── scenarios/
│   ├── rdp/
│   │   ├── execution.md
│   │   ├── timeline.md
│   │   └── wazuh-filter.kql
│   │
│   ├── smb-psexec-like/
│   │   ├── execution.md
│   │   ├── timeline.md
│   │   └── wazuh-filter.kql
│   │
│   └── pass-the-hash/
│       ├── execution.md
│       ├── timeline.md
│       └── wazuh-filter.kql
│
├── evidence/
│   ├── rdp/
│   │   ├── rdp-attack-summary.csv
│   │   └── json/
│   │       ├── alert-100001-rdp-logon.json
│   │       └── alert-67027-post-access-process.json
│   │
│   ├── smb-psexec-like/
│   │   ├── smb-attack-summary.csv
│   │   └── json/
│   │       ├── alert-100011-ntlm-logon.json
│   │       ├── alert-100021-special-privileges.json
│   │       └── alert-67027-process-created.json
│   │
│   └── pass-the-hash/
│       ├── pth-attack-summary.csv
│       └── json/
│           ├── alert-100011-ntlm-logon.json
│           ├── alert-100021-special-privileges.json
│           ├── alert-100030-dcsync.json
│           ├── alert-100033-pth-correlation.json
│           ├── alert-92052-cmd-abnormal-process.json
│           └── alert-92650-service-creation.json
│
└── wazuh/
    └── rules/
        ├── local_rules.xml
        └── rules-explanation.md
```

---

## Recommended Reading Order

For a quick technical review, read the repository in this order:

| Order | File | Purpose |
|---:|---|---|
| 1 | [`docs/project-summary.md`](docs/project-summary.md) | Short project overview |
| 2 | [`docs/lab-architecture.md`](docs/lab-architecture.md) | Lab topology, IPs and communication flows |
| 3 | [`docs/deployment-notes.md`](docs/deployment-notes.md) | Recommended deployment order |
| 4 | [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md) | Required Windows audit configuration |
| 5 | [`docs/sysmon-configuration.md`](docs/sysmon-configuration.md) | Sysmon installation and purpose |
| 6 | [`docs/wazuh-sysmon-collection.md`](docs/wazuh-sysmon-collection.md) | Wazuh collection of the Sysmon channel |
| 7 | [`detections/detection-hypotheses.md`](detections/detection-hypotheses.md) | Full H1-H7 analytical model |
| 8 | [`detections/detection-matrix.md`](detections/detection-matrix.md) | Technique, telemetry and rule matrix |
| 9 | [`wazuh/rules/local_rules.xml`](wazuh/rules/local_rules.xml) | Wazuh custom rules |
| 10 | [`wazuh/rules/rules-explanation.md`](wazuh/rules/rules-explanation.md) | Explanation of each Wazuh rule |
| 11 | [`docs/detection-latencies.md`](docs/detection-latencies.md) | Measured detection latency in the lab |
| 12 | [`docs/incident-reports.md`](docs/incident-reports.md) | Incident-style interpretation of each scenario |

---

## Detection Hypotheses

The repository uses seven detection hypotheses.

A hypothesis is not the same as a rule.

A hypothesis answers:

```text
What behavior should be visible in logs if the technique was executed?
```

A Wazuh rule answers:

```text
Can the SIEM alert when this behavior appears?
```

| Hypothesis | Scenario | MITRE Technique | Main Question | Main Rules |
|---|---|---|---|---|
| **H1** | RDP | `T1021.001` | Did a remote RDP logon occur from Kali to `WS01`? | `92653`, `100001` |
| **H2** | RDP | `T1021.001` | Was there post-access command execution after the RDP session? | `67027`, `92052` |
| **H3** | SMB/PsExec-like | `T1021.002` | Did `DC01` receive NTLM network authentication from Kali? | `100011` |
| **H4** | SMB/PsExec-like | `T1021.002` | Was there access to administrative shares? | `92218`, `5145` |
| **H5** | SMB/PsExec-like | `T1021.002`, `T1569.002` | Was a remote service created on the target? | `100010`, `92307`, `92650` |
| **H6** | Pass-the-Hash | `T1550.002` | Was there privileged NTLM network authentication compatible with credential reuse? | `100011`, `100021` |
| **H7** | Pass-the-Hash / DCSync | `T1550.002`, `T1003.006` | Was DCSync-like activity correlated with privileged access? | `100030`, `100033` |

Full explanation:

- [`detections/detection-hypotheses.md`](detections/detection-hypotheses.md)

---

## Detection Logic by Scenario

## RDP — `T1021.001`

The RDP scenario is based on this chain:

```text
RDP logon → post-access process execution
```

Main files:

| File | Purpose |
|---|---|
| [`detections/T1021.001-rdp.md`](detections/T1021.001-rdp.md) | RDP detection write-up |
| [`scenarios/rdp/execution.md`](scenarios/rdp/execution.md) | Execution notes |
| [`scenarios/rdp/timeline.md`](scenarios/rdp/timeline.md) | Timeline |
| [`scenarios/rdp/wazuh-filter.kql`](scenarios/rdp/wazuh-filter.kql) | Wazuh query filter |
| [`evidence/rdp/rdp-attack-summary.csv`](evidence/rdp/rdp-attack-summary.csv) | Filtered evidence summary |
| [`evidence/rdp/json/alert-100001-rdp-logon.json`](evidence/rdp/json/alert-100001-rdp-logon.json) | RDP contextual alert |
| [`evidence/rdp/json/alert-67027-post-access-process.json`](evidence/rdp/json/alert-67027-post-access-process.json) | Post-access process evidence |

Main Wazuh filter:

```kql
agent.name:WS01 AND rule.id:(100001 OR 92653 OR 92052 OR 67027)
```

---

## SMB / PsExec-like — `T1021.002`

The SMB/PsExec-like scenario is based on this chain:

```text
NTLM network logon → privileged session → administrative share access → remote service creation → process execution
```

Main files:

| File | Purpose |
|---|---|
| [`detections/T1021.002-smb-psexec-like.md`](detections/T1021.002-smb-psexec-like.md) | SMB/PsExec-like detection write-up |
| [`scenarios/smb-psexec-like/execution.md`](scenarios/smb-psexec-like/execution.md) | Execution notes |
| [`scenarios/smb-psexec-like/timeline.md`](scenarios/smb-psexec-like/timeline.md) | Timeline |
| [`scenarios/smb-psexec-like/wazuh-filter.kql`](scenarios/smb-psexec-like/wazuh-filter.kql) | Wazuh query filter |
| [`evidence/smb-psexec-like/smb-attack-summary.csv`](evidence/smb-psexec-like/smb-attack-summary.csv) | Filtered evidence summary |
| [`evidence/smb-psexec-like/json/alert-100011-ntlm-logon.json`](evidence/smb-psexec-like/json/alert-100011-ntlm-logon.json) | NTLM network logon evidence |
| [`evidence/smb-psexec-like/json/alert-100021-special-privileges.json`](evidence/smb-psexec-like/json/alert-100021-special-privileges.json) | Privileged session evidence |
| [`evidence/smb-psexec-like/json/alert-67027-process-created.json`](evidence/smb-psexec-like/json/alert-67027-process-created.json) | Process execution evidence |

Main Wazuh filter:

```kql
agent.name:DC01 AND rule.id:(100010 OR 100011 OR 100021 OR 92218 OR 92307 OR 92650 OR 67027 OR 92052)
```

---

## Pass-the-Hash / DCSync — `T1550.002`

The Pass-the-Hash scenario is based on this chain:

```text
DCSync-like activity → privileged NTLM authentication → critical correlation alert
```

Main files:

| File | Purpose |
|---|---|
| [`detections/T1550.002-pass-the-hash.md`](detections/T1550.002-pass-the-hash.md) | Pass-the-Hash / DCSync detection write-up |
| [`scenarios/pass-the-hash/execution.md`](scenarios/pass-the-hash/execution.md) | Execution notes |
| [`scenarios/pass-the-hash/timeline.md`](scenarios/pass-the-hash/timeline.md) | Timeline |
| [`scenarios/pass-the-hash/wazuh-filter.kql`](scenarios/pass-the-hash/wazuh-filter.kql) | Wazuh query filter |
| [`evidence/pass-the-hash/pth-attack-summary.csv`](evidence/pass-the-hash/pth-attack-summary.csv) | Filtered evidence summary |
| [`evidence/pass-the-hash/json/alert-100030-dcsync.json`](evidence/pass-the-hash/json/alert-100030-dcsync.json) | DCSync-like activity |
| [`evidence/pass-the-hash/json/alert-100033-pth-correlation.json`](evidence/pass-the-hash/json/alert-100033-pth-correlation.json) | Critical correlation alert |
| [`evidence/pass-the-hash/json/alert-100011-ntlm-logon.json`](evidence/pass-the-hash/json/alert-100011-ntlm-logon.json) | NTLM network logon |
| [`evidence/pass-the-hash/json/alert-100021-special-privileges.json`](evidence/pass-the-hash/json/alert-100021-special-privileges.json) | Privileged session |
| [`evidence/pass-the-hash/json/alert-92650-service-creation.json`](evidence/pass-the-hash/json/alert-92650-service-creation.json) | Suspicious service creation |
| [`evidence/pass-the-hash/json/alert-92052-cmd-abnormal-process.json`](evidence/pass-the-hash/json/alert-92052-cmd-abnormal-process.json) | Abnormal command execution |

Main Wazuh filter:

```kql
agent.name:DC01 AND rule.id:(100030 OR 100033 OR 100011 OR 100021 OR 92650 OR 92052)
```

---

## Wazuh Rules

The main custom Wazuh rules are located in:

- [`wazuh/rules/local_rules.xml`](wazuh/rules/local_rules.xml)

Rule explanations are located in:

- [`wazuh/rules/rules-explanation.md`](wazuh/rules/rules-explanation.md)

| Rule ID | Purpose | Main Technique |
|---:|---|---|
| `100001` | RDP logon context for the controlled laboratory user | `T1021.001` |
| `100010` | Remote service creation compatible with PsExec-like behavior | `T1021.002`, `T1569.002` |
| `100011` | NTLM network logon indicator | `T1021.002`, `T1550.002` |
| `100021` | Special privileges assigned to a non-system account | `T1078`, `T1550.002` |
| `100022` | Defender-related activity followed by privileged access | `T1550.002`, `T1562.001` |
| `100030` | DCSync / secretsdump-like activity | `T1003.006` |
| `100033` | Critical Pass-the-Hash / DCSync correlation | `T1550.002`, `T1003.006` |

---

## Telemetry Requirements

The detections require proper telemetry collection.

Wazuh cannot alert on events that Windows does not generate or that the Wazuh agent does not collect.

| Telemetry | Required For | Documentation |
|---|---|---|
| Windows logon auditing | `4624`, `4625`, RDP, SMB and NTLM activity | [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md) |
| Special logon auditing | `4672` privileged sessions | [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md) |
| Process creation auditing | `4688` post-access activity | [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md) |
| Detailed file share auditing | `5145` administrative share access | [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md) |
| Directory Service Access auditing | `4662` DCSync-like activity | [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md) |
| Sysmon | Optional process enrichment | [`docs/sysmon-configuration.md`](docs/sysmon-configuration.md) |
| Sysmon Wazuh collection | Sysmon Event Channel ingestion | [`docs/wazuh-sysmon-collection.md`](docs/wazuh-sysmon-collection.md) |

---

## Evidence Included

This repository includes **anonymized evidence**.

Evidence is organized by scenario:

```text
evidence/
├── rdp/
├── smb-psexec-like/
└── pass-the-hash/
```

Included evidence types:

| Evidence Type | Description |
|---|---|
| CSV summaries | Filtered alert summaries for each scenario |
| JSON alerts | Selected anonymized Wazuh alerts |
| Scenario timelines | Markdown timelines describing the observed chain |

Sensitive values are represented with placeholders such as:

```text
<standard_user>
<privileged_user>
<PASSWORD>
<NTLM_HASH>
<SID_DOMAIN>
<SOURCE_PORT>
```

---

## Detection Latencies

The controlled lab measured detection latency for each scenario.

Full details:

- [`docs/detection-latencies.md`](docs/detection-latencies.md)

Summary:

| Scenario | Measured Rule | Average Latency | Evidence Quality |
|---|---:|---:|---|
| RDP | `100001` | `20.557 s` | Medium / High |
| SMB / PsExec-like | `100010` | `13.336 s` | High |
| Pass-the-Hash | `100011` as early signal | `11.056 s` | High correlated |

Important distinction:

```text
early signal ≠ strongest alert
```

For Pass-the-Hash, `100011` is an early NTLM signal, but `100033` is the strongest correlated alert.

---

## How to Use This Repository

## 1. Review the Lab Design

Start with:

- [`docs/lab-architecture.md`](docs/lab-architecture.md)
- [`docs/deployment-notes.md`](docs/deployment-notes.md)

## 2. Configure Telemetry

Review:

- [`docs/windows-audit-policy.md`](docs/windows-audit-policy.md)
- [`docs/sysmon-configuration.md`](docs/sysmon-configuration.md)
- [`docs/wazuh-sysmon-collection.md`](docs/wazuh-sysmon-collection.md)

## 3. Review the Wazuh Rules

Read:

- [`wazuh/rules/local_rules.xml`](wazuh/rules/local_rules.xml)
- [`wazuh/rules/rules-explanation.md`](wazuh/rules/rules-explanation.md)

## 4. Execute a Scenario

Use the scenario notes:

- [`scenarios/rdp/execution.md`](scenarios/rdp/execution.md)
- [`scenarios/smb-psexec-like/execution.md`](scenarios/smb-psexec-like/execution.md)
- [`scenarios/pass-the-hash/execution.md`](scenarios/pass-the-hash/execution.md)

## 5. Filter Alerts in Wazuh

Use the scenario KQL filters:

- [`scenarios/rdp/wazuh-filter.kql`](scenarios/rdp/wazuh-filter.kql)
- [`scenarios/smb-psexec-like/wazuh-filter.kql`](scenarios/smb-psexec-like/wazuh-filter.kql)
- [`scenarios/pass-the-hash/wazuh-filter.kql`](scenarios/pass-the-hash/wazuh-filter.kql)

## 6. Interpret the Alerts

Read:

- [`detections/detection-hypotheses.md`](detections/detection-hypotheses.md)
- [`detections/detection-matrix.md`](detections/detection-matrix.md)
- [`docs/incident-reports.md`](docs/incident-reports.md)

---

## Project Status

Current public repository version:

```text
1.2.x — Detection documentation and repository consistency improvements
```

See:

- [`CHANGELOG.md`](CHANGELOG.md)

---

## Author

**Benjamín Gerardo Gutiérrez García**

- MITRE ATT&CK mapping;
- Blue Team detection engineering.
