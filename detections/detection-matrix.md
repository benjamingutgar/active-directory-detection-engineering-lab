# Detection Matrix

This matrix summarizes the relationship between simulated lateral movement techniques, telemetry prerequisites, Wazuh rules, detection confidence, false-positive risk and production readiness.

The purpose of this file is to provide a compact operational view of the project.

## 1. Main Detection Matrix

| Technique | Scenario | Main Events | Wazuh Rules | Prerequisite Telemetry | False-Positive Risk | Evidence Quality | Production Readiness |
|---|---|---|---|---|---|---|---|
| `T1021.001` | RDP lateral movement | `4624`, `4688`, `4634`, `4647`, optional Sysmon Event ID `1` | `92653`, `100001`, `92052`, `67027` | Logon auditing, process creation auditing, command-line logging, Wazuh Windows agent on `WS01` | Medium | Medium / High | Needs tuning |
| `T1021.002` | SMB / PsExec-like execution | `4624`, `4672`, `5145`, `7045`, `4688` | `100011`, `100021`, `100010`, `92218`, `92307`, `92650`, `92052` | Logon auditing, special logon auditing, detailed file share auditing, service creation telemetry, Wazuh Windows agent on `DC01` | Medium / High | High | Needs tuning |
| `T1550.002`, `T1003.006` | Pass-the-Hash / DCSync correlation | `4624`, `4672`, `4662`, `5145`, `7045`, `4688` | `100011`, `100021`, `100030`, `100033`, `92650`, `92052` | Logon auditing, special logon auditing, Directory Service Access auditing, DCSync-related `4662` visibility, Wazuh Windows agent on `DC01` | Medium | High correlated | Prototype / needs tuning |

## 2. Hypothesis Coverage

| Hypothesis | Technique | Scenario | Main Rules | Evidence |
|---|---|---|---|---|
| H1 | `T1021.001` | RDP access | `92653`, `100001` | RDP logon from Kali-ATK01 to `WS01` |
| H2 | `T1021.001` | RDP post-access | `67027`, `92052`, `100001` | Post-access process execution on `WS01` |
| H3 | `T1021.002` | SMB authentication | `100011` | Logon Type 3 / NTLM toward `DC01` |
| H4 | `T1021.002` | Administrative shares | `92218`, `5145` | Access to `ADMIN$`, `C$` or `IPC$` |
| H5 | `T1021.002`, `T1569.002` | PsExec-like execution | `100010`, `92307`, `92650` | Remote service creation with suspicious `ImagePath` |
| H6 | `T1550.002` | Pass-the-Hash authentication effect | `100011`, `100021` | NTLM authentication with special privileges |
| H7 | `T1550.002`, `T1003.006` | Pass-the-Hash / DCSync correlation | `100030`, `100033` | DCSync-like activity and privileged access correlation |

## 3. Rule-Level Matrix

| Rule ID | Main Purpose | Event Basis | MITRE Mapping | Detection Value | Limitation |
|---:|---|---|---|---|---|
| `92653` | Native RDP-related detection | `4624` / RDP context | `T1021.001` | Identifies RDP access | RDP can be legitimate |
| `100001` | RDP post-access context | RDP or process context depending on rule version | `T1021.001` | Adds controlled lab context to RDP activity | Requires tuning to the real lab username |
| `67027` | Process creation | `4688` | Supporting telemetry | Shows post-access commands | Low severity by itself |
| `92052` | Abnormal command prompt / suspicious command execution | Process telemetry | Supporting telemetry | Helps identify command execution | Needs context |
| `100011` | NTLM network logon | `4624`, Logon Type `3`, NTLM | `T1021.002`, `T1550.002` | Early signal for SMB/PtH chains | High false-positive risk if isolated |
| `100021` | Special privileges assigned to non-system account | `4672` | `T1078`, `T1550.002` | Identifies privileged session context | Admin logons are common |
| `92218` | Administrative share access | `5145` | `T1021.002` | Supports admin share abuse hypothesis | Admin shares can be legitimate |
| `100010` | Remote service creation | `7045` | `T1021.002`, `T1569.002` | Strong PsExec-like indicator | Some admin tools create services |
| `92307` | Native suspicious service or execution behavior | Service/process telemetry | `T1021.002`, `T1569.002` | Supporting high-signal native detection | Depends on Wazuh ruleset behavior |
| `92650` | Suspicious service creation from Windows root path | `7045` | `T1021.002`, `T1569.002` | Strong supporting service creation evidence | Needs service path review |
| `100030` | DCSync-like activity | `4662` with replication permissions | `T1003.006` | High-value credential access signal | Requires Directory Service Access telemetry |
| `100033` | DCSync + privileged access correlation | `100030` + `100021` | `T1550.002`, `T1003.006` | Highest-confidence correlation in the lab | Does not directly observe the NTLM hash |

## 4. Evidence Quality

| Scenario | Evidence Quality | Reason |
|---|---|---|
| RDP | Medium / High | The lab observes remote access and post-access execution, but RDP is a legitimate administration protocol |
| SMB / PsExec-like | High | The chain combines NTLM authentication, privileges, administrative shares, service creation and process execution |
| Pass-the-Hash / DCSync | High correlated | The chain combines DCSync-like evidence, privileged NTLM access and a critical correlation rule |

## 5. False-Positive Risk

| Scenario | Risk | Explanation |
|---|---|---|
| RDP | Medium | Helpdesk, remote support and administrators may legitimately use RDP |
| SMB / PsExec-like | Medium / High | Backup agents, endpoint management tools, software deployment systems and administrators may use SMB and remote service creation |
| Pass-the-Hash / DCSync | Medium | NTLM privileged logons may be legitimate, but DCSync-like behavior by non-machine accounts is higher signal |

## 6. Production Readiness Definitions

| Readiness Level | Meaning |
|---|---|
| Prototype | Validated in a controlled lab, not ready for production without tuning |
| Needs tuning | Detection logic is useful but requires allowlists, baselines and environment-specific thresholds |
| Production-ready | Suitable for production after validation with real traffic and documented false-positive handling |

Current repository status:

| Scenario | Readiness |
|---|---|
| RDP | Needs tuning |
| SMB / PsExec-like | Needs tuning |
| Pass-the-Hash / DCSync | Prototype / needs tuning |

## 7. Operational Interpretation

The detections should be read as chains, not isolated alerts.

### RDP

```text
RDP logon → post-access command execution
```

### SMB / PsExec-like

```text
NTLM network logon → special privileges → admin share access → service creation → process execution
```

### Pass-the-Hash / DCSync

```text
DCSync-like activity → NTLM privileged access → correlation alert
```

## 8. Key Takeaway

The strongest value of the repository is not only the Wazuh rules. It is the documented relationship between:

```text
telemetry prerequisites → detection hypotheses → Wazuh rules → evidence → analyst interpretation → limitations
```

That relationship is what makes the lab reusable by another Blue Team analyst.
