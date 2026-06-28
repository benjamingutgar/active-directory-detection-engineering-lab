# SMB / PsExec-like Scenario Execution

This scenario simulates **SMB-based lateral movement** and **PsExec-like remote execution** from the attack simulation host to the domain controller `DC01`.

The objective is to generate observable telemetry related to:

- NTLM network authentication;
- privileged session creation;
- administrative share access;
- remote service creation;
- process execution.

---

## Target

| Field | Value |
|---|---|
| Source host | `Kali-ATK01` |
| Source IP | `192.168.56.40` |
| Target host | `DC01` |
| Target IP | `192.168.56.20` |
| Technique | `T1021.002 — SMB / Windows Admin Shares` |
| Related technique | `T1569.002 — Service Execution` |
| Main hypotheses | `H3`, `H4`, `H5` |

---

## Execution Command

```bash
crackmapexec smb 192.168.56.20 -d LAB -u <privileged_user> -p '<PASSWORD>' -x 'whoami' --exec-method smbexec
```

---

## Expected Behavior

```text
NTLM network logon → privileged session → administrative share access → remote service creation → process execution
```

---

## Expected Wazuh Rules

| Rule ID | Meaning |
|---:|---|
| `100011` | NTLM network logon |
| `100021` | Special privileges assigned |
| `92218` | Administrative share access |
| `100010` | Remote service creation compatible with PsExec-like behavior |
| `92307` | Native suspicious service / execution behavior |
| `92650` | Suspicious service creation |
| `67027` | Process creation |
| `92052` | Abnormal command execution context |

---

## Wazuh Filter

```kql
agent.name:DC01 AND rule.id:(100010 OR 100011 OR 100021 OR 92218 OR 92307 OR 92650 OR 67027 OR 92052)
```

---

## Analyst Note

A single NTLM network logon is not enough to attribute malicious behavior.

The detection becomes stronger when NTLM authentication is followed by privileged access, administrative share access and service creation on the target host.
