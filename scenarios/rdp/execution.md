# RDP Scenario Execution

This scenario simulates **RDP-based lateral movement** from the attack simulation host to the Windows workstation `WS01`.

The objective is not to perform complex post-exploitation. The objective is to generate observable remote access and post-access activity that can be collected, normalized and correlated by Wazuh.

---

## Target

| Field | Value |
|---|---|
| Source host | `Kali-ATK01` |
| Source IP | `192.168.56.40` |
| Target host | `WS01` |
| Target IP | `192.168.56.30` |
| Technique | `T1021.001 — Remote Desktop Protocol` |
| Main hypotheses | `H1`, `H2` |

---

## Execution Command

```bash
xfreerdp /v:192.168.56.30 /u:'LAB\<standard_user>' /p:'<PASSWORD>' /cert:ignore /sec:tls /dynamic-resolution +clipboard
```

---

## Post-access Commands

After the RDP session was established, the following commands were executed inside the remote session:

```cmd
whoami
hostname
ipconfig
```

---

## Expected Detection Chain

```text
RDP logon → post-access command execution
```

Expected Wazuh rules:

| Rule ID | Meaning |
|---:|---|
| `92653` | Native RDP-related detection |
| `100001` | Project-specific RDP contextual rule |
| `67027` | Process creation evidence |
| `92052` | Abnormal command prompt / command execution context |

---

## Wazuh Filter

```kql
agent.name:WS01 AND rule.id:(100001 OR 92653 OR 92052 OR 67027)
```

---

## Analyst Note

A single RDP logon should not be treated as malicious by itself.

The scenario becomes more relevant when the RDP logon is followed by command execution from the authenticated user context.
