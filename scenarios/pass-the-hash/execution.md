# Pass-the-Hash Scenario Execution

This scenario simulates credential-based lateral movement using NTLM authentication material in a controlled Active Directory laboratory.

The scenario is divided into three phases:

1. Controlled remote access preparation.
2. Credential material extraction.
3. Remote authentication using NTLM hash material.

All credentials and hashes shown in this file are placeholders.

## Target

| Field | Value |
|---|---|
| Source host | Kali-ATK01 |
| Source IP | 192.168.56.40 |
| Target host | DC01 |
| Target IP | 192.168.56.20 |
| Technique | T1550.002 - Pass the Hash |
| Related technique | T1003.006 - DCSync |

## Phase 1 — Controlled Remote Access

```bash
impacket-wmiexec 'LAB/<privileged_user>:<PASSWORD>@192.168.56.20'
