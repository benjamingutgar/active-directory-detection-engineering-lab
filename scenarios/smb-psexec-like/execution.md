# SMB / PsExec-like Scenario Execution

This scenario simulates SMB-based lateral movement and PsExec-like remote execution from the attack simulation host to the domain controller `DC01`.

The objective is to generate observable telemetry related to NTLM network authentication, privileged session creation and remote process execution.

## Target

| Field | Value |
|---|---|
| Source host | Kali-ATK01 |
| Source IP | 192.168.56.40 |
| Target host | DC01 |
| Target IP | 192.168.56.20 |
| Technique | T1021.002 - SMB / Windows Admin Shares |

## Execution Command

```bash
crackmapexec smb 192.168.56.20 -d LAB -u <privileged_user> -p '<PASSWORD>' -x 'whoami' --exec-method smbexec
