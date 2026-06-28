# RDP Scenario Execution

This scenario simulates RDP-based lateral movement from the attack simulation host to the Windows workstation `WS01`.

The objective is not to perform complex post-exploitation, but to generate observable remote access and post-access activity that can be collected and correlated by Wazuh.

## Target

| Field | Value |
|---|---|
| Source host | Kali-ATK01 |
| Source IP | 192.168.56.40 |
| Target host | WS01 |
| Target IP | 192.168.56.30 |
| Technique | T1021.001 - Remote Desktop Protocol |

## Execution Command

```bash
xfreerdp /v:192.168.56.30 /u:'LAB\<standard_user>' /p:'<PASSWORD>' /cert:ignore /sec:tls /dynamic-resolution +clipboard
