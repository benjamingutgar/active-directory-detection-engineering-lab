# Project Summary

This project presents the design and implementation of a SIEM laboratory using Wazuh to detect lateral movement and credential-access techniques in a Windows and Active Directory environment.

The laboratory was built under local resource constraints, using a single physical host and several virtual machines. The main goal was to create a realistic but reproducible defensive detection environment.

The project combines:

- Windows event-log collection;
- Sysmon telemetry;
- Wazuh agent deployment;
- custom Wazuh rules;
- frequency and temporal correlation;
- MITRE ATT&CK mapping;
- sanitized technical evidence;
- analyst-oriented documentation;
- detection limitations and false-positive analysis.

---

## Laboratory Components

| System | Role |
|---|---|
| `Wazuh-Manager` | Central SIEM, indexer and dashboard |
| `DC01` | Active Directory Domain Controller and Kerberos KDC |
| `WS01` | Domain-joined Windows workstation |
| `Kali-ATK01` | Controlled offensive host |

The main laboratory network uses the range:

```text
192.168.56.0/24
