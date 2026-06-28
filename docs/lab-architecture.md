# Lab Architecture

## Purpose

This document describes the virtual laboratory used to simulate and detect lateral movement techniques in a Windows Active Directory environment with Wazuh.

The lab was designed as a minimum viable corporate-like network. Its goal is not to reproduce a full enterprise infrastructure, but to provide enough realism to observe authentication, privilege assignment, administrative share access, service creation, process execution and directory replication events.

The laboratory supports three detection scenarios:

| Scenario | MITRE ATT&CK technique | Main target |
|---|---|---|
| RDP lateral movement | T1021.001 - Remote Desktop Protocol | WS01 |
| SMB / PsExec-like remote execution | T1021.002 - SMB / Windows Admin Shares | DC01 |
| Pass the Hash with DCSync-related evidence | T1550.002 - Pass the Hash / T1003.006 - DCSync | DC01 |

---

## Logical Topology

```text
                         +----------------------+
                         |    Wazuh-Manager     |
                         | Ubuntu Server 24.04  |
                         |   192.168.56.10      |
                         | SIEM / Indexer / UI  |
                         +----------^-----------+
                                    |
                                    | Wazuh agent traffic
                                    |
        ---------------------------------------------------------
        |                 Host-only network                     |
        |                  192.168.56.0/24                      |
        ---------------------------------------------------------
             |                         |                       |
             |                         |                       |
+------------+------------+  +---------+----------+  +---------+----------+
|          DC01           |  |        WS01        |  |      Kali-ATK01    |
| Windows Server 2022     |  | Windows 10 Ent.   |  |      Kali Linux    |
| Domain Controller       |  | Domain workstation|  | Attack simulation  |
| 192.168.56.20           |  | 192.168.56.30     |  | 192.168.56.40      |
+-------------------------+  +-------------------+  +--------------------+
