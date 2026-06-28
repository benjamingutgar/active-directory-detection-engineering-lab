# Lab Architecture

This document describes the virtual laboratory used to simulate and detect lateral movement techniques in a Windows Active Directory environment using Wazuh.

The goal of the lab is not to reproduce a full enterprise network. Its goal is to provide the minimum realistic infrastructure required to generate, collect, correlate and analyze security events related to lateral movement.

## 1. Architecture Overview

The laboratory is composed of four virtual machines:

| Host | Role | Operating System | IP Address | Main Purpose |
|---|---|---|---|---|
| `Wazuh-Manager` | SIEM / monitoring server | Ubuntu Server 24.04 LTS | `192.168.56.10` | Central collection, indexing, rule processing and alert review |
| `DC01` | Domain Controller | Windows Server 2022 Standard | `192.168.56.20` | Active Directory, authentication, domain services and DC-side telemetry |
| `WS01` | Domain workstation | Windows 10 Enterprise | `192.168.56.30` | Domain-joined endpoint and RDP target |
| `Kali-ATK01` | Attack simulation host | Kali Linux | `192.168.56.40` | Controlled execution of offensive commands inside the isolated lab |

The lab follows a simple corporate-like structure:

```text
                          Host-only network: 192.168.56.0/24

        +-------------------+          Wazuh agent telemetry         +-------------------+
        |      DC01         | -------------------------------------> |   Wazuh-Manager   |
        | Domain Controller |                                        | SIEM all-in-one   |
        | 192.168.56.20     |                                        | 192.168.56.10     |
        +-------------------+                                        +-------------------+
                 ^
                 |
                 | Domain services / authentication
                 |
        +-------------------+
        |      WS01         |
        | Domain workstation|
        | 192.168.56.30     |
        +-------------------+
                 ^
                 |
                 | RDP / TCP 3389
                 |
        +-------------------+
        |    Kali-ATK01     |
        | Attack simulator  |
        | 192.168.56.40     |
        +-------------------+

        Kali-ATK01 also connects to DC01 over SMB/TCP 445 during SMB/PsExec-like
        and Pass-the-Hash scenarios.
```

## 2. Network Design

The lab uses two types of VirtualBox network adapters:

| Network Type | Purpose |
|---|---|
| Host-only | Internal communication between Wazuh, DC01, WS01 and Kali |
| NAT | Auxiliary Internet access for installation, package downloads and updates |

The detection scenarios are executed over the Host-only network using the range:

```text
192.168.56.0/24
```

The NAT adapter is only used for auxiliary tasks such as installing packages, downloading Sysmon or updating systems. It is not the relevant network for detection analysis.

## 3. Why Host-only Networking Was Used

Host-only networking was selected for four main reasons:

1. **Isolation**

   The lab services are not directly exposed to the external network. This reduces the risk of accidentally exposing RDP, SMB, Wazuh components or Windows domain services outside the controlled environment.

2. **Stable attribution**

   Static IP addresses make it easier to correlate events. For example, `192.168.56.40` is always interpreted as the attack simulation host. This is important when reviewing fields such as `ipAddress`, `agent.name`, `computer`, source host and target host.

3. **Controlled traffic**

   Since the lab is isolated, most observed traffic is caused by the configured systems or by the executed scenarios. This reduces noise and makes it easier to explain why each event appears.

4. **Reproducibility**

   A fixed addressing scheme allows another analyst to reproduce the same lab structure and use the same Wazuh filters, evidence paths and scenario documentation.

<details>
<summary>Explanation: why not bridge networking?</summary>

A bridged adapter would place the virtual machines directly on the same network as the physical host. That may be useful in some labs, but it introduces unnecessary risk and noise for this project.

The purpose of this repository is not to expose a domain controller, SMB services or RDP to a real LAN. The purpose is to generate controlled telemetry and observe how Wazuh handles lateral movement indicators.

For that reason, Host-only networking is the safest and most reproducible option.
</details>

## 4. Main Communication Flows

| Flow | Source | Destination | Service / Port | Purpose |
|---|---|---|---|---|
| Kali-ATK01 → WS01 | `192.168.56.40` | `192.168.56.30` | RDP / TCP 3389 | RDP lateral movement scenario |
| Kali-ATK01 → DC01 | `192.168.56.40` | `192.168.56.20` | SMB / TCP 445 | SMB/PsExec-like and Pass-the-Hash scenarios |
| WS01 ↔ DC01 | `192.168.56.30` | `192.168.56.20` | Domain services | Domain membership, authentication and normal AD interaction |
| DC01 → Wazuh-Manager | `192.168.56.20` | `192.168.56.10` | Wazuh agent communication | Forwarding Windows events to Wazuh |
| WS01 → Wazuh-Manager | `192.168.56.30` | `192.168.56.10` | Wazuh agent communication | Forwarding Windows events to Wazuh |

## 5. Monitoring Scope

The monitored systems are:

| Host | Monitoring Status | Reason |
|---|---|---|
| `DC01` | Monitored | Generates authentication, privilege, SMB, service creation and DCSync-related events |
| `WS01` | Monitored | Generates RDP, logon and post-access process execution events |
| `Kali-ATK01` | Not monitored by Wazuh in the final detection chain | Used as the controlled origin of the simulated actions |
| `Wazuh-Manager` | Central collector | Receives, normalizes and correlates events |

Kali is intentionally treated as the origin of the activity, not as a monitored victim endpoint. The relevant detection evidence is generated on the Windows targets and collected by Wazuh.

## 6. Scenario Mapping

| Scenario | Source | Target | Main Technique | Main Telemetry |
|---|---|---|---|---|
| RDP lateral movement | Kali-ATK01 | WS01 | `T1021.001` | `4624`, `4688`, Wazuh `92653`, `100001`, `67027`, `92052` |
| SMB/PsExec-like execution | Kali-ATK01 | DC01 | `T1021.002` | `4624`, `4672`, `5145`, `7045`, Wazuh `100011`, `100021`, `100010`, `92218`, `92307`, `92650` |
| Pass-the-Hash / DCSync correlation | Kali-ATK01 | DC01 | `T1550.002`, related `T1003.006` | `4624`, `4672`, `4662`, `7045`, Wazuh `100011`, `100021`, `100030`, `100033`, `92650`, `92052` |

## 7. Design Limitations

This lab is intentionally small and controlled. That has consequences:

- It does not reproduce the volume of traffic of a real corporate network.
- It does not include concurrent legitimate administrative activity.
- It cannot measure production false positives with statistical rigor.
- It does not prove attacker intent by itself.
- It validates detection logic under controlled conditions.

The value of the lab is that it makes the detection chain observable and explainable: authentication, privileges, administrative access, service creation, process execution and DCSync-like activity can be reviewed as a sequence instead of isolated events.
