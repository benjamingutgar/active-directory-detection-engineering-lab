# wazuh-lateral-movement-detection

This repository contains the public technical material of a Master's Final Project focused on the design and implementation of a SIEM-based detection laboratory using Wazuh.

The project simulates and detects lateral movement techniques in a controlled Windows/Active Directory environment. The detection logic is based on Windows Security events, Sysmon telemetry, Wazuh rules and MITRE ATT&CK mapping.

## Project Overview

The objective of this project is to demonstrate how a lightweight SIEM deployment can detect relevant lateral movement activity in a local laboratory environment.

The lab was built using VirtualBox and includes:

| Host | Role | Operating System | IP |
|---|---|---|---|
| Wazuh-Manager | SIEM | Ubuntu 24.04 | 192.168.56.10 |
| DC01 | Domain Controller | Windows Server 2022 | 192.168.56.20 |
| WS01 | Workstation | Windows 10 Enterprise | 192.168.56.30 |
| Kali-ATK01 | Attack simulation host | Kali Linux | 192.168.56.40 |

## Detection Scope

The project focuses on the following MITRE ATT&CK techniques:

| Technique | Name | Scenario |
|---|---|---|
| T1021.001 | Remote Services: RDP | Remote Desktop lateral movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | PsExec-like remote execution |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | NTLM-based lateral movement and DCSync correlation |

## Data Sources

The detection logic uses the following telemetry sources:

- Windows Security Event Log
- Sysmon events
- Wazuh agent telemetry
- Wazuh custom rules
- MITRE ATT&CK technique mapping

## Main Windows Event IDs

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 / 4647 | Logoff events |
| 4672 | Special privileges assigned to new logon |
| 4688 | Process creation |
| 5145 | Detailed file share access |
| 7045 | Service creation |
| 4662 | Directory Service object access / DCSync-related evidence |

## Custom Wazuh Rules

| Rule ID | Description | Main Detection Purpose |
|---|---|---|
| 100001 | RDP post-access activity | Detect command execution after RDP access |
| 100010 | Remote service creation | Detect PsExec-like service creation |
| 100011 | NTLM network logon | Detect NTLM-based lateral movement indicators |
| 100021 | Special privileges assigned | Detect privileged logon context |
| 100030 | DCSync-like activity | Detect suspicious directory replication access |
| 100033 | Pass-the-Hash + DCSync correlation | Correlate NTLM logon and replication activity |

## Repository Structure

| Folder | Description |
|---|---|
| `/docs` | Public documentation, diagrams and project summary |
| `/lab` | Laboratory topology and deployment notes |
| `/wazuh` | Custom Wazuh rules and explanations |
| `/detections` | Detection logic by MITRE ATT&CK technique |
| `/evidence` | Anonymized event samples |
| `/dashboards` | Dashboard screenshots and reporting notes |

## Results Summary

The laboratory demonstrated that a local Wazuh deployment can detect relevant lateral movement indicators by correlating Windows event logs, Sysmon telemetry and custom SIEM rules.

The strongest detection results were obtained in the SMB/PsExec-like and Pass-the-Hash/DCSync scenarios, where service creation, privileged logon and directory replication events provided high-quality evidence.

The RDP scenario provided useful evidence through successful logon events and post-access command execution, although detection quality depends strongly on Windows configuration, Network Level Authentication settings and process creation logging.

## Disclaimer

This project was developed in a private, isolated and controlled laboratory environment for educational and defensive cybersecurity purposes.

No third-party systems, real organizations or unauthorized targets were used.

The published evidence has been anonymized. Virtual machine images, credentials, hashes and raw event logs are not included in this repository for security and privacy reasons.
