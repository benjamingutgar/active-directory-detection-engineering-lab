# Deployment Notes

This document describes the recommended deployment order for the Wazuh lateral movement detection laboratory.

The order matters because several components depend on previous steps: the domain controller must exist before domain-joining the workstation, Windows agents must be connected before reliable alert validation, and telemetry must be enabled before executing the scenarios.

## 1. Recommended Deployment Order

The recommended order is:

1. Deploy `Wazuh-Manager`.
2. Deploy and configure `DC01`.
3. Install and register the Wazuh agent on `DC01`.
4. Deploy and configure `WS01`.
5. Join `WS01` to the `lab.local` domain.
6. Install and register the Wazuh agent on `WS01`.
7. Deploy `Kali-ATK01`.
8. Validate connectivity.
9. Validate telemetry.
10. Execute the scenarios.

## 2. Step-by-Step Deployment

## Step 1 — Deploy Wazuh-Manager

Deploy the Wazuh server first.

| Field | Value |
|---|---|
| Hostname | `Wazuh-Manager` |
| IP | `192.168.56.10` |
| Role | SIEM all-in-one |
| Network | Host-only + optional NAT for installation |

Why first?

Because the Windows agents need a destination manager to register with. Deploying Wazuh first also allows telemetry validation immediately after each Windows host is configured.

## Step 2 — Deploy DC01

Deploy the domain controller.

| Field | Value |
|---|---|
| Hostname | `DC01` |
| IP | `192.168.56.20` |
| OS | Windows Server 2022 Standard |
| Domain | `lab.local` |
| NetBIOS | `LAB` |

DC01 must be available before WS01 is joined to the domain.

## Step 3 — Install Wazuh Agent on DC01

Install the Wazuh agent on `DC01` and register it against `Wazuh-Manager`.

After installation, verify that the agent appears in Wazuh.

Expected result:

```text
agent.name: DC01
agent.ip: 192.168.56.20
status: active
```

## Step 4 — Configure Windows Audit Policy on DC01

Enable the audit policy required for:

- logon events,
- special privileges,
- file share access,
- detailed file share access,
- process creation,
- DCSync-related evidence.

See:

```text
docs/windows-audit-policy.md
```

## Step 5 — Deploy WS01

Deploy the Windows workstation.

| Field | Value |
|---|---|
| Hostname | `WS01` |
| IP | `192.168.56.30` |
| OS | Windows 10 Enterprise |
| Domain | `lab.local` |

Join it to the domain only after DC01 is already available.

## Step 6 — Install Wazuh Agent on WS01

Install the Wazuh agent on `WS01` and register it against `Wazuh-Manager`.

Expected result:

```text
agent.name: WS01
agent.ip: 192.168.56.30
status: active
```

## Step 7 — Install Sysmon Where Required

Install Sysmon on the Windows hosts where endpoint process telemetry is needed.

See:

```text
docs/sysmon-configuration.md
docs/wazuh-sysmon-collection.md
```

## Step 8 — Deploy Kali-ATK01

Deploy the Kali Linux host last.

| Field | Value |
|---|---|
| Hostname | `Kali-ATK01` |
| IP | `192.168.56.40` |
| Role | Controlled attack simulation host |

Kali is the source of the simulated actions. It should not be used until Wazuh, DC01 and WS01 telemetry have already been validated.

## 3. Connectivity Validation

From Kali:

```bash
ping -c 4 192.168.56.20
ping -c 4 192.168.56.30
```

From WS01:

```powershell
ping 192.168.56.20
ping 192.168.56.10
```

From DC01:

```powershell
ping 192.168.56.10
```

## 4. Telemetry Validation Before Running Attacks

Before executing any scenario, verify that Wazuh receives events from the Windows systems.

Example Wazuh filters:

```kql
agent.name:DC01
```

```kql
agent.name:WS01
```

Check recent Windows Security events:

```kql
data.win.system.channel:Security
```

Check Sysmon collection:

```kql
data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

## 5. What Goes Wrong If the Order Is Reversed?

| Wrong Order | Problem |
|---|---|
| Running attacks before Wazuh agents are active | Alerts may be missed or incomplete |
| Joining WS01 before DC01 is ready | Domain join and authentication may fail |
| Installing Sysmon but not collecting its channel in Wazuh | Sysmon events exist locally but not in the SIEM |
| Executing SMB/PsExec-like tests before enabling audit policy | Key events such as `5145` may not appear |
| Running Pass-the-Hash before Directory Service auditing is configured | DCSync-related evidence may be missing |
| Using dynamic IPs | Event correlation becomes harder and less reproducible |

## 6. Recommended Validation Checklist

Before running the three scenarios, confirm:

| Check | Expected Result |
|---|---|
| Wazuh dashboard reachable | Yes |
| `DC01` agent active | Yes |
| `WS01` agent active | Yes |
| Static IPs configured | Yes |
| `DC01` resolves domain correctly | Yes |
| `WS01` joined to `lab.local` | Yes |
| Windows audit policy enabled | Yes |
| Sysmon installed where required | Yes |
| Sysmon channel collected by Wazuh | Yes |
| RDP enabled on WS01 for the RDP scenario | Yes |
| SMB/WMI/firewall requirements configured on DC01 | Yes |

## 7. Key Takeaway

The lab should be deployed from the monitoring layer outward:

```text
Wazuh → DC01 → WS01 → Kali → scenarios
```

This order ensures that when the offensive actions are executed, the defensive telemetry is already available and the generated alerts can be trusted as complete evidence for the scenario.
