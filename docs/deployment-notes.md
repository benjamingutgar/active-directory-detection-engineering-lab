# Deployment Notes

This document describes the recommended deployment order for the Wazuh Active Directory security laboratory.

The order matters because several components depend on previous steps:

- the Domain Controller must exist before joining the workstation to the domain;
- Windows agents must be connected before reliable alert validation;
- Windows and Sysmon telemetry must be enabled before executing the scenarios;
- Kerberos auditing and the controlled service account must be prepared before running Kerberoasting.

The laboratory currently supports five controlled scenarios:

- RDP lateral movement;
- SMB / PsExec-like remote execution;
- Pass-the-Hash with DCSync-related evidence;
- Kerberoasting.
- AS-REP Roasting.

---

## 1. Recommended Deployment Order

The recommended order is:

1. Deploy `Wazuh-Manager`.
2. Deploy and configure `DC01`.
3. Install and register the Wazuh agent on `DC01`.
4. Configure Windows auditing on `DC01`.
5. Deploy and configure `WS01`.
6. Join `WS01` to the `lab.local` domain.
7. Install and register the Wazuh agent on `WS01`.
8. Install and configure Sysmon where required.
9. Deploy `Kali-ATK01`.
10. Validate network connectivity.
11. Validate Windows and Sysmon telemetry.
12. Install and validate the custom Wazuh rules.
13. Prepare the individual attack scenarios.
14. Execute the scenarios and preserve the evidence.

---

## 2. Step-by-Step Deployment

### Step 1 — Deploy Wazuh-Manager

Deploy the Wazuh server first.

| Field | Value |
|---|---|
| Hostname | `Wazuh-Manager` |
| IP | `192.168.56.10` |
| Role | SIEM all-in-one |
| Network | Host-only + optional NAT for installation |

Wazuh-Manager provides:

- Wazuh Manager;
- Wazuh Indexer;
- Wazuh Dashboard.

Deploying it first allows telemetry to be validated immediately after each Windows agent is installed.

---

### Step 2 — Deploy DC01

Deploy the Domain Controller.

| Field | Value |
|---|---|
| Hostname | `DC01` |
| IP | `192.168.56.20` |
| Operating system | Windows Server 2022 Standard |
| Domain | `lab.local` |
| NetBIOS name | `LAB` |
| Roles | Active Directory, DNS and Kerberos KDC |

`DC01` must be available before:

- joining `WS01` to the domain;
- creating domain users;
- creating the controlled Kerberoasting service account;
- registering a Service Principal Name;
- generating Kerberos Event ID `4769`.

---

### Step 3 — Install the Wazuh Agent on DC01

Install the Wazuh agent on `DC01` and register it against `Wazuh-Manager`.

Expected state:

```text
agent.name: DC01
agent.ip: 192.168.56.20
status: active
```

Verify the Windows service:

```powershell
Get-Service WazuhSvc |
    Format-Table Name,Status,StartType
```

Expected result:

```text
WazuhSvc    Running    Automatic
```

Verify the manager address in:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

The configuration should contain values equivalent to:

```xml
<address>192.168.56.10</address>
<port>1514</port>
<protocol>tcp</protocol>
```

---

### Step 4 — Configure Windows Auditing on DC01

Enable the audit policy required for:

- successful and failed logons;
- special privileges;
- process creation;
- file-share activity;
- detailed file-share access;
- Directory Service Access;
- Kerberos service-ticket operations.

See:

```text
docs/windows-audit-policy.md
```

The main events generated on `DC01` include:

```text
4624
4625
4662
4672
4688
4769
5145
7045
```

Kerberoasting specifically requires:

```powershell
auditpol.exe `
    /set `
    /subcategory:"Kerberos Service Ticket Operations" `
    /success:enable `
    /failure:enable
```

Verify it:

```powershell
auditpol.exe `
    /get `
    /subcategory:"Kerberos Service Ticket Operations"
```

Expected result:

```text
Kerberos Service Ticket Operations    Success and Failure
```

Without this configuration, the Kerberos ticket request can succeed while Event ID `4769` remains unavailable to Wazuh.

---

### Step 5 — Deploy WS01

Deploy the Windows workstation.

| Field | Value |
|---|---|
| Hostname | `WS01` |
| IP | `192.168.56.30` |
| Operating system | Windows 10 Enterprise |
| Domain | `lab.local` |
| Role | Domain-joined monitored workstation |

Join it to the domain only after `DC01` is operational.

Configure its preferred DNS server as:

```text
192.168.56.20
```

Verify domain membership:

```powershell
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name,Domain,PartOfDomain
```

Expected result:

```text
Name          : WS01
Domain        : lab.local
PartOfDomain  : True
```

---

### Step 6 — Install the Wazuh Agent on WS01

Install and register the Wazuh agent against `Wazuh-Manager`.

Expected state:

```text
agent.name: WS01
agent.ip: 192.168.56.30
status: active
```

Verify the service:

```powershell
Get-Service WazuhSvc |
    Format-Table Name,Status,StartType
```

---

### Step 7 — Install Sysmon Where Required

Install Sysmon on the Windows systems where endpoint process and network telemetry is needed.

See:

```text
docs/sysmon-configuration.md
docs/wazuh-sysmon-collection.md
```

Sysmon supports:

| Event ID | Purpose |
|---:|---|
| `1` | Detailed process creation |
| `3` | Network connection context |
| `10` | Process-access telemetry when configured |

The main Kerberoasting validation does not require Sysmon.

However, rule `100042` depends on Sysmon Event ID `3` and can provide optional context when a process on `WS01` connects to the Kerberos service on `DC01`.

The Wazuh agent must collect:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

### Step 8 — Deploy Kali-ATK01

Deploy the Kali Linux host after the defensive telemetry is operational.

| Field | Value |
|---|---|
| Hostname | `Kali-ATK01` |
| IP | `192.168.56.40` |
| Role | Controlled attack-simulation host |

Kali is the source of the authorized offensive actions.

It should not be used until:

- `DC01` and `WS01` are available;
- both Wazuh agents are active;
- the required audit policies are enabled;
- the custom rules have been validated;
- the Wazuh Dashboard is receiving events.

Required tools depend on the scenario.

Examples include:

```text
xfreerdp
Impacket
NetExec or CrackMapExec
Hashcat
```

For Kerberoasting, verify:

```bash
command -v impacket-GetUserSPNs
hashcat --version
```

Do not store real passwords, complete Kerberos tickets or Hashcat potfiles in the public repository.

---

## 3. Network Connectivity Validation

### From Kali-ATK01

```bash
ping -c 2 192.168.56.20
ping -c 2 192.168.56.30
ping -c 2 192.168.56.10
```

Check the main services:

```bash
nc -zv 192.168.56.20 88
nc -zv 192.168.56.20 389
nc -zv 192.168.56.20 445
nc -zv 192.168.56.30 3389
```

Expected uses:

| Port | Purpose |
|---:|---|
| `88` | Kerberos |
| `389` | LDAP |
| `445` | SMB |
| `3389` | RDP |

### From WS01

```powershell
Test-Connection 192.168.56.20 -Count 2
Test-Connection 192.168.56.10 -Count 2
Test-NetConnection 192.168.56.20 -Port 88
```

### From DC01

```powershell
Test-Connection 192.168.56.10 -Count 2
Test-NetConnection 192.168.56.10 -Port 1514
```

---

## 4. Time Synchronization

Kerberos is sensitive to significant clock differences.

Before executing Kerberoasting, verify the time on Kali and `DC01`.

On Kali:

```bash
date
```

On `DC01`:

```powershell
Get-Date
w32tm /query /status
```

A large time difference can cause Kerberos authentication or ticket requests to fail.

Time synchronization should therefore be validated before troubleshooting:

- credentials;
- SPNs;
- Kerberos ports;
- Impacket commands;
- Wazuh detection rules.

---

## 5. Wazuh Rule Deployment

The public rule file is stored at:

```text
wazuh/rules/local_rules.xml
```

The active manager rule file is normally:

```text
/var/ossec/etc/rules/local_rules.xml
```

Before modifying the manager:

```bash
sudo cp -a \
  /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.backup
```

Validate the XML:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

If the validation succeeds:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Expected result:

```text
active
```

The main custom rules currently include:

```text
100001
100010
100011
100021
100022
100030
100033
100040
100041
100042
```

Do not replace the active file with an incomplete or older rule set.

Always preserve the existing validated rules and add new groups carefully.

---

## 6. Telemetry Validation Before Running Scenarios

Before executing any attack, verify that Wazuh receives events from both Windows systems.

### Agent filters

```kql
agent.name:DC01
```

```kql
agent.name:WS01
```

### Windows Security channel

```kql
data.win.system.channel:Security
```

### System channel

```kql
data.win.system.channel:System
```

### Sysmon channel

```kql
data.win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

### Kerberos Event ID 4769

```kql
agent.name:DC01 AND data.win.system.eventID:4769
```

A successful local Windows event does not guarantee that Wazuh has ingested it.

The analyst must verify both:

```text
event exists in Windows
```

and:

```text
event is visible in Wazuh
```

---

## 7. Scenario Preparation

### RDP

Before the RDP scenario:

- enable Remote Desktop on `WS01`;
- allow TCP port `3389`;
- grant the controlled account remote-logon permission;
- verify Event ID `4624`;
- verify process-creation auditing.

Scenario files:

```text
scenarios/rdp/
```

---

### SMB / PsExec-like

Before the SMB/PsExec-like scenario:

- verify SMB access to `DC01`;
- enable the required firewall rules;
- verify administrative-share availability;
- verify Event IDs `4624`, `4672`, `5145` and `7045`;
- confirm the controlled account has the intended laboratory permissions.

Scenario files:

```text
scenarios/smb-psexec-like/
```

---

### Pass-the-Hash / DCSync

Before the Pass-the-Hash scenario:

- verify NTLM is available in the controlled environment;
- enable Directory Service Access auditing;
- configure the necessary Active Directory SACL;
- verify Event ID `4662`;
- verify the correlation rules `100030` and `100033`;
- preserve evidence without publishing reusable credential material.

Scenario files:

```text
scenarios/pass-the-hash/
```

---

### Kerberoasting

Before the Kerberoasting scenario:

1. Create a controlled non-privileged service account.
2. Register a controlled SPN.
3. Temporarily configure RC4 support for the account.
4. Enable Kerberos service-ticket auditing.
5. Verify Event ID `4769` reaches Wazuh.
6. Confirm rules `100040` and `100041` are active.
7. Verify Kali can reach `DC01` on ports `88` and `389`.
8. Confirm system clocks are synchronized.
9. Keep passwords and complete ticket material outside the repository.

Scenario files:

```text
scenarios/kerberoasting/
```

The principal expected chain is:

```text
Event ID 4769
        ↓
ticketEncryptionType = 0x17
        ↓
unexpected source
        ↓
rule 100040
        ↓
three matching requests
        ↓
rule 100041
```

Rule `100042` is optional supporting coverage and requires Sysmon network telemetry from `WS01`.

---

## 8. What Goes Wrong If the Order Is Reversed?

| Wrong Order | Problem |
|---|---|
| Running attacks before Wazuh agents are active | Alerts may be missed or incomplete |
| Joining `WS01` before `DC01` is ready | Domain join and authentication may fail |
| Installing Sysmon without collecting its channel | Sysmon events exist locally but not in Wazuh |
| Executing SMB tests before enabling auditing | Events such as `5145` may be missing |
| Running DCSync before Directory Service auditing and SACL configuration | Event ID `4662` may be absent |
| Running Kerberoasting before enabling Kerberos auditing | Event ID `4769` may be absent |
| Testing Kerberoasting with unsynchronized clocks | Kerberos authentication may fail |
| Requesting tickets before the SPN is registered | The KDC cannot resolve the intended service identity |
| Testing rule `100042` from Kali | No Windows Sysmon event is generated on Linux |
| Replacing `local_rules.xml` with an older file | Existing detections may be removed |
| Using dynamic IP addresses | Correlation and source-based rules become unreliable |
| Publishing raw attack output | Credentials, tickets or reusable hashes may be exposed |

---

## 9. Recommended Validation Checklist

Before running the five scenarios, confirm:

| Check | Expected Result |
|---|---|
| Wazuh Dashboard reachable | Yes |
| `DC01` agent active | Yes |
| `WS01` agent active | Yes |
| Static IPs configured | Yes |
| `DC01` provides DNS for the domain | Yes |
| `WS01` joined to `lab.local` | Yes |
| Windows Security channel collected | Yes |
| Windows System channel collected | Yes |
| Required audit policy enabled | Yes |
| Sysmon installed where required | Yes |
| Sysmon channel collected where required | Yes |
| Custom Wazuh rules validate successfully | Yes |
| RDP enabled on `WS01` for the RDP scenario | Yes |
| SMB and remote administration requirements configured on `DC01` | Yes |
| Event ID `4662` available for the DCSync scenario | Yes |
| Kerberos auditing enabled on `DC01` | Yes |
| Controlled service account created | Yes |
| Controlled SPN registered | Yes |
| Event ID `4769` visible in Wazuh | Yes |
| Kali and `DC01` clocks synchronized | Yes |
| Sensitive output excluded from Git | Yes |

---

## 10. Evidence Preservation

After each scenario:

1. Export the relevant Wazuh alerts.
2. Preserve the Windows event record IDs.
3. Preserve Windows and Wazuh timestamps.
4. Export a filtered CSV summary.
5. Sanitize usernames where appropriate.
6. Remove passwords and secrets.
7. Remove complete Kerberos tickets.
8. Remove reusable hashes.
9. Remove Hashcat potfiles and private wordlists.
10. Store only sanitized evidence in the public repository.

Evidence directories:

```text
evidence/rdp/
evidence/smb-psexec-like/
evidence/pass-the-hash/
evidence/kerberoasting/
```

For Kerberoasting, the public evidence should preserve fields such as:

```text
timestamp
agent.name
rule.id
rule.level
rule.description
data.win.system.eventID
data.win.system.eventRecordID
data.win.system.systemTime
data.win.eventdata.targetUserName
data.win.eventdata.serviceName
data.win.eventdata.ticketEncryptionType
data.win.eventdata.ticketOptions
data.win.eventdata.ipAddress
```

It must not preserve:

```text
domain passwords
service-account passwords
complete $krb5tgs$ ticket strings
Hashcat potfiles
private dictionaries
recovered passwords
```

---

## 11. Recommended Execution Order

Once deployment and validation are complete, execute the scenarios in this order:

```text
1. RDP
2. SMB / PsExec-like
3. Pass-the-Hash / DCSync
4. Kerberoasting
5. AS-REP Roasting
```

This order follows the original project progression and then adds the credential-access extensions.

Kerberoasting can also be executed independently after:

- the service account exists;
- the SPN is registered;
- Kerberos auditing is active;
- the rules are installed;
- the evidence directory is prepared.

---

## 12. Key Takeaway

The laboratory should be deployed from the monitoring layer outward:

```text
Wazuh
    ↓
DC01
    ↓
Windows auditing
    ↓
WS01
    ↓
Sysmon
    ↓
Kali
    ↓
custom rules
    ↓
scenario preparation
    ↓
controlled execution
    ↓
sanitized evidence
```

This order ensures that the defensive telemetry is available before the offensive actions occur.

For Kerberoasting, the critical dependency chain is:

```text
service account with SPN
        ↓
Kerberos auditing
        ↓
Event ID 4769 collection
        ↓
rules 100040 and 100041
        ↓
controlled TGS requests
        ↓
sanitized evidence
```

Correct deployment order prevents missing telemetry and makes the resulting alerts reproducible and trustworthy.

---

## 13. AS-REP Roasting Deployment Extension

### Required Components

| Component | Requirement |
|---|---|
| Source | `Kali-ATK01 / 192.168.56.40` |
| Kerberos infrastructure | `DC01 / 192.168.56.20` |
| Domain | `lab.local` |
| Controlled account | `svc_asrep_lab` |
| Windows event | `4768` |
| Security channel | Collected by the Wazuh agent on `DC01` |
| Custom rules | `100050`, `100051`, `100052` |

### Audit Requirement

The relevant audit subcategory is:

```text
Kerberos Authentication Service
```

The supplied event evidence confirms that Event ID `4768` was generated. The original enablement command used during each validation date was not preserved.

### Wazuh Validation

Use:

```kql
agent.name:DC01 AND (rule.id:(100050 OR 100051 OR 100052) OR (data.win.system.eventID:4768 AND data.win.eventdata.preAuthType:0))
```

The XML rule chain is:

```text
native Windows rule 60103
        ↓
100050
        ↓
100051
        ↓
100052
```

The public evidence does not include a standalone alert for native rule `60103`.

### Evidence Preservation

Preserve:

```text
evidence/as-rep-roasting/as-rep-roasting-attack-summary.csv
evidence/as-rep-roasting/json/alert-100050-as-rep-no-preauth.json
evidence/as-rep-roasting/json/alert-100051-as-rep-rc4.json
evidence/as-rep-roasting/json/alert-100052-as-rep-correlation.json
scenarios/as-rep-roasting/execution.md
scenarios/as-rep-roasting/timeline.md
scenarios/as-rep-roasting/wazuh-filter.kql
```

Do not commit:

```text
*.hash
*.pot
*.potfile
complete AS-REP strings
passwords
recovered passwords
complete SIDs
raw Wazuh full_log fields
```

### Validation Boundary

Rules `100050`, `100051` and `100052` have direct alert evidence, but the evidence was collected on two dates.

The repository must not describe the three stored alert documents as one continuous command execution.

The description of the stored `100052` alert also differs from the current XML wording, indicating a rule-revision difference.
