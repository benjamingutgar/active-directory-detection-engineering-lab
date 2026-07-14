# Kerberoasting Scenario Timeline

This timeline reconstructs the controlled Kerberoasting scenario from preparation to mitigation.

No credentials, complete tickets or password hashes are included.

---

## Scenario Summary

| Field | Value |
|---|---|
| Technique | `T1558.003 — Kerberoasting` |
| Source | `Kali-ATK01` |
| Kerberos infrastructure | `DC01` |
| Target identity | Controlled non-privileged service account |
| Main Windows event | `4769` |
| Main Wazuh rules | `100040`, `100041` |
| Supporting rule | `100042` |
| Vulnerable encryption | RC4-HMAC / `0x17` |
| Correlation window | 120 seconds |
| Correlation threshold | 3 requests from the same source |

---

## Detection Timeline

| Order | Phase | Source | Destination | Event or rule | Interpretation |
|---:|---|---|---|---|---|
| 1 | Preparation | Administrator | Active Directory | Service account created | Controlled account prepared for the scenario |
| 2 | Preparation | Administrator | Active Directory | SPN registered | Account becomes eligible for service-ticket requests |
| 3 | Preparation | Administrator | Active Directory | RC4 enabled temporarily | Deliberately vulnerable laboratory configuration |
| 4 | Preparation | Administrator | `DC01` | Kerberos auditing enabled | Event `4769` becomes available |
| 5 | Enumeration | `Kali-ATK01` | `DC01` | Authenticated LDAP query | Accounts with SPNs are enumerated |
| 6 | Ticket request | `Kali-ATK01` | `DC01:88` | Windows Event `4769` | KDC issues a ticket for the controlled SPN |
| 7 | Initial detection | `DC01` | Wazuh | Rule `100040` | RC4 TGS request observed from an unusual source |
| 8 | Repeated request | `Kali-ATK01` | `DC01:88` | Windows Event `4769` | Second suspicious request from the same source |
| 9 | Repeated request | `Kali-ATK01` | `DC01:88` | Windows Event `4769` | Third suspicious request inside the correlation window |
| 10 | Correlation | Wazuh | Analyst | Rule `100041` | Three rule `100040` matches from the same source in 120 seconds |
| 11 | Offline activity | `Kali-ATK01` | Local files only | No domain event | Password candidates tested against the exported ticket |
| 12 | Investigation | Analyst | Wazuh / `DC01` | JSON and CSV review | Account, source, SPN, encryption and timing verified |
| 13 | Mitigation | Administrator | Active Directory | Password rotated | Weak service credential invalidated |
| 14 | Mitigation | Administrator | Active Directory | AES enabled | RC4 removed from the controlled account |
| 15 | Mitigation | Administrator | Active Directory | Password expiration restored | Static-password configuration corrected |

---

## Core Observable Sequence

```text
SPN enumeration
        ↓
TGS request
        ↓
4769
        ↓
ticketEncryptionType = 0x17
        ↓
source address outside the approved list
        ↓
100040
        ↓
three matches from the same source
        ↓
100041
