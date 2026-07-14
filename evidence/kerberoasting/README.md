# Kerberoasting Evidence

This directory contains the sanitized evidence collected during the controlled Kerberoasting scenario.

The scenario is mapped to:

```text
T1558.003 — Kerberoasting
```

## Scenario Summary

| Field | Value |
|---|---|
| Source host | `Kali-ATK01` |
| Target system | `DC01` |
| Windows event | `4769` |
| Ticket encryption | RC4-HMAC / `0x17` |
| Initial detection | `100040` |
| Correlation detection | `100041` |
| Correlation threshold | 3 requests |
| Correlation window | 120 seconds |

## Detection Chain

```text
Authenticated domain account
        ↓
Service account with an SPN identified
        ↓
Kerberos service ticket requested
        ↓
Windows Security Event ID 4769
        ↓
Ticket encryption type 0x17
        ↓
Request from Kali-ATK01
        ↓
Wazuh rule 100040
        ↓
Three requests from the same source in 120 seconds
        ↓
Wazuh rule 100041
```

## Evidence Files

The final directory will contain:

```text
evidence/kerberoasting/
├── README.md
├── kerberoasting-attack-summary.csv
└── json/
    ├── alert-100040-rc4-tgs-request.json
    └── alert-100041-kerberoasting-correlation.json
```

| File | Description |
|---|---|
| `kerberoasting-attack-summary.csv` | Chronological summary of the validated Kerberoasting alerts |
| `json/alert-100040-rc4-tgs-request.json` | Sanitized alert for an RC4 Kerberos service-ticket request from the controlled attacker source |
| `json/alert-100041-kerberoasting-correlation.json` | Sanitized correlation alert generated after three matching requests from the same source |

Rule `100042` is documented as complementary coverage but is not included as validated evidence for the Kali-based scenario.

## Main Evidence Fields

The relevant fields preserved in the sanitized JSON files are:

```text
timestamp
agent.name
rule.id
rule.level
rule.description
rule.mitre.id
data.win.system.eventID
data.win.system.eventRecordID
data.win.system.systemTime
data.win.eventdata.targetUserName
data.win.eventdata.serviceName
data.win.eventdata.ticketEncryptionType
data.win.eventdata.ticketOptions
data.win.eventdata.ipAddress
data.win.eventdata.status
```

The evidence demonstrates:

- a successful Kerberos service-ticket request;
- RC4-HMAC represented as `0x17`;
- a request originating from the controlled attacker host;
- generation of rule `100040`;
- three suspicious requests from the same source;
- generation of the correlated rule `100041`.

## Evidence Interpretation

Rule `100040` identifies the initial observable condition:

```text
Event ID 4769
+
RC4-HMAC
+
source outside the approved list
```

Rule `100041` increases the confidence by correlating three matches from the same source within 120 seconds.

The correct conclusion is:

> Wazuh detected repeated RC4 Kerberos service-ticket requests from an unexpected source, producing activity compatible with Kerberoasting.

The evidence does not prove by itself that:

- the ticket was cracked;
- the service-account password was recovered;
- the recovered credential was reused;
- every request was malicious.

The offline password-testing phase occurs locally on the attacker host and does not generate one event on the Domain Controller for every password candidate.

## Sanitization

The public evidence must not contain:

- domain passwords;
- service-account passwords;
- complete `$krb5tgs$` ticket material;
- reusable Kerberos hashes;
- private dictionaries;
- Hashcat potfiles;
- recovered passwords;
- Wazuh credentials;
- agent keys;
- private keys or certificates.

Sensitive values must be replaced with placeholders such as:

```text
<DOMAIN_USER>
<SERVICE_ACCOUNT>
<SERVICE_SPN>
<ATTACKER_IP>
<REDACTED_KERBEROS_TICKET>
<REDACTED_SENSITIVE_VALUE>
```

The private original evidence must remain outside the public repository.

## Related Documentation

- [Kerberoasting detection](../../detections/T1558.003-kerberoasting.md)
- [Scenario execution](../../scenarios/kerberoasting/execution.md)
- [Scenario timeline](../../scenarios/kerberoasting/timeline.md)
- [Wazuh filter](../../scenarios/kerberoasting/wazuh-filter.kql)
- [Detection hypotheses](../../detections/detection-hypotheses.md)
- [Detection matrix](../../detections/detection-matrix.md)
