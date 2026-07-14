## Versioning Model

This repository uses a simple semantic versioning style:

| Version Type | Meaning |
|---|---|
| `1.0.x` | Thesis baseline and initial public repository structure |
| `1.1.x` | Repository hardening, missing documentation and reproducibility fixes |
| `1.2.x` | Detection engineering documentation and analyst-facing explanations |
| `1.3.x` | New detection scenarios and expanded MITRE ATT&CK coverage |
| `1.4.x` | Future portable detection logic, such as Sigma rules |

---

## [1.3.0] - Kerberoasting Detection Extension

### Added

* Kerberoasting detection write-up:

  * `detections/T1558.003-kerberoasting.md`

* Kerberoasting scenario documentation:

  * `scenarios/kerberoasting/execution.md`
  * `scenarios/kerberoasting/timeline.md`
  * `scenarios/kerberoasting/wazuh-filter.kql`

* Kerberoasting evidence directory:

  * `evidence/kerberoasting/`

* Three new detection hypotheses:

  * `H8` — RC4 Kerberos service ticket from an unexpected source.
  * `H9` — Repeated suspicious RC4 service-ticket requests.
  * `H10` — Optional unusual process connection to the Kerberos service.

* Three custom Wazuh rules:

  * `100040` — RC4 Kerberos service-ticket request from an unexpected source.
  * `100041` — Three matching requests from the same source within 120 seconds.
  * `100042` — Optional Sysmon process context for connections to `DC01:88`.

### Changed

* Expanded the project from three to four controlled scenarios.
* Expanded the hypothesis model from seven to ten hypotheses.
* Added Windows Security Event ID `4769` to the telemetry model.
* Added Kerberos Service Ticket Operations to the Windows audit-policy documentation.
* Updated the detection matrix, project summary, deployment notes, incident reports and latency documentation.
* Updated the main README with brief Kerberoasting coverage.
* Updated the rule documentation with the new Kerberos detection logic.

### Detection Chain

The main validated Kerberoasting detection chain is:

```text
Kerberos service-ticket request
        ↓
Windows Security Event ID 4769
        ↓
RC4-HMAC encryption type 0x17
        ↓
request from an unexpected source
        ↓
rule 100040
        ↓
three matching requests from the same source
        ↓
rule 100041
```

Rule `100042` provides optional endpoint context when equivalent activity originates from a monitored Windows workstation.

### Detection Boundaries

Wazuh observes:

```text
Kerberos service-ticket request
+
ticket encryption type
+
request source
+
request frequency
```

Wazuh does not directly observe:

```text
every offline password candidate
+
the complete cracking process
+
successful password recovery
```

The correct interpretation is:

```text
repeated RC4 Kerberos service-ticket requests compatible with Kerberoasting
```

not:

```text
direct proof that the service-account password was cracked
```

### Security and Privacy

The public repository excludes:

* service-account passwords;
* domain credentials;
* complete Kerberos ticket material;
* complete `$krb5tgs$` strings;
* Hashcat potfiles;
* private dictionaries;
* recovered passwords;
* reusable credential material.

Only sanitized alert fields and defensive evidence are included.

---
