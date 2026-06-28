# Changelog

This file documents the evolution of the public repository.

The goal is to make changes explicit instead of silently mixing thesis code, laboratory code and public reusable detection logic.

The repository is based on a Master's Final Project about detecting lateral movement in a Windows Active Directory laboratory with Wazuh and MITRE ATT&CK. The public version extends the thesis by improving documentation, reproducibility and rule explanation.

---

## Versioning Model

This repository uses a simple semantic versioning style:

| Version Type | Meaning                                                               |
| ------------ | --------------------------------------------------------------------- |
| `1.0.x`      | Thesis baseline and initial public repository structure               |
| `1.1.x`      | Repository hardening, missing documentation and reproducibility fixes |
| `1.2.x`      | Detection engineering documentation and analyst-facing explanations   |
| `1.3.x`      | Future portable detection logic, such as Sigma rules                  |

---

## [1.2.0] - Detection Documentation Expansion

### Added

* Detection hypothesis documentation:

  * `detections/detection-hypotheses.md`

* Detection latency documentation:

  * `docs/detection-latencies.md`

* Incident-style reports:

  * `docs/incident-reports.md`

* Dedicated Pass-the-Hash detection write-up:

  * `detections/T1550.002-pass-the-hash.md`

### Changed

* Expanded the detection matrix:

  * `detections/detection-matrix.md`

* Expanded the RDP detection write-up:

  * `detections/T1021.001-rdp.md`

* Expanded the SMB / PsExec-like detection write-up:

  * `detections/T1021.002-smb-psexec-like.md`

### Detection Engineering Notes

The repository now documents the full hypothesis model used in the project:

| Hypothesis | Scenario               | Purpose                                                                 |
| ---------- | ---------------------- | ----------------------------------------------------------------------- |
| `H1`       | RDP                    | RDP access from the controlled attacker host to `WS01`                  |
| `H2`       | RDP                    | Post-access command execution after RDP                                 |
| `H3`       | SMB / PsExec-like      | NTLM network authentication from Kali to `DC01`                         |
| `H4`       | SMB / PsExec-like      | Administrative share access                                             |
| `H5`       | SMB / PsExec-like      | Remote service creation compatible with PsExec-like execution           |
| `H6`       | Pass-the-Hash          | Privileged NTLM network authentication compatible with credential reuse |
| `H7`       | Pass-the-Hash / DCSync | DCSync-like activity correlated with privileged access                  |

### Rationale

This version makes the repository more useful for Blue Team review.

The detection logic is no longer documented only as rules. It is now explained as:

```text
MITRE technique → detection hypothesis → telemetry → Wazuh rule → evidence → analyst interpretation → limitation
```

This is important because many Windows events are ambiguous when analyzed in isolation.

Examples:

* An RDP logon can be legitimate.
* An NTLM network logon can be normal in legacy environments.
* A `4672` privileged logon can be normal for administrators.
* Access to `ADMIN$` or `IPC$` can be legitimate.
* Service creation can be performed by deployment tools.
* DCSync-like telemetry requires careful interpretation and correct audit configuration.

The repository therefore emphasizes correlation and analyst interpretation instead of overclaiming from individual events.

---

## [1.1.0] - Public Repository Hardening

### Added

* Missing documentation files referenced by the repository documentation:

  * `docs/lab-architecture.md`
  * `docs/windows-audit-policy.md`
  * `docs/sysmon-configuration.md`
  * `docs/wazuh-sysmon-collection.md`
  * `docs/deployment-notes.md`

* Scenario-specific Wazuh filters:

  * `scenarios/rdp/wazuh-filter.kql`
  * `scenarios/smb-psexec-like/wazuh-filter.kql`
  * `scenarios/pass-the-hash/wazuh-filter.kql`

### Changed

* Public repository documentation now separates:

  * telemetry prerequisites;
  * deployment order;
  * detection logic;
  * analyst interpretation;
  * scenario evidence;
  * operational limitations.

### Rationale

This version fixes visible repository gaps and makes the project easier to understand without reading the original thesis PDF.

The main goal was to move the repository from a thesis-support archive toward a self-contained laboratory resource.

---

## Rule Evolution

This section documents important differences between the thesis version of the Wazuh rules and the public repository version.

The public repository version may be stricter than the thesis excerpt where additional rule constraints were added to reduce ambiguity or make the correlation logic more explicit.

---

## Rule `100022` - Defender Disabled Followed by Privileged Access

### Purpose

Rule `100022` documents a controlled laboratory chain where Windows Defender-related activity is followed by privileged access.

It represents the following sequence:

```text
Defender-related reduction of protection → privileged access
```

### Thesis Version

The thesis version used a temporal correlation based on the native Defender-related rule and the custom privileged access rule:

```xml
<rule id="100022" level="14" timeframe="300">
  <if_matched_sid>92008</if_matched_sid>
  <if_sid>100021</if_sid>
  <description>TFM - Controlled Pass the Hash chain: Defender disabled followed by privileged NTLM access (T1550.002 + T1562.001)</description>
  <options>alert_by_email</options>
  <group>tfm,lateral_movement,pth_controlled,defense_evasion,</group>
  <mitre>
    <id>T1550.002</id>
    <id>T1562.001</id>
  </mitre>
</rule>
```

### Public Repository Version

The public repository version uses:

```xml
<rule id="100022" level="14" frequency="2" timeframe="300">
  <if_matched_sid>92008</if_matched_sid>
  <if_sid>100021</if_sid>
  <description>TFM - Controlled Pass the Hash chain: Defender disabled followed by privileged access (T1550.002 + T1562.001)</description>
  <options>alert_by_email</options>
  <group>tfm,lateral_movement,pth_controlled,defense_evasion,correlation,</group>
  <mitre>
    <id>T1550.002</id>
    <id>T1562.001</id>
  </mitre>
</rule>
```

### Change Summary

| Change                        | Reason                                                                   |
| ----------------------------- | ------------------------------------------------------------------------ |
| Added `frequency="2"`         | Makes the correlation threshold explicit inside the configured timeframe |
| Added `correlation` group tag | Makes the rule easier to identify as a correlation rule                  |
| Adjusted description wording  | Avoids implying that the rule universally proves Pass-the-Hash           |

### Operational Note

Rule `100022` should **not** be treated as a universal Pass-the-Hash detection.

It represents a controlled lab chain combining defense evasion context and privileged access. In production, legitimate administrative changes to endpoint protection may cause false positives.

Expected tuning before production use:

* approved security administration accounts;
* maintenance windows;
* EDR/AV management platforms;
* change-management tickets;
* known Defender policy deployment sources.

---

## Rule `100033` - Critical Pass-the-Hash / DCSync Correlation

### Purpose

Rule `100033` is the strongest Pass-the-Hash-related correlation rule in the repository.

It correlates:

1. `100030` — DCSync / secretsdump-like activity.
2. `100021` — privileged session.

The analytical goal is to detect a sequence compatible with:

```text
credential access behavior → privileged NTLM-related access
```

### Thesis Version

The thesis version used a temporal correlation between `100030` and `100021` inside a `300` second window:

```xml
<rule id="100033" level="15" timeframe="300">
  <if_matched_sid>100030</if_matched_sid>
  <if_sid>100021</if_sid>
  <description>TFM - Controlled Pass the Hash chain: DCSync/secretsdump followed by privileged NTLM access (T1550.002 + T1003.006)</description>
  <options>alert_by_email</options>
  <group>tfm,lateral_movement,pth_controlled,credential_access,correlation,</group>
  <mitre>
    <id>T1550.002</id>
    <id>T1003.006</id>
  </mitre>
</rule>
```

### Public Repository Version

The public repository version is stricter:

```xml
<rule id="100033" level="15" frequency="2" timeframe="300">
  <if_matched_sid>100030</if_matched_sid>
  <if_sid>100021</if_sid>
  <same_field>win.eventdata.subjectUserName</same_field>
  <description>TFM - Controlled Pass the Hash chain: DCSync/secretsdump followed by privileged access using the same account (T1550.002 + T1003.006)</description>
  <options>alert_by_email</options>
  <group>tfm,lateral_movement,pth_controlled,credential_access,correlation,</group>
  <mitre>
    <id>T1550.002</id>
    <id>T1003.006</id>
  </mitre>
</rule>
```

### Change Summary

| Change                 | Reason                                                                                  |
| ---------------------- | --------------------------------------------------------------------------------------- |
| Added `frequency="2"`  | Makes the multi-signal correlation requirement explicit inside the configured timeframe |
| Added `same_field`     | Requires the correlated activity to involve the same `win.eventdata.subjectUserName`    |
| Updated description    | Makes clear that the public version correlates activity using the same account          |
| Kept `timeframe="300"` | Preserves the five-minute correlation window used in the laboratory                     |

### Detection Impact

The public repository version is more conservative than the thesis excerpt.

It reduces the risk of correlating unrelated events from different accounts inside the same timeframe.

However, it may require tuning if:

* Wazuh field normalization changes;
* the relevant username field differs between events;
* the decoder produces different field paths;
* events contain `targetUserName` in one case and `subjectUserName` in another;
* the environment contains legitimate DCSync-like activity.

### Analytical Limitation

Even rule `100033` does not directly prove that a hash was used.

The correct interpretation is:

```text
behavior compatible with Pass-the-Hash / DCSync activity
```

not:

```text
direct proof that the NTLM hash was used
```

This distinction is important because Windows records the authentication effects, not the attacker's internal credential material.

---

## [1.0.0] - Thesis Baseline

### Added

* Initial Wazuh custom rules for the three main controlled scenarios:

  * RDP lateral movement.
  * SMB / PsExec-like remote execution.
  * Pass-the-Hash with DCSync-related evidence.

* MITRE ATT&CK mappings:

  * `T1021.001` — Remote Services: Remote Desktop Protocol.
  * `T1021.002` — Remote Services: SMB/Windows Admin Shares.
  * `T1550.002` — Use Alternate Authentication Material: Pass the Hash.
  * `T1003.006` — OS Credential Dumping: DCSync.
  * `T1569.002` — System Services: Service Execution.
  * `T1078` — Valid Accounts.
  * `T1562.001` — Impair Defenses: Disable or Modify Tools.

* Anonymized evidence samples.

* Scenario execution notes.

* Detection write-ups.

* Initial Wazuh rule explanations.

### Baseline Scope

The baseline repository represents the controlled laboratory work:

```text
Wazuh Manager + DC01 + WS01 + Kali-ATK01
```

The evaluated techniques were:

| Scenario               | Technique                | Target |
| ---------------------- | ------------------------ | ------ |
| RDP                    | `T1021.001`              | `WS01` |
| SMB / PsExec-like      | `T1021.002`, `T1569.002` | `DC01` |
| Pass-the-Hash / DCSync | `T1550.002`, `T1003.006` | `DC01` |

### Baseline Limitation

The baseline rules were validated in a controlled laboratory.

They should not be treated as production-ready detections without:

* telemetry validation;
* false-positive analysis;
* environment-specific baselining;
* privileged account review;
* administrative source allowlisting;
* service creation baselines;
* NTLM usage baselines;
* domain controller replication baselines.

---

## Future Work

Planned improvements:

* Add Sigma versions of the main detections.
* Add `REPRODUCE.md` with full end-to-end lab reproduction steps.
* Add `docs/false-positives.md`.
* Add production tuning recommendations per rule.
* Add a portable detection mapping for other SIEMs.
* Add screenshots or dashboard examples if sanitized safely.
