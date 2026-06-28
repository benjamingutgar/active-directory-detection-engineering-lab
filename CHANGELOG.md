# Changelog

This file documents relevant changes between the original thesis version of the detection logic and the public repository version.

The goal is to make rule evolution explicit instead of silently mixing thesis code, lab code and public reusable code.

## [1.1.0] - Public Repository Hardening

### Added

- Missing documentation files referenced by the README:
  - `docs/lab-architecture.md`
  - `docs/windows-audit-policy.md`
  - `docs/sysmon-configuration.md`
  - `docs/wazuh-sysmon-collection.md`
  - `docs/deployment-notes.md`

- Scenario-specific Wazuh filters:
  - `scenarios/rdp/wazuh-filter.kql`
  - `scenarios/smb-psexec-like/wazuh-filter.kql`
  - `scenarios/pass-the-hash/wazuh-filter.kql`

### Changed

- Public repository documentation now separates:
  - telemetry prerequisites,
  - deployment order,
  - detection logic,
  - analyst interpretation,
  - scenario evidence.

## Rule `100022` - Defender Disabled Followed by Privileged Access

### Thesis context

Rule `100022` documents a controlled laboratory chain where Windows Defender-related activity is followed by privileged access.

### Public repository version

The public repository version uses:

```xml
frequency="2"
timeframe="300"
```

### Reason

The explicit `frequency="2"` requirement makes the correlation stricter by requiring multiple related matches inside the configured timeframe.

This is useful in the public repository because the rule is presented as reusable detection logic, not only as a thesis excerpt.

### Operational note

This rule should not be treated as a universal Pass-the-Hash detection.

It represents a controlled lab chain combining defense evasion context and privileged access. In production, legitimate administrative changes to endpoint protection may cause false positives.

## Rule `100033` - Critical Pass-the-Hash / DCSync Correlation

### Thesis version

The thesis version used a temporal correlation between:

1. Rule `100030` — DCSync/secretsdump-like activity.
2. Rule `100021` — privileged session.

The thesis version used a `300` second timeframe:

```xml
<rule id="100033" level="15" timeframe="300">
  <if_matched_sid>100030</if_matched_sid>
  <if_sid>100021</if_sid>
  ...
</rule>
```

### Public repository version

The public repository version is stricter:

```xml
<rule id="100033" level="15" frequency="2" timeframe="300">
  <if_matched_sid>100030</if_matched_sid>
  <if_sid>100021</if_sid>
  <same_field>win.eventdata.subjectUserName</same_field>
  ...
</rule>
```

### Reason

The public repository version adds two hardening changes:

1. `frequency="2"`

   Makes the correlation requirement explicit and reduces overly weak single-event interpretation.

2. `same_field`

   Requires the correlated activity to involve the same `win.eventdata.subjectUserName`.

This reduces the risk of correlating unrelated events from different accounts inside the same timeframe.

### Detection impact

The repository version is more conservative than the thesis excerpt.

It is better suited for public reuse because it reduces correlation ambiguity. However, it may require tuning if the field name differs depending on the event source, decoder or Wazuh version.

## [1.0.0] - Thesis Baseline

### Added

- Wazuh custom rules for the three main scenarios:
  - RDP lateral movement.
  - SMB/PsExec-like remote execution.
  - Pass-the-Hash with DCSync-related evidence.

- MITRE ATT&CK mappings:
  - `T1021.001`
  - `T1021.002`
  - `T1550.002`
  - `T1003.006`
  - `T1569.002`
  - `T1078`

- Anonymized evidence samples.
- Scenario execution notes.
- Detection write-ups.
