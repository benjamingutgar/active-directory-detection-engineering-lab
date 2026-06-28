# Detection Methodology

The detection methodology follows the same process for each lateral movement technique:

1. Configure the required telemetry sources.
2. Execute the controlled laboratory scenario.
3. Identify the generated Windows and Wazuh events.
4. Build or adapt Wazuh rules.
5. Map the detection logic to MITRE ATT&CK.
6. Validate the generated alerts.
7. Document the evidence and limitations.

## Telemetry Sources

The project uses the following telemetry sources:

| Source | Purpose |
|---|---|
| Windows Security Event Log | Authentication, privileges, process creation, object access and service creation |
| Sysmon | Additional process and endpoint telemetry |
| Wazuh Agent | Event forwarding and normalization |
| Wazuh Manager | Rule processing and alert generation |

## Detection Philosophy

The detections do not rely only on tool names. They focus on observable behavior:

- remote logons
- NTLM authentication
- special privileges
- administrative share access
- service creation
- directory replication access
- post-access process execution

Single events are treated as weak or medium indicators. Stronger conclusions are obtained by correlating several events in the same scenario.
