# Project Summary

This project presents the design and implementation of a SIEM laboratory using Wazuh to detect lateral movement techniques in a Windows/Active Directory environment.

The laboratory was built under local resource constraints, using a single physical host and several virtual machines. The main goal was to create a realistic but reproducible defensive detection environment.

The project combines:

- Windows event log collection.
- Sysmon telemetry.
- Wazuh agent deployment.
- Custom Wazuh correlation rules.
- MITRE ATT&CK mapping.
- Technical and executive reporting.

The detection scenarios focus on three lateral movement techniques:

1. RDP-based access.
2. SMB/PsExec-like remote execution.
3. Pass-the-Hash with DCSync-related evidence.

The work demonstrates that even a lightweight local SIEM deployment can provide meaningful detection capabilities when logs are properly collected, correlated and mapped to attacker behavior.
