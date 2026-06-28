# Detection Matrix

This matrix summarizes the relationship between the simulated techniques, telemetry sources, Wazuh rules and detection confidence.

| Technique | Scenario | Main Events | Wazuh Rules | Evidence Quality |
|---|---|---|---|---|
| T1021.001 | RDP lateral movement | 4624, 4688, 4634, 4647 | 92653, 100001, 92052, 67027 | Medium/High |
| T1021.002 | SMB / PsExec-like execution | 4624, 4672, 5145, 7045, 4688 | 100011, 100021, 100010, 92218, 92052 | High |
| T1550.002 | Pass the Hash / DCSync correlation | 4624, 4672, 4662, 5145, 4688 | 100011, 100021, 100030, 100033, 92218, 92052 | High |

## Interpretation

The RDP scenario provides useful evidence when remote access is followed by post-access activity.

The SMB / PsExec-like scenario provides strong evidence because remote service creation and administrative share access are highly relevant lateral movement indicators.

The Pass-the-Hash scenario provides the strongest correlation when NTLM authentication, privileged access and DCSync-like activity appear within the same attack chain.
