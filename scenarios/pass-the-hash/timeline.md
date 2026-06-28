# Pass-the-Hash Scenario Timeline

| Time | Agent | Rule ID | Level | Description |
|---|---|---:|---:|---|
| 20:01:11 | DC01 | 100021 | 12 | Special privileges assigned |
| 20:01:11 | DC01 | 100011 | 10 | NTLM network logon |
| 20:01:11 - 20:01:12 | DC01 | 100030 | 13 | DCSync-like activity |
| 20:01:40 | DC01 | 92052 | 4 | Abnormal cmd.exe execution |
| 20:01:40 | DC01 | 92650 | 12 | Suspicious service creation |
| 20:01:40 | DC01 | 100033 | 15 | DCSync + privileged NTLM correlation |
| 20:01:40 | DC01 | 100011 | 10 | NTLM network logon |

## Interpretation

The strongest detection is rule `100033`, because it correlates DCSync-like credential access with later privileged NTLM activity.

The scenario also generated supporting evidence through NTLM network logons, privileged sessions, suspicious service creation and abnormal command execution.
