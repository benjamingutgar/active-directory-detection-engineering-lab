# SMB / PsExec-like Scenario Timeline

| Time | Agent | Rule ID | Level | Description |
|---|---|---:|---:|---|
| 19:29:22 | DC01 | 100011 | 10 | NTLM network logon |
| 19:29:22 | DC01 | 100021 | 12 | Special privileges assigned |
| 19:29:22 | DC01 | 100011 | 10 | NTLM network logon |
| 19:29:22 | DC01 | 100021 | 12 | Special privileges assigned |
| 19:29:23 | DC01 | 100011 | 10 | NTLM network logon |
| 19:29:23 | DC01 | 100021 | 12 | Special privileges assigned |
| 19:29:23 | DC01 | 67027 | 3 | Process created |
| 19:29:23 | DC01 | 67027 | 3 | Process created |
| 19:29:23 | DC01 | 67027 | 3 | Process created |

## Interpretation

The sequence shows repeated NTLM authentication and privileged session creation followed by process execution on `DC01`.

A single NTLM logon is a weak indicator on its own. The sequence becomes stronger when combined with privileged access and process creation on the target host.
