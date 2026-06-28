# RDP Scenario Timeline

| Time | Agent | Rule ID | Level | Description |
|---|---|---:|---:|---|
| 16:53:31 | WS01 | 100001 | 10 | RDP post-access context |
| 16:55:08 | WS01 | 92052 | 4 | Windows command prompt started by abnormal process |
| 17:03:43 | WS01 | 67027 | 3 | Process created |
| 17:03:51 | WS01 | 67027 | 3 | Process created |
| 17:03:56 | WS01 | 67027 | 3 | Process created |
| 17:04:03 | WS01 | 67027 | 3 | Process created |

## Interpretation

The timeline shows an RDP authentication context followed by command and process activity on `WS01`.

The strongest signal is not the RDP logon alone, but the combination of remote access and post-access activity from the authenticated user context.
