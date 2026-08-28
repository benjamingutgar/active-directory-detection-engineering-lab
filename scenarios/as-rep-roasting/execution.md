# AS-REP Roasting Scenario Execution

## Objective

Generate controlled Kerberos TGT requests for `svc_asrep_lab` and validate the resulting Windows and Wazuh telemetry.

The scenario is mapped to:

```text
MITRE ATT&CK T1558.004 — AS-REP Roasting
```

---

## Scenario

| Component | Value |
| --------- | ----- |
| Source | `Kali-ATK01 / 192.168.56.40` |
| Destination | `DC01 / 192.168.56.20` |
| Domain | `lab.local` |
| Target account | `svc_asrep_lab` |
| Main Windows event | `4768` |
| Wazuh rules | `100050`, `100051`, `100052` |

---

## Command Executed

```bash
impacket-GetNPUsers 'lab.local/svc_asrep_lab' -dc-ip 192.168.56.20 -no-pass -request -format hashcat -outputfile asrep_lab.hash
```

The screenshots show:

```text
Impacket v0.13.0.dev0
```

No additional command variant is documented in this scenario.

---

## Screenshot Executions

| Execution | EDT | UTC | CEST | Result |
| --------: | --- | --- | ---- | ------ |
| 1 | `16:08:10` | `20:08:10` | `22:08:10` | Complete result visible |
| 2 | `16:08:55` | `20:08:55` | `22:08:55` | Complete result visible |
| 3 | `16:08:59` | `20:08:59` | `22:08:59` | Complete result visible |
| 4 | `16:09:04` | `20:09:04` | `22:09:04` | Result outside screenshot |
| 5 | `16:09:08` | `20:09:08` | `22:09:08` | Complete result visible |
| 6 | `16:09:12` | `20:09:12` | `22:09:12` | Complete result visible |

The screenshots demonstrate six command starts and five complete visible results.

Complete returned AS-REP strings are excluded from the public repository.

---

## Observed Sequence

1. The execution timestamp was recorded with `date`.
2. `impacket-GetNPUsers` requested Kerberos authentication material for `svc_asrep_lab`.
3. `DC01` processed the TGT request.
4. Windows generated Event ID `4768`.
5. The event contained `preAuthType=0`.
6. The event completed with `status=0x0`.
7. The event used `ticketEncryptionType=0x17`.
8. Wazuh generated rules `100050` and `100052` during the 28 August validation.
9. A separate validation from 18 August preserved rule `100051`.
10. No offline password recovery or later account use is documented.

---

## Validation Results

| Detection | Result | Evidence date |
| --------- | ------ | ------------- |
| Event ID `4768` | Confirmed | 18 and 28 August |
| `preAuthType=0` | Confirmed | 18 and 28 August |
| `status=0x0` | Confirmed | 18 and 28 August |
| `ticketEncryptionType=0x17` | Confirmed | 18 and 28 August |
| Rule `100050` | Confirmed | 28 August |
| Rule `100051` | Confirmed | 18 August |
| Rule `100052` | Confirmed | 28 August |
| Password recovery | Not demonstrated | — |
| Account cleanup | Not preserved | — |

---

## Evidence Boundary

The three rules are validated across two different collection dates.

The repository does not claim that rules `100050`, `100051` and `100052` were stored as separate alerts during one identical command execution.

The current `100052` XML description also differs from the description stored in the alert, indicating a rule-version difference.

---

## Related Files

- [Detection write-up](../../detections/T1558.004-as-rep-roasting.md)
- [Windows internals](../../docs/windows-internals/T1558.004-as-rep-roasting-internals.md)
- [Timeline](timeline.md)
- [Wazuh filter](wazuh-filter.kql)
- [Evidence](../../evidence/as-rep-roasting/)
