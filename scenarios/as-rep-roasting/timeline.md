# AS-REP Roasting Timeline

## Validation Session — 18 August 2026

This session provides direct evidence for rule `100051`.

| Order | UTC time | Event |
| ----: | -------- | ----- |
| 1 | `01:28:22.2865658` | Windows Event ID `4768`, record `136332` |
| 2 | `01:33:59.401` | Wazuh rule `100051`, level `13` |

Observable event-to-alert timestamp difference:

```text
337.114 seconds
```

The alert contains:

```text
preAuthType = 0
ticketEncryptionType = 0x17
status = 0x0
source = ::ffff:192.168.56.40
```

The unusually long timestamp difference is preserved as observed. The available evidence does not determine whether it was caused by collection delay, queueing, indexing, clock synchronization or another processing factor.

---

## Validation Session — 28 August 2026

This session provides direct evidence for rules `100050` and `100052`.

### Native Windows events

| Order | UTC time | Event |
| ----: | -------- | ----- |
| 1 | `20:08:11.6139542` | Event ID `4768`, record `139034` |
| 2 | `20:08:27.5104550` | Event ID `4768`, record `139064` |
| 3 | `20:08:31.0812711` | Event ID `4768`, record `139070` |

### Wazuh alerts

| Order | UTC time | Alert |
| ----: | -------- | ----- |
| 4 | `20:08:33.669` | Rule `100050`, level `12` |
| 5 | `20:09:03.086` | Rule `100052`, level `14`, frequency `3` |

### Event intervals

| Interval | Duration |
| -------- | -------: |
| Record `139034` → `139064` | `15.897 s` |
| Record `139064` → `139070` | `3.571 s` |
| Record `139034` → `139070` | `19.467 s` |

### Event-to-alert differences

| Alert | Native event | Difference |
| ----- | ------------ | ---------: |
| `100050` | Record `139034` | `22.055 s` |
| `100052` | Record `139070` | `32.005 s` |

---

## Screenshot Timeline

| Execution | UTC marker | Evidence |
| --------: | ---------- | -------- |
| 1 | `20:08:10` | Complete result visible |
| 2 | `20:08:55` | Complete result visible |
| 3 | `20:08:59` | Complete result visible |
| 4 | `20:09:04` | Command visible; result outside screenshot |
| 5 | `20:09:08` | Complete result visible |
| 6 | `20:09:12` | Complete result visible |

The first screenshot marker is temporally compatible with record `139034`.

The later screenshot markers are not mapped to individual Windows records because the supplied evidence does not contain matching native event timestamps for every visible execution.

---

## Validated Detection Chain

```text
Event ID 4768
        ↓
preAuthType = 0
        ↓
rule 100050
        ↓
ticketEncryptionType = 0x17
        ↓
rule 100051
        ↓
three qualifying requests from the same source
        ↓
rule 100052
```

The rule logic is validated across two separate dates rather than one single continuous timeline.
