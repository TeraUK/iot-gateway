# detect-volume-anomaly.zeek

**Location:** `zeek/site/iot-detection/detect-volume-anomaly.zeek`

Uses Zeek's `SumStats` framework to accumulate outbound bytes per IoT
device across each epoch window. Byte counts are collected from
`connection_state_remove` events using `orig_ip_bytes` so the full
connection total is captured after the connection closes. Crossing the
WARNING threshold produces a WARNING alert; crossing the CRITICAL threshold
produces a CRITICAL alert.

Default thresholds (override in `local.zeek`):

| Option | Default | Severity |
|--------|---------|---------|
| `volume_warning_threshold` | 50 MB (52428800 bytes) | WARNING |
| `volume_critical_threshold` | 200 MB (209715200 bytes) | CRITICAL |
| `volume_epoch` | 10 minutes | |

---

```text
--8<-- "zeek/site/iot-detection/detect-volume-anomaly.zeek"
```
