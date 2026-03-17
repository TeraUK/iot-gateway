# detect-port-scan.zeek

**Location:** `zeek/site/iot-detection/detect-port-scan.zeek`

Detects reconnaissance behaviour by counting the number of distinct
`(dst_ip, dst_port)` pairs each IoT device contacts within a rolling
`port_scan_epoch` window using Zeek's `SumStats` framework. Crossing the
WARNING threshold produces a WARNING alert; crossing the CRITICAL threshold
produces a CRITICAL alert that triggers isolation when `auto_isolate = T`.

Default thresholds (override in `local.zeek`):

| Option | Default | Severity |
|--------|---------|---------|
| `port_scan_warning_threshold` | 15 unique pairs | WARNING |
| `port_scan_critical_threshold` | 30 unique pairs | CRITICAL |
| `port_scan_epoch` | 60 seconds | |

---

```text
--8<-- "zeek/site/iot-detection/detect-port-scan.zeek"
```
