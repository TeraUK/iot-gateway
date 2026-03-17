# detect-new-destination.zeek

**Location:** `zeek/site/iot-detection/detect-new-destination.zeek`

Maintains a per-device baseline of destination IPs observed during a
learning phase. Once switched to `detecting` mode, any connection to a
destination not in the baseline generates an INFO alert. The number of new
destinations within an epoch can escalate to WARNING or CRITICAL if the
count crosses the configured thresholds, which indicates active scanning
rather than a one-off new connection.

Default thresholds (override in `local.zeek`):

| Option | Default | Notes |
|--------|---------|-------|
| `new_dest_mode` | `"learning"` | Switch to `"detecting"` once baseline is established |
| `new_dest_warning_threshold` | 3 new destinations/epoch | WARNING |
| `new_dest_critical_threshold` | 10 new destinations/epoch | CRITICAL |
| `new_dest_epoch` | 1 hour | |

---

```text
--8<-- "zeek/site/iot-detection/detect-new-destination.zeek"
```
