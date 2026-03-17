# detect-dns-anomaly.zeek

**Location:** `zeek/site/iot-detection/detect-dns-anomaly.zeek`

Uses Zeek's `SumStats` framework to count DNS queries per device per epoch
and flag devices that exceed the configured rate thresholds. Also computes
the Shannon entropy of each queried domain name and counts high-entropy
queries separately as a signal for DGA (domain generation algorithm)
activity or DNS tunnelling.

Default thresholds (override in `local.zeek`):

| Option | Default | Severity |
|--------|---------|---------|
| `dns_rate_warning_threshold` | 100 queries/epoch | WARNING |
| `dns_rate_critical_threshold` | 500 queries/epoch | CRITICAL |
| `dga_warning_threshold` | 5 high-entropy queries/epoch | WARNING |
| `dns_rate_epoch` | 60 seconds | |

---

```text
--8<-- "zeek/site/iot-detection/detect-dns-anomaly.zeek"
```
