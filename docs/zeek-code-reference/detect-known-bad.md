# detect-known-bad.zeek

**Location:** `zeek/site/iot-detection/detect-known-bad.zeek`

Loads two IOC files via Zeek's `Input::add_table` framework with
`Input::REREAD` mode, meaning the files are re-read on change without
requiring a Zeek restart. Any connection to a known-bad IP or DNS query for
a known-bad domain generates a CRITICAL alert immediately. The IOC files
use a tab-separated format: value in the first column, optional description
in the second.

IOC file locations (override in `local.zeek`):

| Option | Default path |
|--------|-------------|
| `known_bad_ips_file` | `zeek/site/iot-iocs/known-bad-ips.dat` |
| `known_bad_domains_file` | `zeek/site/iot-iocs/known-bad-domains.dat` |

---

```text
--8<-- "zeek/site/iot-detection/detect-known-bad.zeek"
```
