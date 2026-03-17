# local.zeek

**Location:** `zeek/site/local.zeek`

The root Zeek policy file, loaded automatically by Zeek on startup. Loads
all protocol analysers that feed the ML pipeline (`conn`, `dns`, `http`,
`ssl`, `dhcp`, `ntp`, `ssh`, `ftp`), configures hourly log rotation and
JSON output format, and loads the IoT detection scripts via
`@load ./iot-detection`. Detection thresholds and operating modes can be
overridden at the bottom of this file using `redef` statements without
modifying the individual detection scripts.

See [Components: Zeek](../components/zeek.md) for a description of each
protocol analyser and the detection threshold options.

---

```text
--8<-- "zeek/site/local.zeek"
```
