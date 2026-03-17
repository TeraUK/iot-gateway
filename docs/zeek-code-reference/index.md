# Zeek Code Reference

This section embeds the full source of every Zeek script and configuration
file in the repository directly from the source files. Content is included
at build time via MkDocs' snippet system so the pages always reflect the
current version on disk.

For a functional description of the detection pipeline see
[Components: Zeek](../components/zeek.md).

!!! note "Syntax highlighting"
    Zeek uses its own scripting language for which no Pygments lexer exists.
    The `.zeek` files are rendered as plain text to avoid incorrect
    highlighting from a mismatched lexer. `entrypoint.sh` is standard bash
    and is highlighted normally.

---

## Files in this section

| File | Location | Purpose |
|------|----------|---------|
| [entrypoint.sh](entrypoint.md) | `zeek/` | Container startup - waits for mirror interface before starting Zeek |
| [local.zeek](local-zeek.md) | `zeek/site/` | Protocol analysers, logging config, and detection script loader |
| [\_\_load\_\_.zeek](load.md) | `zeek/site/iot-detection/` | Loads the alert framework and all detection scripts in dependency order |
| [alert-framework.zeek](alert-framework.md) | `zeek/site/iot-detection/` | Shared alert infrastructure: `emit_alert()`, IP-to-MAC resolution, Ryu REST calls |
| [detect-port-scan.zeek](detect-port-scan.md) | `zeek/site/iot-detection/` | Counts unique dst-IP/port pairs per device per epoch |
| [detect-dns-anomaly.zeek](detect-dns-anomaly.md) | `zeek/site/iot-detection/` | Flags high DNS query rates and high-entropy domain names |
| [detect-new-destination.zeek](detect-new-destination.md) | `zeek/site/iot-detection/` | Flags connections to destinations not seen during the learning phase |
| [detect-protocol-anomaly.zeek](detect-protocol-anomaly.md) | `zeek/site/iot-detection/` | Flags new ports and inherently suspicious protocols |
| [detect-volume-anomaly.zeek](detect-volume-anomaly.md) | `zeek/site/iot-detection/` | Flags devices exceeding outbound byte thresholds per epoch |
| [detect-known-bad.zeek](detect-known-bad.md) | `zeek/site/iot-detection/` | Matches connections and DNS queries against IOC files |
