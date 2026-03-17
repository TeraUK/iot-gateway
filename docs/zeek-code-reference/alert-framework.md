# alert-framework.zeek

**Location:** `zeek/site/iot-detection/alert-framework.zeek`

Shared infrastructure used by all six detection scripts. Defines the
`IoT::ALERT_LOG` stream that writes structured JSON entries to
`iot_alerts.log`, the `emit_alert()` function that all detectors call, and
the `request_isolation()` function that POSTs to the Ryu REST API for
CRITICAL alerts when `auto_isolate = T`. Also maintains the `dhcp_table`
used by `ip_to_mac()` for MAC address resolution and provides the
`is_iot_device()` helper.

All configuration options (`auto_isolate`, `iot_subnet`, `gateway_ip`,
`ryu_api_url`) are declared as Zeek `option` values and can be overridden
in `local.zeek` without modifying this file.

See [Components: Zeek](../components/zeek.md#alert-frameworkzeek) for the
full option reference.

---

```text
--8<-- "zeek/site/iot-detection/alert-framework.zeek"
```
