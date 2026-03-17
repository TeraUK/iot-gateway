# \_\_load\_\_.zeek

**Location:** `zeek/site/iot-detection/__load__.zeek`

The entry point for the `iot-detection` script package. Zeek's `@load`
directive resolves this file automatically when `@load ./iot-detection` is
used in `local.zeek`. It loads `alert-framework.zeek` first (a hard
dependency for all detectors) then loads each detection script in
order.

---

```text
--8<-- "zeek/site/iot-detection/__load__.zeek"
```
