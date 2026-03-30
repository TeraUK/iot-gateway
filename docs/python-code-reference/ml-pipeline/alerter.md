# alerter.py

**Location:** `ml-pipeline/app/alerter.py`

Handles the output stage of the pipeline. It always writes a JSON alert
entry to `ml_alerts.log` using the same schema as Zeek's `iot_alerts.log`
so both log sources can be parsed by the same tooling. For CRITICAL alerts
when `ML_AUTO_ISOLATE=true`, it additionally calls the Ryu SDN controller's
REST API to install a drop rule for the device at the data plane, with
exponential backoff retry on transient failures.

For the alert response workflow see
[Operations: Alert Response](../../operations/alert-response.md).

---

## Code Reference

The following reference is auto-generated from the source code docstrings.

::: alerter
