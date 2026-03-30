# Python Code Reference

This section documents every Python module in the repository. References
are auto-generated from the source code docstrings using
[mkdocstrings](https://mkdocstrings.github.io/), so the pages always
reflect the current implementation.

For functional descriptions of what each component does and how to operate it,
see the [Components](../components/ml-pipeline/ml-pipeline.md) and
[Operations](../operations/training-the-model.md) sections.

---

## Modules in this section

### ML Pipeline

The six runtime modules that make up the anomaly detection pipeline
(`ml-pipeline/app/`).

| Module | Purpose |
|--------|---------|
| [pipeline.py](ml-pipeline/pipeline.md) | Main orchestration loop - loads config and models, then runs the four-stage processing cycle on a configurable poll interval |
| [state.py](ml-pipeline/state.md) | Shared mutable runtime state - IP-to-MAC table, per-device rolling windows, feature baselines, and alert deduplication |
| [ingestor.py](ml-pipeline/ingestor.md) | Tails Zeek log files using inode-based rotation detection, returning only new lines on each poll |
| [features.py](ml-pipeline/features.md) | Extracts the fixed 15-feature numerical vector from a device's rolling window |
| [detector.py](ml-pipeline/detector.md) | Loads `.joblib` model files, selects per-device or fleet model, and returns an anomaly score |
| [alerter.py](ml-pipeline/alerter.md) | Writes `ml_alerts.log` and calls the Ryu REST API to isolate devices on CRITICAL alerts |

### Other modules

| Module | Location | Purpose |
|--------|----------|---------|
| [train.py](training.md) | `ml-pipeline/train/` | Offline training script - builds Isolation Forest models from historical Zeek logs |
| [gateway_policy.py](ryu-gateway-policy-app.md) | `ryu/apps/` | Ryu SDN application implementing the gateway security policy and REST API |
| [profile_builder.py](profile-builder.md) | `scripts/` | Analyses historical Zeek logs to produce draft per-device traffic profiles |
| [dns_cache_updater.py](dns-cache-updater.md) | `Services/dns-cache-updater/` | Monitors Zeek DNS logs and pushes resolved domain-to-IP mappings to the Ryu REST API |
