# state.py

**Location:** `ml-pipeline/app/state.py`

Holds all shared mutable runtime state for the pipeline. Specifically, it
maintains the IP-to-MAC mapping table (populated from `dhcp.log` entries),
per-device 5-minute rolling event windows, per-feature
exponentially-weighted baselines used by rule-based checks, and alert
deduplication records that suppress repeated identical alerts within a
configurable window (default: 120 seconds).

For a functional description of the pipeline see
[Components: ML Pipeline](../../components/ml-pipeline/ml-pipeline.md).

---

## Code Reference

The following reference is auto-generated from the source code docstrings.

::: state
