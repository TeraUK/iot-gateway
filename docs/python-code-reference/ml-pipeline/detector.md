# detector.py

**Location:** `ml-pipeline/app/detector.py`

Loads all `.joblib` model files at startup and exposes a `score()` method.
Given a device MAC address and its 15-feature vector, it selects the
per-device model if one exists, falling back to the global fleet model for
devices not yet individually trained. The raw `decision_function` score is
inverted so that higher values always indicate more anomalous behaviour,
matching the threshold semantics in `config/thresholds.yml`.

For a functional description of the pipeline see
[Components: ML Pipeline](../../components/ml-pipeline/ml-pipeline.md).

---

## Code Reference

The following reference is auto-generated from the source code docstrings.

::: detector
