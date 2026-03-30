# features.py

**Location:** `ml-pipeline/app/features.py`

Converts a device's 5-minute rolling window of log entries into a
fixed-length vector of 15 numerical features (11 from `conn.log`, 4 from
`dns.log`). The same code is used at training time and at inference time,
which guarantees that the model always sees inputs in exactly the same
format it was trained on.

For the full feature definitions see
[Components: ML Pipeline](../../components/ml-pipeline/ml-pipeline.md).

---

## Code Reference

The following reference is auto-generated from the source code docstrings.

::: features
