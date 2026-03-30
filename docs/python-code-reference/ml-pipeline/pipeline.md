# pipeline.py

**Location:** `ml-pipeline/app/pipeline.py`

The main entry point and orchestration loop for the ML anomaly detection
pipeline. It loads configuration and models at startup, then runs a
four-stage processing cycle (ingest, enrich, score, dispatch) on a
configurable poll interval (default: every 10 seconds). All other runtime
modules are driven from here.

For a functional description of the pipeline see
[Components: ML Pipeline](../../components/ml-pipeline/ml-pipeline.md).

---

## Code Reference

The following reference is auto-generated from the source code docstrings.

::: pipeline
