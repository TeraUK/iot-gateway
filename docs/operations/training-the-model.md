# Training the Model

The ML pipeline requires trained Isolation Forest models to produce anomaly scores. Without models, the pipeline runs in rule-based-only mode (the rule checks in `pipeline.py` still apply), but the Isolation Forest scoring layer is inactive.

## When to train

**Do not train on insufficient data.** A model trained on less than 2 weeks of logs will have an unreliable idea of what "normal" looks like for each device. This produces excessive false positives and undermines confidence in the alerts.

Train the model when:

- At least 2 weeks of Zeek logs have been collected under normal operating conditions with Phases 1–4 active.
- The Zeek detection scripts have been running and auto-isolation has been operational long enough that the logs represent already-filtered, normal traffic.
- There have been no major changes to the device set (adding or removing devices resets the baseline requirement for those devices).

## Prerequisites

The training script runs on the host, not inside the container. It needs access to the Zeek log directory and the scikit-learn package:

```bash
pip3 install scikit-learn joblib numpy pandas --break-system-packages
```

## Running the training script

```bash
python3 ml-pipeline/train/train.py \
    --log-dir /var/lib/docker/volumes/iot-gateway_zeek-logs/_data \
    --output-dir ./ml-pipeline/models \
    --min-windows 576
```

The `--min-windows` value of 576 corresponds to 48 hours of 5-minute windows. This is the minimum recommended value. Increasing it (e.g., to 2016 = 1 week) improves model quality.

### Dry run first

Before saving models, do a dry run to see which devices have enough data:

```bash
python3 ml-pipeline/train/train.py \
    --log-dir /var/lib/docker/volumes/iot-gateway_zeek-logs/_data \
    --output-dir ./ml-pipeline/models \
    --min-windows 576 \
    --dry-run
```

The output reports how many windows each device has. Devices below the threshold are skipped for per-device models but included in the fleet model.

### Adjusting the contamination parameter

`--contamination` tells Isolation Forest what proportion of training examples to treat as anomalies. The default is `0.05` (5%). This is appropriate when the training data was collected with detection scripts active (meaning most genuinely malicious traffic was blocked or isolated before it made it into the logs).

If the training data was collected before detection was fully operational, consider increasing this to `0.10`.

## After training

1. Confirm model files exist in `ml-pipeline/models/`:
   ```bash
   ls -lh ml-pipeline/models/
   # Should show one .joblib file per device + _fleet.joblib
   ```

2. Restart the ML pipeline container to load the new models:
   ```bash
   docker compose restart ml-pipeline
   ```

3. Confirm the models were loaded:
   ```bash
   docker logs ml-pipeline | grep "Model reload complete"
   # Should show: "N per-device model(s), 1 fleet model(s)"
   ```

## Validating the models before enabling auto-isolation

After deploying new models, run the pipeline in dry-run mode (`ML_AUTO_ISOLATE=false`, which is the default) and monitor `ml_alerts.log` for at least one week. Look for:

- **False positives on normal traffic** — a device being scored as CRITICAL during its normal usage pattern. If this happens, check whether the model had enough training data or whether the `critical_threshold` in `thresholds.yml` needs to be raised.
- **Expected alerts** — intentionally generate some anomalous traffic (e.g., a port scan from a test device) and verify it produces a CRITICAL alert.

Once satisfied with the false positive rate, enable auto-isolation:

```yaml
# docker-compose.yml, ml-pipeline environment
- ML_AUTO_ISOLATE=true
```

```bash
docker compose up -d ml-pipeline
```

## Retraining schedule

Retrain the model when:

- A device receives a firmware update that changes its traffic patterns (the denied log or new INFO alerts in `ml_alerts.log` will indicate this).
- A new device is added and has accumulated sufficient baseline data.
- Seasonal patterns change significantly (e.g., a device used heavily in winter but rarely in summer).

There is no fixed retraining schedule. The exponentially-weighted baseline in `state.py` adapts slowly over time to absorb gradual drift, but a full retrain is appropriate for step-change behaviour differences.
