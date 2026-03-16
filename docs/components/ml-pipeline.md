# ML Pipeline

The ML pipeline (POL-08) provides a second layer of anomaly detection that operates alongside the Zeek rule-based detection scripts. Where Zeek catches specific known patterns (port scanning, known-bad IPs, extreme DNS rates), the ML pipeline catches statistical deviations from a device's normal behaviour that don't match any specific rule.

## Overview

The pipeline runs an **Isolation Forest** model per device. Isolation Forest is an unsupervised anomaly detection algorithm that learns what "normal" looks like from a training set and scores new observations against that model. It does not require labelled attack data.

A separate **fleet model** (trained on all devices combined) acts as a fallback for devices that don't yet have a per-device model, providing immediate coverage for newly-connected devices.

## Module structure

| Module | Responsibility |
|--------|----------------|
| `pipeline.py` | Main loop: orchestrates ingestion, enrichment, scoring, and dispatch |
| `state.py` | Shared runtime state: IP→MAC table, per-device rolling windows, baselines, dedup |
| `ingestor.py` | Tails Zeek log files using inode-based rotation detection |
| `features.py` | Extracts the 15-feature vector from a device's rolling window |
| `detector.py` | Loads `.joblib` model files, runs inference, returns anomaly score |
| `alerter.py` | Writes `ml_alerts.log`, calls Ryu REST API for CRITICAL alerts |
| `train/train.py` | Offline training script - run on the host, not in the container |

## Feature set

Features are computed from a 5-minute rolling window of Zeek log entries per device. The same feature extraction code is used at both training time and inference time.

### Connection features (from `conn.log`)

| Feature | Description |
|---------|-------------|
| `conn_count` | Total connections in window |
| `unique_dst_ips` | Unique destination IP addresses |
| `unique_dst_ports` | Unique destination ports |
| `bytes_sent` | Total originator bytes |
| `bytes_recv` | Total responder bytes |
| `bytes_ratio` | `bytes_sent / total` - direction of data flow |
| `mean_duration` | Mean connection duration (seconds) |
| `failed_conn_rate` | Proportion of connections in state S0 or REJ |
| `tcp_ratio` | Proportion of TCP connections |
| `udp_ratio` | Proportion of UDP connections |
| `icmp_ratio` | Proportion of ICMP connections |

### DNS features (from `dns.log`)

| Feature | Description |
|---------|-------------|
| `dns_query_count` | Total DNS queries in window |
| `dns_unique_domains` | Unique domain names queried |
| `dns_nxdomain_rate` | Proportion of queries returning NXDOMAIN |
| `dns_entropy_mean` | Mean Shannon entropy of query names (bits/char). High values indicate DGA or DNS tunnelling. |

## Severity classification

The pipeline applies checks in this order. The first match determines the severity.

### Rule-based checks (applied first, regardless of model score)

These checks run without a trained model and catch high-confidence attack patterns immediately:

| Check | CRITICAL threshold | WARNING threshold |
|-------|--------------------|-------------------|
| Unique destination ports | ≥ 30 | - |
| Failed connection rate | ≥ 80% | ≥ 50% |
| DNS query rate (vs baseline) | ≥ 10× baseline mean | ≥ 2× baseline mean |
| DNS entropy | ≥ 3.80 bits/char | ≥ 3.50 bits/char |
| Traffic volume (vs baseline) | ≥ 10× baseline | ≥ 3× baseline |

Baseline-relative checks require `baseline_established() = True`, which needs at least 50 scoring cycles (~50 minutes at 60s intervals).

### Isolation Forest score (applied after rule checks)

| Score range | Severity |
|-------------|----------|
| ≥ 0.30 | CRITICAL |
| ≥ 0.15 | WARNING |
| ≥ 0.05 | INFO |
| < 0.05 | No alert |

The Isolation Forest returns a `decision_function` value where negative = anomalous. The pipeline inverts this sign so that higher scores mean more anomalous behaviour.

All thresholds are configurable in `ml-pipeline/config/thresholds.yml` without rebuilding the container.

## Auto-isolation

By default, `ML_AUTO_ISOLATE=false` in `docker-compose.yml`. In this mode:

- CRITICAL alerts are written to `ml_alerts.log` with `action_taken: dry_run`.
- No Ryu API calls are made.

To enable automatic isolation after validating the models:

```yaml
# docker-compose.yml, ml-pipeline service
environment:
  - ML_AUTO_ISOLATE=true
```

Then `docker compose up -d ml-pipeline`.

## Alert log format (`ml_alerts.log`)

```json
{
  "ts": "2026-03-15T12:34:56.789012+00:00",
  "severity": "WARNING",
  "detector": "ml-isolation-forest",
  "src_ip": "192.168.50.75",
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "description": "DNS query rate 3.2x above device baseline (96 queries vs mean 30.1).",
  "details": "{\"trigger\": \"dns_rate\", \"dns_query_count\": 96, \"baseline_mean\": 30.1, \"multiplier\": 3.19, \"model_type\": \"per-device\"}",
  "action_taken": "logged"
}
```

## Models directory

Trained models are stored in `ml-pipeline/models/` and bind-mounted read-only into the container:

| File | Description |
|------|-------------|
| `aa_bb_cc_dd_ee_ff.joblib` | Per-device model for MAC `aa:bb:cc:dd:ee:ff` |
| `_fleet.joblib` | Global fleet model (fallback for unprofiled devices) |

The pipeline loads all `.joblib` files at startup. To pick up new models after retraining:

```bash
docker compose restart ml-pipeline
```

For training instructions, see [Training the Model](../operations/training-the-model.md).

## Known limitations

The pipeline analyses outbound traffic only. Features are computed with the IoT device as the originator (`id.orig_h`). Inbound traffic patterns (e.g., an attacker probing the device) are not scored. The Zeek detection scripts provide rule-based coverage for inbound port probing.

## API Reference

The following reference is auto-generated from the source code docstrings.

### pipeline.py

::: pipeline

### state.py

::: state

### ingestor.py

::: ingestor

### features.py

::: features

### detector.py

::: detector

### alerter.py

::: alerter

### train/train.py

::: train