# Detection-to-isolation loop

There are two parallel paths from detection to isolation. Both converge on the Ryu REST API. 

Note. These paths refer to dynamic anomaly detection, not DNS filtering, pre-installed rules or per-device destination allowlits.

### Path 1: Zeek rule-based detection

```
Zeek captures packet
    │
    ▼
Detection script evaluates event
  (detect-port-scan, detect-dns-anomaly,
   detect-new-destination, detect-protocol-anomaly,
   detect-volume-anomaly, detect-known-bad)
    │
    ▼
alert-framework.zeek: emit_alert()
    │
    ├── severity = INFO    → write to iot_alerts.log only
    ├── severity = WARNING → write to iot_alerts.log only
    └── severity = CRITICAL, auto_isolate = T
            │
            ▼
        ActiveHTTP POST → ryu:8080/policy/isolate
            │
            ▼
        Ryu installs priority-65535 DROP rule in OVS
```

see [Zeek](../components/zeek.md)

### Path 2: ML pipeline anomaly detection

```
ML Pipeline polls Zeek log files (every POLL_INTERVAL seconds)
    │
    ▼
ingestor.py: reads new log lines, tagged by type
    │
    ▼
state.py: resolves IP→MAC via dhcp.log entries,
          adds entries to per-device rolling window (5 min)
    │
    ▼
features.py: extracts 15-feature vector from window
    │
    ▼
detector.py: Isolation Forest.decision_function()
             returns anomaly score (higher = more anomalous)
    │
    ▼
pipeline.py: classify() applies rule-based checks
             then Isolation Forest thresholds
    │
    ├── severity = INFO    → write to ml_alerts.log only
    ├── severity = WARNING → write to ml_alerts.log only
    └── severity = CRITICAL, ML_AUTO_ISOLATE = true
            │
            ▼
        alerter.py: POST → ryu:8080/policy/isolate
                    (with exponential backoff retry)
            │
            ▼
        Ryu installs priority-65535 DROP rule in OVS
```

see [ML-Pipeline](../components/ml-pipeline.md)

---