# Machine Learning Pipeline Modules

---

## The seven modules

The pipeline is split into six runtime modules and one offline training script.

### `pipeline.py` - the main loop

This is the entry point. It starts up, loads configuration and models, then
runs a four-stage processing loop forever on a configurable poll interval
(default: every 10 seconds). All other modules are orchestrated by this one.

### `ingestor.py` - reading Zeek logs

Zeek writes its output as JSON log files to a shared Docker volume
(`conn.log`, `dns.log`, `dhcp.log`, `http.log`, `ssl.log`). The ingestor tails
these files, reading only the lines that have been written since the last poll.
It tracks the byte offset and inode of each file so it can detect when Zeek
rotates a log (which happens hourly) and resume reading the new file from the
beginning without missing or duplicating entries.

### `state.py` - shared runtime memory

This module holds all of the pipeline's mutable state. Three things live here:

1. **IP-to-MAC table.** Zeek logs connections by IP address, not MAC address.
   The DHCP log is the only source that maps an IP to the physical device behind
   it. Every time a DHCP log entry is ingested, this table is updated. All other
   log entries are then resolved through this table to find out which device they
   belong to.

2. **Per-device rolling windows.** Each device has a sliding window of the last
   5 minutes of log entries. Entries older than 5 minutes are automatically
   pruned. This window is what the feature extractor reads when it is time to
   score a device.

3. **Per-device baselines.** The pipeline tracks a running statistical baseline
   (mean and variance per feature) for each device using Welford's online
   algorithm. This is used by the rule-based checks - for example, "is this
   device's DNS query rate 10 times higher than its own normal rate?" The
   baseline needs at least 50 scoring cycles (approximately 50 minutes) before
   baseline-relative checks activate.

   It also holds a deduplication record that prevents the same device from
   generating a flood of identical alerts within a short window (default: 120
   seconds).

### `features.py` - turning traffic into numbers

The ML model cannot read raw log entries directly - it works with numbers. This
module converts a device's 5-minute window of log entries into a fixed-length
vector of 15 numbers. The same code is used at training time and at inference
time, which guarantees that the model always sees inputs in exactly the same
format it was trained on.

The 15 features are:

**From `conn.log` (11 features)**

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

**From `dns.log` (4 features)**

| Feature | Description |
|---------|-------------|
| `dns_query_count` | Total DNS queries in window |
| `dns_unique_domains` | Unique domain names queried |
| `dns_nxdomain_rate` | Proportion of queries returning NXDOMAIN |
| `dns_entropy_mean` | Mean Shannon entropy of query names (bits/char). High values indicate DGA or DNS tunnelling. |

### `detector.py` - running the model

This module loads the trained `.joblib` model files at startup and provides a
single `score()` method. Given a device's MAC address and its 15-feature vector,
it selects the appropriate model (per-device if one exists, fleet model
otherwise), runs it, and returns an anomaly score. The score is inverted from
the raw scikit-learn output so that **higher scores always mean more anomalous
behaviour**, which maps intuitively to the threshold configuration in
`thresholds.yml`.

### `alerter.py` - writing alerts and isolating devices

Once the pipeline has decided that a device's behaviour is anomalous, the
alerter handles what happens next. It always writes a JSON entry to
`ml_alerts.log` (using the same schema as Zeek's `iot_alerts.log` so both can
be parsed by the same tooling). For CRITICAL alerts, if `ML_AUTO_ISOLATE=true`,
it also calls the SDN controller's REST API to install a drop rule for that
device's MAC address at the network data plane, cutting it off from the network.
The API call is retried up to three times with exponential backoff in case of a
transient network error.

By default, `ML_AUTO_ISOLATE` is set to `false`. In this mode, CRITICAL alerts
are written to the log with `action_taken: dry_run` and no isolation call is
made. This is the recommended initial deployment posture while models are being
validated against real traffic.

### `train/train.py` - offline training (run on the host)

This script is not part of the running container. It is run manually on the
gateway host after collecting at least two weeks of Zeek logs covering a device's
typical usage patterns. It reads historical log files, builds the same 5-minute
feature windows that the runtime pipeline uses, trains one Isolation Forest per
device, and trains a global fleet model. The resulting `.joblib` files are saved
to `ml-pipeline/models/`, which is bind-mounted into the container. After running
training, the container is restarted to pick up the new models.

---

## Module Diagram

The following diagram shows the module structure, including each components dependencies and responsibilities

---

```kroki-plantuml

@startuml ml_pipeline_components

skinparam backgroundColor #FAFAFA
skinparam defaultFontName Arial
skinparam defaultFontSize 11
skinparam roundCorner 8
skinparam shadowing false
skinparam packageStyle rectangle
skinparam componentBorderColor #888888
skinparam ArrowColor #555555
skinparam ArrowFontSize 10
skinparam ArrowFontColor #444444

title **ML Pipeline - Module Structure**\nComponent dependencies and responsibilities

' ── External systems ──────────────────────────────────────────────────────────

database "Zeek Log Volume\n(shared Docker volume)\nconn.log  dns.log  dhcp.log\nhttp.log  ssl.log" as zeek_vol #C8E6C9
database "ml_alerts.log\n(shared Docker volume)" as alert_log #FFCDD2
database "models/\n*.joblib files\n(bind mount)" as models_dir #FFF9C4
node "SDN Controller\nREST API\nPOST /policy/isolate" as ryu #E0E0E0
actor "Operator\n(offline training)" as operator #E0E0E0

' ── Container boundary ────────────────────────────────────────────────────────

package "ml-pipeline container" as container #EAF4FB {

    ' ── Offline training (run on host) ────────────────────────────────────────

    package "Offline Training\n(run on host, not in container)" as training_pkg #FFF3E0 {
        component "**train.py**\nReads historical Zeek logs,\nbuilds 5-min feature windows\nper device, trains one\nIsolation Forest per device\nplus a global fleet model.\nSaves .joblib files." as train #FFE0B2
    }

    ' ── Runtime modules ───────────────────────────────────────────────────────

    package "Runtime Modules" as runtime_pkg #E3F2FD {

        component "**pipeline.py**\nMain orchestration loop.\nRuns the four processing\nstages (ingest, enrich,\nscore, dispatch) on a\nconfigurable poll interval.\nLoads config/thresholds.yml." as pipeline #BBDEFB

        component "**ingestor.py**\nTails Zeek log files.\nTracks byte offsets and\nfile inodes to detect\nhourly log rotation.\nReturns new JSON entries\non each poll() call." as ingestor #BBDEFB

        component "**state.py**\nShared mutable runtime state.\nHolds: IP-to-MAC table,\nper-device 5-min rolling\nevent windows, per-feature\nexponentially-weighted\nbaselines, and alert\ndeduplication records." as state #BBDEFB

        component "**features.py**\nExtracts the fixed 15-feature\nnumerical vector from a\ndevice's rolling window.\nSame code used at both\ntraining time and inference\ntime to guarantee consistency." as features #BBDEFB

        component "**detector.py**\nLoads all .joblib model files\nat startup. Selects the\nper-device model if one\nexists, falls back to the\nglobal fleet model for new\ndevices. Inverts the\ndecision_function score so\nhigher = more anomalous." as detector #BBDEFB

        component "**alerter.py**\nWrites alert entries to\nml_alerts.log in the same\nJSON schema as Zeek alerts.\nFor CRITICAL alerts with\nML_AUTO_ISOLATE=true,\ncalls Ryu REST API with\nexponential backoff retry." as alerter #BBDEFB

        component "**config/thresholds.yml**\nIsolation Forest score\nthresholds (INFO/WARNING/\nCRITICAL) and rule-based\ncheck thresholds.\nEditable without rebuilding\nthe container image." as config #E8EAF6
    }
}

' ── Training flow ─────────────────────────────────────────────────────────────

operator --> train : runs manually\nafter collecting logs
zeek_vol --> train : reads historical\nconn.log / dns.log\n/ dhcp.log
train --> models_dir : writes\n*.joblib files

' ── Runtime: external inputs ──────────────────────────────────────────────────

zeek_vol --> ingestor : tails live log files\n(new lines only)
models_dir --> detector : loads at startup
config --> pipeline : loads thresholds\nand rule parameters

' ── Runtime: internal dependencies ───────────────────────────────────────────

pipeline --> ingestor : poll() - get new entries
pipeline --> state : update_dhcp()\nadd_entry()\nall_active_macs()\nget_window()
pipeline --> features : extract(window)
pipeline --> detector : score(mac, features)\nmodel_type(mac)
pipeline --> alerter : dispatch(severity,\nmac, ip, desc, details)
pipeline --> state : update_baseline()\nshould_suppress()\nrecord_alert()

features ..> state : reads window entries\n(passed in by pipeline)

' ── Runtime: external outputs ─────────────────────────────────────────────────

alerter --> alert_log : appends JSON\nalert entry
alerter --> ryu : POST /policy/isolate\n(CRITICAL + AUTO_ISOLATE=true)

' ── Shared feature code ───────────────────────────────────────────────────────

train ..> features : imports extract()\nand FEATURE_NAMES\n(same code as runtime)

legend bottom left
  |= Fill |= Meaning |
  | <#BBDEFB> | Runtime module (inside container) |
  | <#FFE0B2> | Offline training script (run on host) |
  | <#C8E6C9> | Shared Docker volume (input) |
  | <#FFCDD2> | Shared Docker volume (output) |
  | <#FFF9C4> | Trained model bind mount |
  | <#E8EAF6> | Configuration file |
endlegend

@enduml
 
                                                              
```