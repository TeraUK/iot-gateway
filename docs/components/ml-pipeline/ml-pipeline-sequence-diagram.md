# Machine Learning Pipeline Sequence Diagram

---

The following sequence diagram shows the series of events that take place between offline training of the models to the end of a single scoring cycle at runtime.

---

```kroki-plantuml
@startuml ml_pipeline_sequence

skinparam backgroundColor #FAFAFA
skinparam defaultFontName Arial
skinparam defaultFontSize 11
skinparam roundCorner 8
skinparam shadowing false
skinparam sequenceArrowThickness 1.5
skinparam sequenceGroupBorderColor #888888
skinparam sequenceGroupFontSize 10
skinparam sequenceParticipantBorderColor #888888
skinparam sequenceLifeLineBorderColor #AAAAAA
skinparam sequenceMessageAlign left
skinparam ArrowColor #555555
skinparam ArrowFontSize 10

title **ML Pipeline - Sequence Diagram**\nOffline training path and one complete runtime scoring cycle

' ── Participants ──────────────────────────────────────────────────────────────

actor "Operator" as op
participant "train.py\n(host)" as train #FFE0B2
database "Zeek Logs\n(volume)" as logs #C8E6C9
database "models/\n(bind mount)" as models #FFF9C4
participant "pipeline.py" as pipeline #BBDEFB
participant "ingestor.py" as ingestor #BBDEFB
participant "state.py" as state #B3E5FC
participant "features.py" as features #E1BEE7
participant "detector.py" as detector #E1BEE7
participant "alerter.py" as alerter #FFCDD2
database "ml_alerts.log" as alertlog #FFCDD2
participant "SDN Controller\nREST API" as ryu #E0E0E0

' ══ Section 1: Offline Training ═══════════════════════════════════════════════

== Offline Training (run once on host before starting container) ==

op -> train : python3 train.py\n--log-dir /path/to/zeek-logs\n--output-dir ./ml-pipeline/models
activate train

train -> logs : read conn.log, dns.log, dhcp.log\n(all rotated archives)
logs --> train : historical JSON log entries

note over train
  Builds IP->MAC table from dhcp.log.
  Groups conn + dns entries into
  5-minute windows per device MAC.
  Calls features.extract() on each
  window to build the training matrix.
end note

train -> features : extract(window) for each\n5-min window per device
features --> train : 15-feature vector

note over train
  Trains one IsolationForest per device
  (requires min_windows, default 576 = 48 h).
  Trains one global fleet model on all
  devices combined (fallback for new devices).
end note

train -> models : save <mac>.joblib per device\nsave _fleet.joblib (global)
deactivate train

op -> pipeline : docker compose restart ml-pipeline\n(picks up new model files)

' ══ Section 2: Container Startup ══════════════════════════════════════════════

== Container Startup ==

activate pipeline
pipeline -> pipeline : load_config(thresholds.yml)
pipeline -> detector : Detector()
activate detector
detector -> models : scan directory\nload all *.joblib files
models --> detector : per-device models + fleet model
detector --> pipeline : ready (N per-device, 1 fleet)
deactivate detector

pipeline -> ingestor : LogIngestor(zeek_log_dir)
activate ingestor
note over ingestor
  Initialises byte offsets and
  inodes to 0/-1. On first poll,
  reads all existing log content.
end note

' ══ Section 3: Stage 1+2 - Ingest and Enrich ══════════════════════════════════

== Polling Cycle - Stage 1: Ingest (every POLL_INTERVAL = 10s) ==

pipeline -> ingestor : poll()
ingestor -> logs : read new lines from\nconn.log, dns.log, dhcp.log\nhttp.log, ssl.log\n(from stored byte offset)
logs --> ingestor : new JSON entries
ingestor -> ingestor : detect log rotation\n(compare current inode vs stored)
ingestor --> pipeline : {conn: [...], dns: [...], dhcp: [...], ...}
deactivate ingestor

== Polling Cycle - Stage 2: Enrich ==

loop for each log entry

  alt entry is from dhcp.log
    pipeline -> state : update_dhcp(entry)
    note right of state
      Stores assigned_addr -> mac
      mapping. Used to resolve
      IPs in all other log types.
    end note

  else entry is from conn / dns / http / ssl
    pipeline -> state : resolve_mac(src_ip)
    state --> pipeline : mac (or "ip:<src_ip>" if not yet seen)
    pipeline -> state : add_entry(mac, entry)
    note right of state
      Appends to device's rolling deque.
      Prunes entries older than
      WINDOW_SECONDS (300s = 5 min).
    end note
  end

end

note over pipeline
  Stages 1+2 repeat every 10s.
  Stage 3 only runs every score_interval
  seconds (default 60s = every 6 polls).
end note

' ══ Section 4: Stage 3 - Score ════════════════════════════════════════════════

== Polling Cycle - Stage 3: Score (every score_interval = 60s) ==

pipeline -> state : all_active_macs()
state --> pipeline : [mac_1, mac_2, ...]

loop for each active MAC

  pipeline -> state : get_window(mac)
  state --> pipeline : list of log entries\n(last 5 minutes)

  alt fewer than min_conn_entries (3) conn records
    note over pipeline : Skip device - too little data\nto produce a reliable score
  else enough data

    pipeline -> features : extract(window)
    activate features
    note over features
      Computes 15 features from
      conn and dns entries only.
      All features default to 0.0
      if no entries of that type exist.
    end note
    features --> pipeline : {conn_count: N, unique_dst_ips: N,\nunique_dst_ports: N, bytes_sent: N,\nbytes_recv: N, bytes_ratio: N,\nmean_duration: N, failed_conn_rate: N,\ntcp_ratio: N, udp_ratio: N, icmp_ratio: N,\ndns_query_count: N, dns_unique_domains: N,\ndns_nxdomain_rate: N, dns_entropy_mean: N}
    deactivate features

    pipeline -> detector : score(mac, features)
    activate detector
    detector -> detector : select model:\nper-device if exists\nelse fleet model
    detector -> detector : IsolationForest\n.decision_function(vector)\nanomaly_score = -raw_score
    detector --> pipeline : anomaly_score (float, higher = more anomalous)\nNone if no model available
    deactivate detector

    pipeline -> state : update_baseline(mac, features)
    note right of state
      Welford online algorithm:
      updates exponentially-weighted
      mean and variance per feature.
      Used for baseline-relative checks
      once min_baseline_observations (50)
      cycles have been recorded.
    end note

    ' ── Classification ──────────────────────────────────────────────────────

    pipeline -> pipeline : classify(mac, features, score, cfg)
    note over pipeline
      Rule checks (in order, first match wins):
      1. unique_dst_ports >= 30         -> CRITICAL
      2. failed_conn_rate >= 0.80       -> CRITICAL
         failed_conn_rate >= 0.50       -> WARNING
      3. dns_query_count >= 10x baseline -> CRITICAL (needs 50 cycles)
         dns_query_count >= 2x baseline  -> WARNING  (needs 50 cycles)
      4. dns_entropy_mean >= 3.80       -> CRITICAL
         dns_entropy_mean >= 3.50       -> WARNING
      5. total_bytes >= 10x baseline    -> CRITICAL (needs 50 cycles)
         total_bytes >= 3x baseline     -> WARNING  (needs 50 cycles)
      Isolation Forest score fallback:
      6. score >= 0.30                  -> CRITICAL
         score >= 0.15                  -> WARNING
         score >= 0.05                  -> INFO
    end note

    alt severity is None
      note over pipeline : No anomaly detected.\nContinue to next device.

    else severity is INFO, WARNING, or CRITICAL
      pipeline -> state : should_suppress(mac, detector, severity)
      state --> pipeline : true / false (dedup_seconds = 120s)

      alt duplicate suppressed
        note over pipeline : Same device + severity seen\nwithin 120s. Skip alert.

      else alert should fire

        ' ── Stage 4: Dispatch ─────────────────────────────────────────────

        == Polling Cycle - Stage 4: Dispatch ==

        pipeline -> alerter : dispatch(severity, ip, mac, description, details)
        activate alerter

        alerter -> alertlog : append JSON alert entry\n{ts, severity, detector, src_ip,\nsrc_mac, description, details,\naction_taken}

        alt severity == CRITICAL AND ML_AUTO_ISOLATE == true AND mac != "unknown"
          alerter -> ryu : POST /policy/isolate\n{mac: "aa:bb:...", reason: "..."}
          activate ryu

          alt Ryu returns HTTP 200
            ryu --> alerter : 200 OK
            deactivate ryu
            alerter -> alertlog : update action_taken = "isolate_requested"
            note over ryu : SDN controller installs\npriority-65535 DROP rule\nin virtual switch for this MAC
          else Ryu unreachable or error (retry up to 3x with exponential backoff)
            alerter -> alertlog : update action_taken = "isolate_failed"
            note over alerter : Device NOT isolated.\nManual intervention required.
          end

        else severity == CRITICAL AND ML_AUTO_ISOLATE == false
          alerter -> alertlog : action_taken = "dry_run"
          note over alerter : Alert logged only.\nNo isolation call made.\n(validation / burn-in mode)

        else severity == INFO or WARNING
          alerter -> alertlog : action_taken = "logged"
        end

        deactivate alerter
        pipeline -> state : record_alert(mac, detector, severity)

      end
    end
  end

end

pipeline -> pipeline : sleep(POLL_INTERVAL)\nRepeat from Stage 1

deactivate pipeline

@enduml                                                                    
```