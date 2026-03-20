# Machine Learning Pipeline Data Flow

---

## The four-stage processing loop

The pipeline runs continuously in a loop. Every `POLL_INTERVAL` seconds
(default: 10s), it executes four stages:

### Stage 1 - Ingest

The ingestor reads any new lines from the Zeek log files since the last poll and
returns them grouped by log type.

### Stage 2 - Enrich

Each log entry is tagged with its source type. DHCP entries update the
IP-to-MAC lookup table. For all other log types, the source IP is resolved to a
MAC address and the entry is added to that device's rolling 5-minute window.

### Stage 3 - Score

This stage only runs every `score_interval` seconds (default: 60s). For each
device that has enough data in its window, the pipeline extracts a 15-feature
vector and runs it through the detector. It then runs classification:

**Rule-based checks run first** (these work even before a model has been
trained, and catch high-confidence patterns immediately):

| Check | CRITICAL threshold | WARNING threshold |
|---|---|---|
| Unique destination ports | 30 or more | - |
| Failed connection rate | 80% or more | 50% or more |
| DNS query rate vs device baseline | 10x or more | 2x or more |
| DNS name entropy | 3.80 bits/char or more | 3.50 bits/char or more |
| Traffic volume vs device baseline | 10x or more | 3x or more |

**Isolation Forest score is applied if no rule matched:**

| Score | Severity |
|---|---|
| 0.30 or above | CRITICAL |
| 0.15 or above | WARNING |
| 0.05 or above | INFO |
| Below 0.05 | No alert |

The device's running baseline is updated after each scoring cycle.

### Stage 4 - Dispatch

If a non-None severity was produced and the alert is not a duplicate, the
alerter writes it to `ml_alerts.log` and optionally calls the SDN controller.

---

## Data Flow Diagram

The following diagram shows the flow of data between components at runtime during the four stage processing loop.

---

```kroki-plantuml

         @startuml ml_pipeline_dataflow

skinparam backgroundColor #FAFAFA
skinparam defaultFontName Arial
skinparam defaultFontSize 11
skinparam roundCorner 8
skinparam shadowing false
skinparam ArrowColor #555555
skinparam ArrowFontSize 10
skinparam ArrowFontColor #444444
skinparam activityBorderColor #777777
skinparam activityBackgroundColor #FFFFFF
skinparam noteBackgroundColor #FFFDE7
skinparam noteBorderColor #AAAAAA
skinparam noteFontSize 10
skinparam partitionBorderColor #888888
skinparam partitionBackgroundColor #F5F5F5
skinparam partitionFontStyle bold

title **ML Pipeline - Runtime Data Flow**\nFour-stage processing loop (repeats every POLL_INTERVAL seconds)

start

' ── STAGE 1: INGEST ──────────────────────────────────────────────────────────

partition "Stage 1: Ingest  [ingestor.py]" <<Rectangle>> {
  #C8E6C9 :Zeek log files on shared volume\nconn.log  dns.log  dhcp.log\nhttp.log  ssl.log;
  note right
    Files are written continuously
    by Zeek as traffic passes
    through the gateway.
  end note

  #BBDEFB :ingestor.poll()\nRead new lines from each file\nusing stored byte offset;
  note right
    Only lines written since the
    last poll are returned.
    If the file inode has changed
    (hourly log rotation), the
    offset resets to 0.
  end note

  #BBDEFB :Returns dict:\nlog_type -> [list of parsed JSON entries];
}

' ── STAGE 2: ENRICH ──────────────────────────────────────────────────────────

partition "Stage 2: Enrich  [pipeline.py + state.py]" <<Rectangle>> {
  #B3E5FC :Tag each entry with its source log type;

  if (log_type == "dhcp"?) then (yes)
    #B3E5FC :state.update_dhcp(entry)\nStore assigned_addr -> MAC mapping;
    note right
      Zeek logs all connection
      types by IP address, not MAC.
      The DHCP table is the only
      source of IP-to-MAC mappings.
    end note

  else (no - conn / dns / http / ssl)
    #B3E5FC :Extract src IP from id.orig_h field;

    if (IP found in DHCP table?) then (yes)
      #B3E5FC :Key entry under MAC address;
    else (no)
      #B3E5FC :Key entry under "ip:<src_ip>"\n(temporary until DHCP entry arrives);
    endif

    #B3E5FC :state.add_entry(mac, entry)\nAppend to per-device rolling deque\nPrune entries older than 300 s;
  endif

  note right
    Stages 1 and 2 run every
    POLL_INTERVAL (default 10 s).
    Stage 3 only runs every
    score_interval (default 60 s).
  end note
}

' ── STAGE 3: SCORE ───────────────────────────────────────────────────────────

partition "Stage 3: Score  [features.py + detector.py + pipeline.py]" <<Rectangle>> {
  #E1BEE7 :state.all_active_macs()\nGet all devices with entries in their window;

  while (more active MACs?) is (yes)

    #E1BEE7 :state.get_window(mac)\nSnapshot of rolling window entries;

    if (fewer than min_conn_entries conn records?) then (yes)
      #E1BEE7 :Skip device\nnot enough data for a reliable score;

    else (no)
      #E1BEE7 :features.extract(window)\nCompute 15-feature vector;
      note right
        11 connection features (from conn.log):
        conn_count, unique_dst_ips, unique_dst_ports,
        bytes_sent, bytes_recv, bytes_ratio,
        mean_duration, failed_conn_rate,
        tcp_ratio, udp_ratio, icmp_ratio

        4 DNS features (from dns.log):
        dns_query_count, dns_unique_domains,
        dns_nxdomain_rate, dns_entropy_mean
      end note

      #E1BEE7 :detector.score(mac, features)\nSelect per-device model or fleet fallback\nRun IsolationForest.decision_function()\nInvert sign: anomaly_score = -raw_score;
      note right
        Higher score = more anomalous.
        Returns None if no model
        is available for this device
        and no fleet model exists.
      end note

      #E1BEE7 :state.update_baseline(mac, features)\nUpdate exponentially-weighted running\nmean and variance per feature;
      note right
        Welford online algorithm.
        Baseline-relative rule checks
        activate after 50 scoring
        cycles (~50 minutes).
      end note

      #E1BEE7 :pipeline.classify(mac, features, score, cfg);
      note right
        Rule checks (first match wins):
        1. unique_dst_ports >= 30         -> CRITICAL
        2. failed_conn_rate >= 0.80       -> CRITICAL
           failed_conn_rate >= 0.50       -> WARNING
        3. dns_query_count >= 10x baseline -> CRITICAL
           dns_query_count >= 2x baseline  -> WARNING
        4. dns_entropy_mean >= 3.80       -> CRITICAL
           dns_entropy_mean >= 3.50       -> WARNING
        5. total_bytes >= 10x baseline    -> CRITICAL
           total_bytes >= 3x baseline     -> WARNING
        Isolation Forest score fallback:
        6. score >= 0.30                  -> CRITICAL
           score >= 0.15                  -> WARNING
           score >= 0.05                  -> INFO
      end note

      if (severity is None?) then (yes)
        #E1BEE7 :No anomaly - continue to next device;

      else (no - INFO / WARNING / CRITICAL)
        #E1BEE7 :state.should_suppress(mac, detector, severity)\nCheck dedup window (120 s);

        if (duplicate alert?) then (yes)
          #E1BEE7 :Suppress - same device + severity\nalerted within 120 s;

        else (no)

          ' ── STAGE 4: DISPATCH ──────────────────────────────────────────────

          partition "Stage 4: Dispatch  [alerter.py]" <<Rectangle>> {
            #FFCDD2 :alerter.dispatch(severity, ip, mac, description, details);

            #FFCDD2 :Write JSON entry to ml_alerts.log\n{ts, severity, detector, src_ip, src_mac,\ndescription, details, action_taken};

            if (severity == CRITICAL?) then (yes)
              if (ML_AUTO_ISOLATE == true?) then (yes)
                if (MAC address known?) then (yes)
                  #FFF9C4 :POST /policy/isolate to SDN Controller\n{mac, reason}\nRetry up to 3x with exponential backoff;

                  if (HTTP 200 OK?) then (yes)
                    #FFF9C4 :action_taken = "isolate_requested"\nSDN controller installs priority-65535\nDROP rule in virtual switch for this MAC;
                  else (no)
                    #FFF9C4 :action_taken = "isolate_failed"\nLog warning - manual action required;
                  endif

                else (no - MAC unknown)
                  #FFCDD2 :action_taken = "isolate_failed"\nCannot isolate without a MAC address;
                endif

              else (no - dry run mode)
                #FFCDD2 :action_taken = "dry_run"\nAlert logged only, no isolation call\n(default until models are validated);
              endif

            else (INFO or WARNING)
              #FFCDD2 :action_taken = "logged";
            endif

            #E1BEE7 :state.record_alert(mac, detector, severity)\nStamp dedup record;
          }

        endif
      endif
    endif

  endwhile (no more MACs)
}

#BBDEFB :sleep(POLL_INTERVAL)\nRepeat from Stage 1;

stop

@enduml


```