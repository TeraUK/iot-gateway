# Getting Started

This page covers installation and initial operation of the IoT Security Gateway.

## Installation

To install the gateway, run **installation/install.sh**

To build the docs, run **installation/build-docs.sh**

## Per-device destination allowlists

This gateway implements per device destination allowlists.

Before enabling enforcing mode, collect Zeek traffic logs during a baseline period, then run `profile_builder.py` to generate device profiles.

```bash
# After collecting baseline logs (recommend several days):
python3 scripts/profile_builder.py \
    --zeek-dir /var/lib/docker/volumes/iot-gateway_zeek-logs/_data \
    --leases /var/lib/misc/dnsmasq.leases \
    --output ryu/config/device_profiles.json

# Review and edit device_profiles.json, then reload Ryu
curl -X POST http://127.0.0.1:8080/policy/allowlists/reload

# Switch to enforcing mode
curl -X POST http://127.0.0.1:8080/policy/allowlists/mode \
     -H 'Content-Type: application/json' \
     -d '{"mode": "enforcing"}'

# Verify
# Script may flag gateway policy app as having no installed rules if the last 50 log lines # dont contain the "Policy rules installed" output from Ryus startup.
sudo ./scripts/verify-phase3.sh
```

## Granular Micro Segmentation

This gateway implements granular micro segmentation. The RYU rest API can be used to grant lateral movement permits for a pair of devices.

see [Rest API Reference](reference/api.md)

## Detection scripts and automated isolation

By default, auto-isolation is disabled (`auto_isolate = F` in `local.zeek`). Enable it only after validating the detection scripts are not generating false positives on legitimate traffic.

```zeek
# In zeek/site/local.zeek, once confident:
redef IoT::auto_isolate = T;
redef IoT::new_dest_mode = "detecting";
redef IoT::proto_anomaly_mode = "detecting";
```

Then restart Zeek: `docker compose restart zeek`

## OVS secure fail mode

Once Ryu is stable and the watchdog restart policy is confirmed working:

```bash
sudo ovs-vsctl set-fail-mode br0 secure
```

This means OVS drops all traffic if Ryu becomes unreachable. Do not enable this until Ryu has been running reliably for several days.

## Training the ML Pipeline

See [Training the Model](operations/training-the-model.md). The ML pipeline requires several weeks of baseline logs before training is meaningful.

## Verifying the full system

After all phases, run the full health check:

```bash
sudo ./scripts/health-check.sh
```
## AdGuard Home Admin Panel

| URL | Purpose |
|-----|---------|
| http://<host>:8088 | Admin panel (after initial setup) |
| http://<host>:3000 | Initial setup wizard only |

*Note. if you used the install.sh script, the initial setup has already been completed*

All items should pass before the system is considered production-ready.

## Routine maintenance

| Task | Frequency | Method |
|------|-----------|--------|
| Log compression and retention | Daily (cron) | `scripts/log-maintenance.sh` |
| AdGuard blocklist review | Monthly | AdGuard admin UI at `:8088` |
| IOC feed updates | As available | Edit `zeek/site/iot-iocs/` files |
| ML model retraining | After significant traffic changes | `ml-pipeline/train/train.py` |
