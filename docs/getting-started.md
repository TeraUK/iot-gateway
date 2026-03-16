# Getting Started

This page covers prerequisites, the initial setup sequence, and how to verify each phase is working before moving to the next.

## Prerequisites

The following must be installed on the host before running any setup scripts.

```bash
# Core networking
sudo apt install openvswitch-switch hostapd dnsmasq nftables

# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Python (for host-side scripts)
sudo apt install python3 python3-pip
pip3 install requests pyyaml

# Utilities
sudo apt install curl dig nmap
```

Verify that NetworkManager is **not** managing `wlp3s0` or `enp2s0`. These interfaces are managed by `systemd-networkd` directly. If NetworkManager is installed, add the interfaces to its unmanaged list:

```bash
# /etc/NetworkManager/conf.d/99-unmanaged.conf
[keyfile]
unmanaged-devices=interface-name:wlp3s0;interface-name:br0
```

## Setup sequence

The system is built in phases. Each phase has a verification script. Do not proceed to the next phase until the current one passes.

### Phase 1 — DNS filtering and logging

Phase 1 starts the Docker containers, enables DNS filtering through AdGuard, intercepts DNS with nftables, and begins Zeek logging.

```bash
# Start all containers
docker compose up -d

# Copy systemd service overrides
sudo cp config/hostapd/override.conf /etc/systemd/system/hostapd.service.d/
sudo cp config/dnsmasq/override.conf /etc/systemd/system/dnsmasq.service.d/
sudo systemctl daemon-reload
sudo systemctl restart hostapd dnsmasq

# Verify
sudo ./scripts/verify-phase1.sh
```

### Phase 2 — Micro-segmentation and essential services

Phase 2 connects OVS to the Ryu controller and installs the default-deny flow rules with essential service exceptions.

```bash
# Run the OVS setup script
sudo /usr/local/bin/setup-native-ovs.sh

# Verify the Ryu controller has connected and rules are installed
sudo ./scripts/verify-phase2.sh
```

At this point IoT devices can join the network, receive DHCP leases, resolve DNS through AdGuard, and reach the internet. They cannot reach each other.

### Phase 3 — Per-device destination allowlists

Phase 3 enables per-device destination enforcement. Before enabling enforcing mode, I collect Zeek traffic logs during a baseline period, then run `profile_builder.py` to generate device profiles.

```bash
# After collecting baseline logs (minimum several days):
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
sudo ./scripts/verify-phase3.sh
```

### Phase 4 — Detection scripts and automated isolation

Phase 4 deploys the Zeek detection scripts and wires them to the Ryu isolation API.

```bash
# The detection scripts are already loaded via zeek/site/local.zeek.
# Verify they are present and the Ryu isolation endpoint is responsive:
sudo ./scripts/verify-phase4.sh
```

By default, auto-isolation is disabled (`auto_isolate = F` in `local.zeek`). Enable it only after validating the detection scripts are not generating false positives on legitimate traffic.

```zeek
# In zeek/site/local.zeek, once confident:
redef IoT::auto_isolate = T;
redef IoT::new_dest_mode = "detecting";
redef IoT::proto_anomaly_mode = "detecting";
```

Then restart Zeek: `docker compose restart zeek`

### Phase 5 — OVS secure fail mode

Once Ryu is stable and the watchdog restart policy is confirmed working:

```bash
sudo ovs-vsctl set-fail-mode br0 secure
```

This means OVS drops all traffic if Ryu becomes unreachable. Do not enable this until Ryu has been running reliably for several days.

### Phase 6 — ML pipeline

See [Training the Model](operations/training-the-model.md). The ML pipeline requires several weeks of baseline logs before training is meaningful.

## Verifying the full system

After all phases, run the full health check:

```bash
sudo ./scripts/health-check.sh
```

All items should pass before the system is considered production-ready.

## Routine maintenance

| Task | Frequency | Method |
|------|-----------|--------|
| Log compression and retention | Daily (cron) | `scripts/log-maintenance.sh` |
| AdGuard blocklist review | Monthly | AdGuard admin UI at `:8088` |
| IOC feed updates | As available | Edit `zeek/site/iot-iocs/` files |
| ML model retraining | After significant traffic changes | `ml-pipeline/train/train.py` |
