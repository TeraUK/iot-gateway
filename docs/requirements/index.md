# IoT Security Gateway

This is the technical documentation for the SDN-based IoT security gateway, built on an Ubuntu mini PC using Open vSwitch, Ryu, Zeek, AdGuard Home, and a custom machine learning pipeline. The gateway enforces a layered security, zero trust security model for IoT devices.

## What the gateway does

Consumer IoT devices are high-risk network participants. They run outdated firmware, have no endpoint security capabilities, and communicate with a mix of legitimate cloud services and potentially unwanted telemetry endpoints. The gateway addresses this by treating every IoT device as untrusted by default and enforcing the policy at the network layer, regardless of the device's own behaviour.

The key capabilities are:

- **Default-deny network isolation** — all traffic is dropped unless an explicit OpenFlow rule permits it.
- **Micro-segmentation** — IoT devices cannot communicate with each other directly.
- **Per-device destination allowlists** — each device is restricted to the destinations it legitimately needs.
- **Forced DNS filtering** — all DNS queries are intercepted and processed by AdGuard Home, including from devices with hardcoded resolvers.
- **Passive traffic analysis** — Zeek monitors all traffic and runs rule-based detection scripts in real time.
- **Automated device isolation** — devices exhibiting malicious or anomalous behaviour are automatically quarantined via SDN flow rules.
- **ML-based anomaly detection** — an Isolation Forest pipeline detects behavioural deviations that rule-based scripts may miss.

## Architecture at a glance

```
Internet
    │
    │ WAN (enp2s0)
    ▼
Open vSwitch (br0 — 192.168.50.1/24)  ←──── Ryu SDN Controller (OpenFlow 1.3)
    │                                              │ REST API :8080
    │ WiFi (wlp3s0 — WPA2-PSK)                    │
    ▼                                         ┌────┴──────────────┐
IoT Devices (192.168.50.50–150)              Zeek      ML Pipeline
                                              │              │
                                         iot_alerts.log  ml_alerts.log
```

All mirrored traffic from OVS passes through Zeek for analysis. Zeek and the ML pipeline both call the Ryu REST API to isolate devices when their detection criteria are met.

## Hardware

| Component | Specification |
|-----------|---------------|
| Platform  | Ubuntu Server 24.04 LTS |
| CPU       | Intel i5-12500T |
| RAM       | 16 GB |
| WiFi      | wlp3s0 (802.11ac, WPA2-PSK) |
| WAN       | enp2s0 (DHCP from upstream router) |

## Quick navigation

- **New to the project?** Start with [Getting Started](../getting-started.md).
- **Understanding the design?** Read the [Architecture Overview](../architecture/overview.md).
- **Adding a device?** See [Device Onboarding](../operations/device-onboarding.md).
- **An alert fired?** See [Alert Response](../operations/alert-response.md).
- **API reference?** See [REST API](../reference/api.md).
