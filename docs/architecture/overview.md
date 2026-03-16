# Architecture Overview

## High Level Architecture Diagram

```kroki-plantuml
@startuml iot_gateway_architecture

skinparam backgroundColor #FAFAFA
skinparam defaultFontName Arial
skinparam defaultFontSize 11
skinparam roundCorner 8
skinparam shadowing false
skinparam packageStyle rectangle

title **IoT Security Gateway Architecture**\nSDN-Based Hybrid Native/Containerised Deployment

' == External Entities ==

node "**Internet**" as internet #E0E0E0
node "**Upstream Router**\n(Home/Corporate Network)" as router #E0E0E0
node "**IoT Devices**\n(Smart Bulbs, Thermostats,\nCameras, etc.)" as iot_devices #E0E0E0

' == Host System ==

package "**Mini PC Host** - Ubuntu Server 24.04 LTS  /  Intel i5-12500T  /  16 GB RAM" as host #E8F4FD {

    ' == Native Components ==

    package "**Native Components** (data path + bootstrapping)" as native #BBDEFB {
        component "**enp2s0**\nWAN Uplink\nDHCP from Router" as enp2s0
        component "**Open vSwitch (br0)**\n192.168.50.1/24\nOpenFlow 1.3 Data Plane" as ovs
        component "**wlp3s0**\nWiFi Radio (OVS Port)" as wlan0
        component "**hostapd**\nWiFi AP: IoT-Security-AP\nWPA2-PSK (CCMP)" as hostapd
        component "**dnsmasq**\nDHCP Only (DNS disabled)\nRange: .50-.150" as dnsmasq
        component "**nftables**\nNAT masquerade\nDNS DNAT to 172.20.0.53\nBlocks DoT (853) + DoQ (8853)" as nftables
    }

    ' == Docker Layer ==

    package "**Docker Engine**" as docker #F3E5F5 {

        package "**gateway-net** (172.20.0.0/24)" as gateway_net #E1BEE7 {
            component "**Ryu SDN Controller**\n172.20.0.x\nOpenFlow: 6653\nREST API: 8080" as ryu
            component "**AdGuard Home**\n172.20.0.53 (static)\nDNS: 53 (TCP/UDP)\nAdmin: host:8088" as adguard
            component "**Zeek**\n172.20.0.x\nPassive Analysis\nMirror: zeek-eth1" as zeek
            component "**ML Pipeline**\n172.20.0.x\nIsolation Forest (per-device)\nLSTM (per-device-type)" as ml_pipeline
        }
    }

    ' == Shared Resources ==

    database "**zeek-logs**\n(Docker Volume)\nconn.log, dns.log, http.log\niot_alerts.log, ml_alerts.log" as zeek_vol #C8E6C9
    database "**adguard-data**\n(Docker Volume)\nquerylog.json" as adguard_vol #C8E6C9
    component "**zeek-mirror.service**\n(systemd watcher)" as mirror_svc #FFCDD2
}

' == External Connections ==

internet --> router
router --> enp2s0 : WAN DHCP
iot_devices --> wlan0 : WiFi (WPA2-PSK)

' == Native Internal ==

wlan0 --> hostapd : Radio Mgmt
wlan0 --> ovs : L2 Frames (OVS Port)
ovs --> nftables : IP Forwarding
nftables --> enp2s0 : NAT Masquerade

' == OVS to Ryu ==

ovs <--> ryu : OpenFlow 1.3\nTCP:6653

' == DNS Flow ==

ovs ..> nftables : DNS queries\n(any destination)
nftables --> adguard : DNAT to\n172.20.0.53

' == DHCP ==

ovs ..> dnsmasq : DHCP (UDP:67/68)

' == Mirror Traffic ==

ovs --> zeek : Mirrored Traffic\n(veth pair)
mirror_svc ..> zeek : Manages veth\nlifecycle

' == Zeek to ML Pipeline ==

zeek --> zeek_vol : Writes logs
zeek_vol --> ml_pipeline : Reads logs
ml_pipeline --> zeek_vol : Writes ml_alerts.log

' == AdGuard Logging ==

adguard --> adguard_vol : Writes querylog.json

' == Analysis to Control Plane ==

zeek --> ryu : REST API POST :8080\n(threat alerts)
ml_pipeline --> ryu : REST API POST :8080\n(anomaly response)

' == Legend ==

legend bottom left
    |= Colour |= Meaning |
    | <#BBDEFB> | Native host component |
    | <#E1BEE7> | Docker network / containerised application |
    | <#C8E6C9> | Shared storage |
    | <#FFCDD2> | System service |
endlegend

@enduml
                                                                        
```

## Design principles

**Default deny.** OVS drops all traffic by default. Every permitted flow requires an explicit OpenFlow rule installed by Ryu. There is no "allow all" fallback.

**Least privilege.** Once device profiles are established, each device can only reach the destinations it legitimately needs. General WAN access is a temporary Phase 2 state, replaced by per-device allowlists in Phase 3.

**Defence in depth.** No single layer is solely responsible for security:

| Layer | Mechanism | What it stops |
|-------|-----------|---------------|
| WiFi | WPA2-PSK (hostapd) | Unauthorised wireless association |
| DNS | AdGuard Home + nftables DNAT | C2 domain resolution, DNS tunnelling, telemetry |
| Network | OVS OpenFlow rules (Ryu) | Lateral movement, unapproved destinations |
| Analysis | Zeek detection scripts | Port scanning, DNS anomalies, known-bad IOCs |
| Analysis | ML pipeline | Behavioural anomalies missed by rules |
| Response | Ryu isolation API | Quarantine of compromised devices |

## Component map

```kroki-plantuml
@startuml component_map

hide circle
hide stereotype

skinparam defaultFontName Arial
skinparam defaultFontSize 11
skinparam roundCorner 6
skinparam shadowing false

skinparam package {
    BackgroundColor #E8F4FD
    BorderColor     #1F4E79
    BorderThickness 2
    FontColor       #1F4E79
    FontStyle       bold
    FontSize        13
}

skinparam class {
    BackgroundColor      #FFFFFF
    BorderColor          #1F4E79
    BorderThickness      1.5
    HeaderBackgroundColor #BBDEFB
    FontColor            #1F4E79
    FontStyle            bold
    FontSize             12
    AttributeFontColor   #333333
    AttributeFontSize    11
}

package "Ubuntu Server 24.04 LTS  ·  Intel i5-12500T  ·  16 GB RAM" {

    class "Native  (data path)" as native {
        enp2s0   ─  WAN uplink, DHCP from upstream router
        wlp3s0   ─  Hostapd WiFi radio, WPA2-PSK
        br0      ─  OVS bridge, 192.168.50.1/24
        nftables ─  NAT masquerade + DNS DNAT + DoT/DoQ block
        dnsmasq  ─  DHCP server, range .50 – .150
        OVS      ─  OpenFlow 1.3 data plane
    }
    class "Docker  ·  gateway-net  172.20.0.0/24" as docker {
        Ryu SDN Controller  ─  OpenFlow :6653  /  REST API :8080
        AdGuard Home        ─  DNS :53  (172.20.0.53 static)
        Zeek                ─  Passive capture on zeek-eth1
        ML Pipeline         ─  Isolation Forest (per-device) + LSTM
        --
        zeek-logs volume    ─  conn.log  dns.log  iot_alerts.log
    }

}
native -[hidden]-> docker
@enduml                                                                    
```

See components section for more information [Components](../components/ovs-ryu.md).

## Traffic path for a typical IoT device

1. Device associates with `IoT-Security-AP` via WPA2-PSK.
2. `wlp3s0` is an OVS port, so the device's traffic enters the OVS data plane immediately.
3. OVS sends the DHCP broadcast to the controller (table-miss). Ryu has a proactive rule permitting DHCP to `192.168.50.1`. dnsmasq assigns an IP.
4. A copy of all traffic on the bridge is mirrored to Zeek via a veth pair (`zeek-veth-h` → `zeek-eth1`).
5. When the device makes a DNS query, nftables intercepts it (DNAT prerouting) and redirects it to AdGuard at `172.20.0.53`, regardless of the target DNS server.
6. For outbound HTTP/HTTPS, OVS checks against the device's allowlist rules. If the destination is permitted, the packet is forwarded via `OFPP_LOCAL` (the host IP stack) and NATed to the WAN. If not permitted, the default-deny rule drops it.
7. If Zeek or the ML pipeline detect anomalous behaviour, they POST to `ryu:8080/policy/isolate`. Ryu installs a priority-65535 DROP rule for all traffic from that MAC.

Detailed UML sequence diagrams showing different device traffic paths [Device Traffic Path Diagrams](traffic-path-sequence-diagrams.md).

## Startup dependency order

The components must start in this order to avoid timing failures:

```
ovs-vswitchd → hostapd → dnsmasq → Docker containers → zeek-mirror.service
```

`systemd` service overrides in `config/hostapd/override.conf` and `config/dnsmasq/override.conf` enforce the first three. `docker compose` handles the container order via `depends_on`. The `zeek-mirror.service` systemd unit watches Docker events and re-attaches the mirror veth pair whenever Zeek restarts.

## What is not yet implemented

| Item | Status | Notes |
|------|--------|-------|
| Granular control of per device communication | Not yet | Hardware driver limitations identified during phase 3 |
| Observability stack | Out of scope | Acknowledged in NFR-10 (Won't Have) |
| Wi-Fi Captive Portal | Out of scope | Acknowledged in NFR-11 (Won't Have) |
