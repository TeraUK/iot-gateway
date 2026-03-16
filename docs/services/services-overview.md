# Services Overview

The gateway runs two long-running host services that sit outside the Docker Compose stack and cannot be containerised. Both are managed by systemd, installed to `/usr/local/bin`, and started automatically by `install.sh`.

They exist because they each need direct, privileged access to host kernel facilities that containers cannot reach on their own:

- **zeek-mirror** needs to create virtual network interfaces, manipulate network namespaces, and configure OVS mirroring - all operations that require host-level capabilities.
- **dns-cache-updater** needs to read files from inside the Zeek container on a tight poll interval and push results to the Ryu REST API. While it could technically run in a container, keeping it on the host avoids adding another container dependency and simplifies its access to the Docker socket.

Both services are designed to be resilient. They do not crash when their dependencies are temporarily unavailable, and systemd restarts them automatically on failure. Neither service carries any persistent state of its own - if either is restarted, it simply resumes from the current live state of the system.

## At a glance

| Service | Unit file | Script | Purpose |
|---------|-----------|--------|---------|
| zeek-mirror | `zeek-mirror.service` | `attach-zeek-mirror.sh` | Creates the veth pair and OVS mirror that feeds traffic to Zeek |
| dns-cache-updater | `dns-cache-updater.service` | `dns_cache_updater.py` | Reads Zeek's DNS logs and pushes domain-to-IP mappings to Ryu |

## Checking service status

```bash
# Status of both services at a glance
sudo systemctl status zeek-mirror dns-cache-updater

# Recent logs for the mirror service
sudo journalctl -u zeek-mirror -n 50

# Recent logs for the DNS cache updater
sudo journalctl -u dns-cache-updater -n 50

# Follow logs from both services in real time
sudo journalctl -u zeek-mirror -u dns-cache-updater -f
```

## Startup dependency order

Both services are started after the Docker Compose stack by `install.sh`, and their systemd unit files declare the correct `After=` and `Requires=` dependencies to ensure they do not start before Docker and OVS are ready. The full startup order for the gateway is:

```
ovs-vswitchd → hostapd → dnsmasq → docker compose up → zeek-mirror.service + dns-cache-updater.service
```

## Detailed documentation

- [Zeek Mirror Service](zeek-mirror.md)
- [DNS Cache Updater](dns-cache-updater.md)
