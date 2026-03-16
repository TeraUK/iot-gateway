# Zeek Mirror Service

## Overview

The zeek-mirror service solves a fundamental networking problem: the Zeek container needs to see a copy of all traffic crossing the OVS bridge (`br0`), but OVS cannot deliver mirrored traffic directly into a Docker container's network namespace because Docker and OVS manage their network interfaces independently.

The service bridges this gap by creating a virtual ethernet pair (veth pair) and wiring it across the boundary between the host and the Zeek container. One end of the pair (`zeek-veth-h`) becomes an OVS port and receives a copy of every packet that crosses `br0`. The other end (`zeek-eth1`) is placed inside the Zeek container's network namespace, where Zeek sniffs on it in promiscuous mode. OVS sees `zeek-veth-h` as a normal port and mirrors traffic to it without needing to know anything about Docker.

The service runs as a long-lived watcher process. It attaches the mirror immediately on startup if Zeek is already running, then listens for Docker `start` events on the Zeek container. Every time Zeek restarts - whether from a crash, a `docker compose restart`, or a reboot - a new container gets a new network namespace, which invalidates the previous veth pair. The service detects the `start` event and re-runs the attachment sequence automatically, so the traffic feed is restored within a few seconds without any manual intervention.

## How it works

The attachment sequence that runs each time the Zeek container starts:

1. Gets the Zeek container's PID from Docker (`docker inspect`).
2. Creates a symlink at `/var/run/netns/zeek` pointing to the container's network namespace in `/proc/<pid>/ns/net`, making it accessible to `ip netns exec`.
3. Removes any stale veth pair and OVS port from a previous attachment.
4. Creates a new veth pair: `zeek-veth-h` on the host and `zeek-eth1` as a temporary name.
5. Moves `zeek-eth1` into the Zeek container's network namespace.
6. Brings both ends up and sets `zeek-eth1` to promiscuous mode so Zeek receives all frames, not just those addressed to it.
7. Adds `zeek-veth-h` to the OVS bridge `br0` as a port.
8. Configures an OVS mirror named `zeek-mirror` with `select-all=true`, which forwards a copy of every packet entering or leaving `br0` to `zeek-veth-h`.

On the Zeek side, `zeek/entrypoint.sh` loops until `zeek-eth1` appears in the container's interface list before starting Zeek. This prevents Zeek from crashing on startup because the interface does not yet exist, and avoids the container restart loop that would create a new namespace and invalidate any veth pair the host-side service had already attached.

## Installed files

| File | Installed location | Purpose |
|------|--------------------|---------|
| `Services/zeek-mirror/attach-zeek-mirror.sh` | `/usr/local/bin/attach-zeek-mirror.sh` | The watcher and attachment script |
| `Services/zeek-mirror/zeek-mirror.service` | `/etc/systemd/system/zeek-mirror.service` | systemd unit file |

## systemd unit

```ini
[Unit]
Description=Watch for Zeek container starts and attach OVS mirror port
After=docker.service ovs-vswitchd.service
Requires=docker.service ovs-vswitchd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/attach-zeek-mirror.sh
ExecStop=/bin/bash -c 'rm -f /var/run/netns/zeek; ovs-vsctl --if-exists del-port br0 zeek-veth-h; ip link delete zeek-veth-h 2>/dev/null || true'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The `ExecStop` command cleans up the network namespace symlink, removes `zeek-veth-h` from OVS, and deletes the veth pair so the system is returned to a clean state when the service is stopped intentionally.

## Managing the service

```bash
# Check status
sudo systemctl status zeek-mirror

# View recent logs
sudo journalctl -u zeek-mirror --since "10 minutes ago"

# Follow logs in real time
sudo journalctl -u zeek-mirror -f

# Restart (triggers a clean re-attachment)
sudo systemctl restart zeek-mirror

# Stop (removes the veth pair and OVS mirror cleanly)
sudo systemctl stop zeek-mirror

# Disable (prevents starting on boot)
sudo systemctl disable zeek-mirror
```

## Verifying the mirror is working

```bash
# Confirm the host-side veth exists and is up
ip link show zeek-veth-h

# Confirm it is registered as an OVS port
sudo ovs-vsctl list-ports br0 | grep zeek-veth-h

# Confirm the OVS mirror is configured
sudo ovs-vsctl list mirror

# Confirm the container-side interface is present inside Zeek
docker exec zeek ip link show zeek-eth1

# Confirm Zeek is writing logs (traffic must be flowing)
docker exec zeek ls -lh /opt/zeek-logs/
```

The `verify-phase4.sh` script performs all of these checks automatically. See [Scripts Reference](../scripts/verification-scripts.md).

## Behaviour on failure

If the `attach_mirror` function fails part-way through - for example because OVS is temporarily unavailable - the script prints the error and returns a non-zero exit code. Because the main event loop is driven by `docker events`, the watcher continues running and will retry the next time a Zeek `start` event is received.

If the script itself crashes, systemd restarts it after 5 seconds (`RestartSec=5`). On restart it immediately checks whether Zeek is already running and re-attaches if so, meaning the mirror is restored promptly regardless of which component failed.

If OVS is stopped and restarted, the OVS mirror configuration is lost along with the veth port. In this case, restart the zeek-mirror service manually to re-run the attachment sequence:

```bash
sudo systemctl restart zeek-mirror
```

## Known limitations

The veth pair is not persistent across OVS restarts. If `ovs-vswitchd` is restarted, the bridge is rebuilt and the `zeek-veth-h` port and `zeek-mirror` configuration are lost. Restarting the zeek-mirror service is sufficient to restore them, but there will be a gap in Zeek's traffic visibility between the OVS restart and the mirror being re-attached.

Network namespace symlinks under `/var/run/netns/` are created as references into `/proc/<pid>/ns/net`. If the host is rebooted uncleanly and the symlink is left behind pointing at a stale PID, the service will clean it up as part of the next attachment sequence before creating a fresh one.
