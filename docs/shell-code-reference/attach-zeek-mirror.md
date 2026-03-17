# attach-zeek-mirror.sh

**Location:** `Services/zeek-mirror/attach-zeek-mirror.sh`

Watches for Zeek container start events via `docker events` and attaches
an OVS mirror port each time the container starts. Creates a veth pair,
moves one end into the Zeek container's network namespace as `zeek-eth1`,
adds the host end to the OVS bridge, and configures an OVS mirror with
`select-all=true` so every packet crossing `br0` is forwarded to Zeek.
Runs as the `zeek-mirror` systemd service; do not invoke directly.

```bash
sudo systemctl status zeek-mirror
sudo journalctl -u zeek-mirror -f
```

See [Services: Zeek Mirror](../services/zeek-mirror.md) for full service
documentation.

---

```bash
--8<-- "Services/zeek-mirror/attach-zeek-mirror.sh"
```
