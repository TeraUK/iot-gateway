# install.sh

**Location:** `installation/install.sh`

Installs and configures the full gateway environment on an Ubuntu 22.04 or
24.04 host. Handles system packages, Docker, OVS bridge configuration,
hostapd, dnsmasq, nftables, AdGuard Home, the Zeek mirror service, the DNS
cache updater, log maintenance, and Docker image builds. Safe to re-run on
an existing installation as it detects and skips unchanged components.

```bash
sudo ./installation/install.sh
# Force a Docker image rebuild:
sudo ./installation/install.sh --rebuild
```

See [Getting Started](../getting-started.md) for the full setup walkthrough.

---

```bash
--8<-- "installation/install.sh"
```
