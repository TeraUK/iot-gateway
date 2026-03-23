#!/bin/bash
#
# Waits for the mirror interface (zeek-eth1) to be attached by the
# host-side attach-zeek-mirror.sh script, then starts Zeek.
# This keeps the container alive and avoids a crash loop.
#
# The container never exits while waiting. Exiting would trigger a
# restart, which creates a new network namespace and invalidates any
# veth pair the host-side script may have already attached to the
# previous namespace. Staying alive keeps the namespace stable.
#
# Requires execute permissions: chmod +x ~/iot-gateway/zeek/entrypoint.sh

IFACE="zeek-eth1"
WARN_INTERVAL=60
ELAPSED=0

echo "Waiting for interface $IFACE to appear..."

while [ ! -d "/sys/class/net/$IFACE" ]; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ "$((ELAPSED % WARN_INTERVAL))" -eq 0 ]; then
        echo "WARNING: $IFACE has not appeared after ${ELAPSED}s. Is attach-zeek-mirror.sh running on the host?"
    fi
done

# ----------------------------------------------------------------------------------------------------

echo "$IFACE is up. Starting Zeek."

# Generate the DHCP seed file from the dnsmasq lease file so that
# alert-framework.zeek can pre-populate the IP-to-MAC table at startup.
# Format: ip<TAB>mac  (one entry per line, consumed by Input::add_table)
LEASES_FILE="/var/lib/misc/dnsmasq.leases"
SEED_FILE="/opt/zeek-logs/dhcp_seed.dat"

if [ -f "$LEASES_FILE" ]; then
    # dnsmasq lease format: <expiry> <mac> <ip> <hostname> <client-id>
    # It outputs: <ip><TAB><mac> for Zeek to consume
    printf '#separator \\x09\n#fields\tip\tmac\n' > "$SEED_FILE"
    awk 'NF>=3 { print $3 "\t" $2 }' "$LEASES_FILE" >> "$SEED_FILE"
    echo "Generated DHCP seed from $LEASES_FILE ($(wc -l < "$SEED_FILE") entries)"
else
    echo "Warning: dnsmasq lease file not found at $LEASES_FILE"
    touch "$SEED_FILE"
fi

# ----------------------------------------------------------------------------------------------------

exec zeek -i "$IFACE" -C /usr/local/zeek/share/zeek/site/local.zeek
