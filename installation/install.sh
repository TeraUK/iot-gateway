#!/usr/bin/env bash
#
# install.sh
#
# Fully automated setup script for the IoT Security Gateway.
# Cloning the repository and running this script is sufficient to build
# and configure the entire gateway on a fresh Ubuntu 22.04/24.04 host.
#
# This script is idempotent and safe to re-run on a system where the
# gateway is already running. Each step checks whether work is needed
# before making any changes, and Docker images are not rebuilt unless
# the --rebuild flag is passed.
#
# What this script does:
#   1.  Verifies prerequisites and confirms all required repository files exist
#   2.  Installs all system packages (OVS, hostapd, dnsmasq, nftables, Docker, Python)
#   3.  Configures NetworkManager to leave the gateway interfaces unmanaged
#   4.  Copies hostapd and dnsmasq configuration files to /etc/
#   5.  Creates /etc/hostapd/hostapd.psk (WiFi passphrase -- prompted interactively)
#   6.  Installs systemd service dependency overrides for hostapd and dnsmasq
#   7.  Deploys the nftables ruleset and enables IP forwarding persistently
#   8.  Sets execute permissions on all repository shell scripts
#   9.  Builds Docker images (skipped if already built, unless --rebuild is passed)
#   10. Creates the OVS bridge (br0), adds wlp3s0, assigns 192.168.50.1/24,
#       and points the OpenFlow controller at Ryu on tcp:127.0.0.1:6653
#   11. Generates adguard/conf/AdGuardHome.yaml from the base template,
#       prompting for an admin username and password (skipped if already exists)
#   12. Installs attach-zeek-mirror.sh and zeek-mirror.service
#   13. Installs dns_cache_updater.py and dns-cache-updater.service
#   14. Installs log-maintenance.sh and configures the daily cron job
#   15. Enables and starts all systemd services in dependency order
#   16. Runs the health check to confirm a working state
#
# Usage:
#   sudo ./install.sh              # Fresh install or safe re-run
#   sudo ./install.sh --rebuild    # Re-run and force a Docker image rebuild
#
# Requirements:
#   - Ubuntu 22.04 LTS or 24.04 LTS
#   - Run as root (sudo)
#   - Run from the repository root directory
#   - Internet access (for apt and Docker image pulls)

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
skip()    { echo -e "        [SKIP] $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() {
    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────${NC}"
}

# ---------------------------------------------------------------------------
# Configuration
# Matches the reference hardware and network design documented in the project.
# Edit these values if the host hardware differs.
# ---------------------------------------------------------------------------

WIFI_IFACE="wlp3s0"
WAN_IFACE="enp2s0"
BRIDGE="br0"
BRIDGE_IP="192.168.50.1"
BRIDGE_PREFIX="24"
RYU_OPENFLOW_PORT="6653"

# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------

FORCE_REBUILD=false

for arg in "$@"; do
    case "$arg" in
        --rebuild) FORCE_REBUILD=true ;;
        *) die "Unknown argument: $arg. Valid options: --rebuild" ;;
    esac
done

# ---------------------------------------------------------------------------
# Helper: compare a source file against an installed destination.
# Returns 0 (true) if the files differ or the destination does not exist.
# ---------------------------------------------------------------------------

needs_update() {
    local src="$1"
    local dst="$2"
    # Destination does not exist yet, or the content differs from the source.
    [ ! -f "$dst" ] || ! diff -q "$src" "$dst" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Helper: apply a config file only if it has changed.
# Backs up the original on first install, then copies and returns 0 if the
# file was updated, 1 if it was already current.
# ---------------------------------------------------------------------------

apply_config() {
    local src="$1"
    local dst="$2"
    local backup="${dst}.pre-gateway"

    if needs_update "$src" "$dst"; then
        # Backs up the very first version of the file that existed before
        # the gateway was installed, preserving the original system config.
        if [ -f "$dst" ] && [ ! -f "$backup" ]; then
            cp "$dst" "$backup"
            info "Backed up $dst -> $backup"
        fi
        cp "$src" "$dst"
        success "Updated $dst"
        return 0
    else
        skip "$dst is already current."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Step 0: Preflight checks
# ---------------------------------------------------------------------------

preflight() {
    section "Step 0: Preflight Checks"

    # Ensures the script is running with root privileges.
    if [ "$(id -u)" -ne 0 ]; then
        die "This script must be run as root. Use: sudo ./install.sh"
    fi

    # Ensures the script is run from the repository root.
    if [ ! -f "docker-compose.yml" ]; then
        die "docker-compose.yml not found. Run this script from the repository root."
    fi

    # Ensures the host is Debian/Ubuntu-based.
    if ! command -v apt-get &>/dev/null; then
        die "apt-get not found. This script requires Ubuntu 22.04 or 24.04."
    fi

    # Records the non-root user who invoked sudo, used later when adding
    # them to the docker group.
    INVOKING_USER="${SUDO_USER:-}"

    # Verifies all required source files are present before starting.
    info "Checking required repository files..."
    local missing=0
    for f in \
        "config/hostapd/hostapd.conf" \
        "config/hostapd/override.conf" \
        "config/dnsmasq/dnsmasq.conf" \
        "config/dnsmasq/override.conf" \
        "config/nftables/nftables.conf" \
        "adguard/conf/AdguardHome.yaml.base" \
        "Services/zeek-mirror/attach-zeek-mirror.sh" \
        "Services/zeek-mirror/zeek-mirror.service" \
        "Services/dns-cache-updater/dns_cache_updater.py" \
        "Services/dns-cache-updater/dns-cache-updater.service" \
        "scripts/log-maintenance.sh"
    do
        if [ ! -f "$f" ]; then
            warn "Missing: $f"
            missing=$((missing + 1))
        fi
    done

    if [ "$missing" -gt 0 ]; then
        die "$missing required file(s) are missing from the repository. Cannot continue."
    fi

    success "All preflight checks passed."
}

# ---------------------------------------------------------------------------
# Running system detection and confirmation
# ---------------------------------------------------------------------------

check_running_system() {
    section "Checking for Existing Installation"

    local running=false
    local running_components=()

    # Checks which major components are already active.
    docker inspect --format '{{.State.Status}}' ryu-controller 2>/dev/null \
        | grep -q "running" && running_components+=("Ryu (Docker)") && running=true || true

    docker inspect --format '{{.State.Status}}' zeek 2>/dev/null \
        | grep -q "running" && running_components+=("Zeek (Docker)") && running=true || true

    systemctl is-active --quiet hostapd 2>/dev/null \
        && running_components+=("hostapd") && running=true || true

    systemctl is-active --quiet dnsmasq 2>/dev/null \
        && running_components+=("dnsmasq") && running=true || true

    ovs-vsctl br-exists "$BRIDGE" 2>/dev/null \
        && running_components+=("OVS bridge ($BRIDGE)") && running=true || true

    if [ "$running" = false ]; then
        info "No existing installation detected. Proceeding with a fresh install."
        return
    fi

    # Formats the list of running components for display.
    echo ""
    warn "An existing gateway installation was detected."
    warn "The following components are currently active:"
    echo ""
    for c in "${running_components[@]}"; do
        echo "    - $c"
    done
    echo ""
    warn "Re-running this script will:"
    warn "  - Update any config files that differ from the repository versions"
    warn "  - Briefly restart hostapd and dnsmasq IF their configs changed"
    warn "    (connected WiFi clients will be dropped for a few seconds)"
    warn "  - Skip Docker image builds unless --rebuild was passed"
    warn "  - Leave all other running components untouched"
    echo ""

    # Prompts the operator to confirm before making any changes to a live system.
    read -r -p "  Continue? [y/N] " confirm
    echo ""
    case "$confirm" in
        [yY][eE][sS]|[yY]) info "Continuing..." ;;
        *) die "Aborted by user." ;;
    esac
}

# ---------------------------------------------------------------------------
# Step 1: System packages
# ---------------------------------------------------------------------------

install_system_packages() {
    section "Step 1: System Packages"

    # Updates the package index if the cached lists are older than one hour,
    # to avoid unnecessary network traffic on re-runs.
    local apt_cache_age=0
    if [ -d /var/lib/apt/lists ]; then
        apt_cache_age=$(find /var/lib/apt/lists -maxdepth 1 -name "*.lz4" -mmin -60 2>/dev/null | head -1 | wc -l)
    fi
    if [ "$apt_cache_age" -eq 0 ]; then
        info "Updating apt package index..."
        apt-get update -qq
    fi

    info "Installing system packages (skipped automatically if already installed)..."
    apt-get install -y \
        openvswitch-switch \
        hostapd \
        dnsmasq \
        nftables \
        iw \
        python3 \
        python3-pip \
        python3-venv \
        python3-bcrypt \
        curl \
        dnsutils \
        nmap \
        git

    success "System packages up to date."
}

# ---------------------------------------------------------------------------
# Step 2: Docker
# ---------------------------------------------------------------------------

install_docker() {
    section "Step 2: Docker"

    if command -v docker &>/dev/null; then
        skip "Docker is already installed ($(docker --version))."
    else
        info "Installing Docker via the official get.docker.com script..."
        curl -fsSL https://get.docker.com | sh
        success "Docker installed."
    fi

    # Adds the invoking user to the docker group if they are not already in it.
    if [ -n "$INVOKING_USER" ] && ! groups "$INVOKING_USER" | grep -q docker; then
        usermod -aG docker "$INVOKING_USER"
        warn "User '$INVOKING_USER' added to the 'docker' group. A logout/login is required before running docker without sudo."
    fi

    systemctl enable docker --quiet
    if ! systemctl is-active --quiet docker; then
        systemctl start docker
        success "Docker daemon started."
    else
        skip "Docker daemon is already running."
    fi
}

# ---------------------------------------------------------------------------
# Step 3: Host-side Python packages
# ---------------------------------------------------------------------------

install_python_deps() {
    section "Step 3: Host-Side Python Packages"

    # pip itself reports 'already satisfied' for packages that are current,
    # so this step is safe to re-run with no side effects.
    pip3 install --break-system-packages --quiet \
        requests \
        pyyaml

    success "requests and pyyaml up to date."
}

# ---------------------------------------------------------------------------
# Step 4: NetworkManager exclusions
# ---------------------------------------------------------------------------

configure_networkmanager() {
    section "Step 4: NetworkManager"

    if ! systemctl is-active --quiet NetworkManager 2>/dev/null; then
        skip "NetworkManager is not active."
        return
    fi

    local nm_conf="/etc/NetworkManager/conf.d/99-iot-gateway-unmanaged.conf"

    # Checks whether the exclusion file already contains the correct content
    # before writing it, to avoid an unnecessary reload.
    local expected
    expected=$(printf '[keyfile]\nunmanaged-devices=interface-name:%s;interface-name:%s\n' \
        "$WIFI_IFACE" "$BRIDGE")

    if [ -f "$nm_conf" ] && grep -q "unmanaged-devices=interface-name:${WIFI_IFACE}" "$nm_conf"; then
        skip "NetworkManager exclusions already configured."
    else
        mkdir -p /etc/NetworkManager/conf.d
        cat > "$nm_conf" <<EOF
# Generated by the IoT Security Gateway install.sh script.
# Prevents NetworkManager from managing the OVS-controlled interfaces.
[keyfile]
unmanaged-devices=interface-name:${WIFI_IFACE};interface-name:${BRIDGE}
EOF
        systemctl reload NetworkManager 2>/dev/null || true
        success "$WIFI_IFACE and $BRIDGE excluded from NetworkManager."
    fi
}

# ---------------------------------------------------------------------------
# Step 5: hostapd configuration
# ---------------------------------------------------------------------------

configure_hostapd() {
    section "Step 5: hostapd"

    mkdir -p /etc/hostapd

    # Tracks whether the config file changed. If it did, a restart is needed
    # later; if it did not, the running service is left untouched.
    HOSTAPD_CONFIG_CHANGED=false
    if apply_config "config/hostapd/hostapd.conf" "/etc/hostapd/hostapd.conf"; then
        HOSTAPD_CONFIG_CHANGED=true
    fi

    # Creates the PSK file only if it does not already exist. It is never
    # overwritten automatically -- the operator must edit it manually.
    if [ -f /etc/hostapd/hostapd.psk ]; then
        skip "/etc/hostapd/hostapd.psk already exists."
    else
        info ""
        info "A WPA2 passphrase is required for the IoT-Security-AP network."
        info "It will be stored in /etc/hostapd/hostapd.psk (root read-only, mode 600)."
        info ""

        local passphrase=""
        local confirm=""

        while true; do
            # Reads the passphrase silently (no echo to the terminal).
            read -r -s -p "  Enter WiFi passphrase (min 8 characters): " passphrase
            echo ""

            if [ "${#passphrase}" -lt 8 ]; then
                echo "  Passphrase must be at least 8 characters. Try again."
                continue
            fi

            read -r -s -p "  Confirm passphrase: " confirm
            echo ""

            if [ "$passphrase" = "$confirm" ]; then
                break
            else
                echo "  Passphrases do not match. Try again."
            fi
        done

        # Writes the PSK in the format hostapd expects for wpa_psk_file.
        # The wildcard MAC (00:00:00:00:00:00) applies to all clients.
        printf '00:00:00:00:00:00 %s\n' "$passphrase" > /etc/hostapd/hostapd.psk
        chmod 600 /etc/hostapd/hostapd.psk
        chown root:root /etc/hostapd/hostapd.psk
        success "Created /etc/hostapd/hostapd.psk (mode 600)."
        HOSTAPD_CONFIG_CHANGED=true
    fi

    # Installs the systemd drop-in override for startup ordering.
    # The directory must exist before apply_config attempts the copy.
    mkdir -p /etc/systemd/system/hostapd.service.d
    HOSTAPD_OVERRIDE_CHANGED=false
    if apply_config "config/hostapd/override.conf" \
                    "/etc/systemd/system/hostapd.service.d/override.conf"; then
        HOSTAPD_OVERRIDE_CHANGED=true
    fi
}

# ---------------------------------------------------------------------------
# Step 6: dnsmasq configuration
# ---------------------------------------------------------------------------

configure_dnsmasq() {
    section "Step 6: dnsmasq"

    DNSMASQ_CONFIG_CHANGED=false
    if apply_config "config/dnsmasq/dnsmasq.conf" "/etc/dnsmasq.conf"; then
        DNSMASQ_CONFIG_CHANGED=true
    fi

    # The directory must exist before apply_config attempts the copy.
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    DNSMASQ_OVERRIDE_CHANGED=false
    if apply_config "config/dnsmasq/override.conf" \
                    "/etc/systemd/system/dnsmasq.service.d/override.conf"; then
        DNSMASQ_OVERRIDE_CHANGED=true
    fi
}

# ---------------------------------------------------------------------------
# Step 7: nftables + IP forwarding
# ---------------------------------------------------------------------------

configure_nftables() {
    section "Step 7: nftables and IP Forwarding"

    NFTABLES_CHANGED=false
    if apply_config "config/nftables/nftables.conf" "/etc/nftables.conf"; then
        NFTABLES_CHANGED=true
    fi

    systemctl enable nftables --quiet

    # Writes the sysctl.d entry only if it is not already in place.
    local sysctl_file="/etc/sysctl.d/99-iot-gateway.conf"
    if [ ! -f "$sysctl_file" ] || ! grep -q "net.ipv4.ip_forward = 1" "$sysctl_file"; then
        cat > "$sysctl_file" <<EOF
# Required by the IoT Security Gateway NAT masquerade rule.
# Allows the host to forward IPv4 packets between br0 and enp2s0.
net.ipv4.ip_forward = 1
EOF
        sysctl -p "$sysctl_file" >/dev/null
        success "IPv4 forwarding enabled (persistent via $sysctl_file)."
    else
        skip "IPv4 forwarding already configured."
    fi
}

# ---------------------------------------------------------------------------
# Step 8: Script permissions
# ---------------------------------------------------------------------------

set_script_permissions() {
    section "Step 8: Script Permissions"

    find scripts/ -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    find Services/ -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    success "Execute permissions confirmed on all .sh files."
}

# ---------------------------------------------------------------------------
# Step 9: Docker images
# ---------------------------------------------------------------------------

build_docker_images() {
    section "Step 9: Docker Images"

    # Checks whether the expected custom images already exist. Only the
    # custom-built images are checked -- pulled images (zeek, adguard) are
    # managed by docker compose pull automatically.
    local images_exist=true
    for image in ryu-controller ml-pipeline; do
        if ! docker images --format '{{.Repository}}' | grep -q "$image"; then
            images_exist=false
            break
        fi
    done

    if [ "$images_exist" = true ] && [ "$FORCE_REBUILD" = false ]; then
        skip "Docker images already built. Pass --rebuild to force a rebuild."
    else
        if [ "$FORCE_REBUILD" = true ]; then
            info "Rebuilding Docker images (--rebuild passed)..."
            docker compose build --no-cache
        else
            info "One or more Docker images not found. Building..."
            docker compose build
        fi
        success "Docker images built."
    fi
}

# ---------------------------------------------------------------------------
# Step 10: OVS bridge
# ---------------------------------------------------------------------------

configure_ovs() {
    section "Step 10: Open vSwitch Bridge"

    # Ensures OVS is running before any vsctl commands.
    if ! systemctl is-active --quiet ovs-vswitchd; then
        info "Starting ovs-vswitchd..."
        systemctl start ovs-vswitchd
        sleep 2
    fi

    # Creates the bridge only if it does not already exist.
    if ! ovs-vsctl br-exists "$BRIDGE" 2>/dev/null; then
        ovs-vsctl add-br "$BRIDGE"
        success "Created OVS bridge: $BRIDGE"
    else
        skip "OVS bridge $BRIDGE already exists."
    fi

    # Adds the WiFi interface as an OVS port only if it is not already one.
    if ! ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "^${WIFI_IFACE}$"; then
        if ip link show "$WIFI_IFACE" &>/dev/null; then
            ovs-vsctl add-port "$BRIDGE" "$WIFI_IFACE"
            success "Added $WIFI_IFACE as a port on $BRIDGE."
        else
            warn "$WIFI_IFACE not found. OVS port not added."
            warn "If the interface name differs from '$WIFI_IFACE', update the WIFI_IFACE variable at the top of this script."
        fi
    else
        skip "$WIFI_IFACE is already an OVS port on $BRIDGE."
    fi

    # Assigns the gateway IP to the bridge's internal port only if not set.
    if ! ip addr show "$BRIDGE" 2>/dev/null | grep -q "$BRIDGE_IP"; then
        ip addr add "${BRIDGE_IP}/${BRIDGE_PREFIX}" dev "$BRIDGE"
        ip link set "$BRIDGE" up
        success "Assigned ${BRIDGE_IP}/${BRIDGE_PREFIX} to $BRIDGE."
    else
        skip "$BRIDGE already has IP $BRIDGE_IP."
    fi

    # Sets fail mode only if it is not already correct.
    local current_fail_mode
    current_fail_mode=$(ovs-vsctl get-fail-mode "$BRIDGE" 2>/dev/null || echo "")
    if [ "$current_fail_mode" != "standalone" ]; then
        ovs-vsctl set-fail-mode "$BRIDGE" standalone
        success "OVS fail mode set to 'standalone'."
    else
        skip "OVS fail mode is already 'standalone'."
    fi

    # Sets the controller only if it is not already pointing at Ryu.
    local current_controller
    current_controller=$(ovs-vsctl get-controller "$BRIDGE" 2>/dev/null || echo "")
    local expected_controller="tcp:127.0.0.1:${RYU_OPENFLOW_PORT}"
    if ! echo "$current_controller" | grep -q "$expected_controller"; then
        ovs-vsctl set-controller "$BRIDGE" "$expected_controller"
        success "OVS controller set to $expected_controller (Ryu)."
    else
        skip "OVS controller already set to $expected_controller."
    fi
}

# ---------------------------------------------------------------------------
# Step 11: AdGuard Home configuration
# ---------------------------------------------------------------------------

configure_adguard() {
    section "Step 11: AdGuard Home Configuration"

    local base_file="adguard/conf/AdguardHome.yaml.base"
    local output_file="adguard/conf/AdGuardHome.yaml"

    # AdGuard is already configured if the output file exists. The file is
    # gitignored so it will never be present on a fresh clone. On re-runs
    # it is left untouched -- credentials are never overwritten automatically.
    if [ -f "$output_file" ]; then
        skip "$output_file already exists. AdGuard configuration unchanged."
        return
    fi

    info ""
    info "AdGuard Home requires an admin username and password."
    info "These credentials are used to access the admin UI at http://<host>:8088."
    info "They will be stored (hashed) in $output_file."
    info ""

    local ag_user=""
    local ag_pass=""
    local ag_confirm=""

    # Prompts for the admin username.
    while [ -z "$ag_user" ]; do
        read -r -p "  Enter AdGuard admin username: " ag_user
        if [ -z "$ag_user" ]; then
            echo "  Username cannot be empty. Try again."
        fi
    done

    # Prompts for the admin password with confirmation.
    while true; do
        read -r -s -p "  Enter AdGuard admin password (min 8 characters): " ag_pass
        echo ""

        if [ "${#ag_pass}" -lt 8 ]; then
            echo "  Password must be at least 8 characters. Try again."
            continue
        fi

        read -r -s -p "  Confirm password: " ag_confirm
        echo ""

        if [ "$ag_pass" = "$ag_confirm" ]; then
            break
        else
            echo "  Passwords do not match. Try again."
        fi
    done

    info "Hashing password..."

    # Generates a bcrypt hash of the password using the python3-bcrypt package.
    # The hash is passed via a temp file to avoid exposing it in the process
    # list or through shell variable interpolation of special characters.
    local hash_file
    hash_file=$(mktemp)

    python3 - "$ag_pass" "$hash_file" <<'PYEOF'
import sys
import bcrypt

password = sys.argv[1].encode('utf-8')
pw_hash = bcrypt.hashpw(password, bcrypt.gensalt(rounds=10)).decode('utf-8')

with open(sys.argv[2], 'w') as f:
    f.write(pw_hash)
PYEOF

    local pw_hash
    pw_hash=$(cat "$hash_file")
    rm -f "$hash_file"

    if [ -z "$pw_hash" ]; then
        die "Failed to generate bcrypt hash. Ensure python3-bcrypt is installed."
    fi

    # Writes the final AdGuardHome.yaml by substituting the blank users block
    # in the base template with the provided credentials. Python handles the
    # file writing to avoid any issues with the $ characters in the bcrypt hash.
    python3 - "$base_file" "$output_file" "$ag_user" "$pw_hash" <<'PYEOF'
import sys

base_path   = sys.argv[1]
output_path = sys.argv[2]
username    = sys.argv[3]
pw_hash     = sys.argv[4]

with open(base_path, 'r') as f:
    content = f.read()

# Replaces the blank users block in the base template.
old_users = 'users:\n  - name:\n    password:'
new_users = f'users:\n  - name: {username}\n    password: {pw_hash}'

if old_users not in content:
    print(f"ERROR: Expected users block not found in {base_path}.", file=sys.stderr)
    sys.exit(1)

content = content.replace(old_users, new_users)

with open(output_path, 'w') as f:
    f.write(content)
PYEOF

    # The config file contains a hashed credential, so it should not be
    # world-readable. The adguard container runs as root internally, so
    # root ownership is correct.
    chmod 640 "$output_file"
    chown root:root "$output_file"

    success "Created $output_file with admin credentials."
    info "AdGuard admin UI will be available at http://<host>:8088 after startup."
}

# ---------------------------------------------------------------------------
# Step 12: Zeek mirror service
# ---------------------------------------------------------------------------

install_zeek_mirror_service() {
    section "Step 12: Zeek Mirror Service"

    # Copies the attachment script only if it differs from the installed version.
    if needs_update "Services/zeek-mirror/attach-zeek-mirror.sh" \
                    "/usr/local/bin/attach-zeek-mirror.sh"; then
        cp Services/zeek-mirror/attach-zeek-mirror.sh /usr/local/bin/attach-zeek-mirror.sh
        chmod +x /usr/local/bin/attach-zeek-mirror.sh
        success "Updated /usr/local/bin/attach-zeek-mirror.sh"
        ZEEK_MIRROR_CHANGED=true
    else
        skip "/usr/local/bin/attach-zeek-mirror.sh is already current."
        ZEEK_MIRROR_CHANGED=false
    fi

    if needs_update "Services/zeek-mirror/zeek-mirror.service" \
                    "/etc/systemd/system/zeek-mirror.service"; then
        cp Services/zeek-mirror/zeek-mirror.service /etc/systemd/system/zeek-mirror.service
        success "Updated /etc/systemd/system/zeek-mirror.service"
        ZEEK_MIRROR_CHANGED=true
    else
        skip "/etc/systemd/system/zeek-mirror.service is already current."
    fi
}

# ---------------------------------------------------------------------------
# Step 13: DNS cache updater service
# ---------------------------------------------------------------------------

install_dns_cache_updater() {
    section "Step 13: DNS Cache Updater Service"

    DNS_UPDATER_CHANGED=false

    if needs_update "Services/dns-cache-updater/dns_cache_updater.py" \
                    "/usr/local/bin/dns_cache_updater.py"; then
        cp Services/dns-cache-updater/dns_cache_updater.py /usr/local/bin/dns_cache_updater.py
        chmod +x /usr/local/bin/dns_cache_updater.py
        success "Updated /usr/local/bin/dns_cache_updater.py"
        DNS_UPDATER_CHANGED=true
    else
        skip "/usr/local/bin/dns_cache_updater.py is already current."
    fi

    if needs_update "Services/dns-cache-updater/dns-cache-updater.service" \
                    "/etc/systemd/system/dns-cache-updater.service"; then
        cp Services/dns-cache-updater/dns-cache-updater.service \
           /etc/systemd/system/dns-cache-updater.service
        success "Updated /etc/systemd/system/dns-cache-updater.service"
        DNS_UPDATER_CHANGED=true
    else
        skip "/etc/systemd/system/dns-cache-updater.service is already current."
    fi
}

# ---------------------------------------------------------------------------
# Step 14: Log maintenance cron job
# ---------------------------------------------------------------------------

install_log_maintenance() {
    section "Step 14: Log Maintenance"

    if needs_update "scripts/log-maintenance.sh" "/usr/local/bin/log-maintenance.sh"; then
        cp scripts/log-maintenance.sh /usr/local/bin/log-maintenance.sh
        chmod +x /usr/local/bin/log-maintenance.sh
        success "Updated /usr/local/bin/log-maintenance.sh"
    else
        skip "/usr/local/bin/log-maintenance.sh is already current."
    fi

    local cron_entry="0 3 * * * /usr/local/bin/log-maintenance.sh >> /var/log/gateway-maintenance.log 2>&1"
    if crontab -l 2>/dev/null | grep -qF "log-maintenance.sh"; then
        skip "Log maintenance cron job already installed."
    else
        ( crontab -l 2>/dev/null || true; echo "$cron_entry" ) | crontab -
        success "Installed daily log maintenance cron job (runs at 03:00)."
    fi
}

# ---------------------------------------------------------------------------
# Step 15: Start / reload services
#
# Services are only restarted if their configuration actually changed.
# This avoids dropping connected WiFi clients on re-runs where nothing
# has changed.
# ---------------------------------------------------------------------------

start_services() {
    section "Step 15: Services"

    # Starts Docker containers. 'docker compose up -d' is idempotent:
    # it starts containers that are not running and leaves running
    # containers untouched.
    info "Ensuring Docker containers are running..."
    docker compose up -d
    success "Docker containers running."

    # Reloads the systemd daemon only when at least one unit file changed.
    # Avoids unnecessary daemon-reload noise on clean re-runs.
    local daemon_reload_needed=false
    ${HOSTAPD_OVERRIDE_CHANGED:-false}  && daemon_reload_needed=true
    ${DNSMASQ_OVERRIDE_CHANGED:-false}  && daemon_reload_needed=true
    ${ZEEK_MIRROR_CHANGED:-false}       && daemon_reload_needed=true
    ${DNS_UPDATER_CHANGED:-false}       && daemon_reload_needed=true

    if [ "$daemon_reload_needed" = true ]; then
        systemctl daemon-reload
        info "systemd daemon reloaded (unit files changed)."
    else
        skip "No unit file changes detected. systemd daemon-reload skipped."
    fi

    # OVS -- enable and ensure it is running; never restart it here as
    # restarting OVS on a live system would tear down the bridge.
    systemctl enable ovs-vswitchd --quiet
    if ! systemctl is-active --quiet ovs-vswitchd; then
        systemctl start ovs-vswitchd
        success "ovs-vswitchd started."
    else
        skip "ovs-vswitchd is already running."
    fi

    # nftables -- reload the ruleset if the config changed.
    systemctl enable nftables --quiet
    if [ "${NFTABLES_CHANGED:-false}" = true ]; then
        systemctl restart nftables
        success "nftables ruleset reloaded (config changed)."
    elif ! systemctl is-active --quiet nftables; then
        systemctl start nftables
        success "nftables started."
    else
        skip "nftables is running and config is unchanged."
    fi

    # hostapd -- restart only if the config or PSK changed.
    # A restart briefly drops all connected WiFi clients.
    systemctl enable hostapd --quiet
    if [ "${HOSTAPD_CONFIG_CHANGED:-false}" = true ] || \
       [ "${HOSTAPD_OVERRIDE_CHANGED:-false}" = true ]; then
        warn "hostapd config changed. Restarting (connected clients will be briefly dropped)..."
        systemctl restart hostapd
        success "hostapd restarted."
    elif ! systemctl is-active --quiet hostapd; then
        systemctl start hostapd
        success "hostapd started."
    else
        skip "hostapd is running and config is unchanged."
    fi

    # dnsmasq -- restart only if the config changed.
    systemctl enable dnsmasq --quiet
    if [ "${DNSMASQ_CONFIG_CHANGED:-false}" = true ] || \
       [ "${DNSMASQ_OVERRIDE_CHANGED:-false}" = true ]; then
        warn "dnsmasq config changed. Restarting..."
        systemctl restart dnsmasq
        success "dnsmasq restarted."
    elif ! systemctl is-active --quiet dnsmasq; then
        systemctl start dnsmasq
        success "dnsmasq started."
    else
        skip "dnsmasq is running and config is unchanged."
    fi

    # zeek-mirror.service -- restart only if the unit file or script changed.
    systemctl enable zeek-mirror --quiet
    if [ "${ZEEK_MIRROR_CHANGED:-false}" = true ]; then
        systemctl restart zeek-mirror
        success "zeek-mirror.service restarted (script or unit changed)."
    elif ! systemctl is-active --quiet zeek-mirror; then
        systemctl start zeek-mirror
        success "zeek-mirror.service started."
    else
        skip "zeek-mirror.service is running and unchanged."
    fi

    # dns-cache-updater.service -- restart only if the script or unit changed.
    systemctl enable dns-cache-updater --quiet
    if [ "${DNS_UPDATER_CHANGED:-false}" = true ]; then
        systemctl restart dns-cache-updater
        success "dns-cache-updater.service restarted (script or unit changed)."
    elif ! systemctl is-active --quiet dns-cache-updater; then
        systemctl start dns-cache-updater
        success "dns-cache-updater.service started."
    else
        skip "dns-cache-updater.service is running and unchanged."
    fi
}

# ---------------------------------------------------------------------------
# Step 16: Health check
# ---------------------------------------------------------------------------

run_health_check() {
    section "Step 16: Health Check"

    info "Waiting 15 seconds for all services to stabilise..."
    sleep 15

    if [ -f "scripts/health-check.sh" ]; then
        # Runs the health check without aborting the script on failures.
        # The operator should review the output and address any FAIL/WARN items.
        bash scripts/health-check.sh || true
    else
        warn "scripts/health-check.sh not found. Skipping."
    fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo "============================================================"
    echo "  IoT Security Gateway - Setup Complete"
    echo "  $(date)"
    echo "============================================================"
    echo ""
    echo "  Review the health check output above for any FAIL or WARN"
    echo "  items that need attention."
    echo ""
    echo "  Useful commands:"
    echo ""
    echo "  Verify Phase 1 (DNS + logging):"
    echo "    sudo ./scripts/verify-phase1.sh"
    echo ""
    echo "  AdGuard admin UI (DNS filtering, blocklists):"
    echo "    http://<gateway-host>:8088"
    echo ""
    echo "  Verify Phase 2 (micro-segmentation):"
    echo "    sudo ./scripts/verify-phase2.sh"
    echo ""
    echo "  Full health check at any time:"
    echo "    sudo ./scripts/health-check.sh"
    echo ""
    echo "  Build the documentation site:"
    echo "    ./installation/build-docs.sh"
    echo ""
    echo "  Force a Docker image rebuild on the next run:"
    echo "    sudo ./installation/install.sh --rebuild"
    echo ""
    echo "  NOTE: OVS fail mode is set to 'standalone' (development)."
    echo "  Once Ryu has been running reliably for several days, harden"
    echo "  it with: sudo ovs-vsctl set-fail-mode br0 secure"
    echo ""
    echo "  Pre-gateway config backups (if applicable):"
    echo "    /etc/dnsmasq.conf.pre-gateway"
    echo "    /etc/nftables.conf.pre-gateway"
    echo "============================================================"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

main() {
    echo "============================================================"
    echo "  IoT Security Gateway - Environment Setup"
    echo "  $(date)"
    if [ "$FORCE_REBUILD" = true ]; then
        echo "  Mode: rebuild (--rebuild passed, Docker images will be rebuilt)"
    fi
    echo "============================================================"

    preflight
    check_running_system
    install_system_packages
    install_docker
    install_python_deps
    configure_networkmanager
    configure_hostapd
    configure_dnsmasq
    configure_nftables
    set_script_permissions
    build_docker_images
    configure_ovs
    configure_adguard
    install_zeek_mirror_service
    install_dns_cache_updater
    install_log_maintenance
    start_services
    run_health_check
    print_summary
}

main "$@"
