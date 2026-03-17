"""
IoT Security Gateway - SDN Policy Application
Phase 5: Per-Pair Lateral Movement Permits

Builds on Phase 4 (anomaly detection and automated isolation) by adding
administrator-controlled per-pair lateral movement permits. By default all
IoT-to-IoT communication remains blocked by the anti-lateral-movement rule.
An administrator may POST to the lateral-permits endpoint to install a
priority-160 exception that allows bidirectional unicast IP traffic between
a specific pair of devices.

Pre-requisite for lateral permits to function:
    Proxy ARP must be enabled on br0 so that devices can resolve each other's
    MAC address via the gateway rather than directly:

        sudo sysctl -w net.ipv4.conf.br0.proxy_arp=1

    To make this persistent across reboots, add the following line to
    /etc/sysctl.d/99-iot-gateway.conf:

        net.ipv4.conf.br0.proxy_arp = 1

    Without proxy ARP, ARP broadcasts between associated stations are blocked
    by ap_isolate=1 in hostapd, and devices will never resolve each other's
    IP address, preventing any IP communication even if the permit rule exists.

Known limitation - multicast service discovery:
    mDNS (port 5353, group 224.0.0.251) and SSDP (port 1900,
    group 239.255.255.250) are blocked by ap_isolate at the 802.11 layer and
    by the OVS default-deny rule. Devices cannot organically discover each
    other by name. The administrator must know the IP addresses of both devices
    before creating a permit. A selective multicast proxy service is required
    to support full device discovery; this is documented as a future
    enhancement.

Flow Rule Priority Scheme (updated for Phase 5):
    0     - Table-miss (send to controller, safety net)
    1     - Default deny (drop everything not explicitly allowed)
    50    - General WAN access (active for un-profiled devices)
    100   - Per-device WAN intercept (send to controller for evaluation)
            and per-device inbound deny (block un-allowed return traffic)
    150   - Anti-lateral-movement (block IoT-to-IoT via gateway routing)
    160   - Per-pair lateral permit (bidirectional exception to rule 150)
    200   - Essential services (DHCP, DNS, NTP, ARP)
    500   - Per-device allowlist entries (reactive, installed on first
            matching packet, with idle timeout)
    65535 - Dynamic isolation (Phase 4)
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, dhcp, udp
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
import json
import logging
import os
import struct
import socket
import time
from webob import Response
from datetime import datetime, timezone

LOG = logging.getLogger(__name__)

# -- Configuration ----------------------------------------------------------
# Adjust these to match the network environment.

GATEWAY_IP = "192.168.50.1"
IOT_SUBNET = "192.168.50.0"
IOT_SUBNET_MASK = "255.255.255.0"

# The WiFi interface name on the OVS bridge. IoT devices connect
# through this interface. The app discovers the port number at
# runtime by matching this name in the port description reply.
WIFI_INTERFACE = "wlp3s0"

# Path to the device profiles config file inside the container.
# This is mounted from the host via docker-compose.
DEVICE_PROFILES_PATH = os.environ.get(
    "DEVICE_PROFILES_PATH",
    "/opt/ryu/config/device_profiles.json",
)

# -- Priority Levels --------------------------------------------------------
# Higher number = higher priority = matched first in OVS.

PRI_TABLE_MISS      = 0      # Safety net: send unmatched to controller
PRI_DEFAULT_DENY    = 1      # Drop everything not explicitly allowed
PRI_WAN_ACCESS      = 50     # General internet access (un-profiled devices)
PRI_DEVICE_INTERCEPT = 100   # Per-device WAN intercept/deny (profiled devices)
PRI_ANTI_LATERAL    = 150    # Block IoT-to-IoT via gateway routing
PRI_LATERAL_PERMIT  = 160    # Per-pair exception to the anti-lateral rule
PRI_ESSENTIAL       = 200    # DHCP, DNS, NTP, ARP
PRI_DEVICE_ALLOW    = 500    # Per-device allowlist entries (reactive)
PRI_ISOLATE         = 65535  # Dynamic device isolation (Phase 4)

# Default idle timeout for reactive allowlist flow rules (seconds).
# When no matching traffic flows for this duration, OVS removes the
# rule automatically. The next packet triggers a new controller
# evaluation. This keeps the flow table clean and allows the DNS
# cache to stay current.
DEFAULT_IDLE_TIMEOUT = 300

# -- REST API Configuration -------------------------------------------------

POLICY_API_INSTANCE = "gateway_policy_app"
BASE_URL = "/policy"


# -- Helper: CIDR matching --------------------------------------------------

def ip_to_int(ip_str):
    """Convert a dotted-quad IP string to a 32-bit integer."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def cidr_contains(cidr_str, ip_str):
    """Return True if ip_str falls within the CIDR range cidr_str."""
    if "/" in cidr_str:
        network, prefix_len = cidr_str.split("/")
        prefix_len = int(prefix_len)
    else:
        network = cidr_str
        prefix_len = 32

    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return (ip_to_int(network) & mask) == (ip_to_int(ip_str) & mask)


# -- REST API Controller ----------------------------------------------------
# Exposes endpoints for policy status, device management, allowlist
# management, DNS cache updates, and lateral movement permits.
#
# Phase 2 endpoints:
#   GET  /policy/status                - engine state
#   GET  /policy/devices               - known MACs on the WiFi port
#   POST /policy/isolate               - quarantine a device by MAC
#   POST /policy/release               - remove quarantine
#
# Phase 3 endpoints:
#   GET  /policy/allowlists            - current device profiles and mode
#   POST /policy/allowlists/reload     - reload profiles from config file
#   POST /policy/allowlists/mode       - switch between learning/enforcing
#   POST /policy/dns-cache             - update domain-to-IP mappings
#   GET  /policy/dns-cache             - view current DNS cache
#   GET  /policy/denied-log            - recent denied connection attempts
#
# Phase 5 endpoints:
#   GET    /policy/lateral-permits     - list all active permits
#   POST   /policy/lateral-permits     - add a permit between two devices
#   DELETE /policy/lateral-permits     - remove a permit between two devices

class GatewayPolicyController(ControllerBase):
    """REST API controller for the gateway policy app."""

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[POLICY_API_INSTANCE]

    # -- Phase 2 endpoints --------------------------------------------------

    @route("policy", BASE_URL + "/status", methods=["GET"])
    def get_status(self, req, **kwargs):
        """Return the current policy engine status."""
        body = json.dumps(self.app.get_status(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/devices", methods=["GET"])
    def get_devices(self, req, **kwargs):
        """Return the list of known devices (MACs seen on the WiFi port)."""
        body = json.dumps(self.app.get_known_devices(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/isolate", methods=["POST"])
    def isolate_device(self, req, **kwargs):
        """Isolate a device by MAC address."""
        try:
            body = json.loads(req.body)
            mac = body.get("mac", "").lower()
            reason = body.get("reason") or "API request (no reason provided)"
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mac:
            return Response(status=400, charset="utf-8", body='Missing "mac" field')

        result = self.app.isolate_device(mac, reason)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/release", methods=["POST"])
    def release_device(self, req, **kwargs):
        """Release a previously isolated device."""
        try:
            body = json.loads(req.body)
            mac = body.get("mac", "").lower()
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mac:
            return Response(status=400, charset="utf-8", body='Missing "mac" field')

        result = self.app.release_device(mac)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    # -- Phase 3 endpoints --------------------------------------------------

    @route("policy", BASE_URL + "/allowlists", methods=["GET"])
    def get_allowlists(self, req, **kwargs):
        """Return the current device profiles and enforcement mode."""
        body = json.dumps(self.app.get_allowlists(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/allowlists/reload", methods=["POST"])
    def reload_allowlists(self, req, **kwargs):
        """Reload device profiles from the config file on disk."""
        result = self.app.reload_profiles()
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/allowlists/mode", methods=["POST"])
    def set_mode(self, req, **kwargs):
        """
        Switch between learning and enforcing mode.

        Expected JSON body: ``{"mode": "learning"}`` or
        ``{"mode": "enforcing"}``.
        """
        try:
            body = json.loads(req.body)
            mode = body.get("mode", "").lower()
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if mode not in ("learning", "enforcing"):
            return Response(
                status=400, charset="utf-8",
                body='Invalid mode. Must be "learning" or "enforcing".',
            )

        result = self.app.set_enforcement_mode(mode)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/dns-cache", methods=["POST"])
    def update_dns_cache(self, req, **kwargs):
        """
        Update the DNS cache with domain-to-IP mappings.

        Expected JSON body::

            {
                "mappings": {
                    "api.vendor.com": ["203.0.113.50", "203.0.113.51"],
                    "cloud.vendor.com": ["198.51.100.10"]
                }
            }
        """
        try:
            body = json.loads(req.body)
            mappings = body.get("mappings", {})
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mappings:
            return Response(
                status=400, charset="utf-8",
                body='Missing or empty "mappings" field',
            )

        result = self.app.update_dns_cache(mappings)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/dns-cache", methods=["GET"])
    def get_dns_cache(self, req, **kwargs):
        """Return the current DNS cache contents."""
        body = json.dumps(self.app.get_dns_cache(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/denied-log", methods=["GET"])
    def get_denied_log(self, req, **kwargs):
        """Return recent denied connection attempts from profiled devices."""
        body = json.dumps(self.app.get_denied_log(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    # -- Phase 5 endpoints --------------------------------------------------

    @route("policy", BASE_URL + "/lateral-permits", methods=["GET"])
    def get_lateral_permits(self, req, **kwargs):
        """
        Return all active lateral movement permits.

        Each permit entry includes the MAC address and last-known IP of
        both devices, the creation timestamp, and whether the OpenFlow
        rules are currently installed.
        """
        body = json.dumps(self.app.get_lateral_permits(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/lateral-permits", methods=["POST"])
    def add_lateral_permit(self, req, **kwargs):
        """
        Grant bidirectional unicast communication between two IoT devices.

        Both devices must already be known to the policy engine (i.e. they
        must have connected and generated traffic since the last restart)
        and both must have a recorded IP address before the permit can be
        installed.

        Expected JSON body::

            {
                "mac_a": "aa:bb:cc:dd:ee:ff",
                "mac_b": "11:22:33:44:55:66"
            }

        **Pre-requisite:** proxy ARP must be enabled on br0::

            sudo sysctl -w net.ipv4.conf.br0.proxy_arp=1

        Without proxy ARP, the permit rules will be installed but devices
        will not be able to resolve each other's IP address via ARP, so no
        communication will occur.
        """
        try:
            body = json.loads(req.body)
            mac_a = body.get("mac_a", "").lower().strip()
            mac_b = body.get("mac_b", "").lower().strip()
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mac_a or not mac_b:
            return Response(
                status=400, charset="utf-8",
                body='Both "mac_a" and "mac_b" fields are required',
            )

        if mac_a == mac_b:
            return Response(
                status=400, charset="utf-8",
                body="mac_a and mac_b must be different devices",
            )

        result = self.app.add_lateral_permit(mac_a, mac_b)
        status = 200 if result.get("success") else 400
        return Response(
            status=status,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/lateral-permits", methods=["DELETE"])
    def remove_lateral_permit(self, req, **kwargs):
        """
        Revoke a lateral movement permit between two devices.

        Removes the OpenFlow exception rules immediately. Subsequent
        traffic between the pair is dropped by the anti-lateral-movement
        rule at priority 150.

        Expected JSON body::

            {
                "mac_a": "aa:bb:cc:dd:ee:ff",
                "mac_b": "11:22:33:44:55:66"
            }

        The order of mac_a and mac_b does not matter.
        """
        try:
            body = json.loads(req.body)
            mac_a = body.get("mac_a", "").lower().strip()
            mac_b = body.get("mac_b", "").lower().strip()
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mac_a or not mac_b:
            return Response(
                status=400, charset="utf-8",
                body='Both "mac_a" and "mac_b" fields are required',
            )

        result = self.app.remove_lateral_permit(mac_a, mac_b)
        status = 200 if result.get("success") else 400
        return Response(
            status=status,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )


# -- Policy Application -----------------------------------------------------

class GatewayPolicy(app_manager.RyuApp):
    """
    SDN policy engine for the IoT security gateway.

    On switch connection, installs proactive flow rules implementing
    micro-segmentation and essential service access (Phase 2), per-device
    allowlist enforcement (Phase 3), and the anti-lateral-movement baseline
    (Phase 5). Per-pair lateral permits are installed dynamically via the
    REST API.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Register the REST API controller.
        wsgi = kwargs["wsgi"]
        wsgi.register(GatewayPolicyController, {POLICY_API_INSTANCE: self})

        # -- Phase 2 state --------------------------------------------------
        self.datapath = None
        self.wifi_port = None
        self.rules_installed = False
        self.connect_time = None
        self.rule_count = 0

        # Tracks every MAC seen on the WiFi port.
        # {mac: {"first_seen": ts, "last_seen": ts, "ip": str|None}}
        # The "ip" field is populated from observed IPv4 packet headers
        # and is used by the lateral permit feature to resolve IPs at
        # rule installation time.
        self.known_devices = {}

        # Tracks devices that have been quarantined.
        # {mac: {"since": ts, "reason": str}}
        self.isolated_devices = {}

        # -- Phase 3 state --------------------------------------------------
        # {mac: {name, manufacturer, allowed_domains, allowed_cidrs}}
        self.device_profiles = {}
        self.enforcement_mode = "learning"
        self.idle_timeout = DEFAULT_IDLE_TIMEOUT
        # {domain: {"ips": [...], "updated": ts}}
        self.dns_cache = {}
        # Recent denied connection attempts (capped circular buffer).
        self.denied_log = []
        self.denied_log_max = 500
        # {mac: set of dest IPs with currently active reactive rules}
        self.active_allowlist_rules = {}

        # -- Phase 5 state --------------------------------------------------
        # Stores all active lateral movement permits.
        # Key: frozenset({mac_a, mac_b})
        # Value: {
        #     "mac_a": str, "mac_b": str,
        #     "ip_a": str|None, "ip_b": str|None,
        #     "created_at": str,
        #     "rules_installed": bool
        # }
        # The frozenset key ensures the pair is order-independent.
        self.lateral_permits = {}

        # Load device profiles from config on startup.
        self._load_profiles_from_file()

    # -- Profile loading ----------------------------------------------------

    def _load_profiles_from_file(self):
        """Load device profiles from the JSON config file."""
        if not os.path.exists(DEVICE_PROFILES_PATH):
            LOG.info(
                "No device profiles config found at %s. "
                "Starting with empty profiles (all devices get general WAN access).",
                DEVICE_PROFILES_PATH,
            )
            return

        try:
            with open(DEVICE_PROFILES_PATH, "r") as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            LOG.error(
                "Failed to load device profiles from %s: %s",
                DEVICE_PROFILES_PATH, e,
            )
            return

        self.enforcement_mode = config.get("mode", "learning")
        self.idle_timeout = config.get("idle_timeout", DEFAULT_IDLE_TIMEOUT)

        devices = config.get("devices", {})
        self.device_profiles = {}
        for mac, profile in devices.items():
            mac = mac.lower()
            self.device_profiles[mac] = {
                "name": profile.get("name", "Unknown"),
                "manufacturer": profile.get("manufacturer", "Unknown"),
                "allowed_domains": [
                    d.lower() for d in profile.get("allowed_domains", [])
                ],
                "allowed_cidrs": profile.get("allowed_cidrs", []),
            }

        LOG.info(
            "Loaded %d device profiles from %s. Mode: %s. Idle timeout: %ds.",
            len(self.device_profiles),
            DEVICE_PROFILES_PATH,
            self.enforcement_mode,
            self.idle_timeout,
        )

    # -- Phase 2: status and device queries --------------------------------

    def get_status(self):
        """
        Return a snapshot of the current policy engine state.

        Includes switch connection status, rule count, known and isolated
        device counts, enforcement mode, profiled device count, DNS cache
        size, denied-log entry count, and the number of active lateral
        movement permits.
        """
        return {
            "switch_connected": self.datapath is not None,
            "switch_dpid": self.datapath.id if self.datapath else None,
            "wifi_port": self.wifi_port,
            "wifi_interface": WIFI_INTERFACE,
            "rules_installed": self.rules_installed,
            "rule_count": self.rule_count,
            "known_devices": len(self.known_devices),
            "isolated_devices": len(self.isolated_devices),
            "connect_time": self.connect_time,
            "gateway_ip": GATEWAY_IP,
            "iot_subnet": f"{IOT_SUBNET}/{IOT_SUBNET_MASK}",
            "enforcement_mode": self.enforcement_mode,
            "profiled_devices": len(self.device_profiles),
            "dns_cache_entries": len(self.dns_cache),
            "denied_log_size": len(self.denied_log),
            "lateral_permit_count": len(self.lateral_permits),
        }

    def get_known_devices(self):
        """
        Return all MAC addresses seen on the WiFi port, augmented with
        profile, isolation, IP, and lateral permit status.
        """
        devices = {}
        for mac, info in self.known_devices.items():
            entry = dict(info)
            entry["has_profile"] = mac in self.device_profiles
            if mac in self.device_profiles:
                entry["profile_name"] = self.device_profiles[mac]["name"]
            entry["is_isolated"] = mac in self.isolated_devices
            # Indicate whether this device participates in any permit.
            entry["has_lateral_permit"] = any(
                mac in key for key in self.lateral_permits
            )
            devices[mac] = entry
        return {
            "devices": devices,
            "total": len(devices),
        }

    def isolate_device(self, mac, reason="API request (no reason provided)"):
        """
        Install a max-priority DROP rule for all traffic to and from a device.

        Isolation takes effect immediately and overrides all other rules
        including any active lateral permits.
        """
        if not self.datapath or not self.wifi_port:
            return {"success": False, "error": "Switch not connected"}

        if mac in self.isolated_devices:
            return {"success": False, "error": f"{mac} is already isolated"}

        dp = self.datapath
        parser = dp.ofproto_parser

        match = parser.OFPMatch(in_port=self.wifi_port, eth_src=mac)
        self._add_flow(dp, PRI_ISOLATE, match, actions=[], tag="isolate")

        match_to = parser.OFPMatch(in_port=dp.ofproto.OFPP_LOCAL, eth_dst=mac)
        self._add_flow(dp, PRI_ISOLATE, match_to, actions=[], tag="isolate")

        ts = datetime.now(timezone.utc).isoformat()
        self.isolated_devices[mac] = {"since": ts, "reason": reason}
        LOG.warning("ISOLATED device %s at %s - reason: %s", mac, ts, reason)

        return {"success": True, "mac": mac, "isolated_at": ts}

    def release_device(self, mac):
        """
        Remove isolation rules for a device, restoring normal policy.

        If the device participates in a lateral permit, those rules
        remain in place and take effect again once isolation is lifted.
        """
        if not self.datapath:
            return {"success": False, "error": "Switch not connected"}

        if mac not in self.isolated_devices:
            return {"success": False, "error": f"{mac} is not isolated"}

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        match_from = parser.OFPMatch(in_port=self.wifi_port, eth_src=mac)
        self._delete_flow(dp, PRI_ISOLATE, match_from)

        match_to = parser.OFPMatch(in_port=ofproto.OFPP_LOCAL, eth_dst=mac)
        self._delete_flow(dp, PRI_ISOLATE, match_to)

        del self.isolated_devices[mac]
        LOG.info("RELEASED device %s from isolation", mac)

        return {"success": True, "mac": mac}

    # -- Phase 3: allowlist management -------------------------------------

    def get_allowlists(self):
        """Return the current device profiles and enforcement mode."""
        profiles_summary = {}
        for mac, profile in self.device_profiles.items():
            profiles_summary[mac] = {
                "name": profile["name"],
                "manufacturer": profile["manufacturer"],
                "allowed_domains": profile["allowed_domains"],
                "allowed_cidrs": profile["allowed_cidrs"],
                "active_rules": len(self.active_allowlist_rules.get(mac, set())),
            }
        return {
            "mode": self.enforcement_mode,
            "idle_timeout": self.idle_timeout,
            "profiles": profiles_summary,
            "total_profiles": len(self.device_profiles),
        }

    def reload_profiles(self):
        """Reload profiles from the config file and re-apply enforcement rules."""
        old_mode = self.enforcement_mode
        old_profiles = set(self.device_profiles.keys())

        self._load_profiles_from_file()

        new_profiles = set(self.device_profiles.keys())
        added = new_profiles - old_profiles
        removed = old_profiles - new_profiles

        if not self.datapath:
            return {
                "success": True,
                "profiles_loaded": len(self.device_profiles),
                "note": "Switch not connected; rules will be applied on next connection.",
            }

        # Remove intercept rules for devices that are no longer profiled.
        for mac in removed:
            self._remove_device_intercept_rules(mac)
            self._flush_device_allowlist_rules(mac)

        # Install intercept rules for newly added devices if in enforcing mode.
        if self.enforcement_mode == "enforcing":
            for mac in added:
                self._install_device_intercept_rules(mac)

        # If the mode changed, apply the new mode across all profiles.
        if old_mode != self.enforcement_mode:
            self.set_enforcement_mode(self.enforcement_mode)

        LOG.info(
            "Profiles reloaded. Total: %d. Added: %d. Removed: %d.",
            len(self.device_profiles), len(added), len(removed),
        )

        return {
            "success": True,
            "profiles_loaded": len(self.device_profiles),
            "added": len(added),
            "removed": len(removed),
        }

    def set_enforcement_mode(self, mode):
        """
        Switch the policy engine between learning and enforcing mode.

        In enforcing mode, per-device intercept rules are installed for
        all profiled devices. In learning mode, those rules are removed
        and all devices revert to general WAN access.
        """
        self.enforcement_mode = mode

        if not self.datapath:
            return {
                "success": True,
                "mode": mode,
                "note": "Switch not connected; mode will take effect on next connection.",
            }

        if mode == "enforcing":
            count = 0
            for mac in self.device_profiles:
                self._install_device_intercept_rules(mac)
                count += 1
            LOG.info(
                "Switched to ENFORCING mode. Installed intercept rules for %d devices.",
                count,
            )
            return {
                "success": True,
                "mode": mode,
                "message": f"Enforcing mode active. {count} devices have intercept rules.",
            }
        else:
            count = 0
            for mac in self.device_profiles:
                self._remove_device_intercept_rules(mac)
                count += 1
            self._flush_allowlist_rules()
            LOG.info(
                "Switched to LEARNING mode. Removed intercept rules for %d devices.",
                count,
            )
            return {
                "success": True,
                "mode": mode,
                "message": f"Learning mode active. {count} devices returned to general WAN access.",
            }

    def update_dns_cache(self, mappings):
        """
        Update the DNS cache with domain-to-IP mappings.

        Called by the dns_cache_updater service which monitors Zeek DNS
        logs and pushes resolved IPs here so domain-based allowlists
        can be evaluated against current IP addresses.
        """
        ts = datetime.now(timezone.utc).isoformat()
        updated = 0
        for domain, ips in mappings.items():
            domain = domain.lower()
            self.dns_cache[domain] = {
                "ips": list(ips),
                "updated": ts,
            }
            updated += 1
        LOG.debug("DNS cache updated: %d domains refreshed", updated)
        return {"success": True, "domains_updated": updated}

    def get_dns_cache(self):
        """Return the current DNS cache."""
        return {
            "cache": self.dns_cache,
            "total_domains": len(self.dns_cache),
        }

    def get_denied_log(self):
        """Return recent denied connection attempts."""
        return {
            "entries": self.denied_log[-100:],
            "total": len(self.denied_log),
        }

    # -- Phase 3: allowlist evaluation -------------------------------------

    def _is_destination_allowed(self, mac, dst_ip):
        """
        Check whether a profiled device is permitted to reach dst_ip.

        Returns a tuple of (allowed: bool, reason: str). Devices without
        a profile are always allowed (general WAN access).
        """
        profile = self.device_profiles.get(mac)
        if not profile:
            return True, "no profile (general WAN access)"

        for cidr in profile["allowed_cidrs"]:
            try:
                if cidr_contains(cidr, dst_ip):
                    return True, f"matched CIDR {cidr}"
            except (OSError, ValueError):
                LOG.warning("Invalid CIDR in profile for %s: %s", mac, cidr)
                continue

        for domain in profile["allowed_domains"]:
            cache_entry = self.dns_cache.get(domain)
            if cache_entry and dst_ip in cache_entry["ips"]:
                return True, f"matched domain {domain} (resolved to {dst_ip})"

        return False, f"not in allowlist for {profile['name']}"

    def _log_denied_attempt(self, mac, dst_ip, reason):
        """Append a denied connection attempt to the in-memory denied log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mac": mac,
            "dst_ip": dst_ip,
            "reason": reason,
        }
        profile = self.device_profiles.get(mac)
        if profile:
            entry["device_name"] = profile["name"]

        self.denied_log.append(entry)
        if len(self.denied_log) > self.denied_log_max:
            self.denied_log = self.denied_log[-self.denied_log_max:]

    # -- Phase 3: per-device intercept rules --------------------------------

    def _install_device_intercept_rules(self, mac):
        """
        Install rules that intercept WAN traffic from a profiled device
        and send it to the controller for allowlist evaluation.

        Two rules are installed per device:

        1. **Outbound intercept** (priority 100): IPv4 from this MAC on
           the WiFi port is sent to the controller. The controller
           evaluates it and either installs a priority-500 allow rule
           or drops the packet.
        2. **Inbound deny** (priority 100): IPv4 addressed to this MAC
           arriving from OFPP_LOCAL is dropped unless a priority-500
           allow rule exists for that source IP.
        """
        if not self.datapath or not self.wifi_port:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        match_out = parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac,
            eth_type=0x0800,
        )
        actions_out = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(
            dp, PRI_DEVICE_INTERCEPT, match_out, actions_out,
            tag=f"intercept-out-{mac[:8]}",
        )

        match_in = parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac,
            eth_type=0x0800,
        )
        self._add_flow(
            dp, PRI_DEVICE_INTERCEPT, match_in, actions=[],
            tag=f"intercept-in-{mac[:8]}",
        )

        LOG.info("Installed intercept rules for profiled device %s", mac)

    def _remove_device_intercept_rules(self, mac):
        """Remove the per-device intercept rules for a device."""
        if not self.datapath or not self.wifi_port:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        match_out = parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac,
            eth_type=0x0800,
        )
        self._delete_flow(dp, PRI_DEVICE_INTERCEPT, match_out)

        match_in = parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac,
            eth_type=0x0800,
        )
        self._delete_flow(dp, PRI_DEVICE_INTERCEPT, match_in)

        LOG.info("Removed intercept rules for device %s", mac)

    def _flush_device_allowlist_rules(self, mac):
        """Remove all reactive allowlist rules for a specific device."""
        if not self.datapath:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        active_ips = self.active_allowlist_rules.pop(mac, set())
        for dst_ip in active_ips:
            match_out = parser.OFPMatch(
                in_port=self.wifi_port,
                eth_src=mac,
                eth_type=0x0800,
                ipv4_dst=dst_ip,
            )
            self._delete_flow(dp, PRI_DEVICE_ALLOW, match_out)

            match_in = parser.OFPMatch(
                in_port=ofproto.OFPP_LOCAL,
                eth_dst=mac,
                eth_type=0x0800,
                ipv4_src=dst_ip,
            )
            self._delete_flow(dp, PRI_DEVICE_ALLOW, match_in)

    def _flush_allowlist_rules(self):
        """Remove all reactive allowlist rules for all devices."""
        for mac in list(self.active_allowlist_rules.keys()):
            self._flush_device_allowlist_rules(mac)

    # -- Phase 5: lateral movement permits ---------------------------------

    def get_lateral_permits(self):
        """
        Return all active lateral movement permits.

        Each entry in the response includes both device MACs, their
        last-known IPs, the creation timestamp, and whether the
        corresponding OpenFlow rules are currently installed in OVS.
        """
        result = []
        for key, permit in self.lateral_permits.items():
            result.append({
                "mac_a": permit["mac_a"],
                "mac_b": permit["mac_b"],
                "ip_a": permit["ip_a"],
                "ip_b": permit["ip_b"],
                "created_at": permit["created_at"],
                "rules_installed": permit["rules_installed"],
            })
        return {
            "permits": result,
            "total": len(result),
        }

    def add_lateral_permit(self, mac_a, mac_b):
        """
        Grant bidirectional unicast communication between two IoT devices.

        Installs four OpenFlow rules at priority PRI_LATERAL_PERMIT (160),
        which is above the anti-lateral-movement drop rule at 150:

        - mac_a → ip_b  (outbound from A)
        - mac_b → ip_a  (outbound from B)
        - ip_b  → mac_a (return traffic to A)
        - ip_a  → mac_b (return traffic to B)

        Both devices must be known to the policy engine and must have a
        recorded IP address. If either IP is not yet known, the permit is
        recorded but rules are not installed until both IPs are seen.

        Returns a dict with ``success`` (bool) and either an ``error``
        string or a ``permit`` summary.
        """
        key = frozenset({mac_a, mac_b})

        if key in self.lateral_permits:
            return {
                "success": False,
                "error": f"A permit between {mac_a} and {mac_b} already exists.",
            }

        if mac_a not in self.known_devices:
            return {
                "success": False,
                "error": (
                    f"{mac_a} is not a known device. "
                    "It must connect and generate traffic before a permit can be created."
                ),
            }

        if mac_b not in self.known_devices:
            return {
                "success": False,
                "error": (
                    f"{mac_b} is not a known device. "
                    "It must connect and generate traffic before a permit can be created."
                ),
            }

        ip_a = self.known_devices[mac_a].get("ip")
        ip_b = self.known_devices[mac_b].get("ip")

        ts = datetime.now(timezone.utc).isoformat()
        permit = {
            "mac_a": mac_a,
            "mac_b": mac_b,
            "ip_a": ip_a,
            "ip_b": ip_b,
            "created_at": ts,
            "rules_installed": False,
        }
        self.lateral_permits[key] = permit

        rules_installed = False
        if ip_a and ip_b:
            self._install_lateral_permit_rules(mac_a, mac_b, ip_a, ip_b)
            self.lateral_permits[key]["rules_installed"] = True
            rules_installed = True
            LOG.info(
                "Lateral permit ADDED: %s (%s) <-> %s (%s)",
                mac_a, ip_a, mac_b, ip_b,
            )
        else:
            # Permit is stored but rules cannot be installed yet because one
            # or both IPs are unknown. Rules will be installed automatically
            # once both IPs are observed in packet_in_handler.
            missing = []
            if not ip_a:
                missing.append(mac_a)
            if not ip_b:
                missing.append(mac_b)
            LOG.warning(
                "Lateral permit recorded for %s <-> %s but rules NOT installed: "
                "IP address unknown for %s. Rules will be installed automatically "
                "once traffic is observed from the missing device(s).",
                mac_a, mac_b, ", ".join(missing),
            )

        # Warn if proxy ARP has not been enabled. Without it devices will
        # not be able to resolve each other's IP via ARP and no communication
        # will occur even with the permit rules in place.
        try:
            with open("/proc/sys/net/ipv4/conf/br0/proxy_arp") as f:
                proxy_arp_enabled = f.read().strip() == "1"
        except IOError:
            proxy_arp_enabled = False

        if not proxy_arp_enabled:
            LOG.warning(
                "Lateral permit created but proxy ARP is NOT enabled on br0. "
                "Devices will not be able to resolve each other's IP address. "
                "Enable it with: sudo sysctl -w net.ipv4.conf.br0.proxy_arp=1"
            )

        return {
            "success": True,
            "permit": {
                "mac_a": mac_a,
                "mac_b": mac_b,
                "ip_a": ip_a,
                "ip_b": ip_b,
                "created_at": ts,
                "rules_installed": rules_installed,
            },
            "proxy_arp_enabled": proxy_arp_enabled,
        }

    def remove_lateral_permit(self, mac_a, mac_b):
        """
        Revoke a lateral movement permit between two devices.

        Removes the OpenFlow exception rules immediately. Subsequent
        traffic between the pair is dropped by the anti-lateral-movement
        rule at priority 150. The order of mac_a and mac_b does not matter.
        """
        key = frozenset({mac_a, mac_b})

        if key not in self.lateral_permits:
            return {
                "success": False,
                "error": f"No permit exists between {mac_a} and {mac_b}.",
            }

        permit = self.lateral_permits[key]
        ip_a = permit["ip_a"]
        ip_b = permit["ip_b"]

        if permit["rules_installed"] and ip_a and ip_b:
            self._remove_lateral_permit_rules(
                permit["mac_a"], permit["mac_b"], ip_a, ip_b
            )
            LOG.info(
                "Lateral permit REMOVED: %s (%s) <-> %s (%s)",
                permit["mac_a"], ip_a, permit["mac_b"], ip_b,
            )

        del self.lateral_permits[key]

        return {
            "success": True,
            "mac_a": mac_a,
            "mac_b": mac_b,
        }

    def _install_lateral_permit_rules(self, mac_a, mac_b, ip_a, ip_b):
        """
        Install four OpenFlow rules at PRI_LATERAL_PERMIT (160) that
        allow bidirectional unicast traffic between mac_a/ip_a and
        mac_b/ip_b, overriding the anti-lateral-movement rule at 150.

        Rules installed:

        1. Outbound A→B: ``in_port=wifi, eth_src=mac_a, ipv4_dst=ip_b``
           → ``OFPP_LOCAL``
        2. Outbound B→A: ``in_port=wifi, eth_src=mac_b, ipv4_dst=ip_a``
           → ``OFPP_LOCAL``
        3. Return  B→A: ``in_port=LOCAL, eth_dst=mac_a, ipv4_src=ip_b``
           → ``wifi``
        4. Return  A→B: ``in_port=LOCAL, eth_dst=mac_b, ipv4_src=ip_a``
           → ``wifi``

        Return rules (3 and 4) override the per-device inbound deny rule
        at priority 100 that is installed for profiled devices in enforcing
        mode.
        """
        if not self.datapath or not self.wifi_port:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        # Outbound A -> B
        match = parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac_a,
            eth_type=0x0800,
            ipv4_dst=ip_b,
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        self._add_flow(
            dp, PRI_LATERAL_PERMIT, match, actions,
            tag=f"lateral-out-{mac_a[:8]}->{ip_b}",
        )

        # Outbound B -> A
        match = parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac_b,
            eth_type=0x0800,
            ipv4_dst=ip_a,
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        self._add_flow(
            dp, PRI_LATERAL_PERMIT, match, actions,
            tag=f"lateral-out-{mac_b[:8]}->{ip_a}",
        )

        # Return traffic to A (response from B's IP)
        match = parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac_a,
            eth_type=0x0800,
            ipv4_src=ip_b,
        )
        actions = [parser.OFPActionOutput(self.wifi_port)]
        self._add_flow(
            dp, PRI_LATERAL_PERMIT, match, actions,
            tag=f"lateral-ret-{mac_a[:8]}<-{ip_b}",
        )

        # Return traffic to B (response from A's IP)
        match = parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac_b,
            eth_type=0x0800,
            ipv4_src=ip_a,
        )
        actions = [parser.OFPActionOutput(self.wifi_port)]
        self._add_flow(
            dp, PRI_LATERAL_PERMIT, match, actions,
            tag=f"lateral-ret-{mac_b[:8]}<-{ip_a}",
        )

    def _remove_lateral_permit_rules(self, mac_a, mac_b, ip_a, ip_b):
        """
        Remove the four OpenFlow rules for a lateral permit pair.

        Uses the same match criteria as ``_install_lateral_permit_rules``
        to ensure the correct rules are deleted from OVS.
        """
        if not self.datapath or not self.wifi_port:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        # Outbound A -> B
        self._delete_flow(dp, PRI_LATERAL_PERMIT, parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac_a,
            eth_type=0x0800,
            ipv4_dst=ip_b,
        ))

        # Outbound B -> A
        self._delete_flow(dp, PRI_LATERAL_PERMIT, parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac_b,
            eth_type=0x0800,
            ipv4_dst=ip_a,
        ))

        # Return to A
        self._delete_flow(dp, PRI_LATERAL_PERMIT, parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac_a,
            eth_type=0x0800,
            ipv4_src=ip_b,
        ))

        # Return to B
        self._delete_flow(dp, PRI_LATERAL_PERMIT, parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac_b,
            eth_type=0x0800,
            ipv4_src=ip_a,
        ))

    def _refresh_lateral_permits_for_mac(self, mac, new_ip):
        """
        Called when a device's IP address changes (e.g. after a new DHCP
        lease). Finds all permits involving the given MAC, removes the
        stale rules that were keyed to the old IP, updates the stored IP,
        and reinstalls the rules with the new IP if the peer IP is also
        known.

        This ensures lateral permit rules remain correct across DHCP
        renewals without requiring administrator intervention.
        """
        for key, permit in list(self.lateral_permits.items()):
            if mac not in key:
                continue

            # Determine which side of the pair this MAC is, and which is
            # the peer.
            if permit["mac_a"] == mac:
                old_ip = permit["ip_a"]
                peer_ip = permit["ip_b"]
                peer_mac = permit["mac_b"]
                side = "a"
            else:
                old_ip = permit["ip_b"]
                peer_ip = permit["ip_a"]
                peer_mac = permit["mac_a"]
                side = "b"

            if old_ip == new_ip:
                # IP has not actually changed; nothing to do.
                continue

            LOG.info(
                "Device %s IP changed from %s to %s. "
                "Refreshing lateral permit rules for pair %s <-> %s.",
                mac, old_ip, new_ip, permit["mac_a"], permit["mac_b"],
            )

            # Remove old rules if they were installed.
            if permit["rules_installed"] and old_ip and peer_ip:
                self._remove_lateral_permit_rules(
                    permit["mac_a"], permit["mac_b"],
                    permit["ip_a"], permit["ip_b"],
                )
                self.lateral_permits[key]["rules_installed"] = False

            # Update the stored IP.
            if side == "a":
                self.lateral_permits[key]["ip_a"] = new_ip
            else:
                self.lateral_permits[key]["ip_b"] = new_ip

            # Reinstall with the updated IPs if both sides are now known.
            updated_ip_a = self.lateral_permits[key]["ip_a"]
            updated_ip_b = self.lateral_permits[key]["ip_b"]
            if updated_ip_a and updated_ip_b:
                self._install_lateral_permit_rules(
                    permit["mac_a"], permit["mac_b"],
                    updated_ip_a, updated_ip_b,
                )
                self.lateral_permits[key]["rules_installed"] = True
                LOG.info(
                    "Lateral permit rules reinstalled after IP change: "
                    "%s (%s) <-> %s (%s)",
                    permit["mac_a"], updated_ip_a,
                    permit["mac_b"], updated_ip_b,
                )

    # -- Rule installation --------------------------------------------------

    def _install_all_rules(self, datapath):
        """
        Install the complete set of proactive flow rules.

        Called once when the switch connects and port discovery is
        complete. Establishes the full security policy baseline.
        """
        self.rule_count = 0
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        wifi = self.wifi_port
        local = ofproto.OFPP_LOCAL

        LOG.info("Installing security policy rules...")

        # 1. Table-miss: send unmatched packets to the controller (priority 0).
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, PRI_TABLE_MISS, match, actions, tag="table-miss")

        # 2. Default deny: drop everything not explicitly permitted (priority 1).
        match = parser.OFPMatch()
        self._add_flow(datapath, PRI_DEFAULT_DENY, match, actions=[], tag="default-deny")

        # 3. ARP: permit in both directions between devices and the gateway (priority 200).
        match = parser.OFPMatch(in_port=wifi, eth_type=0x0806)
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="arp-to-gw")

        match = parser.OFPMatch(in_port=local, eth_type=0x0806)
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="arp-from-gw")

        # 4. DHCP: permit requests and responses (priority 200).
        # Both rules also send a copy to the controller so packet_in_handler
        # can snoop the exchange and populate known_devices with MAC-to-IP
        # mappings without interfering with normal DHCP forwarding.
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800, ip_proto=17, udp_dst=67,
        )
        actions = [
            parser.OFPActionOutput(local),
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
            ),
        ]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dhcp-request")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800, ip_proto=17, udp_dst=68,
        )
        actions = [
            parser.OFPActionOutput(wifi),
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
            ),
        ]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dhcp-response")

        # 5. DNS: permit queries to the gateway IP (priority 200).
        # nftables DNAT intercepts these and redirects to AdGuard.
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800, ip_proto=17, udp_dst=53,
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-query-udp")

        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800, ip_proto=6, tcp_dst=53,
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-query-tcp")

        # DNS responses from AdGuard back to devices.
        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800, ip_proto=17, udp_src=53,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-response-udp")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800, ip_proto=6, tcp_src=53,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-response-tcp")

        # 6. NTP: permit queries and responses (priority 200).
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800, ip_proto=17, udp_dst=123,
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="ntp-query")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800, ip_proto=17, udp_src=123,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="ntp-response")

        # 7. Anti-lateral-movement: drop IoT-to-IoT routed traffic (priority 150).
        # Per-pair lateral permits at priority 160 override this for permitted pairs.
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ipv4_dst=(IOT_SUBNET, IOT_SUBNET_MASK),
        )
        self._add_flow(
            datapath, PRI_ANTI_LATERAL, match, actions=[], tag="anti-lateral"
        )

        # 8. General WAN access: allow all other IPv4 in/out (priority 50).
        # Profiled devices in enforcing mode are intercepted at priority 100
        # before these rules are reached.
        match = parser.OFPMatch(in_port=wifi, eth_type=0x0800)
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_WAN_ACCESS, match, actions, tag="wan-outbound")

        match = parser.OFPMatch(in_port=local, eth_type=0x0800)
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_WAN_ACCESS, match, actions, tag="wan-inbound")

        # 9. Per-device intercept rules (enforcing mode only).
        enforced_count = 0
        if self.enforcement_mode == "enforcing":
            for mac in self.device_profiles:
                self._install_device_intercept_rules(mac)
                enforced_count += 1

        # 10. Reinstall any lateral permits that survived a controller restart.
        # On reconnect the OVS flow table is reset, so all dynamic rules must
        # be reinstalled. The permit metadata is preserved in self.lateral_permits.
        for key, permit in self.lateral_permits.items():
            ip_a = permit["ip_a"]
            ip_b = permit["ip_b"]
            if ip_a and ip_b:
                self._install_lateral_permit_rules(
                    permit["mac_a"], permit["mac_b"], ip_a, ip_b
                )
                self.lateral_permits[key]["rules_installed"] = True
                LOG.info(
                    "Reinstalled lateral permit on reconnect: %s <-> %s",
                    permit["mac_a"], permit["mac_b"],
                )
            else:
                self.lateral_permits[key]["rules_installed"] = False

        self.rules_installed = True
        LOG.info(
            "Policy rules installed: %d rules. "
            "Micro-segmentation ACTIVE. Essential services PERMITTED. "
            "Mode: %s. Profiled devices: %d. Enforced: %d. "
            "Lateral permits: %d.",
            self.rule_count,
            self.enforcement_mode,
            len(self.device_profiles),
            enforced_count,
            len(self.lateral_permits),
        )

    # -- OpenFlow event handlers --------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called when a switch connects. Requests port descriptions so the
        WiFi port number can be discovered before rules are installed.
        """
        datapath = ev.msg.datapath
        self.datapath = datapath
        self.connect_time = datetime.now(timezone.utc).isoformat()
        LOG.info(
            "Switch %s connected. Requesting port descriptions...",
            datapath.id,
        )
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):
        """
        Called when OVS responds with port descriptions. Resolves the
        WiFi port number from the interface name, then installs all
        proactive rules.
        """
        ports = {}
        for port in ev.msg.body:
            name = port.name
            if isinstance(name, bytes):
                name = name.decode("utf-8").rstrip("\x00")
            ports[name] = port.port_no
            LOG.info("  Port discovered: %s = %d", name, port.port_no)

        if WIFI_INTERFACE not in ports:
            LOG.error(
                "WiFi interface '%s' not found on OVS bridge. "
                "Available ports: %s. Check WIFI_INTERFACE in the config.",
                WIFI_INTERFACE,
                list(ports.keys()),
            )
            return

        self.wifi_port = ports[WIFI_INTERFACE]
        LOG.info(
            "WiFi port resolved: %s = port %d", WIFI_INTERFACE, self.wifi_port
        )

        # Reset reactive rule tracking on reconnect; the flow table has
        # been cleared and all rules must be reinstalled from scratch.
        self.active_allowlist_rules = {}
        self._install_all_rules(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle packets forwarded to the controller by OVS.

        Serves two purposes:

        1. **Device tracking** (all phases): records each new MAC seen on
           the WiFi port in ``known_devices``. Also extracts the source IP
           from IPv4 packets to keep ``known_devices["ip"]`` current. When
           an IP change is detected for a MAC that participates in a lateral
           permit, ``_refresh_lateral_permits_for_mac`` is called to
           reinstall the permit rules with the new IP.

        2. **Allowlist evaluation** (Phase 3, enforcing mode): PacketIn
           events from the per-device intercept rules (priority 100) carry
           WAN-bound traffic from profiled devices. The handler checks the
           destination against the device's allowlist and either installs a
           reactive priority-500 forwarding rule (and forwards the buffered
           packet) or drops it and logs the attempt.
        """
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        src_mac = eth.src.lower()
        in_port = msg.match["in_port"]

        # -- DHCP snooping --------------------------------------------------
        # Handle DHCP packets first (they may arrive from either the WiFi
        # port or LOCAL) to populate known_devices for all devices regardless
        # of profile or enforcement mode.
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt and udp_pkt.dst_port in (67, 68):
            self._handle_dhcp_packet(pkt, in_port)
            if in_port != self.wifi_port:
                # DHCP ACKs arrive from LOCAL - no further processing needed.
                return

        # -- Device tracking ------------------------------------------------
        if in_port == self.wifi_port and src_mac != "ff:ff:ff:ff:ff:ff":
            now = datetime.now(timezone.utc).isoformat()
            if src_mac not in self.known_devices:
                self.known_devices[src_mac] = {
                    "first_seen": now,
                    "last_seen": now,
                    "ip": None,
                }
                LOG.info("New device detected: %s on port %d", src_mac, in_port)
            else:
                self.known_devices[src_mac]["last_seen"] = now

            # Extract and track the source IP from IPv4 packets.
            # This is used by the lateral permit feature and is also a
            # more reliable source than DHCP log parsing for the live IP.
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                observed_ip = ip_pkt.src
                current_ip = self.known_devices[src_mac].get("ip")
                if observed_ip != current_ip:
                    self.known_devices[src_mac]["ip"] = observed_ip
                    if current_ip is not None:
                        # IP has changed - refresh any active lateral permits
                        # that reference this MAC so their rules stay accurate.
                        self._refresh_lateral_permits_for_mac(src_mac, observed_ip)
                    else:
                        # First time seeing an IP for this device - check whether
                        # any pending lateral permits (recorded without IPs) can
                        # now have their rules installed.
                        self._try_install_pending_permits_for_mac(src_mac, observed_ip)

        # -- Phase 3: allowlist evaluation for profiled devices --------------
        if in_port == self.wifi_port and src_mac in self.device_profiles:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt is None:
                return

            dst_ip = ip_pkt.dst
            allowed, reason = self._is_destination_allowed(src_mac, dst_ip)

            if allowed:
                # Install reactive forwarding rules so subsequent packets on
                # this flow are handled directly by OVS without a PacketIn.
                match_out = parser.OFPMatch(
                    in_port=self.wifi_port,
                    eth_src=src_mac,
                    eth_type=0x0800,
                    ipv4_dst=dst_ip,
                )
                actions_out = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
                self._add_flow(
                    dp, PRI_DEVICE_ALLOW, match_out, actions_out,
                    idle_timeout=self.idle_timeout,
                    tag=f"allow-{src_mac[:8]}->{dst_ip}",
                )

                match_ret = parser.OFPMatch(
                    in_port=ofproto.OFPP_LOCAL,
                    eth_dst=src_mac,
                    eth_type=0x0800,
                    ipv4_src=dst_ip,
                )
                actions_ret = [parser.OFPActionOutput(self.wifi_port)]
                self._add_flow(
                    dp, PRI_DEVICE_ALLOW, match_ret, actions_ret,
                    idle_timeout=self.idle_timeout,
                    tag=f"allow-ret-{src_mac[:8]}<-{dst_ip}",
                )

                if src_mac not in self.active_allowlist_rules:
                    self.active_allowlist_rules[src_mac] = set()
                self.active_allowlist_rules[src_mac].add(dst_ip)

                LOG.info("ALLOW %s -> %s (%s)", src_mac, dst_ip, reason)

                # Forward the original packet so it is not lost while the
                # flow rule was being installed.
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions_out,
                    data=data,
                )
                dp.send_msg(out)

            else:
                LOG.info("DENY %s -> %s (%s)", src_mac, dst_ip, reason)
                self._log_denied_attempt(src_mac, dst_ip, reason)

    # -- Phase 5: pending permit helper -------------------------------------

    def _try_install_pending_permits_for_mac(self, mac, ip):
        """
        Check whether any recorded lateral permit is waiting on an IP for
        the given MAC and install its rules if the peer IP is also now known.

        Called from ``packet_in_handler`` the first time an IP is observed
        for a device. Handles the case where ``add_lateral_permit`` was
        called before one or both devices had sent any traffic.
        """
        for key, permit in list(self.lateral_permits.items()):
            if mac not in key or permit["rules_installed"]:
                continue

            if permit["mac_a"] == mac:
                self.lateral_permits[key]["ip_a"] = ip
                peer_ip = permit["ip_b"]
            else:
                self.lateral_permits[key]["ip_b"] = ip
                peer_ip = permit["ip_a"]

            updated_ip_a = self.lateral_permits[key]["ip_a"]
            updated_ip_b = self.lateral_permits[key]["ip_b"]

            if updated_ip_a and updated_ip_b:
                self._install_lateral_permit_rules(
                    permit["mac_a"], permit["mac_b"],
                    updated_ip_a, updated_ip_b,
                )
                self.lateral_permits[key]["rules_installed"] = True
                LOG.info(
                    "Pending lateral permit rules installed after IP discovery: "
                    "%s (%s) <-> %s (%s)",
                    permit["mac_a"], updated_ip_a,
                    permit["mac_b"], updated_ip_b,
                )

    # -- DHCP snooping ------------------------------------------------------

    def _handle_dhcp_packet(self, pkt, in_port):
        """
        Snoop DHCP packets to populate ``known_devices`` with MAC-to-IP
        mappings for all connected devices, regardless of whether they are
        profiled or in enforcing mode.

        Two packet types are handled:

        - **DHCP REQUEST / DISCOVER** (from device, in_port=wifi_port):
          Records the client MAC in ``known_devices`` with the timestamp.
          The IP is not yet known at this stage but the device becomes
          visible in ``/policy/devices`` immediately.

        - **DHCP ACK** (from dnsmasq, in_port=LOCAL):
          Reads the ``yiaddr`` field (the IP being assigned) and the
          ``chaddr`` field (the client MAC). Updates ``known_devices``
          with the confirmed IP assignment and triggers lateral permit
          rule installation for any permits that were waiting on this IP.

        This method is called from ``packet_in_handler`` for all DHCP
        PacketIn events. It does not affect packet forwarding, which is
        handled by the proactive OVS rules.
        """
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        if dhcp_pkt is None:
            return

        # Parse the DHCP message type from option 53.
        msg_type = None
        if dhcp_pkt.options and dhcp_pkt.options.option_list:
            for opt in dhcp_pkt.options.option_list:
                if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                    msg_type = opt.value[0]
                    break

        if msg_type is None:
            return

        # DHCP message type constants:
        #   1 = DISCOVER, 2 = OFFER, 3 = REQUEST, 5 = ACK
        DHCP_DISCOVER = 1
        DHCP_REQUEST  = 3
        DHCP_ACK      = 5

        now = datetime.now(timezone.utc).isoformat()

        if msg_type in (DHCP_DISCOVER, DHCP_REQUEST):
            # Extract the client MAC from chaddr.
            # Ryu returns chaddr as a colon-separated MAC string.
            client_mac = dhcp_pkt.chaddr
            if not client_mac or client_mac == "ff:ff:ff:ff:ff:ff":
                return

            client_mac = client_mac.lower()
            if client_mac not in self.known_devices:
                self.known_devices[client_mac] = {
                    "first_seen": now,
                    "last_seen": now,
                    "ip": None,
                }
                LOG.info(
                    "New device registered via DHCP %s: %s",
                    "DISCOVER" if msg_type == DHCP_DISCOVER else "REQUEST",
                    client_mac,
                )
            else:
                self.known_devices[client_mac]["last_seen"] = now

        elif msg_type == DHCP_ACK:
            # yiaddr is the IP address being assigned to the client.
            assigned_ip = dhcp_pkt.yiaddr
            client_mac = dhcp_pkt.chaddr

            if (not assigned_ip or assigned_ip == "0.0.0.0"
                    or not client_mac):
                return

            client_mac = client_mac.lower()
            current_ip = None

            if client_mac not in self.known_devices:
                # ACK arrived before a DISCOVER/REQUEST was seen (e.g. on
                # Ryu restart with devices already connected). Create the
                # device entry now.
                self.known_devices[client_mac] = {
                    "first_seen": now,
                    "last_seen": now,
                    "ip": None,
                }
                LOG.info(
                    "New device registered via DHCP ACK: %s -> %s",
                    client_mac, assigned_ip,
                )
            else:
                current_ip = self.known_devices[client_mac].get("ip")
                self.known_devices[client_mac]["last_seen"] = now

            # Update the stored IP and handle lateral permit side-effects.
            if assigned_ip != current_ip:
                self.known_devices[client_mac]["ip"] = assigned_ip
                LOG.info(
                    "DHCP ACK: %s assigned IP %s", client_mac, assigned_ip,
                )
                if current_ip is not None:
                    # IP changed - refresh permits that reference this MAC.
                    self._refresh_lateral_permits_for_mac(
                        client_mac, assigned_ip
                    )
                else:
                    # First IP seen - install any pending permits.
                    self._try_install_pending_permits_for_mac(
                        client_mac, assigned_ip
                    )

    # -- Flow rule helpers --------------------------------------------------

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, tag=""):
        """
        Install a flow rule in OVS.

        Args:
            datapath: The OVS datapath object.
            priority: OpenFlow priority. Higher values take precedence.
            match: OFPMatch object specifying the packet match criteria.
            actions: List of OFPAction objects. An empty list drops the packet.
            idle_timeout: Seconds of inactivity before OVS removes the rule.
                          Zero means the rule persists indefinitely.
            hard_timeout: Absolute lifetime in seconds. Zero means no limit.
            tag: Short label used in log output for debugging.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)
        self.rule_count += 1
        if tag:
            LOG.debug("  Rule [%s] installed at priority %d", tag, priority)

    def _delete_flow(self, datapath, priority, match):
        """
        Delete a specific flow rule from OVS.

        Args:
            datapath: The OVS datapath object.
            priority: Priority of the rule to delete.
            match: OFPMatch identifying the rule to remove. Must exactly
                   match the criteria used when the rule was installed.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=priority,
            match=match,
        )
        datapath.send_msg(mod)