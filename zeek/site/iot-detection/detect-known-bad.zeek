@load ./alert-framework
@load base/frameworks/input

module IoT;

export {
    # Path to the file containing known-bad IP addresses (one per line).
    # Each line should be an IP address optionally followed by a tab
    # and a description. Lines starting with # are comments.
    option known_bad_ips_file = "/usr/local/zeek/share/zeek/site/iot-iocs/known-bad-ips.dat";

    # Path to the file containing known-bad domain names (one per line).
    option known_bad_domains_file = "/usr/local/zeek/share/zeek/site/iot-iocs/known-bad-domains.dat";

    # Schema for reading the IOC IP file.
    type IdxIP: record { ip: addr; };
    type ValIP: record { description: string &default="No description"; };

    # Schema for reading the IOC domain file.
    type IdxDomain: record { domain: string; };
    type ValDomain: record { description: string &default="No description"; };

    # Table of known-bad IP addresses. Populated from the input file.
    global bad_ip_table: table[addr] of ValIP = {};

    # Table of known-bad domain names. Populated from the input file.
    global bad_domain_table: table[string] of ValDomain = {};
}

event zeek_init()
    {
    if ( file_size(known_bad_ips_file) >= 0 )
        {
        Input::add_table([
            $source = known_bad_ips_file,
            $name = "bad_ips_feed",
            $idx = IdxIP,
            $val = ValIP,
            $destination = bad_ip_table,
            $mode = Input::REREAD
        ]);
        }

    if ( file_size(known_bad_domains_file) >= 0 )
        {
        Input::add_table([
            $source = known_bad_domains_file,
            $name = "bad_domains_feed",
            $idx = IdxDomain,
            $val = ValDomain,
            $destination = bad_domain_table,
            $mode = Input::REREAD
        ]);
        }
    }

# Check every new connection against the known-bad IP list.
event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! is_iot_device(src) )
        return;

    if ( dst in bad_ip_table )
        {
        local ip_desc = bad_ip_table[dst]$description;
        local ip_details = fmt(
            "{\"bad_ip\": \"%s\", \"dst_port\": \"%s\", \"ioc_description\": \"%s\"}",
            dst, c$id$resp_p, ip_desc);

        emit_alert(CRITICAL, "known-bad-ip", src,
            fmt("Connection to known-bad IP: %s:%s (%s)",
                dst, c$id$resp_p, ip_desc),
            ip_details,
            dst, c$id$resp_p);
        }
    }

# Check DNS queries against the known-bad domain list.
event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
    {
    local src = c$id$orig_h;

    if ( ! is_iot_device(src) )
        return;

    local q = to_lower(query);
    if ( q in bad_domain_table )
        {
        local dom_desc = bad_domain_table[q]$description;
        local dom_details = fmt(
            "{\"bad_domain\": \"%s\", \"ioc_description\": \"%s\"}",
            q, dom_desc);

        emit_alert(CRITICAL, "known-bad-domain", src,
            fmt("DNS query for known-bad domain: %s (%s)", q, dom_desc),
            dom_details);
        }
    }