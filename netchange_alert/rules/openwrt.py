import re
from core import (
    max_sev, ports_from_text, extract_ips,
    MGMT_PORTS, APPROVED_DNS, APPROVED_NTP, APPROVED_DEFAULT_GW,
    SENSITIVE_HOSTS, SENSITIVE_SUBNET_RE, split_diff
)

def match(model: str, node_name: str = "") -> bool:
    m = (model or "").lower()
    return "openwrt" in m or "lede" in m

def analyze(added: str, removed: str, before_cfg: str, after_cfg: str):
    severity = "LOW"
    reasons = []
    tags = []
    added_lower = added.lower()

    # OpenWrt UCI patterns
    openwrt_rule_from_wan = re.search(r"option\s+src\s+'wan'", added_lower) is not None
    openwrt_rule_accept = re.search(r"option\s+target\s+'accept'", added_lower) is not None

    # (1) CRITICAL: ACCEPT from WAN + mgmt ports
    if openwrt_rule_from_wan and openwrt_rule_accept:
        pset = ports_from_text(added)
        if pset & MGMT_PORTS:
            severity = max_sev(severity, "CRITICAL")
            reasons.append(f"OpenWrt(UCI): ACCEPT from WAN on management port(s): {sorted(list(pset & MGMT_PORTS))}.")
            tags.append("openwrt-uci-wan-mgmt")
        else:
            severity = max_sev(severity, "HIGH")
            reasons.append("OpenWrt(UCI): ACCEPT from WAN detected (internet-facing).")
            tags.append("openwrt-uci-wan-accept")

    # (2) any/0.0.0.0/0 + mgmt ports (genérico)
    if re.search(r"\b0\.0\.0\.0/0\b|\bany\b", added_lower):
        pset = ports_from_text(added)
        if pset & MGMT_PORTS:
            severity = max_sev(severity, "HIGH")
            reasons.append(f"Broad source/dest (any/0.0.0.0/0) + management ports: {sorted(list(pset & MGMT_PORTS))}.")
            tags.append("broad-mgmt")

    # (3) HIGH: WAN zone input/forward ACCEPT
    if ("config zone" in added_lower) or ("firewall.@zone" in added_lower):
        if re.search(r"option\s+name\s+'wan'", added_lower) and re.search(r"option\s+input\s+'accept'", added_lower):
            severity = max_sev(severity, "HIGH")
            reasons.append("OpenWrt(UCI): WAN zone input set to ACCEPT - risky.")
            tags.append("openwrt-uci-wan-zone-input-accept")
        if re.search(r"option\s+name\s+'wan'", added_lower) and re.search(r"option\s+forward\s+'accept'", added_lower):
            severity = max_sev(severity, "HIGH")
            reasons.append("OpenWrt(UCI): WAN zone forward set to ACCEPT - risky.")
            tags.append("openwrt-uci-wan-zone-forward-accept")

    # (4) NAT / Port-forward inbound
    if ("config redirect" in added_lower) or ("option target 'dnat'" in added_lower):
        if re.search(r"option\s+src\s+'wan'", added_lower):
            ips = extract_ips(added)
            hit_sensitive = [ip for ip in ips if ip in SENSITIVE_HOSTS]
            hit_subnet = [ip for ip in ips if SENSITIVE_SUBNET_RE.match(ip)]
            if hit_sensitive:
                severity = max_sev(severity, "CRITICAL")
                reasons.append(f"OpenWrt(UCI): Port-forward/DNAT from WAN to sensitive host(s): {hit_sensitive}.")
                tags.append("openwrt-nat-sensitive")
            elif hit_subnet:
                severity = max_sev(severity, "HIGH")
                reasons.append(f"OpenWrt(UCI): Port-forward/DNAT from WAN into lab subnet: {hit_subnet}.")
                tags.append("openwrt-nat-subnet")
            else:
                severity = max_sev(severity, "MEDIUM")
                reasons.append("OpenWrt(UCI): Port-forward/DNAT from WAN changed (review).")
                tags.append("openwrt-nat-change")

    # (5) DNS no aprobado (heurístico por IPs nuevas)
    if ("option dns" in added_lower) or ("list dns" in added_lower) or ("dns" in added_lower):
        ips = extract_ips(added)
        bad = sorted([ip for ip in ips if ip not in APPROVED_DNS])
        if bad:
            severity = max_sev(severity, "HIGH")
            reasons.append(f"DNS server(s) not approved detected: {bad}.")
            tags.append("dns-unapproved")

    # (6) NTP no aprobado
    if ("config timeserver" in added_lower) or ("timeserver" in added_lower) or ("list server" in added_lower and "ntp" in added_lower):
        ips = extract_ips(added)
        bad = sorted([ip for ip in ips if ip not in APPROVED_NTP])
        if bad:
            severity = max_sev(severity, "HIGH")
            reasons.append(f"NTP server(s) not approved detected: {bad}.")
            tags.append("ntp-unapproved")

    # (7) Default route/gateway inesperado
    if ("config route" in added_lower) or ("option target" in added_lower and "0.0.0.0" in added_lower) or ("0.0.0.0/0" in added_lower):
        ips = extract_ips(added)
        bad_gw = sorted([ip for ip in ips if ip not in APPROVED_DEFAULT_GW])
        if bad_gw:
            severity = max_sev(severity, "HIGH")
            reasons.append(f"Default route/gateway changed to unexpected IP(s): {bad_gw}.")
            tags.append("route-default-unexpected")
        else:
            if "0.0.0.0" in added_lower:
                severity = max_sev(severity, "MEDIUM")
                reasons.append("Default route change detected (review).")
                tags.append("route-default-change")

    if "blackhole" in added_lower:
        severity = max_sev(severity, "HIGH")
        reasons.append("Blackhole route added.")
        tags.append("route-blackhole")

    # (8) Logging reducido
    if ("option log_size" in added_lower and re.search(r"option\s+log_size\s+'?0'?", added_lower)) or \
       ("syslog" in added_lower and ("none" in added_lower or "off" in added_lower or "disable" in added_lower)):
        severity = max_sev(severity, "HIGH")
        reasons.append("Logging/syslog appears disabled or reduced (log_size=0/none/off).")
        tags.append("logging-reduced")

    return severity, reasons, tags
