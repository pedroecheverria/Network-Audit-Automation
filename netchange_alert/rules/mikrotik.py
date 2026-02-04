import re
from core import (
    max_sev, ports_from_text, extract_ips,
    MGMT_PORTS, SENSITIVE_HOSTS, SENSITIVE_SUBNET_RE
)

def match(model: str, node_name: str = "") -> bool:
    m = (model or "").lower()
    return "mikrotik" in m or "routeros" in m

def analyze(added: str, removed: str, before_cfg: str, after_cfg: str):
    severity = "LOW"
    reasons = []
    tags = []
    added_lower = added.lower()

    # any-any
    if re.search(r"\bpermit\b.*\bany\b.*\bany\b", added_lower) or re.search(r"\ballow\b.*\bany\b.*\bany\b", added_lower):
        severity = max_sev(severity, "CRITICAL")
        reasons.append("Detected permit/allow any-any style rule.")
        tags.append("any-any")

    # MikroTik INPUT accept mgmt
    if "/ip firewall filter add" in added_lower and "chain=input" in added_lower and "action=accept" in added_lower:
        pset = ports_from_text(added)
        if pset & MGMT_PORTS:
            if "src-address=0.0.0.0/0" in added_lower or "src-address" not in added_lower:
                severity = max_sev(severity, "CRITICAL")
                reasons.append(f"MikroTik: chain=input accept for management ports with broad source: {sorted(list(pset & MGMT_PORTS))}.")
                tags.append("mikrotik-input-mgmt")

    # MikroTik dstnat
    if "/ip firewall nat add" in added_lower and ("chain=dstnat" in added_lower or "action=dst-nat" in added_lower):
        ips = extract_ips(added)
        hit_sensitive = [ip for ip in ips if ip in SENSITIVE_HOSTS]
        hit_subnet = [ip for ip in ips if SENSITIVE_SUBNET_RE.match(ip)]
        if hit_sensitive:
            severity = max_sev(severity, "CRITICAL")
            reasons.append(f"MikroTik: dstnat to sensitive host(s): {hit_sensitive}.")
            tags.append("mikrotik-dstnat-sensitive")
        elif hit_subnet:
            severity = max_sev(severity, "HIGH")
            reasons.append(f"MikroTik: dstnat into lab subnet: {hit_subnet}.")
            tags.append("mikrotik-dstnat-subnet")
        else:
            severity = max_sev(severity, "MEDIUM")
            reasons.append("MikroTik: NAT change detected (review).")
            tags.append("mikrotik-nat-change")

    # SNMP public
    if re.search(r"\bcommunity\b", added_lower) and re.search(r"\bpublic\b", added_lower):
        severity = max_sev(severity, "HIGH")
        reasons.append("SNMP community 'public' detected.")
        tags.append("snmp-public")

    # Logging deshabilitado (genérico)
    if "logging" in added_lower and (("disabled" in added_lower) or ("discard" in added_lower) or ("none" in added_lower)):
        severity = max_sev(severity, "HIGH")
        reasons.append("Logging change suggests reduced visibility (disabled/discard/none).")
        tags.append("logging-disabled")

    return severity, reasons, tags
