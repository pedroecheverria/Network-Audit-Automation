import os
import re
import json
import subprocess
import urllib.request
import urllib.error

# CONFIG (tu entorno)
# AJUSTA SEGUN TU ENTORNO
OX_GIT_DIR = "tu-repo-bare"   # repo git de Oxidized (bare)
STATE_FILE = "tu-last-commited-file"
TOKEN_FILE = "token-file"

OX_URL = "http://IP:PUERTO"                  
GITEA_URL = "http://IP:PUERTO"                
GITEA_OWNER = "OWNER"                         
GITEA_REPO  = "TU_REPO"

USE_LABELS = True
LABEL_PREFIX = "severity::"

# Policy knobs
MGMT_PORTS = {22, 23, 80, 443, 8443, 3389, 5900, 8291, 8728, 8729}

APPROVED_DNS = {"10.0.3.2", "1.1.1.1", "8.8.8.8"}
APPROVED_NTP = {"10.0.3.2", "1.1.1.1", "8.8.8.8"}
APPROVED_DEFAULT_GW = {"10.0.3.2"}

SENSITIVE_HOSTS = {"10.0.3.10", "10.0.3.20", "10.0.3.30"}
SENSITIVE_SUBNET_RE = re.compile(r"^10\.0\.3\.\d{1,3}$")

MAX_DIFF_LINES = 220
MAX_SNAPSHOT_LINES = 160

SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# Helpers
def clamp(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines] + ["", f"... (truncated: {len(lines)-max_lines} more lines)"])

def run_git(args):
    cmd = ["git", f"--git-dir={OX_GIT_DIR}"] + args
    out = subprocess.check_output(cmd)  # bytes
    return out.decode("utf-8", errors="replace").strip()

def git_show_file(commit, path):
    try:
        out = subprocess.check_output(
            ["git", f"--git-dir={OX_GIT_DIR}", "show", f"{commit}:{path}"]
        )  # bytes
        return out.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError:
        return ""

def load_last():
    if not os.path.exists(STATE_FILE):
        return ""
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def save_last(commit):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write(commit + "\n")

def read_token():
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def http_get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read().decode("utf-8", errors="ignore")
        return json.loads(raw)

def oxidized_node_info(node_name):
    return http_get_json(f"{OX_URL}/node/show/{node_name}.json")

def gitea_create_issue(title, body, labels=None):
    token = read_token()
    url = f"{GITEA_URL}/api/v1/repos/{GITEA_OWNER}/{GITEA_REPO}/issues"

    payload = {"title": title, "body": body}
    if USE_LABELS and labels:
        payload["labels"] = labels

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return True, resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        # retry sin labels (por si no existen)
        if labels:
            payload.pop("labels", None)
            data2 = json.dumps(payload).encode("utf-8")
            req2 = urllib.request.Request(
                url,
                data=data2,
                headers={
                    "Authorization": f"token {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req2, timeout=15) as resp2:
                    return True, resp2.read().decode("utf-8", errors="ignore")
            except Exception as e2:
                return False, f"HTTPError {e.code}: {e.read().decode('utf-8', errors='ignore')} | retry failed: {e2}"
        return False, f"HTTPError {e.code}: {e.read().decode('utf-8', errors='ignore')}"
    except Exception as e:
        return False, str(e)

def max_sev(a, b):
    return a if SEV_ORDER[a] >= SEV_ORDER[b] else b

def extract_ips(text: str):
    return set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))

def ports_from_text(text: str):
    ports = set()

    # MikroTik: dst-port=22,80,443
    for m in re.findall(r"dst-port=([0-9,]+)", text):
        for p in m.split(","):
            if p.isdigit():
                ports.add(int(p))

    # OpenWrt old-style (no UCI): dest_port='80 443'
    for m in re.findall(r"dest_port='([^']+)'", text):
        for p in re.split(r"[\s,]+", m.strip()):
            if p.isdigit():
                ports.add(int(p))

    # OpenWrt UCI: option dest_port '22'  or '22 443'
    for m in re.findall(r"option\s+dest_port\s+'([^']+)'", text, flags=re.IGNORECASE):
        for p in re.split(r"[\s,]+", m.strip()):
            if p.isdigit():
                ports.add(int(p))

    return ports

def split_diff(diff_raw: str):
    added = []
    removed = []
    for ln in diff_raw.splitlines():
        if ln.startswith("+++ ") or ln.startswith("--- "):
            continue
        if ln.startswith("+") and not ln.startswith("+++"):
            added.append(ln[1:])
        elif ln.startswith("-") and not ln.startswith("---"):
            removed.append(ln[1:])
    return "\n".join(added), "\n".join(removed)

# Risk engine
def evaluate_risk(node_name: str, diff_raw: str, before_cfg: str, after_cfg: str):
    severity = "LOW"
    reasons = []
    tags = []

    added, _removed = split_diff(diff_raw)
    added_lower = added.lower()

    # -------------------------
    # OpenWrt UCI: CRITICAL/HIGH
    # -------------------------
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

    # (2) CRITICAL/HIGH: any/0.0.0.0/0 + mgmt ports (genérico)
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

    # (4) NAT / Port-forward inbound (OpenWrt UCI: config redirect / DNAT)
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

    # (6) NTP no aprobado (OpenWrt /etc/config/system suele tener list server) En produccion es mejor restringirlo solo para /etc/config/system.
    if ("config timeserver" in added_lower) or ("timeserver" in added_lower) or ("list server" in added_lower) or  ("list server" in added_lower and "ntp" in added_lower):
        ips = extract_ips(added)
        bad = sorted([ip for ip in ips if ip not in APPROVED_NTP])
        if bad:
            severity = max_sev(severity, "HIGH")
            reasons.append(f"NTP server(s) not approved detected: {bad}.")
            tags.append("ntp-unapproved")

    # (7) Rutas extrañas (default route / gateway inesperado)
    if ("config route" in added_lower) or ("option target" in added_lower and "0.0.0.0" in added_lower) or ("0.0.0.0/0" in added_lower):
        ips = extract_ips(added)
        bad_gw = sorted([ip for ip in ips if ip not in APPROVED_DEFAULT_GW])
        if bad_gw:
            severity = max_sev(severity, "HIGH")
            reasons.append(f"Default route/gateway changed to unexpected IP(s): {bad_gw}.")
            tags.append("route-default-unexpected")
        else:
            # si no sabemos gateway pero detectamos cambio en default route, lo dejamos MEDIUM
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

    # -------------------------
    # MikroTik / Generic patterns
    # -------------------------
    # any-any (genérico)
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

    # Si nada matcheó pero hubo cambios, LOW informativo
    if not reasons and diff_raw.strip():
        reasons.append("No risky patterns matched (baseline change).")
        tags.append("baseline")

    return severity, reasons, tags

# Main
def main():
    head = run_git(["rev-parse", "HEAD"])
    last = load_last()

    # primera ejecución: baseline
    if not last:
        save_last(head)
        print(f"[INIT] baseline set to {head}")
        return

    if last == head:
        print("[OK] no new commits")
        return

    commits = run_git(["rev-list", "--reverse", f"{last}..{head}"]).splitlines()
    print(f"[INFO] processing {len(commits)} new commit(s)")

    for c in commits:
        try:
            parent = run_git(["rev-parse", f"{c}^"])
        except subprocess.CalledProcessError:
            parent = ""  # root commit

        when = run_git(["show", "-s", "--format=%cI", c])
        short = c[:7]

        files = run_git(["diff-tree", "--no-commit-id", "--name-only", "-r", c]).splitlines()
        for f in files:
            # metadata desde Oxidized API
            try:
                node = oxidized_node_info(f)
            except Exception:
                node = {"name": f, "ip": "unknown", "model": "unknown", "last": {"status": "unknown"}}

            ip = node.get("ip", "unknown")
            model = node.get("model", "unknown")
            last_obj = node.get("last", {}) or {}
            last_status = last_obj.get("status", "unknown")
            last_start = last_obj.get("start", "unknown")
            last_end = last_obj.get("end", "unknown")
            last_time = last_obj.get("time", "unknown")

            # diff + snapshots
            if parent:
                diff_raw = run_git(["diff", parent, c, "--", f])
                before_cfg = git_show_file(parent, f)
            else:
                diff_raw = run_git(["show", c, "--", f])
                before_cfg = ""

            after_cfg = git_show_file(c, f)

            sev, reasons, tags = evaluate_risk(f, diff_raw, before_cfg, after_cfg)

            if sev in ("HIGH", "CRITICAL"):
                title = f"[{sev}] Potential risky config change on {f} ({short})"

                labels = []
                if USE_LABELS:
                    labels = [f"{LABEL_PREFIX}{sev.lower()}", "oxidized", "network-security"]

                diff_short = clamp(diff_raw, MAX_DIFF_LINES)

                body = (
                    f"**Node:** `{f}`\n"
                    f"**IP:** `{ip}`\n"
                    f"**Model:** `{model}`\n"
                    f"**Severity:** **{sev}**\n"
                    f"**Commit:** `{c}`\n"
                    f"**Commit time:** `{when}`\n"
                    f"**Oxidized last:** status=`{last_status}` start=`{last_start}` end=`{last_end}` time=`{last_time}`\n\n"
                    + "**Reasons**:\n- " + "\n- ".join(reasons) + "\n\n"
                    + "**Diff:**\n```diff\n"
                    + diff_short
                    + "\n```"
                    #+ f"**Machine summary (JSON)**:\n```json\n{json.dumps(summary, indent=2)}\n```\n\n"
                    #+ f"**Diff (truncated)**:\n```diff\n{clamp(diff_raw, MAX_DIFF_LINES)}\n```\n\n"
                   # + f"**Before snapshot (truncated)**:\n```text\n{clamp(before_cfg, MAX_SNAPSHOT_LINES)}\n```\n\n"
                   # + f"**After snapshot (truncated)**:\n```text\n{clamp(after_cfg, MAX_SNAPSHOT_LINES)}\n```\n"
                )

                ok, resp = gitea_create_issue(title, body, labels=labels)
                if ok:
                    print(f"[ISSUE] created: node={f} sev={sev} commit={short}")
                else:
                    print(f"[ERR] issue create failed: node={f} sev={sev} commit={short} -> {resp}")
            else:
                print(f"[SKIP] node={f} severity={sev} commit={short}")

    save_last(head)
    print(f"[DONE] state updated to {head}")

if __name__ == "__main__":
    main()
