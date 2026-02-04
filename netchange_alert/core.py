import os
import re
import json
import subprocess
import urllib.request
import urllib.error

# =========================
# CONFIG (tu entorno)
# =========================
OX_GIT_DIR = "PATH_TU_REPO_BARE"   # repo git de Oxidized (bare)
STATE_FILE = "PATH_TU_LAST-COMMITED_FILE"
TOKEN_FILE = "TU_GITEA_TOKEN"

OX_URL = "http://TU_IP:PUERTO"                   # Oxidized REST
GITEA_URL = "http://TU_IP:PUERTO"                # Gitea
GITEA_OWNER = "GITEA_OWNER"
GITEA_REPO  = "TU_REPO"

USE_LABELS = True
LABEL_PREFIX = "severity::" 

# =========================
# Policy knobs (globales)
# =========================
MGMT_PORTS = {22, 23, 80, 443, 8443, 3389, 5900, 8291, 8728, 8729}

APPROVED_DNS = {"10.0.3.2", "1.1.1.1", "8.8.8.8"}
APPROVED_NTP = {"10.0.3.2", "1.1.1.1", "8.8.8.8"}
APPROVED_DEFAULT_GW = {"10.0.3.2"}

SENSITIVE_HOSTS = {"10.0.3.10", "10.0.3.20", "10.0.3.30"}
SENSITIVE_SUBNET_RE = re.compile(r"^10\.0\.3\.\d{1,3}$")

MAX_DIFF_LINES = 220
MAX_SNAPSHOT_LINES = 160

SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# =========================
# Helpers genéricos
# =========================
def clamp(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines] + ["", f"... (truncated: {len(lines)-max_lines} more lines)"])


def max_sev(a: str, b: str) -> str:
    return a if SEV_ORDER[a] >= SEV_ORDER[b] else b


def extract_ips(text: str):
    return set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))


def ports_from_text(text: str):
    """
    Parser genérico de puertos (solo para vendors que lo expresan en texto).
    Vendors con objetos (ej FortiGate) probablemente no usarán esto.
    """
    ports = set()

    # MikroTik: dst-port=22,80,443
    for m in re.findall(r"dst-port=([0-9,]+)", text):
        for p in m.split(","):
            if p.isdigit():
                ports.add(int(p))

    # OpenWrt old-style: dest_port='80 443'
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


# =========================
# Git helpers
# =========================
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


# =========================
# State helpers
# =========================
def load_last():
    if not os.path.exists(STATE_FILE):
        return ""
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()


def save_last(commit):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write(commit + "\n")


# =========================
# Oxidized / Gitea clients
# =========================
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
