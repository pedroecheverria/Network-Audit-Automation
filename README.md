
```markdown
# NETWORK-CHANGE-ALERT (Oxidized + Gitea)

Detects potentially risky network configuration changes captured by **Oxidized**, classifies them by severity (**LOW / MEDIUM / HIGH / CRITICAL**), and automatically creates **Gitea Issues** for HIGH/CRITICAL events.  
It also generates a **PDF incident report** (dashboard-style) that can be emailed to a security team / C-level.

> **Lab note:** This project was built and tested in a local lab environment (no Internet).  
> The detection logic was validated **only for OpenWrt** (MikroTik skeleton exists but was not fully validated).

---

## Why this exists

In networks with many devices and multiple admins making changes daily, it’s easy to lose visibility on:
- **What changed**
- **When it changed**
- **Which change increased risk**

Oxidized already provides versioned network configs (Git commits + diffs). This project adds a “security-aware” layer:
1) **Detect risky patterns**
2) **Create issues automatically**
3) **Summarize incidents in a report**

---

## High-level flow

### 1) Detection --> Gitea Issues (`securitywatch`)
- Reads **Oxidized Git repo** (local, where full configs are stored per node and versioned).
- Retrieves **node metadata** (name, IP, model) using Oxidized REST API.
- Computes config change **diff** between commits.
- Runs rules --> assigns severity **LOW/MEDIUM/HIGH/CRITICAL**.
- If severity is **HIGH** or **CRITICAL**, it **POSTs** an Issue to Gitea with:
  - Node name / IP / model
  - Commit hash and time
  - Reasons (human-readable)
  - Diff snippet

### 2) Reporting --> PDF + Email (`gitea_incident_report`)
- Uses **Gitea API** to fetch issues (open + closed).
- Builds an executive-style PDF:
  - Totals / open vs closed
  - Severity distribution
  - Trend timeline chart
  - Latest incidents table (node + reason)
- Optionally emails the PDF through SMTP.

> **Timeline DEMO mode:** For demo, the timeline chart can be generated with a simulated date distribution.
> In production, the timeline must be based on real timestamps (Gitea `created_at` / `closed_at` or Oxidized Git commit timestamps).

---

## Repo layout

```

netchange_alert/
core.py
main.py
rules/
**init**.py
openwrt.py
mikrotik.py

raw_code/
oxidized_security_watch.py
gitea_incident_report.py

.env.example
requirements.txt

````

### `raw_code/` (lab / legacy approach)
This folder contains the original lab implementation where everything lived in standalone scripts:

- **`oxidized_security_watch.py`**  
  Pulls node metadata from Oxidized API, reads diffs from the local Oxidized Git repo, classifies the change, and creates a Gitea Issue if HIGH/CRITICAL.

- **`gitea_incident_report.py`**  
  Fetches issues from Gitea, generates a PDF report, and optionally emails it.

✅ Works for demo/lab  
⚠️ Not ideal for production (harder to maintain and extend)

### Production-ready structure (`netchange_alert/`)
This is the structured approach to scale to multiple vendors and keep logic clean.

- **`core.py`**  
  Shared engine:
  - Git reading helpers (diffs, commit ranges)
  - HTTP helpers (Oxidized/Gitea API calls)
  - Parsing helpers (IPs, ports)
  - Severity ranking logic and common utilities

- **`rules/`**  
  Vendor-specific detection logic.
  - `openwrt.py`: OpenWrt UCI-based patterns (validated)
  - `mikrotik.py`: MikroTik patterns (placeholder / extend)
  
  The goal: **each vendor parses configs differently**, so each file owns its own parsing and detection logic.

- **`main.py`**  
  Orchestrator / entry point:
  - Reads new commits from Oxidized Git repo
  - Identifies which node changed
  - Dispatches to the appropriate vendor rules engine
  - Creates Gitea issues only for HIGH/CRITICAL
  - Updates state (`last_processed_commit.txt`)

> To add a new vendor: create a new file under `rules/` (e.g., `fortigate.py`, `cisco.py`) and register it in the dispatch logic.

---

## Detection policies (OpenWrt – validated)

The OpenWrt rules currently detect (HIGH/CRITICAL/MEDIUM depending on case):

1) **CRITICAL**: ACCEPT from WAN + management ports  
2) **HIGH**: Broad match (`any` / `0.0.0.0/0`) + management ports  
3) **HIGH**: WAN zone policy changed to ACCEPT (`input`/`forward`)  
4) **HIGH/CRITICAL**: Port-forward / DNAT from WAN to internal/sensitive targets  
5) **HIGH**: DNS changed to non-approved servers  
6) **HIGH**: NTP changed to non-approved servers  
7) **HIGH/MEDIUM**: Unexpected default route/gateway / strange routes (blackhole, etc.)  
8) **HIGH**: Logging reduced (`log_size=0`, syslog disabled)

> Approved DNS/NTP/default gateways are environment-specific and should be configured in `.env` (production).

---

## Configuration

Create your `.env` file:

```bash
cp .env.example .env
````

Typical variables:

* Oxidized

  * `OX_URL=http://IP:PORT`
  * `OX_GIT_DIR=YOUR-FILE-PATH`

* Gitea

  * `GITEA_URL=http://10.0.X.XX:PORT`
  * `GITEA_OWNER=gitea`
  * `GITEA_REPO=YOUR_REPO_NAME`
  * `TOKEN_FILE=YOUR_TOKEN_FILE`

* SMTP (optional report email)

  * `MAIL_TO=security@lab.local`
  * `MAIL_FROM=reports@lab.local`
  * `SMTP_HOST=IP`
  * `SMTP_PORT=PORT`
  * `SMTP_STARTTLS=0`

---

## Running

### 1) Create issues from changes

```bash
sudo /usr/local/bin/oxidized_security_watch.py
```

(or structured version)

```bash
python3 -m netchange_alert.main
```

### 2) Generate PDF report (and optionally email it)

```bash
sudo -E /usr/local/bin/gitea_incident_report.py
```

---

## Production notes (what must change)

This repo includes **demo shortcuts** that should be replaced in production:

* ✅ Use real **timestamps**:

  * Timeline should be built using Gitea `created_at / closed_at`, or from Oxidized commit timestamps.
* ✅ Store secrets outside the code:

  * Token, SMTP creds, approved DNS/NTP/GW lists → `.env` or secret manager (Vault, etc.)
* ✅ Add unit tests for each vendor rule file.
* ✅ Add deduplication:

  * Avoid opening multiple issues for repeated identical changes.
* ✅ Add validation / allowlists per environment:

  * Approved DNS/NTP servers, management subnets, “trusted” admin networks, etc.

---

## Status

* [x] Lab demo working (OpenWrt validated)
* [ ] MikroTik rules (extend)
* [ ] FortiGate/Cisco/Juniper rules (future)
* [ ] Better parsing + structured config normalization
* [ ] CI tests and linting

---

## Automation (how to run it automatically)

One simple automation option is using **cron** (or systemd timers / CI runners, depending on the environment):

- **Job 1 — Security watch (classification + issue creation):** run frequently to detect potentially risky changes quickly.
- **Job 2 — Incident report (PDF + optional email):** run periodically (e.g., weekly / biweekly / monthly) to provide a management-level view of network hygiene and trends.

## Disclaimer / maturity level

This repository is a **proposal and proof-of-concept**. The current code and structure can be improved significantly:
- I have **not deployed this in production** yet.
- The detection logic and workflows **must be tested and validated** in each real environment (per vendor, per network, per policy).
- False positives/negatives are expected until the rules are tuned with real operational data.
- Treat this as a starting point to iterate on (better parsing, normalization, testing, etc.).

---