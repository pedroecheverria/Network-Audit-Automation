import subprocess

from core import (
    run_git, git_show_file, load_last, save_last,
    oxidized_node_info, gitea_create_issue,
    clamp, split_diff, max_sev,
    USE_LABELS, LABEL_PREFIX, MAX_DIFF_LINES
)

from rules import ALL_RULES


def evaluate_with_rules(model: str, node_name: str, diff_raw: str, before_cfg: str, after_cfg: str):
    """
    - split_diff es común para todos
    - cada vendor parsea a su manera en su archivo
    - combinamos severidad/reasons/tags
    """
    added, removed = split_diff(diff_raw)

    final_sev = "LOW"
    final_reasons = []
    final_tags = []

    matched = False
    for rule in ALL_RULES:
        if rule.match(model, node_name=node_name):
            matched = True
            sev, reasons, tags = rule.analyze(added, removed, before_cfg, after_cfg)
            final_sev = max_sev(final_sev, sev)
            final_reasons.extend(reasons)
            final_tags.extend(tags)

    # baseline si no matcheó nada pero hubo diff
    if (not matched) and diff_raw.strip():
        final_reasons.append("No vendor rule matched this device model (baseline change).")
        final_tags.append("baseline")

    # de-dup reasons/tags por prolijidad
    final_reasons = list(dict.fromkeys(final_reasons))
    final_tags = list(dict.fromkeys(final_tags))

    return final_sev, final_reasons, final_tags


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

            sev, reasons, tags = evaluate_with_rules(model, f, diff_raw, before_cfg, after_cfg)

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
