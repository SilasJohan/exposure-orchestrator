"""Human-readable run report, grouped by host and explained in plain words."""
from __future__ import annotations

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED ",
             "low": "LOW ", "info": "INFO", "unknown": "??? "}


def _sev_key(f: dict) -> int:
    return SEV_ORDER.get(f.get("severity", "unknown"), 5)


def _tally(findings: list[dict]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "unknown")] = counts.get(f.get("severity", "unknown"), 0) + 1
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
             if counts.get(s)]
    return " · ".join(parts) or "none"


def render(customer: str, run_at: str, scanned: list[str], events: dict,
           tool_results: list[dict], feeds: dict) -> str:
    L: list[str] = []
    w = L.append

    w(f"\n╔══ Exposure run — {customer} ══")
    w(f"║  when:    {run_at}")
    w(f"║  scope:   {len(scanned)} host(s) scanned — {', '.join(scanned) or '(none)'}")

    errors = [t for t in tool_results if not t["ok"]]
    w(f"║  tools:   {len(tool_results)} run, {len(errors)} failed")
    for t in errors:
        w(f"║     ✗ {t['tool']} on {t['target']}: {t['error']}")
    w("╚" + "═" * 40)

    # Change summary
    w("")
    w(f"CHANGES SINCE LAST RUN:  "
      f"NEW {len(events['new'])}   CHANGED {len(events['changed'])}   "
      f"FIXED {len(events['fixed'])}   OPEN {len(events['open'])}   "
      f"(pending-close {len(events['still_missing'])})")

    # All current findings = new + changed + open (not the fixed/missing ones)
    current = events["new"] + events["changed"] + events["open"]
    status_of = {}
    for f in events["new"]:
        status_of[f["fingerprint"]] = "NEW"
    for f in events["changed"]:
        status_of[f["fingerprint"]] = "CHANGED"

    w(f"\nCURRENT FINDINGS ({len(current)}) — by host, most severe first")
    by_host: dict[str, list[dict]] = {}
    for f in current:
        by_host.setdefault(f["host"], []).append(f)

    for host in sorted(by_host):
        items = sorted(by_host[host], key=_sev_key)
        w(f"\n  ▸ {host}   [{_tally(items)}]")
        for f in items:
            tag = status_of.get(f["fingerprint"], "")
            tagtxt = f"  «{tag}»" if tag else ""
            sev = SEV_LABEL.get(f.get("severity", "info"), "??? ")
            w(f"     [{sev}] {f.get('category','')} — {f.get('name','')}{tagtxt}")
            if f.get("explanation"):
                w(f"            → {f['explanation']}")
            if f.get("evidence"):
                w(f"            evidence: {f['evidence'][:150]}")
            w(f"            at {f.get('matched_at','')}   ·   via {f.get('source','?')}")

    if events["fixed"]:
        w(f"\nFIXED THIS RUN ({len(events['fixed'])}) — gone for 2 runs:")
        for f in sorted(events["fixed"], key=_sev_key):
            w(f"     [{SEV_LABEL.get(f.get('severity','info'))}] {f['host']}  {f.get('name','')}")

    if events["still_missing"]:
        w(f"\nPENDING CLOSE ({len(events['still_missing'])}) — missing once, "
          f"needs one more clean run:")
        for f in sorted(events["still_missing"], key=_sev_key):
            w(f"     [{SEV_LABEL.get(f.get('severity','info'))}] {f['host']}  {f.get('name','')}")

    w("")
    w(f"feeds: KEV={feeds.get('kev','n/a')}  EPSS={feeds.get('epss','n/a')}")
    w("note: a match is not proof — a human reviews before anything reaches a customer.\n")
    return "\n".join(L)
