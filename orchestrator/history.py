"""Run storage and the new / changed / fixed diff.

This is the other half of our product value: an asset+finding history that says
what changed since last week. A finding is only closed after it is missing on
two consecutive runs (the plan's 2-miss rule), so one flaky run never clears it.
"""
from __future__ import annotations

import datetime as dt
import json
import os

CLOSE_AFTER_MISSES = 2


def _now() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _state_path(root: str, customer: str) -> str:
    return os.path.join(root, "state", f"{customer}.json")


def load_state(root: str, customer: str) -> dict:
    path = _state_path(root, customer)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_run(root: str, customer: str, findings: list[dict], tool_results: list[dict]) -> str:
    os.makedirs(os.path.join(root, "runs", customer), exist_ok=True)
    stamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(root, "runs", customer, f"run-{stamp}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"customer": customer, "run_at": _now(),
                   "findings": findings, "tools": tool_results}, fh, indent=2)
    return path


def diff_and_update(root: str, customer: str, findings: list[dict]) -> dict:
    """Update the persistent state and return the events for this run."""
    state = load_state(root, customer)
    now = _now()
    current = {f["fingerprint"]: f for f in findings}

    events = {"new": [], "changed": [], "fixed": [], "still_missing": [], "open": []}

    for fp, f in current.items():
        prev = state.get(fp)
        if prev is None:
            state[fp] = {**f, "status": "open", "misses": 0,
                         "first_seen": now, "last_seen": now}
            events["new"].append(f)
        else:
            was_closed = prev.get("status") == "closed"
            # "changed" = the finding got more/less severe. Evidence text is NOT
            # compared: some tools report a different (equally valid) evidence
            # string each run, which would otherwise flag a false change.
            changed = prev.get("severity") != f["severity"]
            state[fp] = {**prev, **f, "status": "open", "misses": 0, "last_seen": now}
            if was_closed:
                events["new"].append(f)       # reappeared
            elif changed:
                events["changed"].append(f)
            else:
                events["open"].append(f)

    for fp, prev in list(state.items()):
        if fp in current or prev.get("status") == "closed":
            continue
        prev["misses"] = prev.get("misses", 0) + 1
        if prev["misses"] >= CLOSE_AFTER_MISSES:
            prev["status"] = "closed"
            prev["closed_at"] = now
            events["fixed"].append(prev)
        else:
            events["still_missing"].append(prev)
        state[fp] = prev

    os.makedirs(os.path.join(root, "state"), exist_ok=True)
    with open(_state_path(root, customer), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    return events
