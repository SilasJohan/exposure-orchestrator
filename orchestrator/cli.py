"""Command-line entry point.

    # manage the lab (targets live in the repo)
    orchestrator lab up | down | status

    # work with customer configs (a bare name resolves to configs/<name>.yaml)
    orchestrator list
    orchestrator new <name>
    orchestrator validate <config>
    orchestrator plan     <config>
    orchestrator scan     <config>

The scan path: validate -> resolve -> loopback pre-flight -> run tiers on
in-scope hosts only -> normalize -> store -> diff -> report.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import os
import subprocess
import sys

from . import scope, lab, runners, history, report

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
DEFAULT_RESOLUTION = os.path.join(ROOT, "configs", "lab-resolution.yaml")
DEFAULT_RESULTS = os.path.join(ROOT, "results")
CONFIG_DIR = os.path.join(ROOT, "configs")
# The lab is bundled in this repo (self-contained). Override with LAB_COMPOSE to
# point at another copy, e.g. the one in lagoasoft-security-research/lab/.
REPO_LAB = os.environ.get("LAB_COMPOSE") or os.path.join(ROOT, "lab", "compose.lab.yaml")

TEMPLATE = """\
# Customer config. One file per customer. Lab/approved targets only.
customer: {name}
contract: "[contract reference]"
approved_by: "[name and role at the customer]"
valid_until: {valid_until}
contact: "[security contact]"
tier: 1
schedule: weekly

# The hosts to scan. For a LOCAL lab target, also give its address under
# `resolution` below (host -> loopback addr/port/scheme). In production this
# mapping comes from real DNS and `resolution` is left out.
targets:
  - myapp.lab
resolution:
  myapp.lab: {{ addr: 127.0.0.1, port: 8080, scheme: http }}

include_subdomains: false
shared_infrastructure_acknowledged: false
exclude: []
max_requests_per_second: 10
"""


def _resolve_config(arg: str) -> str:
    """Accept a path, or a bare name mapping to configs/<name>.yaml."""
    for cand in (arg, os.path.join(CONFIG_DIR, arg),
                 os.path.join(CONFIG_DIR, f"{arg}.yaml"),
                 os.path.join(CONFIG_DIR, f"{arg}.yml")):
        if os.path.isfile(cand):
            return cand
    raise scope.ScopeError(f"config not found: {arg!r} (looked in {CONFIG_DIR})")


def _table(args, cfg: scope.CustomerConfig) -> dict:
    """Lab resolution = the shared file, overridden by the config's own block."""
    table = lab.load_resolution(args.resolution)
    table.update(lab.parse_resolution(cfg.resolution))
    return table


# --------------------------------------------------------------------------- #
# lab management
# --------------------------------------------------------------------------- #
def _compose(*args: str) -> int:
    if not os.path.isfile(REPO_LAB):
        print(f"lab compose not found at {REPO_LAB}", file=sys.stderr)
        return 2
    return subprocess.run(["docker", "compose", "-f", REPO_LAB, *args]).returncode


def cmd_lab(args) -> int:
    if args.action == "up":
        rc = _compose("up", "-d", "--build")
        if rc == 0:
            print("lab starting; waiting for juice-shop to answer on :3000 ...")
            import urllib.request
            for _ in range(40):
                try:
                    urllib.request.urlopen("http://127.0.0.1:3000/", timeout=2)
                    print("lab is up.")
                    return 0
                except Exception:
                    __import__("time").sleep(2)
            print("lab is up (juice-shop may still be booting).")
        return rc
    if args.action == "down":
        return _compose("down", "-v")
    if args.action == "status":
        return _compose("ps")
    return 2


# --------------------------------------------------------------------------- #
# config helpers
# --------------------------------------------------------------------------- #
def cmd_list(_args) -> int:
    files = sorted(glob.glob(os.path.join(CONFIG_DIR, "*.yaml")))
    files = [f for f in files if os.path.basename(f) != "lab-resolution.yaml"]
    if not files:
        print("no customer configs in", CONFIG_DIR)
        return 0
    print(f"customer configs in {CONFIG_DIR}:")
    for f in files:
        try:
            cfg = scope.load_config(f)
            ok = "ok" if not scope.validate(cfg) else "INVALID"
            print(f"  {os.path.basename(f):22} tier={cfg.tier} [{ok}] "
                  f"targets: {', '.join(cfg.targets)}")
        except Exception as exc:
            print(f"  {os.path.basename(f):22} (unreadable: {exc})")
    return 0


def cmd_new(args) -> int:
    path = os.path.join(CONFIG_DIR, f"{args.name}.yaml")
    if os.path.exists(path):
        print(f"already exists: {path}")
        return 1
    valid = (dt.date.today() + dt.timedelta(days=180)).isoformat()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE.format(name=args.name, valid_until=valid))
    print(f"created {path}")
    print("edit the targets, contract and approval fields, then: "
          f"./run.sh validate {args.name}")
    return 0


# --------------------------------------------------------------------------- #
# validate / plan / scan
# --------------------------------------------------------------------------- #
def cmd_validate(args) -> int:
    cfg = scope.load_config(_resolve_config(args.config))
    problems = scope.validate(cfg)
    if problems:
        print(f"INVALID config for {cfg.customer!r}:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK: {cfg.customer!r} is valid. In scope: {', '.join(scope.scope_targets(cfg))}")
    return 0


def cmd_plan(args) -> int:
    cfg = scope.load_config(_resolve_config(args.config))
    problems = scope.validate(cfg)
    if problems:
        print("Refusing to plan — config invalid:")
        for p in problems:
            print(f"  - {p}")
        return 1
    table = _table(args, cfg)
    scoped = scope.scope_targets(cfg)
    print(f"Customer: {cfg.customer}  tier={cfg.tier}  rps={cfg.max_requests_per_second}")
    print(f"Declared: {', '.join(cfg.targets)}   Excluded: {', '.join(cfg.exclude) or '(none)'}")
    print(f"In scope (will scan): {', '.join(scoped)}")
    eps = []
    for host in scoped:
        try:
            ep = lab.resolve(host, table)
            eps.append(ep)
            print(f"  {host} -> {ep.scheme}://{ep.addr}:{ep.port}")
        except lab.SafetyError as exc:
            print(f"  {host} -> UNRESOLVED: {exc}")
    try:
        lab.preflight(eps)
        print("Pre-flight: OK (all targets on loopback)")
        return 0
    except lab.SafetyError as exc:
        print(f"Pre-flight FAILED: {exc}")
        return 1


def cmd_scan(args) -> int:
    cfg = scope.load_config(_resolve_config(args.config))
    problems = scope.validate(cfg)
    if problems:
        print("Refusing to scan — config invalid:")
        for p in problems:
            print(f"  - {p}")
        return 1

    table = _table(args, cfg)
    endpoints = []
    for host in scope.scope_targets(cfg):
        ep = lab.resolve(host, table)
        if not scope.in_scope(cfg, ep.host):      # belt and braces
            print(f"GATE: refusing out-of-scope host {ep.host}")
            continue
        endpoints.append(ep)

    try:
        lab.preflight(endpoints)
    except lab.SafetyError as exc:
        print(f"Pre-flight FAILED, aborting run: {exc}")
        return 2

    rps = cfg.max_requests_per_second
    all_findings: list[runners.Finding] = []
    tool_results: list[dict] = []
    for ep in endpoints:
        stages = [runners.tls_check(ep)]                 # tier 0
        if cfg.tier >= 1:
            stages += [runners.exposed_paths(ep, rps),
                       runners.http_headers(ep, rps),
                       runners.httpx_probe(ep, rps),
                       runners.nuclei_scan(ep, rps)]
        for res in stages:
            tool_results.append({"tool": res.tool, "target": res.target,
                                 "ok": res.ok, "error": res.error, "version": res.version})
            all_findings.extend(res.findings)

    findings_dicts = [f.as_dict() for f in all_findings]
    run_at = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    run_path = history.save_run(args.results_dir, cfg.customer, findings_dicts, tool_results)
    events = history.diff_and_update(args.results_dir, cfg.customer, findings_dicts)

    feeds = {"kev": "not-loaded (flag off)", "epss": "not-loaded (flag off)"}
    print(report.render(cfg.customer, run_at, scope.scope_targets(cfg),
                        events, tool_results, feeds))
    print(f"run saved: {run_path}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="orchestrator", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--resolution", default=DEFAULT_RESOLUTION)
    p.add_argument("--results-dir", default=DEFAULT_RESULTS)
    sub = p.add_subparsers(dest="cmd", required=True)

    # full form:  lab up | lab down | lab status
    sp = sub.add_parser("lab", help="start/stop the lab")
    sp.add_argument("action", choices=["up", "down", "status"])
    sp.set_defaults(func=cmd_lab)

    # short forms:  up | down | status   (redirect to the lab actions)
    for short in ("up", "down", "status"):
        sub.add_parser(short, help=f"shortcut for 'lab {short}'").set_defaults(
            func=cmd_lab, action=short)

    sub.add_parser("list", help="list customer configs").set_defaults(func=cmd_list)

    sp = sub.add_parser("new", help="scaffold a new customer config")
    sp.add_argument("name")
    sp.set_defaults(func=cmd_new)

    # config argument is optional; defaults to the example lab customer.
    for name, fn in (("validate", cmd_validate), ("plan", cmd_plan), ("scan", cmd_scan)):
        sp = sub.add_parser(name, help=f"{name} a customer config (default: example-lab)")
        sp.add_argument("config", nargs="?", default="example-lab")
        sp.set_defaults(func=fn)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (scope.ScopeError, lab.SafetyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
