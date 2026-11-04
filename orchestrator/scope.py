"""Customer config loading, validation, and the scope gate.

This is the part no off-the-shelf scanner gives us: a hard allow-list driven
entirely by the customer file. A host is scanned only if it is declared here
and not excluded. Validation refuses configs that would be unsafe to run.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
from dataclasses import dataclass, field

import yaml

MAX_RPS_CAP = 50
MAX_VALID_DAYS = 400
AUTOMATED_TIERS = {0, 1}  # tier 2 needs human approval; tier 3 has no code path.
REQUIRED_FIELDS = (
    "customer", "contract", "approved_by", "valid_until",
    "contact", "tier", "targets",
)
# Deliberately small: enough to reject a bare public suffix in the lab demo.
PUBLIC_SUFFIXES = {"com", "net", "org", "io", "dev", "br", "de", "co"}
_PLACEHOLDER = re.compile(r"^\s*\[.*\]\s*$")


class ScopeError(Exception):
    """Raised when a config is invalid or a host is out of scope."""


@dataclass
class CustomerConfig:
    customer: str
    contract: str
    approved_by: str
    contact: str
    valid_until: dt.date
    tier: int
    schedule: str
    targets: list[str]
    exclude: list[str] = field(default_factory=list)
    include_subdomains: bool = False
    shared_infrastructure_acknowledged: bool = False
    max_requests_per_second: int = 5
    resolution: dict = field(default_factory=dict)  # optional per-config lab endpoints
    raw: dict = field(default_factory=dict)


def load_config(path: str) -> CustomerConfig:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return _parse(data)


def _parse(data: dict) -> CustomerConfig:
    valid_until = data.get("valid_until")
    if isinstance(valid_until, str):
        valid_until = dt.date.fromisoformat(valid_until)
    return CustomerConfig(
        customer=data.get("customer", ""),
        contract=str(data.get("contract", "")),
        approved_by=str(data.get("approved_by", "")),
        contact=str(data.get("contact", "")),
        valid_until=valid_until,
        tier=data.get("tier", -1),
        schedule=data.get("schedule", "manual"),
        targets=list(data.get("targets") or []),
        exclude=list(data.get("exclude") or []),
        include_subdomains=bool(data.get("include_subdomains", False)),
        shared_infrastructure_acknowledged=bool(
            data.get("shared_infrastructure_acknowledged", False)
        ),
        max_requests_per_second=int(data.get("max_requests_per_second", 5)),
        resolution=dict(data.get("resolution") or {}),
        raw=data,
    )


def validate(cfg: CustomerConfig, *, today: dt.date | None = None) -> list[str]:
    """Return a list of problems. Empty list means the config is safe to run."""
    today = today or dt.date.today()
    problems: list[str] = []

    for field_name in REQUIRED_FIELDS:
        value = cfg.raw.get(field_name)
        if value in (None, "", []):
            problems.append(f"missing required field: {field_name}")
        elif isinstance(value, str) and _PLACEHOLDER.match(value):
            problems.append(f"field still a placeholder: {field_name} = {value!r}")

    if cfg.valid_until is None:
        problems.append("missing required field: valid_until")
    else:
        if cfg.valid_until < today:
            problems.append(f"contract expired: valid_until {cfg.valid_until} < {today}")
        elif (cfg.valid_until - today).days > MAX_VALID_DAYS:
            problems.append(
                f"valid_until too far out: > {MAX_VALID_DAYS} days ({cfg.valid_until})"
            )

    if cfg.tier not in AUTOMATED_TIERS:
        if cfg.tier == 2:
            problems.append("tier 2 requires human approval (not automated here)")
        elif cfg.tier == 3:
            problems.append("tier 3 has no automated code path")
        else:
            problems.append(f"unknown tier: {cfg.tier!r}")

    if not (1 <= cfg.max_requests_per_second <= MAX_RPS_CAP):
        problems.append(
            f"max_requests_per_second {cfg.max_requests_per_second} outside 1..{MAX_RPS_CAP}"
        )

    for host in cfg.targets:
        problems.extend(f"target {host!r}: {m}" for m in _bad_host_reasons(host))

    for ex in cfg.exclude:
        if not any(_covers(t, ex, cfg.include_subdomains) for t in cfg.targets):
            problems.append(f"exclude {ex!r} is not inside any target")

    return problems


def _bad_host_reasons(host: str) -> list[str]:
    reasons = []
    if "*" in host or host.startswith("."):
        reasons.append("wildcard not allowed")
    if _is_ip(host):
        reasons.append("bare IP not allowed (declare a hostname)")
    labels = host.split(".")
    if len(labels) < 2:
        reasons.append("single-label host not allowed")
    elif labels[-1] in PUBLIC_SUFFIXES and len(labels) == 2 and labels[0] in ("", "*"):
        reasons.append("bare public suffix not allowed")
    return reasons


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _covers(target: str, host: str, include_subdomains: bool) -> bool:
    if host == target:
        return True
    if include_subdomains and host.endswith("." + target):
        return True
    return False


def in_scope(cfg: CustomerConfig, host: str) -> bool:
    """The gate. A host is in scope only if a target covers it and nothing excludes it."""
    if any(_covers(ex, host, cfg.include_subdomains) or ex == host for ex in cfg.exclude):
        return False
    return any(_covers(t, host, cfg.include_subdomains) for t in cfg.targets)


def scope_targets(cfg: CustomerConfig) -> list[str]:
    """The declared hosts that will actually be scanned, after exclusions."""
    return [h for h in cfg.targets if in_scope(cfg, h)]
