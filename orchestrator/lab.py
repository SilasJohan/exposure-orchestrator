"""Lab name resolution and the loopback safety guard.

In production the orchestrator resolves via real DNS and a network egress gate.
For local testing we resolve lab names from a static file, and a pre-flight
check refuses to proceed unless every declared target resolves to loopback.
That is the hard stop that keeps this test tool off anything but the lab.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import yaml


class SafetyError(Exception):
    """Raised when a target would resolve off the loopback lab network."""


@dataclass(frozen=True)
class Endpoint:
    host: str          # declared name, e.g. vulnerable.lab
    addr: str          # resolved address, must be loopback
    port: int
    scheme: str        # http | https


def load_resolution(path: str) -> dict[str, Endpoint]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out: dict[str, Endpoint] = {}
    for host, spec in data.items():
        out[host] = Endpoint(
            host=host,
            addr=str(spec["addr"]),
            port=int(spec["port"]),
            scheme=str(spec.get("scheme", "http")),
        )
    return out


def resolve(host: str, table: dict[str, Endpoint]) -> Endpoint:
    if host not in table:
        raise SafetyError(f"no lab resolution for {host!r}")
    return table[host]


def preflight(endpoints: list[Endpoint]) -> None:
    """Abort the whole run unless every endpoint is on loopback (127.0.0.0/8)."""
    loopback = ipaddress.ip_network("127.0.0.0/8")
    for ep in endpoints:
        try:
            ip = ipaddress.ip_address(ep.addr)
        except ValueError as exc:
            raise SafetyError(f"{ep.host}: address {ep.addr!r} is not an IP") from exc
        if ip not in loopback:
            raise SafetyError(
                f"{ep.host}: {ep.addr} is not loopback — refusing to scan (lab only)"
            )
