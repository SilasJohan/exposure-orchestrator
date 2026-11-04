# Exposure orchestrator — local test build

A thin orchestrator that proves the parts no off-the-shelf scanner gives us:
a file-driven **scope gate**, a **loopback safety guard**, scanners as
**workers**, and a **new/changed/fixed history**. Tier 0 (passive TLS) and
tier 1 (curated paths, headers, httpx, nuclei — safe templates) only.

The lab it scans is **bundled in this repo** (`lab/`), so this is self-contained:
you do not need any other repo cloned to test.

## Requirements

Already on this machine: `nuclei`, `httpx`, `openssl`, `docker`, `python3`.
The venv installs only PyYAML.

## The lab (what you are scanning)

The lab is a set of deliberately weak Docker containers, published only on
`127.0.0.1`. Everything in it is a planted fake. It is defined by one file:
`lab/compose.lab.yaml`. See `lab/LAB.md` for the full list of targets and the
exact findings each one should produce (the "ground truth").

| Target            | Address        | What it is                         |
|-------------------|----------------|------------------------------------|
| juiceshop.lab     | 127.0.0.1:3000 | OWASP Juice Shop (realistic app)   |
| vulnerable.lab    | 127.0.0.1:8081 | static exposures (.git/.env/…)     |
| secure.lab        | 127.0.0.1:8443 | good-TLS control                   |
| weak.lab          | 127.0.0.1:8444 | weak-TLS (1024-bit, expiring)      |
| out-of-scope.lab  | 127.0.0.1:8099 | decoy — must never be scanned      |

### Starting the lab — two equivalent ways

The lab is just a compose file, so "starting it" is always the same containers;
only the folder you call it from differs.

```bash
# A) via the orchestrator (recommended — also waits for Juice Shop to boot)
./run.sh lab up
./run.sh lab status
./run.sh lab down

# B) directly with docker compose (identical result)
docker compose -f lab/compose.lab.yaml up -d --build
docker compose -f lab/compose.lab.yaml ps
docker compose -f lab/compose.lab.yaml down -v
```

Both run the exact same containers. `./run.sh lab up` just calls `docker
compose` for you and then waits until Juice Shop answers on port 3000.

> If you also have the `lagoasoft-security-research` repo and want to drive *its*
> copy of the lab instead of the bundled one:
> `LAB_COMPOSE=/path/to/lagoasoft-security-research/lab/compose.lab.yaml ./run.sh lab up`

## Short commands (recommended)

Install a one-word `exposure` command once:

```bash
./run.sh install     # creates ~/.local/bin/exposure -> run.sh
```

Then, from anywhere:

```bash
exposure up                 # start the lab (waits for Juice Shop to boot)
exposure scan               # scan the example lab, diff, print the report
exposure down               # stop the lab
```

Every short command just redirects to a longer one:

| Short            | Same as              |
|------------------|----------------------|
| `exposure up`    | `exposure lab up`    |
| `exposure down`  | `exposure lab down`  |
| `exposure status`| `exposure lab status`|
| `exposure scan`  | `exposure scan example-lab` |

If you don't install it, use `./run.sh <command>` instead of `exposure <command>`
— they are identical.

Run `scan` twice to see findings move from NEW to OPEN, and to FIXED after two
clean runs.

## Customize the target (one file, no code changes)

```bash
exposure new acme            # creates configs/acme.yaml you can edit
$EDITOR configs/acme.yaml    # set targets, contract, approval, tier, rate
exposure validate acme       # check it is safe to run
exposure scan acme
```

A customer config holds **both** what to scan and, for a local lab target, where
it lives — in one file:

```yaml
targets:
  - myapp.lab
resolution:                              # only needed for LOCAL lab targets
  myapp.lab: { addr: 127.0.0.1, port: 8080, scheme: http }
```

So to point at your own local app, set `targets` and `resolution` and run
`exposure scan <name>`. In production the `resolution` block is left out and the
name comes from real DNS. The target must resolve to `127.0.0.1` or the run is
refused (test-build safety).

## Viewing the TLS lab targets in a browser

`secure.lab` (`https://127.0.0.1:8443`) and `weak.lab` (`https://127.0.0.1:8444`)
serve HTTPS with **self-signed** certificates and only return a one-line text
response — they are scan targets, not real websites. So:

- You must use `https://` (not `http://`) on ports 8443/8444.
- The browser shows a "Your connection is not private" warning because the cert
  is self-signed. That is expected — click Advanced → Proceed, or use
  `curl -k https://127.0.0.1:8443`.
- `weak.lab` uses a 1024-bit key on purpose; modern browsers may refuse it
  outright (SSL error). That is the point — it is a deliberately weak server.
  The scanner reads it fine via openssl regardless.

None of this is a problem with your network.

## The five commands

| Command | What it does |
|---|---|
| `lab up / down / status` | start / stop / inspect the lab containers |
| `list` | show every customer config and whether it validates |
| `new <name>` | scaffold a new customer config |
| `validate <cfg>` | check the config is safe to run (no traffic) |
| `plan <cfg>` | show scope + resolution + pre-flight (no traffic) |
| `scan <cfg>` | run the tiers, diff, and print the report |

## How a scan works (6 stages)

1. **Scope gate** (`scope.py`) — only hosts declared in the config, minus
   exclusions, are allowed. Wildcards, bare IPs, public suffixes, expired or
   too-long contracts, over-cap rates and tier 2/3 are refused.
2. **Pre-flight** (`lab.py`) — aborts unless every target resolves to loopback.
3. **Workers** (`runners.py`) — tier 0: TLS cert (openssl). tier 1: curated
   sensitive paths, response headers, httpx tech-detect, nuclei (safe templates).
4. **Normalize** — every tool's output becomes the same finding record, with a
   plain-language category and explanation (`catalog.py`).
5. **Diff** (`history.py`) — new / changed / fixed vs the stored history; a
   finding only closes after it is missing on two consecutive runs.
6. **Report** (`report.py`) — grouped by host, most severe first, in plain words.

## Safety model (test build)

- **Scope gate**: config-driven allow-list; nothing else is scanned.
- **Loopback guard**: the run aborts unless every target is `127.0.0.0/8`.
- **Decoy proof**: `out-of-scope.lab` is reachable but never declared; after a
  run, `docker logs lab-decoy` is empty.
- Tool output is treated as untrusted data and never executed.

## What this is NOT (yet)

No egress-proxy/nftables gate, no Postgres/procrastinate queue, no approval
MCP server, no KEV/EPSS enrichment, no ticketing. Those belong to the production
engine (`exposure-engine`), per `docs/architecture/DECISIONS.md`. This build
exists to test the core ideas against the lab.

## Layout

```
orchestrator/
  scope.py     config load, validation, the scope gate
  lab.py       lab name resolution + loopback pre-flight
  runners.py   tls / paths / headers / httpx / nuclei workers -> findings
  catalog.py   plain-language category + explanation per finding
  history.py   run storage + new/changed/fixed diff (2-miss close)
  report.py    human-readable report
  cli.py       lab | list | new | validate | plan | scan
configs/
  example-lab.yaml     fake customer pointed at the lab
  bad-expired.yaml     invalid on purpose (gate demo)
  lab-resolution.yaml  lab name -> loopback endpoint
```
