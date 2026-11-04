# Lab

Local fake targets with known answers, run with Docker Compose. Built by the
"build the vulnerable lab" track.

The lab only listens on `127.0.0.1`, never on a public interface. Everything in
it is fake and deliberately weak.

- **[`compose.lab.yaml`](compose.lab.yaml)** — four targets on an isolated network.
- **[`LAB.md`](LAB.md)** — the targets and the expected findings (ground truth).

## Quick start

```bash
docker compose -f lab/compose.lab.yaml up -d --build
# ... run tools against the lab targets only ...
docker compose -f lab/compose.lab.yaml down -v
```

## Targets (summary)

| Name              | Address          | Purpose                              |
|-------------------|------------------|--------------------------------------|
| juiceshop.lab     | 127.0.0.1:3000   | OWASP Juice Shop (realistic app)     |
| vulnerable.lab    | 127.0.0.1:8081   | web exposures (.git, .env, listing)  |
| secure.lab        | 127.0.0.1:8443   | good-TLS control                     |
| weak.lab          | 127.0.0.1:8444   | weak-TLS target                      |
| out-of-scope.lab  | 127.0.0.1:8099   | decoy: must never be scanned         |

See [`LAB.md`](LAB.md) for the full ground-truth list.
