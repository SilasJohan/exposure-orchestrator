# Lab targets and known answers

Five targets on an isolated Docker network, published only on `127.0.0.1`.
Every secret here is a **planted fake**. This file is the ground truth a scan
run is measured against: a good run finds the expected findings below and
touches nothing on the decoy.

## Start / stop

```bash
docker compose -f lab/compose.lab.yaml up -d --build
docker compose -f lab/compose.lab.yaml down -v
```

Juice Shop takes ~30–60s to finish booting after `up`.

## Targets

| Name              | Address          | Scheme | In customer scope? | Kind                     |
|-------------------|------------------|--------|--------------------|--------------------------|
| juiceshop.lab     | 127.0.0.1:3000   | http   | yes                | OWASP Juice Shop (real)  |
| vulnerable.lab    | 127.0.0.1:8081   | http   | yes                | static web exposures     |
| secure.lab        | 127.0.0.1:8443   | https  | yes                | good-TLS control         |
| weak.lab          | 127.0.0.1:8444   | https  | yes                | weak-TLS target          |
| out-of-scope.lab  | 127.0.0.1:8099   | http   | **no (decoy)**     | must never be scanned    |

## Expected findings (ground truth)

### juiceshop.lab — OWASP Juice Shop (tier 1)
- **Exposed download directory** `/ftp/` — lists downloadable files (incl. backups).
  (Direct GET of the `.bak` files is blocked by the app; the exposed listing is
  the tier-1 finding. Retrieving the backups is a tier-2/3 exercise.)
- **Information-disclosure header** `X-Recruiting`.
- **Missing security header** (no Content-Security-Policy).
- `robots.txt` discloses `/ftp`.
- Tech/stack detected (Express / Node) and title "OWASP Juice Shop".
- NOTE: Juice Shop's deep bugs (SQLi, XSS, broken auth) are **tier 2/3**,
  active testing — intentionally NOT what the automated weekly scan catches.
  The lab uses it as a realistic surface, not to prove exploitation.

### vulnerable.lab — static exposures (tier 1)
- Exposed `/.git/config` (git repo disclosure).
- Exposed `/.env` with fake credentials.
- Exposed `/backup.sql.bak` (database backup disclosure).
- Exposed `/config.json` (fake API key / DB password).
- Exposed `/.htpasswd` (fake user:hash entries).
- Directory listing enabled at `/files/`.
- Missing security headers.
- Server version banner leaked (`Server: nginx/<version>`).
- `robots.txt` discloses sensitive paths.

### weak.lab — weak TLS (tier 0 / 1)
- Self-signed certificate.
- 1024-bit RSA key (weak).
- Certificate expires within days.

### secure.lab — good TLS control (mostly clean)
- Self-signed certificate (expected: it is a lab cert).
- Otherwise strong: RSA-2048, TLS 1.2/1.3, long validity. No weak-key/expiry.

### out-of-scope.lab — decoy
- **No findings, because it must never be scanned.**
- Proof of a correct run: `docker logs lab-decoy` shows **zero** access-log
  lines after the orchestrator runs.

## Why these

They are high-signal, safe (GET/HEAD only, no exploitation), and each maps to a
real detection a weekly external scan should catch. "Nothing found" and "scan
failed" must never look the same — the orchestrator reports tool errors
separately from empty results (lab rule 6).

## Versions to record each run

- `nginx:1.27-alpine` (digest pinned in `compose.lab.yaml`).
- `bkimminich/juice-shop:v17.1.1` (digest pinned in `compose.lab.yaml`).
- Scanner + template/feed versions: record them in the run note, separately.
