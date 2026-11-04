"""Tool runners. Each turns a tool's output into normalized findings.

Scanners are workers behind a tiny interface: given an in-scope endpoint and a
rate limit, return a list of findings plus a clear error string if the tool
failed. "Nothing found" and "tool failed" are never conflated (lab rule 6).

Tool output is untrusted data. We parse it into fields and never execute or act
on anything inside it.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shutil
import ssl
import subprocess
import time
import urllib.request
from dataclasses import asdict, dataclass, field

from . import catalog
from .lab import Endpoint

TIMEOUT = 120

# Small, explicit nuclei set: fast and deterministic. Expand for real customers.
NUCLEI_TEMPLATES = [
    "http/exposures/configs/git-config.yaml",
    "http/misconfiguration/http-missing-security-headers.yaml",
    "http/miscellaneous/dir-listing.yaml",
    "http/miscellaneous/directory-listing.yaml",
    "ssl/self-signed-ssl.yaml",
    "ssl/expired-ssl.yaml",
    "ssl/deprecated-tls.yaml",
    "ssl/weak-cipher-suites.yaml",
    "ssl/tls-version.yaml",
    "ssl/insecure-cipher-suite-detect.yaml",
]

# Curated, GET-only sensitive paths. kind "file" needs the signature in the body;
# kind "listing" needs the response to look like a directory index.
# (path, kind, check, severity, signature-or-None)
EXPOSED_PATHS = [
    ("/.git/config",          "file",    "exposed-git-config",  "high",   "[core]"),
    ("/.env",                 "file",    "exposed-dotenv",      "high",   "DB_PASSWORD"),
    ("/backup.sql.bak",       "file",    "exposed-db-backup",   "high",   "CREATE TABLE"),
    ("/config.json",          "file",    "exposed-config-json", "high",   "api_key"),
    ("/.htpasswd",            "file",    "exposed-htpasswd",    "high",   "$apr1$"),
    ("/files/",               "listing", "directory-listing",   "medium", None),
    ("/ftp/",                 "listing", "exposed-ftp-dir",     "high",   None),
]

# Response headers that leak information, and the hardening header we expect.
INFO_HEADERS = ("x-recruiting", "x-powered-by", "x-aspnet-version", "x-generator")


@dataclass
class Finding:
    host: str
    port: int
    scheme: str
    tier: int
    source: str          # nuclei | httpx | tls | paths | headers
    check: str
    name: str
    severity: str        # info | low | medium | high | critical
    matched_at: str
    evidence: str
    category: str = ""
    explanation: str = ""
    fingerprint: str = ""

    def __post_init__(self):
        # explanation may arrive as a seed (nuclei description); describe refines it.
        cat, expl = catalog.describe(self.check, self.source, self.severity, self.explanation)
        self.category = cat
        self.explanation = expl
        if not self.fingerprint:
            raw = f"{self.host}|{self.source}|{self.check}|{self.matched_at}"
            self.fingerprint = hashlib.sha1(raw.encode()).hexdigest()[:16]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ToolResult:
    tool: str
    target: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    version: str = ""


def _run(cmd: list[str], inp: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=TIMEOUT, check=False, input=inp)


def _unverified_ctx() -> ssl.SSLContext:
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_get(url: str, host: str, ctx, limit: int = 65536):
    req = urllib.request.Request(url, method="GET", headers={"Host": host})
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        body = resp.read(limit).decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, headers, body


def _looks_like_listing(body: str) -> bool:
    # nginx autoindex ("Index of") or node serve-index (<ul id="files">)
    if "Index of" in body or 'id="files"' in body:
        return True
    files = re.findall(r'href="[^"]+\.(?:bak|md|sql|zip|tar|gz|yml|yaml|json|pdf|old|log|txt)"',
                       body, re.I)
    return len(files) >= 2


# --------------------------------------------------------------------------- #
# Tier 0 — TLS certificate via openssl (passive)
# --------------------------------------------------------------------------- #
def tls_check(ep: Endpoint) -> ToolResult:
    if ep.scheme != "https":
        return ToolResult("tls", ep.host, ok=True, findings=[])
    if not shutil.which("openssl"):
        return ToolResult("tls", ep.host, ok=False, error="openssl not found")

    target = f"{ep.addr}:{ep.port}"
    try:
        handshake = _run(["sh", "-c",
                          f"echo | openssl s_client -connect {target} "
                          f"-servername {ep.host} 2>/dev/null"]).stdout
    except subprocess.TimeoutExpired:
        return ToolResult("tls", ep.host, ok=False, error="openssl s_client timeout")

    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                  handshake, re.DOTALL)
    if not m:
        return ToolResult("tls", ep.host, ok=False,
                          error="no certificate returned (handshake failed)")
    text = _run(["openssl", "x509", "-noout", "-subject", "-issuer",
                 "-enddate", "-text"], inp=m.group(0)).stdout

    findings: list[Finding] = []

    def mk(check, name, sev, evidence):
        findings.append(Finding(ep.host, ep.port, ep.scheme, 0, "tls",
                                check, name, sev, f"{ep.scheme}://{ep.host}", evidence))

    subj = re.search(r"subject=.*?CN\s*=\s*([^\n,]+)", text)
    issuer = re.search(r"issuer=.*?CN\s*=\s*([^\n,]+)", text)
    if subj and issuer and subj.group(1).strip() == issuer.group(1).strip():
        mk("tls-self-signed", "Self-signed certificate", "low",
           f"subject == issuer ({subj.group(1).strip()})")

    bits = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
    if bits and int(bits.group(1)) < 2048:
        mk("tls-weak-key", "Weak TLS key size", "medium", f"RSA {bits.group(1)}-bit (< 2048)")

    end = re.search(r"notAfter=(.+)", text)
    if end:
        try:
            exp = dt.datetime.strptime(end.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            days = (exp - dt.datetime.utcnow()).days
            if days < 0:
                mk("tls-cert-expired", "Certificate expired", "high", f"expired {-days} days ago")
            elif days < 14:
                mk("tls-cert-expiring", "Certificate expiring soon", "medium",
                   f"expires in {days} days")
        except ValueError:
            pass

    proto = re.search(r"Protocol\s*:\s*(TLSv[\d.]+)", handshake)
    if proto and proto.group(1) in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        mk("tls-legacy-protocol", "Legacy TLS protocol negotiated", "high",
           f"negotiated {proto.group(1)}")

    return ToolResult("tls", ep.host, ok=True, findings=findings,
                      version=_run(["openssl", "version"]).stdout.strip())


# --------------------------------------------------------------------------- #
# Tier 1 — curated sensitive-path checks (GET only)
# --------------------------------------------------------------------------- #
def exposed_paths(ep: Endpoint, rps: int) -> ToolResult:
    findings: list[Finding] = []
    ctx = _unverified_ctx()
    delay = 1.0 / max(rps, 1)
    base = f"{ep.scheme}://{ep.addr}:{ep.port}"
    for path, kind, check, sev, signature in EXPOSED_PATHS:
        time.sleep(delay)
        try:
            status, _h, body = _http_get(base + path, ep.host, ctx)
        except Exception:
            continue
        if status != 200:
            continue
        hit = (_looks_like_listing(body) if kind == "listing"
               else (signature in body))
        if hit:
            name = {
                "exposed-git-config": "Exposed .git/config",
                "exposed-dotenv": "Exposed .env file",
                "exposed-db-backup": "Exposed database backup",
                "exposed-config-json": "Exposed config.json",
                "exposed-htpasswd": "Exposed .htpasswd",
                "directory-listing": "Directory listing enabled",
                "exposed-ftp-dir": "Exposed download directory",
            }.get(check, check)
            evid = (f"HTTP 200, directory index at {path}" if kind == "listing"
                    else f"HTTP 200, matched {signature!r}")
            findings.append(Finding(ep.host, ep.port, ep.scheme, 1, "paths",
                                    check, name, sev,
                                    f"{ep.scheme}://{ep.host}{path}", evid))
    return ToolResult("paths", ep.host, ok=True, findings=findings, version="builtin")


# --------------------------------------------------------------------------- #
# Tier 1 — response header analysis (GET /)
# --------------------------------------------------------------------------- #
def http_headers(ep: Endpoint, rps: int) -> ToolResult:
    ctx = _unverified_ctx()
    time.sleep(1.0 / max(rps, 1))
    try:
        _status, headers, _body = _http_get(f"{ep.scheme}://{ep.addr}:{ep.port}/", ep.host, ctx)
    except Exception as exc:
        return ToolResult("headers", ep.host, ok=False, error=f"GET / failed: {exc}")

    findings: list[Finding] = []

    def mk(check, name, sev, evidence, matched="/"):
        findings.append(Finding(ep.host, ep.port, ep.scheme, 1, "headers",
                                check, name, sev,
                                f"{ep.scheme}://{ep.host}{matched}", evidence))

    server = headers.get("server")
    if server:
        mk("server-banner", "Server version banner exposed", "info", f"Server: {server}")
    for h in INFO_HEADERS:
        if h in headers:
            mk("info-header", f"Information-disclosure header: {h}", "low",
               f"{h}: {headers[h]}")
    if "content-security-policy" not in headers:
        mk("missing-csp", "Missing Content-Security-Policy", "info",
           "no Content-Security-Policy response header")
    return ToolResult("headers", ep.host, ok=True, findings=findings, version="builtin")


# --------------------------------------------------------------------------- #
# Tier 1 — httpx (technology / title) and nuclei (safe templates)
# --------------------------------------------------------------------------- #
def httpx_probe(ep: Endpoint, rps: int) -> ToolResult:
    if not shutil.which("httpx"):
        return ToolResult("httpx", ep.host, ok=False, error="httpx not found")
    url = f"{ep.scheme}://{ep.addr}:{ep.port}"
    cmd = ["httpx", "-u", url, "-json", "-silent", "-no-color",
           "-title", "-tech-detect", "-H", f"Host: {ep.host}",
           "-rl", str(rps), "-timeout", "10"]
    try:
        proc = _run(cmd)
    except subprocess.TimeoutExpired:
        return ToolResult("httpx", ep.host, ok=False, error="httpx timeout")
    if proc.returncode != 0 and not proc.stdout.strip():
        return ToolResult("httpx", ep.host, ok=False,
                          error=f"httpx rc={proc.returncode}: {proc.stderr.strip()[:200]}")

    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        tech = row.get("tech") or row.get("technologies")
        title = row.get("title", "")
        if tech:
            findings.append(Finding(
                ep.host, ep.port, ep.scheme, 1, "httpx", "tech-stack",
                "Technology/stack detected", "info", f"{ep.scheme}://{ep.host}",
                f"{', '.join(tech)}" + (f"  (title: {title})" if title else "")))
    ver = (_run(["httpx", "-version"]).stderr or _run(["httpx", "-version"]).stdout).strip()
    return ToolResult("httpx", ep.host, ok=True, findings=findings, version=ver)


def nuclei_scan(ep: Endpoint, rps: int) -> ToolResult:
    if not shutil.which("nuclei"):
        return ToolResult("nuclei", ep.host, ok=False, error="nuclei not found")
    url = f"{ep.scheme}://{ep.addr}:{ep.port}"
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-no-color",
           "-H", f"Host: {ep.host}", "-rate-limit", str(rps),
           "-timeout", "10", "-retries", "0", "-c", "50",
           "-disable-update-check", "-ni"]
    for t in NUCLEI_TEMPLATES:
        cmd += ["-t", t]
    try:
        proc = _run(cmd)
    except subprocess.TimeoutExpired:
        return ToolResult("nuclei", ep.host, ok=False, error="nuclei timeout")

    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {})
        findings.append(Finding(
            ep.host, ep.port, ep.scheme, 1, "nuclei",
            row.get("template-id", "unknown"),
            info.get("name", row.get("template-id", "unknown")),
            info.get("severity", "info"),
            (row.get("matched-at") or url).replace(f"{ep.addr}:{ep.port}", ep.host),
            str(row.get("extracted-results") or row.get("matcher-name") or "")[:200],
            explanation=(info.get("description") or "").strip(),
        ))
    if proc.returncode != 0 and not proc.stdout.strip() and "FTL" in proc.stderr:
        return ToolResult("nuclei", ep.host, ok=False, error=proc.stderr.strip()[:200])
    ver = ""
    vout = _run(["nuclei", "-version"])
    for line in (vout.stdout + vout.stderr).splitlines():
        if "Version" in line:
            ver = line.strip()
            break
    return ToolResult("nuclei", ep.host, ok=True, findings=findings, version=ver)
