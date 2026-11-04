"""Plain-language catalog: what each finding actually means.

Keyed by our own check ids. nuclei findings fall back to the description nuclei
itself ships, and to a category derived from severity. The goal is that a
report reads clearly to a non-specialist: category + one honest sentence.
"""
from __future__ import annotations

# category labels (stable, short)
EXPOSED_FILE = "Exposed file"
DIR_LISTING = "Directory listing"
INFO_DISCLOSURE = "Information disclosure"
MISSING_HARDENING = "Missing hardening"
TLS_CERT = "TLS / certificate"
INFORMATION = "Information"

CATALOG: dict[str, tuple[str, str]] = {
    # our own curated path checks
    "exposed-git-config": (EXPOSED_FILE,
        "A downloadable .git/config exposes the repo URL and layout; source code can often be reconstructed."),
    "exposed-dotenv": (EXPOSED_FILE,
        "An .env file is downloadable and usually holds credentials, tokens and database passwords."),
    "exposed-db-backup": (EXPOSED_FILE,
        "A database backup is downloadable, exposing table data directly."),
    "exposed-config-json": (INFO_DISCLOSURE,
        "A config file is downloadable and may contain API keys, DB passwords or internal endpoints."),
    "exposed-htpasswd": (EXPOSED_FILE,
        "An .htpasswd file leaks usernames and password hashes that can be cracked offline."),
    "directory-listing": (DIR_LISTING,
        "The server lists the files in a folder, helping an attacker discover sensitive files."),
    "exposed-ftp-dir": (DIR_LISTING,
        "An exposed download directory lists files, including backups and source archives."),
    "exposed-backup-file": (EXPOSED_FILE,
        "A backup or source file (e.g. package.json.bak) is downloadable."),
    # httpx-derived
    "server-banner": (INFO_DISCLOSURE,
        "The server advertises its exact software and version, enabling version-specific attacks."),
    "info-header": (INFO_DISCLOSURE,
        "A response header leaks internal information (framework, recruiting URL, etc.)."),
    "missing-csp": (MISSING_HARDENING,
        "No Content-Security-Policy header; the app is more exposed to cross-site scripting."),
    "tech-stack": (INFORMATION,
        "The framework/technology behind the site was fingerprinted (useful context, not a flaw)."),
    # tls checks
    "tls-self-signed": (TLS_CERT,
        "The certificate is self-signed, so clients cannot verify the server's identity."),
    "tls-weak-key": (TLS_CERT,
        "The certificate key is smaller than 2048-bit and is considered weak."),
    "tls-cert-expiring": (TLS_CERT,
        "The certificate expires very soon; once expired, clients will see security warnings."),
    "tls-cert-expired": (TLS_CERT,
        "The certificate has already expired; connections are untrusted."),
    "tls-legacy-protocol": (TLS_CERT,
        "The server negotiated an outdated TLS version (1.0/1.1) with known weaknesses."),
}

# A few common nuclei template ids, in plain words.
NUCLEI_HINTS: dict[str, tuple[str, str]] = {
    "git-config": (EXPOSED_FILE,
        "nuclei confirmed a downloadable .git/config (repo disclosure)."),
    "http-missing-security-headers": (MISSING_HARDENING,
        "One or more recommended security headers are missing."),
    "dir-listing": (DIR_LISTING, "nuclei confirmed directory listing is enabled."),
    "directory-listing": (DIR_LISTING, "nuclei confirmed directory listing is enabled."),
    "self-signed-ssl": (TLS_CERT, "nuclei confirmed a self-signed certificate."),
    "expired-ssl": (TLS_CERT, "nuclei confirmed an expired certificate."),
    "deprecated-tls": (TLS_CERT, "nuclei confirmed a deprecated TLS version is accepted."),
    "weak-cipher-suites": (TLS_CERT, "nuclei confirmed weak cipher suites are accepted."),
    "tls-version": (TLS_CERT, "nuclei reported the negotiated TLS version."),
    "insecure-cipher-suite-detect": (TLS_CERT, "nuclei reported an insecure cipher suite."),
}

_SEV_CATEGORY = {
    "critical": "Vulnerability", "high": "Vulnerability", "medium": "Weakness",
    "low": "Information disclosure", "info": "Information",
}


def describe(check: str, source: str, severity: str, nuclei_description: str = "") -> tuple[str, str]:
    """Return (category, plain-language explanation) for a finding."""
    if check in CATALOG:
        return CATALOG[check]
    if source == "nuclei":
        if check in NUCLEI_HINTS:
            return NUCLEI_HINTS[check]
        cat = _SEV_CATEGORY.get(severity, "Finding")
        return cat, (nuclei_description or "Reported by a nuclei template.").strip()
    return _SEV_CATEGORY.get(severity, "Finding"), ""
