from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple
from urllib.parse import urlparse


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass(frozen=True)
class Context:
    url: str
    is_https: bool
    path: str
    is_auth_like: bool
    is_admin_like: bool


def build_context(final_url: str) -> Context:
    p = urlparse(final_url)
    path = (p.path or "/").lower()

    is_https = (p.scheme.lower() == "https")

    # Very lightweight heuristics (safe + easy):
    auth_keywords = ("login", "signin", "sign-in", "auth", "account", "session", "sso", "oauth", "register", "password")
    admin_keywords = ("admin", "dashboard", "panel", "manage")

    is_auth_like = any(k in path for k in auth_keywords)
    is_admin_like = any(k in path for k in admin_keywords)

    return Context(
        url=final_url,
        is_https=is_https,
        path=path,
        is_auth_like=is_auth_like,
        is_admin_like=is_admin_like,
    )


def _max_sev(a: str, b: str) -> str:
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


def score_finding(name: str, status: str, ctx: Context) -> Tuple[str, str]:
    """
    Returns: (severity, reportability)
    severity: LOW / MEDIUM / HIGH
    reportability: short guidance for bug bounty triage
    """
    s = status.upper()
    n = name.strip()

    # Defaults
    severity = "LOW"
    reportability = "Usually informational (hardening)."

    # Helper: context bump for auth/admin-like endpoints
    def bump_if_sensitive(base: str) -> str:
        out = base
        if ctx.is_auth_like or ctx.is_admin_like:
            out = _max_sev(out, "HIGH") if base == "MEDIUM" else _max_sev(out, "MEDIUM")
        return out

    # CSP
    if n == "CSP":
        if s == "FAIL":
            severity = bump_if_sensitive("MEDIUM")
            reportability = "Often rejected unless paired with XSS; sometimes accepted as hardening."
        elif s == "WARN":
            severity = bump_if_sensitive("MEDIUM")
            reportability = "Sometimes accepted if policy is clearly weak; otherwise informational."
        else:
            severity = "LOW"
            reportability = ""

    # HSTS
    elif n == "HSTS":
        if s == "FAIL":
            # Only meaningful for HTTPS endpoints; your checks already return INFO for HTTP.
            severity = bump_if_sensitive("MEDIUM")
            reportability = "Sometimes accepted (hardening), more likely on login/auth flows."
        elif s == "WARN":
            severity = "LOW"
            reportability = "Usually informational unless scoped policy requires stricter HSTS."
        else:
            severity = "LOW"
            reportability = ""

    # Clickjacking-related
    elif n == "X-Frame-Options":
        if s == "FAIL":
            severity = bump_if_sensitive("MEDIUM")
            reportability = "Sometimes accepted if a clickjacking proof-of-concept is possible."
        elif s == "WARN":
            severity = "LOW"
            reportability = "Usually informational; validate expected header values."
        else:
            severity = "LOW"
            reportability = ""

    # MIME sniffing
    elif n == "X-Content-Type-Options":
        if s == "FAIL":
            severity = bump_if_sensitive("LOW")
            reportability = "Sometimes accepted, but often treated as hardening."
        elif s == "WARN":
            severity = "LOW"
            reportability = "Usually informational."
        else:
            severity = "LOW"
            reportability = ""

    # Referrer / privacy
    elif n == "Referrer-Policy":
        if s in ("FAIL", "WARN"):
            severity = bump_if_sensitive("LOW")
            reportability = "Usually informational; sometimes accepted if sensitive referrers leak."
        else:
            severity = "LOW"
            reportability = ""

    # Modern isolation headers
    elif n in ("COOP", "CORP", "COEP"):
        if s in ("FAIL", "WARN"):
            severity = "LOW"
            reportability = "Usually informational (modern hardening)."
        else:
            severity = "LOW"
            reportability = ""

    # Permissions-Policy
    elif n == "Permissions-Policy":
        if s in ("FAIL", "WARN"):
            severity = "LOW"
            reportability = "Usually informational (hardening)."
        else:
            severity = "LOW"
            reportability = ""

    # PASS/INFO generally low signal for reporting
    if s in ("PASS", "INFO"):
        severity = "LOW"
        reportability = ""

    return severity, reportability


def max_severity_for_report(report: Dict) -> str:
    """
    Computes the maximum severity among findings (ignores PASS/INFO by design).
    """
    max_sev = "LOW"
    for r in report.get("results", []):
        sev = (r.get("severity") or "LOW").upper()
        if sev in SEVERITY_ORDER:
            max_sev = _max_sev(max_sev, sev)
    return max_sev
