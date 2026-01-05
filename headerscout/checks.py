from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class CheckResult:
    name: str
    status: str  # PASS / WARN / FAIL / INFO
    detail: str
    recommendation: str = ""


@dataclass
class HeaderCheck:
    name: str
    header: str
    evaluate: Callable[[Optional[str], str], CheckResult]


def check_hsts(value: Optional[str], url: str) -> CheckResult:
    if url.lower().startswith("http://"):
        return CheckResult(
            "HSTS",
            "INFO",
            "Target is HTTP; HSTS applies only to HTTPS."
        )

    if value is None:
        return CheckResult(
            "HSTS",
            "FAIL",
            "Missing Strict-Transport-Security header."
        )

    v = value.lower()

    if "max-age" not in v:
        return CheckResult(
            "HSTS",
            "WARN",
            f"HSTS present but max-age directive is missing: {value}"
        )

    if "includesubdomains" not in v:
        return CheckResult(
            "HSTS",
            "WARN",
            "HSTS present but includeSubDomains is not set (may be acceptable)."
        )

    return CheckResult(
        "HSTS",
        "PASS",
        f"HSTS is properly configured: {value}"
    )


def check_csp(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "CSP",
            "FAIL",
            "Missing Content-Security-Policy header."
        )

    v = value.lower()

    if "unsafe-inline" in v or "unsafe-eval" in v:
        return CheckResult(
            "CSP",
            "WARN",
            f"CSP present but contains unsafe directives: {value}"
        )

    return CheckResult(
        "CSP",
        "PASS",
        "Content-Security-Policy header is present."
    )


def check_xfo(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "X-Frame-Options",
            "FAIL",
            "Missing X-Frame-Options header."
        )

    v = value.strip().upper()

    if v in ("DENY", "SAMEORIGIN"):
        return CheckResult(
            "X-Frame-Options",
            "PASS",
            f"X-Frame-Options set to a safe value: {value}"
        )

    return CheckResult(
        "X-Frame-Options",
        "WARN",
        f"Unexpected X-Frame-Options value: {value}"
    )


def check_xcto(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "X-Content-Type-Options",
            "FAIL",
            "Missing X-Content-Type-Options header."
        )

    if value.strip().lower() == "nosniff":
        return CheckResult(
            "X-Content-Type-Options",
            "PASS",
            "X-Content-Type-Options is set to nosniff."
        )

    return CheckResult(
        "X-Content-Type-Options",
        "WARN",
        f"Unexpected X-Content-Type-Options value: {value}"
    )


def check_referrer(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "Referrer-Policy",
            "WARN",
            "Missing Referrer-Policy header."
        )

    safe_values = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "origin",
        "origin-when-cross-origin",
    }

    v = value.strip().lower()

    if v in safe_values:
        return CheckResult(
            "Referrer-Policy",
            "PASS",
            f"Referrer-Policy set to a reasonable value: {value}"
        )

    return CheckResult(
        "Referrer-Policy",
        "INFO",
        f"Referrer-Policy is set to: {value}"
    )


def check_permissions_policy(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "Permissions-Policy",
            "INFO",
            "Permissions-Policy header is not set."
        )

    return CheckResult(
        "Permissions-Policy",
        "PASS",
        "Permissions-Policy header is present."
    )


def check_coop(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "COOP",
            "INFO",
            "Cross-Origin-Opener-Policy header is not set."
        )

    return CheckResult(
        "COOP",
        "PASS",
        f"Cross-Origin-Opener-Policy is set: {value}"
    )


def check_corp(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "CORP",
            "INFO",
            "Cross-Origin-Resource-Policy header is not set."
        )

    return CheckResult(
        "CORP",
        "PASS",
        f"Cross-Origin-Resource-Policy is set: {value}"
    )


def check_coep(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "COEP",
            "INFO",
            "Cross-Origin-Embedder-Policy header is not set."
        )

    return CheckResult(
        "COEP",
        "PASS",
        f"Cross-Origin-Embedder-Policy is set: {value}"
    )
    
def check_hsts(value: Optional[str], url: str) -> CheckResult:
    if url.lower().startswith("http://"):
        return CheckResult(
            "HSTS",
            "INFO",
            "Target is HTTP; HSTS applies only to HTTPS.",
            "Use HTTPS for the application, then enable HSTS (Strict-Transport-Security).",
        )

    if value is None:
        return CheckResult(
            "HSTS",
            "FAIL",
            "Missing Strict-Transport-Security header.",
            "Enable HSTS on HTTPS endpoints (e.g., set Strict-Transport-Security with an appropriate max-age).",
        )

    v = value.lower()

    if "max-age" not in v:
        return CheckResult(
            "HSTS",
            "WARN",
            f"HSTS present but max-age directive is missing: {value}",
            "Add a max-age directive to HSTS (e.g., max-age=15552000 or higher, depending on your policy).",
        )

    if "includesubdomains" not in v:
        return CheckResult(
            "HSTS",
            "WARN",
            "HSTS present but includeSubDomains is not set (may be acceptable).",
            "Consider adding includeSubDomains if you control and serve all subdomains over HTTPS.",
        )

    return CheckResult(
        "HSTS",
        "PASS",
        f"HSTS is properly configured: {value}",
        "",
    )


def check_csp(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "CSP",
            "FAIL",
            "Missing Content-Security-Policy header.",
            "Add a Content-Security-Policy to reduce XSS impact (start with a restrictive policy and iterate).",
        )

    v = value.lower()

    if "unsafe-inline" in v or "unsafe-eval" in v:
        return CheckResult(
            "CSP",
            "WARN",
            f"CSP present but contains unsafe directives: {value}",
            "Avoid unsafe-inline/unsafe-eval where possible; prefer nonces/hashes and strict script sources.",
        )

    return CheckResult(
        "CSP",
        "PASS",
        "Content-Security-Policy header is present.",
        "",
    )


def check_xfo(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "X-Frame-Options",
            "FAIL",
            "Missing X-Frame-Options header.",
            "Set X-Frame-Options to DENY or SAMEORIGIN to mitigate clickjacking (or use CSP frame-ancestors).",
        )

    v = value.strip().upper()

    if v in ("DENY", "SAMEORIGIN"):
        return CheckResult(
            "X-Frame-Options",
            "PASS",
            f"X-Frame-Options set to a safe value: {value}",
            "",
        )

    return CheckResult(
        "X-Frame-Options",
        "WARN",
        f"Unexpected X-Frame-Options value: {value}",
        "Use DENY or SAMEORIGIN (or migrate to CSP frame-ancestors) and ensure the value is valid.",
    )


def check_xcto(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "X-Content-Type-Options",
            "FAIL",
            "Missing X-Content-Type-Options header.",
            "Set X-Content-Type-Options to nosniff to prevent MIME type sniffing.",
        )

    if value.strip().lower() == "nosniff":
        return CheckResult(
            "X-Content-Type-Options",
            "PASS",
            "X-Content-Type-Options is set to nosniff.",
            "",
        )

    return CheckResult(
        "X-Content-Type-Options",
        "WARN",
        f"Unexpected X-Content-Type-Options value: {value}",
        "Set X-Content-Type-Options to nosniff (recommended).",
    )


def check_referrer(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "Referrer-Policy",
            "WARN",
            "Missing Referrer-Policy header.",
            "Consider setting Referrer-Policy (e.g., strict-origin-when-cross-origin) to reduce information leakage.",
        )

    safe_values = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "origin",
        "origin-when-cross-origin",
    }

    v = value.strip().lower()

    if v in safe_values:
        return CheckResult(
            "Referrer-Policy",
            "PASS",
            f"Referrer-Policy set to a reasonable value: {value}",
            "",
        )

    return CheckResult(
        "Referrer-Policy",
        "INFO",
        f"Referrer-Policy is set to: {value}",
        "Review whether this policy matches your desired privacy and analytics requirements.",
    )


def check_permissions_policy(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "Permissions-Policy",
            "INFO",
            "Permissions-Policy header is not set.",
            "Consider adding Permissions-Policy to restrict powerful browser features if applicable.",
        )

    return CheckResult(
        "Permissions-Policy",
        "PASS",
        "Permissions-Policy header is present.",
        "",
    )


def check_coop(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "COOP",
            "INFO",
            "Cross-Origin-Opener-Policy header is not set.",
            "If you need cross-origin isolation, consider setting COOP (e.g., same-origin).",
        )

    return CheckResult(
        "COOP",
        "PASS",
        f"Cross-Origin-Opener-Policy is set: {value}",
        "",
    )


def check_corp(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "CORP",
            "INFO",
            "Cross-Origin-Resource-Policy header is not set.",
            "If you serve sensitive resources, consider setting CORP (e.g., same-site).",
        )

    return CheckResult(
        "CORP",
        "PASS",
        f"Cross-Origin-Resource-Policy is set: {value}",
        "",
    )


def check_coep(value: Optional[str], url: str) -> CheckResult:
    if value is None:
        return CheckResult(
            "COEP",
            "INFO",
            "Cross-Origin-Embedder-Policy header is not set.",
            "If you need cross-origin isolation, consider setting COEP (e.g., require-corp).",
        )

    return CheckResult(
        "COEP",
        "PASS",
        f"Cross-Origin-Embedder-Policy is set: {value}",
        "",
    )


def get_default_checks():
    return [
        HeaderCheck("HSTS", "Strict-Transport-Security", lambda v, u: check_hsts(v, u)),
        HeaderCheck("CSP", "Content-Security-Policy", lambda v, u: check_csp(v, u)),
        HeaderCheck("X-Frame-Options", "X-Frame-Options", lambda v, u: check_xfo(v, u)),
        HeaderCheck("X-Content-Type-Options", "X-Content-Type-Options", lambda v, u: check_xcto(v, u)),
        HeaderCheck("Referrer-Policy", "Referrer-Policy", lambda v, u: check_referrer(v, u)),
        HeaderCheck("Permissions-Policy", "Permissions-Policy", lambda v, u: check_permissions_policy(v, u)),
        HeaderCheck("COOP", "Cross-Origin-Opener-Policy", lambda v, u: check_coop(v, u)),
        HeaderCheck("CORP", "Cross-Origin-Resource-Policy", lambda v, u: check_corp(v, u)),
        HeaderCheck("COEP", "Cross-Origin-Embedder-Policy", lambda v, u: check_coep(v, u)),
    ]
