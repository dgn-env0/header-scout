import time
from typing import Dict, Any, Tuple

import requests

from .utils import normalize_url, header_get
from .checks import get_default_checks
from .triage import build_context, score_finding, max_severity_for_report

DEFAULT_TIMEOUT = 10


def fetch_headers(url: str, timeout: int, verify_tls: bool) -> Tuple[Dict[str, Any], str, int]:
    """
    Fetch response headers for the given URL.
    Tries HEAD first, falls back to GET if needed.
    Returns: (headers, final_url, status_code)
    """
    try:
        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
        )
        # Some servers respond poorly to HEAD; fallback to GET on 4xx/5xx
        if response.status_code >= 400:
            raise requests.RequestException("HEAD request failed")
        return response.headers, response.url, response.status_code
    except Exception:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
        )
        return response.headers, response.url, response.status_code


def scan(url: str, timeout: int = DEFAULT_TIMEOUT, verify_tls: bool = True) -> Dict[str, Any]:
    start_time = time.time()
    target = normalize_url(url)

    headers, final_url, status_code = fetch_headers(
        target,
        timeout=timeout,
        verify_tls=verify_tls,
    )

    # Build context from the final URL (after redirects)
    ctx = build_context(final_url)

    results = []
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}

    for check in get_default_checks():
        value = header_get(headers, check.header)
        result = check.evaluate(value, final_url)

        # Compute severity + reportability (context-aware)
        severity, reportability = score_finding(result.name, result.status, ctx)

        results.append(
            {
                "name": result.name,
                "status": result.status,
                "detail": result.detail,
                "recommendation": getattr(result, "recommendation", "") or "",
                "severity": severity,
                "reportability": reportability,
            }
        )

        counts[result.status] += 1

    elapsed_ms = int((time.time() - start_time) * 1000)

    report = {
        "url": final_url,
        "status_code": status_code,
        "counts": counts,
        "results": results,
        "raw_headers": dict(headers),
        "elapsed_ms": elapsed_ms,
        "context": {
            "is_https": ctx.is_https,
            "path": ctx.path,
            "is_auth_like": ctx.is_auth_like,
            "is_admin_like": ctx.is_admin_like,
        },
    }

    report["max_severity"] = max_severity_for_report(report)
    return report
