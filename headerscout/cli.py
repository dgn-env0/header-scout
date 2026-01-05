import argparse
import json
import sys
from typing import Iterator, Optional

from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="headerscout",
        description=(
            "HTTP Security Header Scanner for a URL/domain. "
            "Includes context-aware severity and bug-bounty triage hints (hunter mode)."
        )

    )

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "url",
        nargs="?",
        help="Target URL or domain. Example: example.com or https://example.com",
    )
    src.add_argument(
        "--file",
        dest="file_path",
        help="Read targets from a file (one URL/domain per line). Lines starting with # are comments; inline comments supported.",
    )

    p.add_argument("--timeout", type=int, default=10, help="HTTP timeout (seconds). Default: 10")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended).")
    p.add_argument("--json", dest="json_path", help="Write results to a JSON file (includes severity, reportability, context). Example: report.json")
    p.add_argument("--show-headers", action="store_true", help="Print raw response headers.")
    p.add_argument("--only", help="Show only selected statuses. Example: FAIL,WARN")
    p.add_argument("--summary-only", action="store_true", help="Print one summary line per target (includes MAX severity).")
    p.add_argument(
    "--mode",
    choices=["hunter", "hardening"],
    default="hunter",
    help=(
        "Output mode. hunter: show mainly FAIL/WARN plus reportability hints. "
        "hardening: show everything (PASS/INFO included)."
    ),
)



    return p


def iter_targets(file_path: str) -> Iterator[str]:
    """
    Rules for reading targets from a file:
    - empty lines are skipped
    - full-line comments (#...) are skipped
    - inline comments are stripped: example.com # prod  -> example.com
    """
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith("#"):
                continue

            if "#" in line:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue

            yield line


def print_report(report: dict, only_set: Optional[set] = None, mode: str = "hunter"):
    url = report["url"]
    counts = report["counts"]
    
    status_code = report.get("status_code")
    max_sev = (report.get("max_severity") or "LOW").upper()
    
    print(f"Target: {url}")
    if status_code is not None:
        print(
            f"Summary: PASS={counts['PASS']} WARN={counts['WARN']} FAIL={counts['FAIL']} INFO={counts['INFO']} "
            f"| STATUS={status_code} | MAX_SEVERITY={max_sev}"
    )
    else:
        print(
            f"Summary: PASS={counts['PASS']} WARN={counts['WARN']} FAIL={counts['FAIL']} INFO={counts['INFO']} "
            f"| MAX_SEVERITY={max_sev}"
        )

    print("-" * 72)

# Warn if response is likely a block page / WAF / auth wall
    if status_code is not None and status_code >= 400:
        if status_code in (401, 403, 429):
            print(
                f"Warning: Non-2xx response ({status_code}). Headers may belong to an auth wall, rate-limit, or WAF block page "
                f"and may not represent the real application response."
            )
        else:
            print(
                f"Warning: Non-2xx response ({status_code}). Headers may not represent the intended application response."
            )
        print("-" * 72)


    for r in report["results"]:
        status = r["status"].upper()

        # Default filtering by mode (unless --only is used)
        if not only_set:
            if mode == "hunter" and status not in {"FAIL", "WARN"}:
                continue

        if only_set and status not in only_set:
            continue

        sev = (r.get("severity") or "LOW").upper()
        print(f"[{r['status']}][{sev}] {r['name']}: {r['detail']}")

        rec = (r.get("recommendation") or "").strip()
        if rec and status in {"FAIL", "WARN"}:
            print(f"       Recommendation: {rec}")

        rep = (r.get("reportability") or "").strip()
        if rep and status in {"FAIL", "WARN"} and mode == "hunter":
            print(f"       Reportability: {rep}")
            
def print_summary_line(report: dict):
    c = report["counts"]
    max_sev = (report.get("max_severity") or "LOW").upper()
    sc = report.get("status_code")
    sc_txt = f"STATUS={sc}" if sc is not None else "STATUS=?"
    print(
        f"{report['url']:<30} "
        f"FAIL={c['FAIL']} WARN={c['WARN']} PASS={c['PASS']} INFO={c['INFO']} "
        f"MAX={max_sev} {sc_txt}"
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    only_set = None
    if args.only:
        only_set = {x.strip().upper() for x in args.only.split(",") if x.strip()}

    verify_tls = not args.insecure

    try:
        # Single-target JSON is a dict; multi-target JSON is a list.
        reports = None

        if args.file_path:
            reports = []
            total = 0
            fail_hosts = 0
            error_hosts = 0
            interrupted = False

            targets = list(iter_targets(args.file_path))
            if not targets:
                raise ValueError("No targets found in file. Empty lines and # comments are ignored.")

            for t in targets:
                try:
                    report = scan(t, timeout=args.timeout, verify_tls=verify_tls)
                    reports.append(report)
                    total += 1
                    
                    fails = int(report.get("counts", {}).get("FAIL", 0))
                    if fails > 0:
                        fail_hosts += 1
                        
                    
                    if args.summary_only:
                        print_summary_line(report)
                    else:
                        print_report(report, only_set=only_set, mode=args.mode)

                        if args.show_headers:
                            print("-" * 72)
                            print("Raw headers:")
                            for k, v in report["raw_headers"].items():
                                print(f"{k}: {v}")

                        print()  # spacing between targets (detailed mode only)

                except KeyboardInterrupt:
                    interrupted = True
                    print("\nInterrupted by user. Writing partial results...", file=sys.stderr)
                    break

                except Exception as e:
                    error_hosts += 1
                    print(f"Target: {t}")
                    print("Summary: ERROR")
                    print("-" * 72)
                    print(f"[ERROR] Scan failed: {e}")
                    print()

            print("=" * 72)
            print(f"Scanned: {total} | Hosts with FAIL: {fail_hosts} | Errors: {error_hosts}")
            if interrupted:
                print("Note: Scan was interrupted; results may be partial.")
            print("=" * 72)

        else:
            report = scan(args.url, timeout=args.timeout, verify_tls=verify_tls)
            reports = report

            print_report(report, only_set=only_set, mode=args.mode)

            if args.show_headers:
                print("-" * 72)
                print("Raw headers:")
                for k, v in report["raw_headers"].items():
                    print(f"{k}: {v}")

        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(reports, f, ensure_ascii=False, indent=2)
            print(f"JSON report written to: {args.json_path}")

    except KeyboardInterrupt:
        # If Ctrl+C happens in single-target mode, exit gracefully
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
