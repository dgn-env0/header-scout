# HeaderScout

A lightweight HTTP security header scanner designed for quick reconnaissance and triage. It checks common security-related response headers, adds context-aware severity levels, and (in hunter mode) provides bug-bounty-oriented reportability hints.

This tool does **not** exploit vulnerabilities. It helps you identify missing or weak defensive headers and prioritize what to investigate next.

## Features

- Scans a single URL/domain or multiple targets from a file
- Checks common security headers (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP)
- **Two output modes:**
  - **hunter (default):** focuses on FAIL/WARN + reportability hints
  - **hardening:** shows everything (PASS/INFO included)
- Context-aware **severity** per finding (`LOW / MEDIUM / HIGH`) and per-target `MAX_SEVERITY`
- Warns on **non-2xx** responses (e.g., `403/401/429`) where headers may come from WAF/edge/auth walls
- Optional JSON output for automation/saving results
- Optional raw header printing

## Installation

Clone and run in a virtual environment:
```bash
git clone https://github.com/dgn-env0/header-scout.git
cd header-scout
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

**Tip:** If `headerscout` is not found, ensure your venv is activated: `source .venv/bin/activate`

## Usage

### Single target
```bash
headerscout example.com
headerscout https://example.com
```

### Modes
```bash
# Hunter (default): show mainly FAIL/WARN + reportability hints
headerscout example.com

# Hardening: show PASS/INFO as well
headerscout example.com --mode hardening
```

### Show raw headers
```bash
headerscout example.com --show-headers
```

### Write JSON output
```bash
headerscout example.com --json output.json
```

### Filter by status
```bash
headerscout example.com --only FAIL,WARN
```

### Multiple targets from a file

Create `targets.txt` (one target per line). Supports:
- Empty lines
- Full-line comments starting with `#`
- Inline comments after `#`
```
# production
example.com
https://www.cloudflare.com # CDN
http://neverssl.com
```

Run:
```bash
headerscout --file targets.txt
```

### Summary-only for quick triage
```bash
headerscout --file targets.txt --summary-only
```

Output includes MAX severity and STATUS code per target.

## Example Output

### Hardening mode (shows everything):
```
Target: https://eksisozluk.com/
Summary: PASS=7 WARN=1 FAIL=1 INFO=0 | STATUS=403 | MAX_SEVERITY=MEDIUM
------------------------------------------------------------------------
Warning: Non-2xx response (403). Headers may belong to an auth wall, 
rate-limit, or WAF block page and may not represent the real application response.
------------------------------------------------------------------------

[WARN][LOW] HSTS: HSTS present but includeSubDomains is not set (may be acceptable).
       Recommendation: Consider adding includeSubDomains if you control and serve 
       all subdomains over HTTPS.

[FAIL][MEDIUM] CSP: Missing Content-Security-Policy header.
       Recommendation: Add a Content-Security-Policy to reduce XSS impact 
       (start with a restrictive policy and iterate).

[PASS][LOW] X-Frame-Options: X-Frame-Options set to a safe value: SAMEORIGIN
...
```

### Hunter mode (default) focuses on FAIL/WARN and adds reportability hints:
```
[FAIL][MEDIUM] CSP: Missing Content-Security-Policy header.
       Recommendation: Add a Content-Security-Policy to reduce XSS impact 
       (start with a restrictive policy and iterate).
       Reportability: Often rejected unless paired with XSS; sometimes 
       accepted as hardening.
```

## Notes and Limitations

- Header checks are heuristic. Some headers are optional depending on the app.
- A missing header is not automatically a "bug bounty valid" finding.
- CSP absence is often rejected unless paired with a real XSS. Use it as a signal to prioritize XSS testing.
- If the server returns 401/403/429 (or other non-2xx), the response may be an edge/WAF/auth wall. Headers may not represent the real application.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

## License

MIT License. See `LICENSE` for details.
