# R-AScan Technical Development Notes

## Mandatory Development Workflow

`NOTE.md` is the sole repository source for project context and mandatory development workflow. No separate `AGENTS.md` is required.

Every development task must follow this documentation lifecycle:

1. Read `NOTE.md` completely as the first step, before analysis, planning, or implementation.
2. Implement and verify the requested change.
3. As the final step, update:
   - `NOTE.md` when the work changes architecture, behavior, risks, decisions, or development status.
   - `docs/changelog/YYYY/MM/DD.md` with the completed changes and verification performed.

The dated changelog path uses the current year, month, and day. Missing directories and files must be created. A development task is not complete until these final documentation updates are recorded.

## Project Summary

R-AScan is a Python 3.10+ command-line web vulnerability scanner. Its core is a dynamic plugin runner that discovers every Python file under `r_ascan/scanners/`, imports it at runtime, validates scanner metadata, calls a module-level `scan(args)` function, and aggregates each result into a normalized JSON envelope.

The repository is small (about 3,000 lines of Python), but the technical depth is moderate because it combines dynamic loading, nested concurrency, HTTP and raw-socket probing, HTML/JavaScript analysis, heuristic vulnerability detection, package resources, self-updating code, and optional machine-learning post-processing.

The local development branch is `main`. The remote currently exposes only `origin/pypi-release`; an upstream `main` branch has not yet been created or pushed.

## Architecture

```text
CLI arguments
    |
    v
r_ascan.app.RAScan
    |
    +-- validates a host/IP Target and optional port/base path
    +-- recursively discovers and classifies scanners/*.py
    +-- defaults to all scanners and optionally filters by safety mode, scanner ID, and category
    +-- executes one plugin at a time to bound nested concurrency
    +-- wraps heterogeneous scanner data in ScannerResult
    +-- normalizes every legacy scanner payload into findings/observations/errors
    +-- writes versioned JSON and optional self-contained HTML reports
    |
    +-- optional deterministic risk scoring and prioritization

Scanner module
    |
    +-- exposes scan(args)
    +-- performs HTTP/socket tests
    +-- may create its own worker pool
    +-- returns a JSON-serializable dict or list
```

### Main components

- `r_ascan/app.py`: CLI, module discovery/loading, filtering, orchestration, update mechanism, and JSON output.
- `r_ascan/core/`: target validation, scan context, HTTP transport, request budget, metadata registry, and normalized result models.
- `r_ascan/config.py`: shared HTTP headers, timeout, payload parameter names, and resource paths.
- `r_ascan/scanners/`: independent discovery, enumeration, vulnerability, and exploit checks.
- `r_ascan/scanners/exploits/`: product/CVE-specific active checks.
- `r_ascan/resources/`: endpoint, directory, sensitive-file, and HTTP-smuggling payload data.
- `r_ascan/core/normalize.py`: adapter from heterogeneous legacy scanner payloads to the common finding schema.
- `r_ascan/module/ml_optimizer.py`: deterministic confidence/status/severity risk scoring.
- `r_ascan/reporting/html.py`: self-contained, print-friendly HTML rendering
  from the normalized report using an absolute black-and-white palette on a
  white background.
- `r_ascan/module/other.py`: terminal color formatting.

## Scanner Coverage

The current modules cover four broad areas:

1. Reconnaissance and attack-surface discovery:
   service enumeration, endpoint extraction, directory enumeration, web-server fingerprinting, technology/framework detection, entry-point discovery, and HTML/JavaScript extraction.

2. Configuration and information exposure:
   security headers, deployment/hosting details, metadata files, sensitive files, source comments, and client-side credential-like patterns.

3. Generic vulnerability heuristics:
   SQL injection, command injection, LFI, RCE, XSS, SSRF, SSTI, LDAP injection, open redirect, access control, rate limiting, and HTTP request smuggling.

4. Targeted exploit checks:
   Apache Struts, PHPUnit RCE, and CVE-2025-32433-related SSH behavior.

Most findings are heuristic signals rather than confirmed exploit proofs. Status codes, response length differences, reflected payloads, error strings, and suspicious JavaScript constructs are used heavily. Results should therefore be treated as leads requiring validation.

## Execution and Concurrency Model

The runner now executes one scanner plugin at a time because legacy scanners still own internal thread pools. This bounds effective legacy concurrency to approximately `args.threads` instead of multiplying top-level and per-scanner workers.

```text
top-level workers × per-scanner workers
```

The shared `ScanContext` also provides a global request budget and bounded HTTP transport for migrated/new scanners. Legacy scanners still calling `requests` directly do not yet contribute to that request counter, and some still submit every payload/path combination up front.

Development should move toward a shared scan context and global concurrency/request budget. Per-host rate limits, cancellation, backoff, and maximum-request controls are important for predictable and safe operation.

## Current Module Contract

A scanner remains backward compatible with:

```python
def scan(args):
    return {"json_serializable": "result"}
```

The shared `args` object can contain:

- `target`
- `port`
- `path`
- `threads`
- `output`
- `verbose`
- `update`
- `optimize`

New scanners can declare a `SCANNER` metadata dictionary and consume
`args.context`, `args.target_model`, and `args.http`. Missing metadata is
inferred from the scanner path/name. Import and runtime exceptions are
represented as failed scanner results.

Repeatable `-H`, `--header`, and `--headers` options accept `Name: value`
pairs. Header names merge case-insensitively with last-value-wins behavior.
The merged dictionary is installed into both the shared HTTP transport and the
in-place `HTTP_HEADERS` dictionary referenced by legacy HTTP scanners.
Dedicated `--authorization` and `--cookie` values are applied last.

A stronger plugin API should define:

- scanner ID, title, category, severity, and active/passive classification;
- supported protocols and required arguments;
- standardized `ScanContext`;
- standardized finding/evidence/error types;
- request and timeout policy;
- scanner-level status and timing;
- cleanup and cancellation behavior.

## Result and Detection Quality

Output now uses schema version 2.0 with identical scanner result fields:

```json
{
  "schema_version": "2.0",
  "scan": {"target": {}, "mode": "safe-active"},
  "summary": {"finding_count": 0, "risk_score": 0},
  "results": [
    {
      "scanner": {},
      "status": "completed",
      "findings": [],
      "observations": [],
      "errors": [],
      "summary": {}
    }
  ]
}
```

All actionable output is converted to the shared `Finding` schema. Raw legacy
payloads are retained as observations so normalization does not discard useful
data. Scanner identity, mode, status, timing, errors, request count, and summary
fields are identical across modules.

A normalized finding should include at least:

```text
scanner_id, title, target, endpoint, method, severity, confidence,
status, evidence, reproduction, remediation, CWE, timestamps
```

The detection engine also needs explicit separation between:

- informational observations;
- potential findings;
- confirmed findings;
- scanner errors and skipped checks.

## Important Engineering Gaps

### Target and protocol handling

The CLI now requires a hostname or IP address and rejects URL schemes,
embedded ports, and paths. `--port` and `--path` are parsed separately by the
shared `Target` model, including IPv6 authority formatting. Legacy modules
still need incremental migration away from duplicated URL construction.

A single parsed target model should own scheme, host, port, base path, IPv6 formatting, URL joining, redirects, and TLS behavior.

### Networking behavior

- TLS verification is frequently disabled.
- `InsecureRequestWarning` is suppressed globally at the CLI entry point to
  prevent legacy scanners using `verify=False` from flooding terminal output;
  other Python warning categories remain visible.
- Custom HTTP headers are validated against malformed names and CR/LF header
  injection before being propagated to shared and legacy HTTP clients.
- Broad or bare `except` blocks hide timeout, DNS, TLS, parsing, and programming errors.
- Shared authentication headers contain placeholder values and are sent broadly.
- Retry, proxy, user-agent, cookie, authentication, and rate-limit behavior are not configurable enough.
- Several checks issue state-changing POST, PUT, PATCH, or DELETE requests.
- Raw-socket modules need stricter host/port separation and protocol handling.

The scanner now defaults to the maximum `exploit` mode and therefore executes
all discovered scanners. Users can explicitly reduce scope with
`--mode safe-active`, `--mode passive`, category filters, or scanner filters.
Because the default includes intrusive and exploit behavior, authorization
warnings in the README and CLI usage are operationally important.

### False positives and negatives

Several detectors rely on weak evidence:

- reflected text is treated as XSS without checking execution context or encoding;
- suspicious DOM APIs are treated as DOM XSS without source-to-sink data flow;
- successful access-control responses are potential findings without authenticated role comparison;
- response status/length differences can be caused by generic error pages;
- HTTP-smuggling keyword/status heuristics are not sufficient confirmation;
- stored-XSS testing assumes a `/post` endpoint and may mutate target data.

Baseline comparison, random canaries, content similarity, control requests, repeated confirmation, and evidence capture should be reusable framework services rather than scanner-specific code.

### Self-update mechanism

`--update` recursively downloads and overwrites package code directly from GitHub without signature/hash verification, staging, rollback, compatibility validation, or atomic replacement. It also updates more than scanner modules despite the CLI wording.

Prefer signed package releases or a versioned scanner bundle. If live updates remain, download into staging, verify a manifest, validate imports, and atomically switch versions.

### Result optimizer

The invalid per-scan TF-IDF/random-forest optimizer has been replaced. The
current optimizer applies explicit severity, confidence, and finding-status
factors, records its engine version, assigns priorities, and produces a
reproducible 0–100 report risk score. This is prioritization, not an independent
proof that a vulnerability exists.

### Testing and delivery

The repository now has `unittest` coverage for target parsing, scanner
selection/mode enforcement, request budgets, result normalization,
deterministic scoring, and safe HTML escaping. Mocked scanner tests,
fixtures, CI, lint/type configuration, coverage targets, and integration
harnesses remain to be added.

Packaging metadata and the README now consistently require Python 3.10+. README installation and usage examples use the packaged `R-AScan` entry point instead of the removed legacy `R-AScan.py` command.

Release `0.1.1` metadata is prepared in `pyproject.toml` with SPDX licensing,
project URLs, classifiers, keywords, synchronized runtime dependencies, package
resource inclusion, and build-artifact exclusions. `RELEASE.md` documents the
maintainer build/upload workflow. Wheel and source archives must pass
`twine check` and a clean local wheel installation before publication.
PyPI rejected `0.1.0` because its filenames had previously been uploaded and
then deleted. PyPI permanently reserves deleted filenames, so the pending
release was advanced to `0.1.1`.

### User documentation

The README now documents PyPI, `pipx`, and editable source installation; current CLI options and examples; JSON output; updater limitations; scanner module development; project structure; authorization requirements; and heuristic-result limitations. The original project badges and screenshot are retained.

## Recommended Development Priorities

### Phase 1: stabilize the core

1. Introduce `Target`, `ScanConfig`, `ScanContext`, `ScannerResult`, and `Finding` models.
2. Centralize HTTP sessions, URL construction, timeout, TLS, proxy, authentication, and retry policy.
3. Validate module metadata and result serialization before execution.
4. Record scanner success, failure, duration, request count, and errors in output.
5. Enforce a global concurrency and request budget.
6. Add graceful interruption and cancellation.

### Phase 2: establish quality controls

1. Add unit tests for URL handling, resource loading, parsers, baselines, and result normalization.
2. Add mocked HTTP tests for every scanner.
3. Build local vulnerable/clean integration fixtures for high-value checks.
4. Add formatting, linting, type checking, security checks, and CI.
5. Add deterministic scanner selection so tests and users can run named categories/modules.

### Phase 3: improve detection

1. Add reusable control-request and response-similarity logic.
2. Preserve sanitized request/response evidence for each finding.
3. Require repeated confirmation for noisy active checks.
4. Add confidence and severity rules with CWE/OWASP mappings.
5. Separate passive, safe-active, intrusive, and exploit checks.

### Phase 4: improve operability

1. Add structured logging and stable exit codes.
2. Support JSON Lines/SARIF in addition to the current JSON report.
3. Add scan metadata, module versions, timestamps, and configuration snapshots.
4. Add checkpointing, resumability, and request statistics.
5. Replace direct source overwrite updates with verified, versioned releases.

## Suggested Package Direction

```text
r_ascan/
├── cli.py
├── core/
│   ├── context.py
│   ├── target.py
│   ├── transport.py
│   ├── scheduler.py
│   ├── models.py
│   └── registry.py
├── scanners/
│   ├── passive/
│   ├── active/
│   └── intrusive/
├── reporting/
├── resources/
└── tests/
```

The most valuable refactor is not adding more scanner modules. It is building a reliable core contract, normalized evidence model, controlled transport layer, and test harness. Those changes would make existing scanners easier to validate and would reduce the cost and risk of every future scanner.

## Development Assessment

- Architecture complexity: moderate
- Networking/security-domain complexity: moderate to high
- Current implementation maturity: prototype/early-stage tool
- Extensibility: high in concept, weakly governed in implementation
- Detection confidence: variable and primarily heuristic
- Testability: low until transport and target handling are decoupled
- Highest technical risk: uncontrolled nested concurrency and inconsistent networking semantics
- Highest product risk: running intrusive/exploit checks by default without the
  operator understanding their potential side effects

R-AScan already demonstrates broad scanner coverage and a useful drop-in module model. The next engineering milestone should be reliability and evidence quality, followed by additional vulnerability coverage.
