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

R-AScan is a Python 3.10+ command-line web vulnerability scanner. Its core is a dynamic plugin runner that discovers every Python file under `r_ascan/scanners/`, imports it at runtime, calls a module-level `scan(args)` function, and aggregates each result into JSON.

The repository is small (about 3,000 lines of Python), but the technical depth is moderate because it combines dynamic loading, nested concurrency, HTTP and raw-socket probing, HTML/JavaScript analysis, heuristic vulnerability detection, package resources, self-updating code, and optional machine-learning post-processing.

The local development branch is `main`. The remote currently exposes only `origin/pypi-release`; an upstream `main` branch has not yet been created or pushed.

## Architecture

```text
CLI arguments
    |
    v
r_ascan.app.RAScan
    |
    +-- recursively discovers scanners/*.py
    +-- dynamically imports each module
    +-- executes modules in a ThreadPoolExecutor
    +-- collects heterogeneous scanner results
    +-- writes scan_output-<target>.json
    |
    +-- optional ml_optimizer post-processing

Scanner module
    |
    +-- exposes scan(args)
    +-- performs HTTP/socket tests
    +-- may create its own worker pool
    +-- returns a JSON-serializable dict or list
```

### Main components

- `r_ascan/app.py`: CLI, module discovery/loading, top-level scheduling, update mechanism, and JSON output.
- `r_ascan/config.py`: shared HTTP headers, timeout, payload parameter names, and resource paths.
- `r_ascan/scanners/`: independent discovery, enumeration, vulnerability, and exploit checks.
- `r_ascan/scanners/exploits/`: product/CVE-specific active checks.
- `r_ascan/resources/`: endpoint, directory, sensitive-file, and HTTP-smuggling payload data.
- `r_ascan/module/ml_optimizer.py`: per-run TF-IDF and random-forest classification of scanner output.
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

The application runs all scanner modules concurrently using `args.threads`. Many individual scanners also create thread pools of the same size. Effective concurrency can therefore approach:

```text
top-level workers × per-scanner workers
```

This creates potentially high connection counts, memory use, target load, and nondeterministic result order. Some scanners submit every payload/path combination up front, which can produce a large pending-future queue.

Development should move toward a shared scan context and global concurrency/request budget. Per-host rate limits, cancellation, backoff, and maximum-request controls are important for predictable and safe operation.

## Current Module Contract

A scanner is currently expected to provide:

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

This contract is implicit. There is no interface, abstract base class, metadata model, lifecycle hook, or result schema. Modules can also fail during import, and exceptions are reduced to console messages rather than represented in output.

A stronger plugin API should define:

- scanner ID, title, category, severity, and active/passive classification;
- supported protocols and required arguments;
- standardized `ScanContext`;
- standardized finding/evidence/error types;
- request and timeout policy;
- scanner-level status and timing;
- cleanup and cancellation behavior.

## Result and Detection Quality

Output currently has this shape:

```json
{
  "result": [
    {"scanner_name": {"scanner_specific": "data"}}
  ]
}
```

Every scanner returns a different structure. There is no common severity, confidence, CWE, OWASP mapping, evidence, remediation, timestamp, or request/response reference. This limits filtering, reporting, deduplication, regression testing, and machine processing.

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

Target construction is duplicated throughout the project. Most modules append `port` manually and try both HTTP and HTTPS, while others force HTTP, ignore the supplied port, or scan a fixed port list. `--path` is defined but is effectively unused. Passing a target that already contains a scheme or path can generate invalid URLs.

A single parsed target model should own scheme, host, port, base path, IPv6 formatting, URL joining, redirects, and TLS behavior.

### Networking behavior

- TLS verification is frequently disabled.
- Some modules suppress warnings globally.
- Broad or bare `except` blocks hide timeout, DNS, TLS, parsing, and programming errors.
- Shared authentication headers contain placeholder values and are sent broadly.
- Retry, proxy, user-agent, cookie, authentication, and rate-limit behavior are not configurable enough.
- Several checks issue state-changing POST, PUT, PATCH, or DELETE requests.
- Raw-socket modules need stricter host/port separation and protocol handling.

The scanner needs an explicit safe/default mode and a clearly authorized intrusive mode.

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

### ML optimizer

The optimizer creates labels from the same heuristic output it trains on, trains on only the modules from one scan, and predicts those same samples. Its probability is therefore not a meaningful independent vulnerability confidence score. Small scans may also lack two label classes and skip training.

Treat this feature as experimental. A production model requires a labeled multi-scan dataset, held-out evaluation, stable features, calibration, model persistence/versioning, and metrics. A deterministic scoring/rules engine would currently be more defensible.

### Testing and delivery

The repository has no automated test suite, fixtures, CI configuration, lint/type configuration, coverage target, or integration test harness. Network-heavy code is tightly coupled to `requests` and sockets, making deterministic testing difficult.

Packaging metadata requires Python 3.10+, while the README says Python 3.8+. Installation examples also refer to a legacy `R-AScan.py` file that is not present in this repository.

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
- Highest product risk: presenting heuristic signals as vulnerabilities without normalized confidence and evidence

R-AScan already demonstrates broad scanner coverage and a useful drop-in module model. The next engineering milestone should be reliability and evidence quality, followed by additional vulnerability coverage.
