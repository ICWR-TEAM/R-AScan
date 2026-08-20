# R-AScan

---

Project Start Date: 2025-06-13
Last Update Project: 2026-08-21
Project Phase: Alpha
Project Status: Active development; command-line Python web security scanner with packaged release metadata and test coverage.

---

## Project Summary

R-AScan (Rusher Automatic Scanner) is a modular, multithreaded web security scanner written in Python. It discovers scanner modules at runtime from `r_ascan/scanners/`, runs them against an authorized target, normalizes heterogeneous scanner output, and writes JSON plus optional self-contained HTML reports. Its scope includes reconnaissance, configuration exposure checks, OWASP-style vulnerability heuristics, and selected product/CVE exploit checks. Results are heuristic and must be manually validated before remediation or disclosure.

## Mandatory Workflow

- First step for every task: always read NOTE.md before making changes.
- Check existing documentation before modifying architecture.
- Preserve existing project conventions.
- Last step for every task: always update NOTE.md and docs/changelog/[yyyy]/[mm]/[dd].md.

## Restrictions

- Do not modify core architecture without documentation.
- Do not remove existing features without confirmation.
- Do not introduce dependency without justification.
- Do not ignore existing project constraints.
- Use R-AScan only against systems the operator owns or has explicit permission to test; several modules send active payloads or state-changing HTTP requests.
- Treat scanner findings as leads, not proof; avoid presenting heuristic results as confirmed vulnerabilities without evidence.

## AI Operating Context

- AI acts as development assistant for the R-AScan repository.
- AI must read `NOTE.md` before making changes and update project memory/changelog at the end of meaningful tasks.
- AI must prioritize consistency with existing CLI, scanner module contracts, normalized result schema, packaging, and tests over speed.
- AI must document important behavior, architecture, risk, or workflow decisions.
- AI must avoid fabricating project facts; unknowns should be marked `TBD — confirm with maintainer`.
- AI must keep security-safety context visible because this project contains intrusive and exploit-oriented scanning modules.

## Technical Development Details

- Programming language: Python 3.10+.
- Framework: No web framework; console application packaged with setuptools.
- Package/build: `pyproject.toml` uses `setuptools>=77` and `wheel`; package name is `R-AScan`, version `0.0.17`, MIT license.
- CLI entrypoint: `[project.scripts] R-AScan = "r_ascan.app:main"`.
- Dependencies: `requests>=2.25.1`, `colorama>=0.4.6`, `beautifulsoup4>=4.12.3`.
- Infrastructure: Local command-line/network scanner; no server process or cloud infrastructure is defined in the repository.
- Database: None found; scan results are written to files rather than persisted in a DB.
- API structure: Plugin-style Python scanner API. Scanner files expose `scan(args)` and may optionally provide `SCANNER` metadata. The runner injects `args.context`, `args.target_model`, `args.http`, and `args.base_urls` for newer scanners while preserving legacy arguments.
- Deployment model: Installable from PyPI/pipx or source; supports Linux and Windows per README badges/docs. Package data includes resources, scanner files, module files, and HTML template resources.
- Coding convention: Python modules use type hints in core/entrypoint code, JSON-serializable result dictionaries, normalized result models, deterministic scanner discovery/filtering, and unittest-based tests under `tests/`.
- Security requirement: Authorized testing only; CLI supports headers, authorization, cookies, proxy, TLS verification controls, timeout/request budget, mode filtering, scanner/category selection, and warns that default/basic usage may run intrusive/exploit checks.

## Core Flow Project

- Input: CLI arguments such as target host/IP, port, path, threads, timeout, headers, authorization/cookie, proxy, TLS mode, scan mode, scanner/category filters, output path, HTML reporting, update, verbose, and optimizer options.
- Processing: `r_ascan.app.RAScan` parses target data with `Target`, merges/validates headers, creates `ScanConfig` and `ScanContext`, discovers Python modules recursively under `r_ascan/scanners/`, loads modules dynamically, infers/validates metadata, filters by mode/scanner/category, executes scanner `scan(args)` functions, captures exceptions as failed scanner results, and normalizes output via `r_ascan/core/normalize.py`.
- Logic: Scanner modules perform HTTP, HTTPS, raw-socket, parsing, and heuristic vulnerability checks for discovery, exposure, injection, access-control, rate-limiting, smuggling, and selected exploit scenarios. The runner aggregates findings, observations, errors, timing, request counts, and summaries using shared models.
- Output: Versioned normalized JSON reports with scan metadata, summary, and per-scanner results; optional self-contained PTES-style HTML report rendered by `r_ascan/reporting/html.py` using `r_ascan/resources/report_template.html`.
- External integration: Network requests to authorized scan targets; optional GitHub-based update mechanism fetching from `https://api.github.com/repos/ICWR-TEAM/R-AScan/contents/r_ascan?ref=pypi-release`; project URLs point to `https://github.com/ICWR-TEAM/R-AScan`.

## Architecture Decision Log

Date: 2025-06-13
Decision: Start R-AScan as a Python package/CLI web security scanner.
Reason: First git commit date and repository packaging identify a Python command-line security tool.
Impact: Project conventions center on Python modules, CLI arguments, package resources, and file-based reports.

Date: 2026-06-27
Decision: Harden several heuristic scanners against false positives and move HTML report structure/CSS into `r_ascan/resources/report_template.html`.
Reason: Existing changelog records stricter baselines/control checks and a resource-based PTES-style report template.
Impact: Scanner findings should distinguish potential from confirmed signals; HTML report structure is maintained as a package resource rather than hardcoded Python.

Date: 2026-08-20
Decision: Bootstrap standard documentation memory in `NOTE.md` and maintain daily changelog entries under `docs/changelog/`.
Reason: Future tasks need consistent repository context, workflow requirements, and change history.
Impact: Every task should begin by reading `NOTE.md` and end by updating `NOTE.md` plus the dated changelog when relevant.

Date: 2026-08-21
Decision: Execute scanner modules through a bounded `ThreadPoolExecutor` (`--scanner-workers`, auto = `max(threads, 4)`) instead of the previous strictly sequential loop, and attribute request counts per worker thread via a `RequestBudget` scope counter.
Reason: The sequential scanner loop was the primary wall-clock bottleneck for I/O-bound scans; the shared `RequestBudget` semaphore still caps concurrent transport requests to `--threads` and enforces `--max-requests`, so total request pressure stays bounded while latency overlaps.
Impact: Faster scans; discovery order of results preserved; per-scanner `request_count` remains precise for transport requests issued on the worker thread; scanner output is serialized through a print lock. Concurrency behavior is configurable and documented.

Date: 2026-08-21
Decision: Upgrade the risk optimizer to `deterministic-risk-v2` (bounded noisy-OR aggregation, cross-result finding de-duplication, precise 2-decimal scoring, priority bands, endpoint hotspots) and enrich normalized findings with OWASP Top 10 mapping, representative CVSS v3.1 vectors/scores, CVE hints, and references. The HTML report gained severity/priority/OWASP breakdowns, a risk-model section, hotspots, per-scanner request counts, and richer detail blocks.
Reason: The prior naive `min(100, sum(...))` aggregation saturated easily and double-counted findings; reports needed to be more detailed and the optimizer output more precise/auditable.
Impact: Aggregate risk is bounded, order-independent, deterministic, and de-duplicated; finding scores are explainable; reports carry substantially more context. Optimizer engine string changed to `deterministic-risk-v2` (tests updated accordingly).

Date: 2026-08-21
Decision: Published `R-AScan` `0.0.17` to PyPI using the PyPI API token stored in the AI's brainmemory (credential id `2ad6ef020c2e4cc0a62668033502ae21`), which the memory record originally documented as scoped to the unrelated `brainmemory-mcp` PyPI project.
Reason: The same token was already present in the local `~/.pypirc` and was requested for reuse; upload was attempted to fulfill the release request and observed to succeed for R-AScan too.
Impact: `https://pypi.org/project/R-AScan/0.0.17/` is now live (verified via PyPI JSON API). The brainmemory credential record was annotated (not replaced) to note the token's real scope is broader than originally documented — treat as potentially account-wide/multi-project going forward. The literal token value is intentionally not written into this repository.

## Current State

The repository contains a working Python package for R-AScan with a CLI entry point, dynamic scanner discovery, core target/context/transport/registry/normalization models, multiple scanner modules, package resources, HTML reporting, and unittest tests. README documents installation from PyPI, pipx, and source; usage examples; security warnings; and feature coverage. The manifest/package metadata include Python 3.10+ support, MIT license, dependencies, package data, and GitHub project URLs. Git history shows recent commits labeled mostly `Update`; first available commit date is 2025-06-13. Current working tree had `NOTE.md` deleted relative to git before this initialization; this task recreates it using the required standard structure.

## Pending Issue

Issue: Many scanners are heuristic and may produce false positives or false negatives.
Priority: High
Status: Ongoing; README and changelog acknowledge manual validation and recent false-positive hardening.
Possible Solution: Continue adding baseline/control requests, confidence levels, evidence quality checks, and tests for detector behavior.

Issue: Legacy scanners may bypass shared `ScanContext` request budgeting/transport by calling `requests` directly or managing their own concurrency.
Priority: High
Status: Partially migrated; shared context exists but backward compatibility remains.
Possible Solution: Incrementally migrate scanners to `args.context`/`args.http` and central request budget/rate-limit controls.

Issue: Default/basic scanning can include intrusive and exploit behavior.
Priority: High
Status: Documented in README; safety modes and filters exist.
Possible Solution: Keep authorization warnings prominent, consider safer default modes only with maintainer confirmation, and document behavior changes before implementation.

Issue: CI configuration was not found in the inspected file list.
Priority: Medium
Status: TBD — confirm with maintainer.
Possible Solution: Add documented CI for unittest/compile/package checks if desired.

Issue: Deployment beyond Python package installation is not defined.
Priority: Low
Status: No Dockerfile or service deployment config found.
Possible Solution: Document that the supported deployment model is local CLI installation unless container/server deployment is intentionally added.

## Changelog Reference

Daily changelog entries are maintained under `docs/changelog/` using `docs/changelog/[yyyy]/[mm]/[dd].md`.
