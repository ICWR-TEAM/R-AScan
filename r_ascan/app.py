from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import requests
from urllib3.exceptions import InsecureRequestWarning

from r_ascan.config import DEFAULT_TIMEOUT, HTTP_HEADERS
from r_ascan.core.context import ScanConfig, ScanContext
from r_ascan.core.models import MODE_ORDER, ScannerResult
from r_ascan.core.normalize import normalize_result, summarize
from r_ascan.core.registry import csv_set, inferred_metadata, selected
from r_ascan.core.target import Target
from r_ascan.module.other import Other

sys.dont_write_bytecode = True
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
DEFAULT_HTTP_HEADERS = dict(HTTP_HEADERS)

BANNER = r"""
$$$$$$$\           $$$$$$\   $$$$$$\
$$  __$$\         $$  __$$\ $$  __$$\
$$ |  $$ |        $$ /  $$ |$$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\
$$$$$$$  |$$$$$$\ $$$$$$$$ |\$$$$$$\  $$  _____|\____$$\ $$  __$$\
$$  __$$< \______|$$  __$$ | \____$$\ $$ /      $$$$$$$ |$$ |  $$ |
$$ |  $$ |        $$ |  $$ |$$\   $$ |$$ |     $$  __$$ |$$ |  $$ |
$$ |  $$ |        $$ |  $$ |\$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |
\__|  \__|        \__|  \__| \______/  \_______|\_______|\__|  \__|
===================================================================
[+] R-AScan (Rusher Automatic Scan) | HarshXor - incrustwerush.org
===================================================================
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_headers(values: list[str] | None) -> dict[str, str]:
    """Parse repeatable ``Name: value`` headers with case-insensitive merging."""
    merged: dict[str, tuple[str, str]] = {}
    for raw in values or []:
        if "\r" in raw or "\n" in raw:
            raise ValueError("header values cannot contain CR or LF characters")
        name, separator, value = raw.partition(":")
        name = name.strip()
        value = value.strip()
        if not separator or not name:
            raise ValueError(
                f"invalid header {raw!r}; expected 'Name: value'"
            )
        if any(char.isspace() for char in name):
            raise ValueError(f"invalid header name: {name!r}")
        key = name.casefold()
        merged[key] = (name, value)
    return {name: value for name, value in merged.values()}


def merge_headers(base: dict[str, str], extra: dict[str, str]) -> dict[str, str]:
    """Merge headers case-insensitively; later values replace earlier values."""
    merged: dict[str, tuple[str, str]] = {
        name.casefold(): (name, value) for name, value in base.items()
    }
    for name, value in extra.items():
        merged[name.casefold()] = (name, value)
    return {name: value for name, value in merged.values()}


class RAScan:
    def __init__(self, args: argparse.Namespace, scanner_dir: str = "./"):
        self.args = args
        self.scanner_dir = Path(__file__).parent / scanner_dir
        self.module_dir = Path(__file__).parent / "scanners"
        self.target = Target.parse(args.target, args.port, args.path) if args.target else None
        self.headers = self._headers()
        # Legacy scanners import this dictionary by reference. Mutating it
        # propagates CLI headers without replacing each legacy request call.
        HTTP_HEADERS.clear()
        HTTP_HEADERS.update(self.headers)
        config = ScanConfig(
            threads=args.threads,
            max_requests=args.max_requests,
            timeout=args.timeout,
            verify_tls=not args.insecure,
            max_mode=args.mode,
            verbose=args.verbose,
        )
        self.context = (
            ScanContext.create(self.target, config, self.headers, args.proxy)
            if self.target else None
        )
        # Backward-compatible plugin attributes. New plugins should use args.context.
        args.context = self.context
        args.target_model = self.target
        args.http = self.context.transport if self.context else None
        args.base_urls = (
            [self.target.base_url("https"), self.target.base_url("http")]
            if self.target else []
        )
        self.results: list[dict[str, Any]] = []

    def _headers(self) -> dict[str, str]:
        headers = merge_headers(
            DEFAULT_HTTP_HEADERS, parse_headers(self.args.headers)
        )
        if self.args.authorization:
            headers = merge_headers(
                headers, {"Authorization": self.args.authorization}
            )
        if self.args.cookie:
            headers = merge_headers(headers, {"Cookie": self.args.cookie})
        return headers

    def update_scanners_from_github(self) -> None:
        print("[*] [Update Scanners]")
        base_url = (
            "https://api.github.com/repos/ICWR-TEAM/R-AScan/contents/"
            "r_ascan?ref=pypi-release"
        )

        def fetch_and_save(remote_url: str, local_dir: Path) -> None:
            response = requests.get(remote_url, timeout=10)
            response.raise_for_status()
            contents = response.json()
            if not isinstance(contents, list):
                raise RuntimeError(f"unexpected update response from {remote_url}")
            for item in contents:
                item_path = local_dir / item["name"]
                if item["type"] == "dir":
                    item_path.mkdir(parents=True, exist_ok=True)
                    fetch_and_save(item["url"], item_path)
                elif item.get("download_url"):
                    code = requests.get(item["download_url"], timeout=10)
                    code.raise_for_status()
                    temporary = item_path.with_suffix(f"{item_path.suffix}.tmp")
                    temporary.write_bytes(code.content)
                    temporary.replace(item_path)
                    print(f"[+] [Downloaded: {item_path.relative_to(self.scanner_dir.parent)}]")

        fetch_and_save(base_url, self.scanner_dir)

    def discover_modules(self) -> list[Path]:
        return sorted(
            path for path in self.module_dir.rglob("*.py")
            if not path.name.startswith("__")
        )

    def load_module(self, file_path: Path) -> tuple[str, ModuleType]:
        relative = file_path.relative_to(self.module_dir).with_suffix("")
        module_name = "r_ascan.dynamic." + ".".join(relative.parts)
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot create import spec for {file_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return file_path.stem, module

    def scanner_catalog(self) -> list[tuple[Path, ModuleType, object]]:
        catalog = []
        for path in self.discover_modules():
            try:
                _, module = self.load_module(path)
                catalog.append((path, module, inferred_metadata(path, getattr(module, "SCANNER", None))))
            except Exception as exc:
                print(f"[!] [Cannot load {path.name}: {type(exc).__name__}: {exc}]")
        return catalog

    def scan_module(self, path: Path, module: ModuleType, metadata: object) -> dict[str, Any]:
        started_at = utc_now()
        started = time.monotonic()
        initial_requests = self.context.budget.count if self.context else 0
        colored = Other().color_text(metadata.id, "cyan")
        print(f"[*] [Module: {colored}] [Started Scan] [Mode: {metadata.mode}]")
        try:
            scan = getattr(module, "scan", None)
            if not callable(scan):
                raise TypeError("module does not expose callable scan(args)")
            data = scan(self.args)
            json.dumps(data)
            status = "completed"
            findings, observations, errors = normalize_result(metadata, self.target, data)
            if self.args.verbose:
                print(json.dumps(data, indent=2, default=str))
        except KeyboardInterrupt:
            if self.context:
                self.context.budget.cancel()
            raise
        except Exception as exc:
            status = "failed"
            findings = []
            observations = []
            errors = [{"type": type(exc).__name__, "message": str(exc)}]
            print(f"[-] [Error in {path.name}: {errors[0]['type']}: {errors[0]['message']}]")

        duration_ms = round((time.monotonic() - started) * 1000)
        request_count = (
            self.context.budget.count - initial_requests if self.context else 0
        )
        return ScannerResult(
            scanner=metadata,
            status=status,
            started_at=started_at,
            finished_at=utc_now(),
            duration_ms=duration_ms,
            request_count=request_count,
            findings=findings,
            observations=observations,
            errors=errors,
            summary={
                "finding_count": len(findings),
                "error_count": len(errors),
                "risk_score": round(sum(item.score for item in findings), 1),
            },
        ).as_dict()

    def run_all(self) -> Path | None:
        if self.args.update:
            self.update_scanners_from_github()
            print("[*] [Update complete]")
            if not self.target:
                return None

        catalog = self.scanner_catalog()
        if self.args.list_scanners:
            for _, _, metadata in catalog:
                print(f"{metadata.id:32} {metadata.mode:12} {metadata.category}")
            return None

        include = csv_set(self.args.scanners)
        exclude = csv_set(self.args.exclude)
        categories = csv_set(self.args.category)
        runnable = [
            item for item in catalog
            if selected(
                item[2],
                max_mode=self.args.mode,
                include=include,
                exclude=exclude,
                categories=categories,
            )
        ]
        if not runnable:
            raise RuntimeError("no scanners matched the requested filters")
        skipped = len(catalog) - len(runnable)

        print(
            f"[*] [Starting scan on: {Other().color_text(self.target.authority, 'yellow')}] "
            f"[Mode: {self.args.mode}] [Scanners: {len(runnable)}/{len(catalog)}]"
        )
        if skipped:
            print(
                f"[*] [Scanner filter] [{skipped} skipped by mode/category/include/exclude]"
            )
        # Plugins may own a worker pool. Running one plugin at a time keeps total
        # concurrency bounded by --threads until every plugin uses ScanContext.
        for path, module, metadata in runnable:
            self.results.append(self.scan_module(path, module, metadata))

        output_path = (
            Path(self.args.output)
            if self.args.output
            else Path.cwd() / f"scan_output-{self.target.host}.json"
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "schema_version": "2.0",
            "scan": {
                "target": self.target.as_dict(),
                "mode": self.args.mode,
                "threads": self.args.threads,
                "max_requests": self.args.max_requests,
                "request_count": self.context.budget.count,
                "scanner_count": len(self.results),
                "discovered_scanner_count": len(catalog),
                "skipped_scanner_count": skipped,
            },
            "summary": summarize(self.results),
            "results": self.results,
        }

        if self.args.optimize:
            from r_ascan.module import ml_optimizer
            print("[*] [Optimizer] Applying deterministic risk prioritization...")
            ml_optimizer.optimize_report(report)

        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        html_path = None
        if not self.args.no_html:
            from r_ascan.reporting import render_html_report
            html_path = Path(self.args.html_output) if self.args.html_output else output_path.with_suffix(".html")
            render_html_report(report, html_path)
            print(f"[*] [HTML report saved to '{html_path}']")

        print(f"[*] [Scan complete. Results saved to '{output_path}']")
        return output_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dynamic web security scanner for authorized targets."
    )
    parser.add_argument("-x", "--target", help="Target hostname or IP (not a URL)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Global worker limit")
    parser.add_argument("-o", "--output", help="JSON output path")
    parser.add_argument("-p", "--port", type=int, help="Custom target port")
    parser.add_argument("--path", default="/", help="Base URL path (default: /)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-requests", type=int, default=5000)
    parser.add_argument(
        "--mode",
        choices=tuple(MODE_ORDER),
        default="exploit",
        help="Maximum authorized scanner mode (default: exploit/all scanners)",
    )
    parser.add_argument("--scanners", action="append", help="Comma-separated scanner IDs")
    parser.add_argument("--exclude", action="append", help="Comma-separated scanner IDs")
    parser.add_argument("--category", action="append", help="Comma-separated categories")
    parser.add_argument("--list-scanners", action="store_true")
    parser.add_argument("--proxy", help="HTTP/S proxy URL")
    parser.add_argument(
        "-H",
        "--header",
        "--headers",
        dest="headers",
        action="append",
        default=[],
        metavar="'NAME: VALUE'",
        help=(
            "Custom HTTP header; repeat to add more. "
            "Later duplicate names replace earlier values."
        ),
    )
    parser.add_argument("--authorization", help="Authorization header value")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--optimize", action="store_true")
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate an HTML report (enabled by default; retained for compatibility)",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Do not generate the default HTML report",
    )
    parser.add_argument("--html-output", help="Custom HTML report path")
    return parser


def main() -> int:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.max_requests < 1:
        parser.error("--max-requests must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not args.update and not args.target and not args.list_scanners:
        parser.error("--target is required unless --update or --list-scanners is used")
    try:
        RAScan(args).run_all()
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled.")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
