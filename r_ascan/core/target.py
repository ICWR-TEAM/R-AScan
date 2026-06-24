from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urljoin


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


@dataclass(frozen=True, slots=True)
class Target:
    """A host/IP target with an optional explicit port and base path."""

    host: str
    port: int | None = None
    base_path: str = "/"

    @classmethod
    def parse(
        cls,
        host: str,
        port: str | int | None = None,
        base_path: str | None = None,
    ) -> "Target":
        value = (host or "").strip()
        if not value:
            raise ValueError("target host is required")
        if "://" in value or "/" in value or "?" in value or "#" in value:
            raise ValueError("target must be a hostname or IP address, not a URL")

        normalized = value
        if value.startswith("[") and value.endswith("]"):
            normalized = value[1:-1]
        elif value.count(":") == 1:
            raise ValueError("put the port in --port, not in --target")

        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(normalized):
                raise ValueError(f"invalid target host: {value!r}") from None
            normalized = normalized.rstrip(".").lower()

        parsed_port = None
        if port not in (None, ""):
            try:
                parsed_port = int(port)
            except (TypeError, ValueError):
                raise ValueError("port must be an integer between 1 and 65535") from None
            if not 1 <= parsed_port <= 65535:
                raise ValueError("port must be between 1 and 65535")

        path = (base_path or "/").strip() or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        if "?" in path or "#" in path:
            raise ValueError("base path cannot contain a query string or fragment")
        return cls(normalized, parsed_port, path)

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}" if self.port else host

    def socket_port(self, scheme: str) -> int:
        return self.port or (443 if scheme == "https" else 80)

    def base_url(self, scheme: str) -> str:
        if scheme not in {"http", "https"}:
            raise ValueError(f"unsupported URL scheme: {scheme}")
        return f"{scheme}://{self.authority}{self.base_path.rstrip('/')}"

    def url(self, scheme: str, path: str = "", query: str | None = None) -> str:
        base = f"{self.base_url(scheme)}/"
        safe_path = quote(path.lstrip("/"), safe="/:@%+;=")
        value = urljoin(base, safe_path)
        return f"{value}?{query}" if query else value

    def as_dict(self) -> dict[str, object]:
        return {"host": self.host, "port": self.port, "base_path": self.base_path}
