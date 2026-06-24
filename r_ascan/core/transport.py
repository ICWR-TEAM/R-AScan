from __future__ import annotations

import threading
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .scheduler import RequestBudget
from .target import Target


class HttpTransport:
    def __init__(
        self,
        target: Target,
        budget: RequestBudget,
        *,
        timeout: float,
        verify_tls: bool,
        headers: dict[str, str],
        proxy: str | None = None,
    ):
        self.target = target
        self.budget = budget
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = headers
        self.proxy = proxy
        self._local = threading.local()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(self.headers)
            retry = Retry(
                total=1,
                connect=1,
                read=0,
                backoff_factor=0.2,
                status_forcelist=(429, 502, 503, 504),
                allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            )
            session.mount("http://", HTTPAdapter(max_retries=retry))
            session.mount("https://", HTTPAdapter(max_retries=retry))
            if self.proxy:
                session.proxies.update({"http": self.proxy, "https": self.proxy})
            self._local.session = session
        return session

    def request(
        self,
        method: str,
        url: str,
        *,
        intrusive: bool = False,
        **kwargs: Any,
    ) -> requests.Response:
        if intrusive and not kwargs.pop("_intrusive_allowed", False):
            raise PermissionError("intrusive request was not explicitly authorized")
        self.budget.acquire()
        try:
            kwargs.setdefault("timeout", self.timeout)
            kwargs.setdefault("verify", self.verify_tls)
            return self._session().request(method, url, **kwargs)
        finally:
            self.budget.release()

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)
