#python
import time
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import requests

from .Passive.headers import check_headers
from .Passive.cookies import check_cookies
from .Passive.redirects import check_redirects
from .Passive.disclosure import check_disclosure

from .Active.methods import check_methods
from .Active.cors import check_cors
from .Active.endpoints import check_safe_endpoints


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status_code: int | None = None
    content_type: str = ""
    server: str = ""
    response_time: float = 0.0
    error: str = ""
    findings: list = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []

    def to_dict(self):
        data = asdict(self)

        data["findings"] = [
            finding.to_dict()
            if hasattr(finding, "to_dict")
            else finding
            for finding in self.findings
        ]

        return data


class Scanner:

    def __init__(self, timeout=10):

        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": "PROBE/0.1 Security Scanner"
        })

    @staticmethod
    def validate_url(target):

        target = target.strip()

        parsed = urlparse(target)

        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                "Target must start with http:// or https://"
            )

        if not parsed.netloc:
            raise ValueError(
                "Invalid target URL"
            )

        return target

    def _run_passive_checks(self, response, target):

        findings = []

        checks = (
            check_headers,
            check_cookies,
            check_redirects,
            check_disclosure,
        )

        for check in checks:

            try:
                findings.extend(
                    check(
                        response,
                        target
                    )
                )

            except Exception:
                # One passive check should never
                # stop the complete scan.
                continue

        return findings

    def _run_active_checks(self, target):

        findings = []

        active_checks = (
            (
                "HTTP Methods",
                check_methods
            ),
            (
                "CORS",
                check_cors
            ),
            (
                "Safe Endpoints",
                check_safe_endpoints
            ),
        )

        for _, check in active_checks:

            try:

                findings.extend(
                    check(
                        self.session,
                        target,
                        timeout=self.timeout
                    )
                )

            except Exception:
                # Active checks are isolated so one
                # failed check does not stop the scan.
                continue

        return findings

    def scan(
        self,
        target,
        passive=True,
        active=False,
        full=False
    ):

        target = self.validate_url(target)

        # -------------------------------------------------
        # MODE HANDLING
        # -------------------------------------------------

        if full:

            passive = True
            active = True

        elif not passive and not active:

            # Default mode
            passive = True

        start = time.perf_counter()

        try:

            # -------------------------------------------------
            # BASE HTTP REQUEST
            # -------------------------------------------------

            response = self.session.get(
                target,
                timeout=self.timeout,
                allow_redirects=True
            )

            elapsed = time.perf_counter() - start

            findings = []

            # -------------------------------------------------
            # PASSIVE MODE
            # -------------------------------------------------

            if passive:

                findings.extend(
                    self._run_passive_checks(
                        response,
                        target
                    )
                )

            # -------------------------------------------------
            # ACTIVE MODE
            # -------------------------------------------------

            if active:

                findings.extend(
                    self._run_active_checks(
                        target
                    )
                )

            # -------------------------------------------------
            # RESULT
            # -------------------------------------------------

            return ScanResult(
                target=target,
                final_url=response.url,
                status_code=response.status_code,
                content_type=response.headers.get(
                    "Content-Type",
                    ""
                ),
                server=response.headers.get(
                    "Server",
                    ""
                ),
                response_time=round(
                    elapsed,
                    3
                ),
                findings=findings
            )

        except requests.exceptions.Timeout:

            return ScanResult(
                target=target,
                error="Request timed out."
            )

        except requests.exceptions.SSLError as exc:

            return ScanResult(
                target=target,
                error=f"TLS/SSL error: {exc}"
            )

        except requests.exceptions.ConnectionError as exc:

            return ScanResult(
                target=target,
                error=f"Connection error: {exc}"
            )

        except requests.exceptions.HTTPError as exc:

            return ScanResult(
                target=target,
                error=f"HTTP error: {exc}"
            )

        except requests.exceptions.RequestException as exc:

            return ScanResult(
                target=target,
                error=f"Request error: {exc}"
            )

        except Exception as exc:

            return ScanResult(
                target=target,
                error=f"Unexpected error: {exc}"
            )

