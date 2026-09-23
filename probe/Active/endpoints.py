
from urllib.parse import urljoin

from ..models import Finding


SAFE_ENDPOINTS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
)


def check_safe_endpoints(session, target, timeout=10):
    """
    Check a small predefined set of commonly exposed,
    non-destructive endpoints.
    """

    findings = []

    for endpoint in SAFE_ENDPOINTS:
        url = urljoin(target.rstrip("/") + "/", endpoint.lstrip("/"))

        try:
            response = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
            )

            if response.status_code < 400:
                findings.append(
                    Finding(
                        name=f"Safe endpoint discovered: {endpoint}",
                        severity="INFO",
                        category="Endpoint Discovery",
                        description=(
                            "A predefined safe endpoint responded "
                            "successfully."
                        ),
                        target=target,
                        evidence=(
                            f"URL: {response.url}; "
                            f"status: {response.status_code}"
                        ),
                    )
                )

        except Exception:
            # Endpoint failures are intentionally ignored.
            # The main target scan should not fail because
            # one optional endpoint is unavailable.
            continue

    return findings

