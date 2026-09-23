
from ..models import Finding


def check_disclosure(response, target):
    findings = []

    server = response.headers.get("Server")
    powered_by = response.headers.get("X-Powered-By")

    if server:
        findings.append(
            Finding(
                name="Server header disclosure",
                severity="INFO",
                category="Information Disclosure",
                description="The server response exposed a Server header.",
                target=target,
                evidence=f"Server: {server}"
            )
        )

    if powered_by:
        findings.append(
            Finding(
                name="X-Powered-By header disclosure",
                severity="LOW",
                category="Information Disclosure",
                description="The response exposed an X-Powered-By header.",
                target=target,
                evidence=f"X-Powered-By: {powered_by}"
            )
        )

    return findings

