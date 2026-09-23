
from ..models import Finding


def check_redirects(response, target):
    findings = []

    history = response.history

    if not history:
        return findings

    if len(history) >= 3:
        findings.append(
            Finding(
                name="Multiple HTTP redirects observed",
                severity="LOW",
                category="Redirects",
                description="The target required multiple redirects before reaching the final URL.",
                target=target,
                evidence=f"Redirect count: {len(history)}"
            )
        )

    return findings

