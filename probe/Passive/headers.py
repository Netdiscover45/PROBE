
from ..models import Finding


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "MEDIUM",
        "Content Security Policy (CSP) was not observed."
    ),
    "Strict-Transport-Security": (
        "MEDIUM",
        "HTTP Strict Transport Security (HSTS) was not observed."
    ),
    "X-Content-Type-Options": (
        "LOW",
        "X-Content-Type-Options was not observed."
    ),
    "X-Frame-Options": (
        "LOW",
        "X-Frame-Options was not observed."
    ),
    "Referrer-Policy": (
        "LOW",
        "Referrer-Policy was not observed."
    ),
    "Permissions-Policy": (
        "LOW",
        "Permissions-Policy was not observed."
    ),
}


def check_headers(response, target):
    findings = []

    for header, (severity, description) in SECURITY_HEADERS.items():
        if header not in response.headers:
            findings.append(
                Finding(
                    name=f"Missing {header}",
                    severity=severity,
                    category="Security Headers",
                    description=description,
                    target=target,
                    evidence=f"Header '{header}' was not present."
                )
            )

    return findings
