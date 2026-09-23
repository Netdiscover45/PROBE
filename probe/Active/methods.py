
from ..models import Finding


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def check_methods(session, target, timeout=10):
    """
    Controlled HTTP method check.

    Sends an OPTIONS request and inspects the Allow header.
    Only safe, non-destructive methods are considered.
    """

    findings = []

    try:
        response = session.options(
            target,
            timeout=timeout,
            allow_redirects=True,
        )

        allow_header = response.headers.get("Allow", "")

        if not allow_header:
            findings.append(
                Finding(
                    name="HTTP methods not disclosed",
                    severity="INFO",
                    category="HTTP Methods",
                    description=(
                        "The target did not provide an Allow header "
                        "in response to OPTIONS."
                    ),
                    target=target,
                    evidence=f"OPTIONS status: {response.status_code}",
                )
            )
            return findings

        methods = {
            method.strip().upper()
            for method in allow_header.split(",")
            if method.strip()
        }

        unexpected_methods = sorted(
            methods - set(SAFE_METHODS)
        )

        if unexpected_methods:
            findings.append(
                Finding(
                    name="Additional HTTP methods advertised",
                    severity="LOW",
                    category="HTTP Methods",
                    description=(
                        "The target advertised HTTP methods beyond "
                        "the basic safe methods checked by PROBE."
                    ),
                    target=target,
                    evidence=(
                        f"Allow: {allow_header}"
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    name="HTTP methods observed",
                    severity="INFO",
                    category="HTTP Methods",
                    description=(
                        "The target responded to OPTIONS and "
                        "disclosed its advertised HTTP methods."
                    ),
                    target=target,
                    evidence=f"Allow: {allow_header}",
                )
            )

    except Exception as exc:
        findings.append(
            Finding(
                name="HTTP method check failed",
                severity="INFO",
                category="HTTP Methods",
                description=(
                    "The controlled HTTP method check could not "
                    "be completed."
                ),
                target=target,
                evidence=str(exc),
            )
        )

    return findings

