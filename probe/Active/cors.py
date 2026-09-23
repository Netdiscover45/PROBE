
from ..models import Finding


PROBE_ORIGIN = "https://probe.invalid"


def check_cors(session, target, timeout=10):
    """
    Controlled CORS check.

    Sends one GET request with a benign Origin value and
    inspects the returned CORS headers.
    """

    findings = []

    try:
        response = session.get(
            target,
            headers={
                "Origin": PROBE_ORIGIN
            },
            timeout=timeout,
            allow_redirects=True,
        )

        allow_origin = response.headers.get(
            "Access-Control-Allow-Origin"
        )

        allow_credentials = response.headers.get(
            "Access-Control-Allow-Credentials"
        )

        if not allow_origin:
            findings.append(
                Finding(
                    name="CORS header not observed",
                    severity="INFO",
                    category="CORS",
                    description=(
                        "The response did not include "
                        "Access-Control-Allow-Origin."
                    ),
                    target=target,
                    evidence=(
                        f"Origin sent: {PROBE_ORIGIN}; "
                        f"status: {response.status_code}"
                    ),
                )
            )
            return findings

        if allow_origin == "*":
            severity = "LOW"

            if (
                allow_credentials
                and allow_credentials.lower() == "true"
            ):
                severity = "MEDIUM"

            findings.append(
                Finding(
                    name="Wildcard CORS policy observed",
                    severity=severity,
                    category="CORS",
                    description=(
                        "The target allows cross-origin requests "
                        "from any origin according to the response."
                    ),
                    target=target,
                    evidence=(
                        f"Access-Control-Allow-Origin: {allow_origin}; "
                        f"Access-Control-Allow-Credentials: "
                        f"{allow_credentials or 'not observed'}"
                    ),
                )
            )

        elif allow_origin == PROBE_ORIGIN:
            findings.append(
                Finding(
                    name="CORS reflects supplied origin",
                    severity="MEDIUM",
                    category="CORS",
                    description=(
                        "The target returned the supplied probe "
                        "origin in Access-Control-Allow-Origin."
                    ),
                    target=target,
                    evidence=(
                        f"Access-Control-Allow-Origin: "
                        f"{allow_origin}"
                    ),
                )
            )

        else:
            findings.append(
                Finding(
                    name="Specific CORS origin observed",
                    severity="INFO",
                    category="CORS",
                    description=(
                        "The target returned a specific "
                        "Access-Control-Allow-Origin value."
                    ),
                    target=target,
                    evidence=(
                        f"Access-Control-Allow-Origin: "
                        f"{allow_origin}"
                    ),
                )
            )

    except Exception as exc:
        findings.append(
            Finding(
                name="CORS check failed",
                severity="INFO",
                category="CORS",
                description=(
                    "The controlled CORS check could not "
                    "be completed."
                ),
                target=target,
                evidence=str(exc),
            )
        )

    return findings
