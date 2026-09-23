from .scoring import build_risk_summary


PROBE_VERSION = "0.1"


def print_banner():
    print()
    print("=" * 60)
    print(f" PROBE - Python Web Vulnerability Scanner V{PROBE_VERSION}")
    print("=" * 60)


def get_scan_mode(passive=True, active=False, full=False):
    if full:
        return "FULL"

    if active:
        return "ACTIVE"

    if passive:
        return "PASSIVE"

    return "PASSIVE"


def print_scan_result(
    result,
    passive=True,
    active=False,
    full=False
):
    findings = result.findings or []

    summary = build_risk_summary(findings)

    mode = get_scan_mode(
        passive=passive,
        active=active,
        full=full
    )

    print()
    print("-" * 60)
    print("SCAN RESULT")
    print("-" * 60)

    print(f"Target        : {result.target}")
    print(f"Scan Mode     : {mode}")
    print(f"Final URL     : {result.final_url}")
    print(f"Status Code   : {result.status_code}")

    print(
        f"Content-Type  : "
        f"{result.content_type or 'Unknown'}"
    )

    print(
        f"Server        : "
        f"{result.server or 'Unknown'}"
    )

    print(
        f"Response Time : "
        f"{result.response_time:.3f}s"
    )

    if result.error:
        print(
            f"Error         : "
            f"{result.error}"
        )

    print()
    print("-" * 60)
    print("RISK SUMMARY")
    print("-" * 60)

    print(
        f"Overall Risk   : "
        f"{summary['overall_risk']}"
    )

    print(
        f"Total Findings : "
        f"{summary['total_findings']}"
    )

    counts = summary["counts"]

    print(
        f"CRITICAL       : "
        f"{counts['CRITICAL']}"
    )

    print(
        f"HIGH           : "
        f"{counts['HIGH']}"
    )

    print(
        f"MEDIUM         : "
        f"{counts['MEDIUM']}"
    )

    print(
        f"LOW            : "
        f"{counts['LOW']}"
    )

    print(
        f"INFO           : "
        f"{counts['INFO']}"
    )

    print()
    print("-" * 60)
    print("FINDINGS")
    print("-" * 60)

    if not findings:
        print("No findings detected.")

    else:
        for index, finding in enumerate(
            findings,
            start=1
        ):
            print()
            print(
                f"[{index}] "
                f"{finding.name}"
            )

            print(
                f"    Severity   : "
                f"{finding.severity}"
            )

            print(
                f"    Category   : "
                f"{finding.category}"
            )

            print(
                f"    Description: "
                f"{finding.description}"
            )

            if finding.evidence:
                print(
                    f"    Evidence   : "
                    f"{finding.evidence}"
                )

    print()
    print("-" * 60)
    print("SCAN COMPLETE")
    print("-" * 60)