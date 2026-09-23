
from collections import Counter


SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def normalize_severity(severity):
    severity = str(severity).upper().strip()

    if severity not in SEVERITY_ORDER:
        return "INFO"

    return severity


def count_severities(findings):
    counts = Counter()

    for finding in findings:
        severity = normalize_severity(
            finding.severity
        )
        counts[severity] += 1

    return {
        "CRITICAL": counts.get("CRITICAL", 0),
        "HIGH": counts.get("HIGH", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "LOW": counts.get("LOW", 0),
        "INFO": counts.get("INFO", 0),
    }


def calculate_overall_risk(findings):
    if not findings:
        return "INFO"

    highest = 1

    for finding in findings:
        severity = normalize_severity(
            finding.severity
        )

        highest = max(
            highest,
            SEVERITY_ORDER[severity]
        )

    for severity, score in SEVERITY_ORDER.items():
        if score == highest:
            return severity

    return "INFO"


def build_risk_summary(findings):
    counts = count_severities(findings)

    return {
        "overall_risk": calculate_overall_risk(findings),
        "total_findings": len(findings),
        "counts": counts,
    }
