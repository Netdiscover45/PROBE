
import json
from pathlib import Path


def build_report(result):
    """
    Convert a ScanResult into a JSON-serializable dictionary.
    """

    if hasattr(result, "to_dict"):
        return result.to_dict()

    return result


def save_json_report(result, output_dir="reports/json"):
    """
    Save scan result as a JSON report.
    """

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report = build_report(result)

    filename = "probe_report.json"
    file_path = output_path / filename

    with file_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return file_path


def save_text_report(result, output_dir="reports/txt"):
    """
    Save scan result as a readable TXT report.
    """

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    filename = "probe_report.txt"
    file_path = output_path / filename

    findings = getattr(result, "findings", [])

    lines = []

    lines.append("=" * 60)
    lines.append("PROBE - Python Web Vulnerability Scanner")
    lines.append("=" * 60)
    lines.append("")

    lines.append(f"Target        : {getattr(result, 'target', '')}")
    lines.append(f"Final URL     : {getattr(result, 'final_url', '')}")
    lines.append(f"Status Code   : {getattr(result, 'status_code', '')}")
    lines.append(f"Content-Type  : {getattr(result, 'content_type', '')}")
    lines.append(f"Server        : {getattr(result, 'server', '')}")
    lines.append(f"Response Time : {getattr(result, 'response_time', '')}")
    lines.append(f"Error         : {getattr(result, 'error', '')}")
    lines.append("")

    lines.append("=" * 60)
    lines.append(f"FINDINGS: {len(findings)}")
    lines.append("=" * 60)

    if not findings:
        lines.append("No findings detected.")

    else:
        for index, finding in enumerate(
            findings,
            start=1
        ):
            lines.append("")
            lines.append(
                f"[{index}] {finding.name}"
            )
            lines.append(
                f"    Severity   : {finding.severity}"
            )
            lines.append(
                f"    Category   : {finding.category}"
            )
            lines.append(
                f"    Description: {finding.description}"
            )

            if finding.evidence:
                lines.append(
                    f"    Evidence   : {finding.evidence}"
                )

    lines.append("")
    lines.append("=" * 60)
    lines.append("END OF REPORT")
    lines.append("=" * 60)

    file_path.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    return file_path

