
from probe.models import Finding
from probe.scanner import ScanResult
from probe.reporting import (
    build_report,
    save_json_report,
    save_text_report,
)


def make_result():
    finding = Finding(
        name="Missing HSTS",
        severity="MEDIUM",
        category="Security Headers",
        description="HSTS header was not observed.",
        target="https://example.com",
        evidence="Header was missing.",
    )

    return ScanResult(
        target="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        server="test-server",
        response_time=0.123,
        findings=[finding],
    )


def test_build_report():

    result = make_result()

    report = build_report(result)

    assert isinstance(report, dict)
    assert report["target"] == "https://example.com"
    assert report["status_code"] == 200
    assert len(report["findings"]) == 1
    assert report["findings"][0]["severity"] == "MEDIUM"


def test_save_json_report(tmp_path):

    result = make_result()

    file_path = save_json_report(
        result,
        output_dir=tmp_path
    )

    assert file_path.exists()
    assert file_path.suffix == ".json"

    content = file_path.read_text(
        encoding="utf-8"
    )

    assert "Missing HSTS" in content
    assert "MEDIUM" in content


def test_save_text_report(tmp_path):

    result = make_result()

    file_path = save_text_report(
        result,
        output_dir=tmp_path
    )

    assert file_path.exists()
    assert file_path.suffix == ".txt"

    content = file_path.read_text(
        encoding="utf-8"
    )

    assert "PROBE" in content
    assert "Missing HSTS" in content
    assert "MEDIUM" in content
    assert "Security Headers" in content

