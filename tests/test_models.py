
from probe.models import Finding


def test_finding_creation():
    finding = Finding(
        name="Missing HSTS",
        severity="medium",
        category="Headers",
        description="HSTS header was not observed.",
        target="https://example.com",
    )

    assert finding.name == "Missing HSTS"
    assert finding.severity == "MEDIUM"
    assert finding.category == "Headers"
    assert finding.target == "https://example.com"
    assert finding.discovered_at


def test_finding_to_dict():
    finding = Finding(
        name="Server Disclosure",
        severity="LOW",
        category="Information Disclosure",
        description="Server header was observed.",
    )

    data = finding.to_dict()

    assert isinstance(data, dict)
    assert data["name"] == "Server Disclosure"
    assert data["severity"] == "LOW"
