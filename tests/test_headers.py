
import requests

from probe.Passive.headers import check_headers


def test_missing_security_headers():
    response = requests.Response()
    response.status_code = 200
    response.headers = {}

    findings = check_headers(
        response,
        "https://example.com"
    )

    assert len(findings) == 6

    names = [finding.name for finding in findings]

    assert "Missing Content-Security-Policy" in names
    assert "Missing Strict-Transport-Security" in names
    assert "Missing X-Content-Type-Options" in names
    assert "Missing X-Frame-Options" in names
    assert "Missing Referrer-Policy" in names
    assert "Missing Permissions-Policy" in names


def test_security_headers_present():
    response = requests.Response()
    response.status_code = 200
    response.headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }

    findings = check_headers(
        response,
        "https://example.com"
    )

    assert findings == []

