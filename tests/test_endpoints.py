
import requests

from probe.Active.endpoints import check_safe_endpoints


class FakeSession:

    def __init__(self, status_code=200):
        self.status_code = status_code
        self.requested_urls = []

    def get(self, url, *args, **kwargs):

        self.requested_urls.append(url)

        response = requests.Response()
        response.status_code = self.status_code
        response.url = url

        return response


def test_safe_endpoints_detected():

    session = FakeSession(
        status_code=200
    )

    findings = check_safe_endpoints(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 3

    names = [
        finding.name
        for finding in findings
    ]

    assert "Safe endpoint discovered: /robots.txt" in names

    assert "Safe endpoint discovered: /sitemap.xml" in names

    assert (
        "Safe endpoint discovered: "
        "/.well-known/security.txt"
    ) in names


def test_safe_endpoints_not_found():

    session = FakeSession(
        status_code=404
    )

    findings = check_safe_endpoints(
        session,
        "https://example.com",
        timeout=5
    )

    assert findings == []


def test_safe_endpoints_use_expected_urls():

    session = FakeSession(
        status_code=200
    )

    check_safe_endpoints(
        session,
        "https://example.com",
        timeout=5
    )

    assert (
        "https://example.com/robots.txt"
        in session.requested_urls
    )

    assert (
        "https://example.com/sitemap.xml"
        in session.requested_urls
    )

    assert (
        "https://example.com/.well-known/security.txt"
        in session.requested_urls
    )

