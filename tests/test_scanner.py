
import requests

from probe.scanner import Scanner


def test_scanner_success(monkeypatch):

    response = requests.Response()

    response.status_code = 200
    response.url = "https://example.com/"

    response.headers.update({
        "Content-Type": "text/html",
        "Server": "test-server",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    })

    response._content = b"<html>Test</html>"

    # Mock response.raw because cookies.py reads:
    # response.raw.headers.get_all("Set-Cookie")
    class FakeRaw:
        def __init__(self):
            self.headers = FakeHeaders()

    class FakeHeaders:
        def get_all(self, name):
            return []

    response.raw = FakeRaw()

    scanner = Scanner(timeout=5)

    def fake_get(*args, **kwargs):
        return response

    monkeypatch.setattr(
        scanner.session,
        "get",
        fake_get
    )

    result = scanner.scan(
        "https://example.com"
    )

    assert result.target == "https://example.com"
    assert result.final_url == "https://example.com/"
    assert result.status_code == 200
    assert result.content_type == "text/html"
    assert result.server == "test-server"
    assert result.error == ""


def test_scanner_invalid_url():

    scanner = Scanner(timeout=5)

    try:
        scanner.scan("ftp://example.com")
        assert False, "Expected ValueError"
    except ValueError:
        assert True


def test_scanner_timeout(monkeypatch):

    scanner = Scanner(timeout=5)

    def fake_get(*args, **kwargs):
        raise requests.exceptions.Timeout(
            "Test timeout"
        )

    monkeypatch.setattr(
        scanner.session,
        "get",
        fake_get
    )

    result = scanner.scan(
        "https://example.com"
    )

    assert result.error == "Request timed out."
