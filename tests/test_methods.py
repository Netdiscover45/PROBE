
import requests

from probe.Active.methods import check_methods


class FakeSession:

    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    def options(self, *args, **kwargs):
        if self.error:
            raise self.error
        return self.response


def make_response(allow=None, status=200):
    response = requests.Response()
    response.status_code = status

    if allow is not None:
        response.headers["Allow"] = allow

    return response


def test_methods_with_allow_header():

    session = FakeSession(
        response=make_response(
            "GET, HEAD, OPTIONS"
        )
    )

    findings = check_methods(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].category == "HTTP Methods"


def test_methods_with_additional_method():

    session = FakeSession(
        response=make_response(
            "GET, HEAD, OPTIONS, PUT"
        )
    )

    findings = check_methods(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert "Additional HTTP methods" in findings[0].name


def test_methods_without_allow_header():

    session = FakeSession(
        response=make_response()
    )

    findings = check_methods(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "not disclosed" in findings[0].name


def test_methods_error():

    session = FakeSession(
        error=requests.exceptions.Timeout(
            "test timeout"
        )
    )

    findings = check_methods(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].category == "HTTP Methods"

