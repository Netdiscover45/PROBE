
import requests

from probe.Active.cors import check_cors, PROBE_ORIGIN


class FakeSession:

    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    def get(self, *args, **kwargs):

        if self.error:
            raise self.error

        return self.response


def make_response(
    allow_origin=None,
    allow_credentials=None,
    status=200
):

    response = requests.Response()

    response.status_code = status

    if allow_origin is not None:
        response.headers[
            "Access-Control-Allow-Origin"
        ] = allow_origin

    if allow_credentials is not None:
        response.headers[
            "Access-Control-Allow-Credentials"
        ] = allow_credentials

    return response


def test_cors_header_missing():

    session = FakeSession(
        response=make_response()
    )

    findings = check_cors(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].category == "CORS"


def test_cors_wildcard():

    session = FakeSession(
        response=make_response(
            allow_origin="*"
        )
    )

    findings = check_cors(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert "Wildcard" in findings[0].name


def test_cors_wildcard_with_credentials():

    session = FakeSession(
        response=make_response(
            allow_origin="*",
            allow_credentials="true"
        )
    )

    findings = check_cors(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_cors_reflects_probe_origin():

    session = FakeSession(
        response=make_response(
            allow_origin=PROBE_ORIGIN
        )
    )

    findings = check_cors(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "reflects" in findings[0].name


def test_cors_specific_origin():

    session = FakeSession(
        response=make_response(
            allow_origin="https://trusted.example"
        )
    )

    findings = check_cors(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "INFO"


def test_cors_error():

    session = FakeSession(
        error=requests.exceptions.Timeout(
            "test timeout"
        )
    )

    findings = check_cors(
        session,
        "https://example.com",
        timeout=5
    )

    assert len(findings) == 1
    assert findings[0].severity == "INFO"

