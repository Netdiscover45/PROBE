
import requests

from probe.Passive.cookies import check_cookies


def make_response(cookie_headers):
    response = requests.Response()
    response.status_code = 200

    response.raw = requests.packages.urllib3.response.HTTPResponse()

    response.raw.headers = requests.packages.urllib3._collections.HTTPHeaderDict()

    for cookie in cookie_headers:
        response.raw.headers.add("Set-Cookie", cookie)

    return response


def test_cookie_with_all_security_flags():
    response = make_response([
        "session=abc123; Secure; HttpOnly; SameSite=Strict"
    ])

    findings = check_cookies(
        response,
        "https://example.com"
    )

    assert findings == []


def test_cookie_missing_security_flags():
    response = make_response([
        "session=abc123"
    ])

    findings = check_cookies(
        response,
        "https://example.com"
    )

    assert len(findings) == 3

    names = [finding.name for finding in findings]

    assert "Cookie missing Secure flag: session" in names
    assert "Cookie missing HttpOnly flag: session" in names
    assert "Cookie missing SameSite attribute: session" in names
