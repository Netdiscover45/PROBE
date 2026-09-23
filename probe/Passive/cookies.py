
from ..models import Finding


def check_cookies(response, target):
    findings = []

    set_cookie_headers = response.raw.headers.get_all("Set-Cookie")

    if not set_cookie_headers:
        return findings

    for cookie in set_cookie_headers:
        cookie_name = cookie.split("=", 1)[0].strip()

        if "Secure" not in cookie:
            findings.append(
                Finding(
                    name=f"Cookie missing Secure flag: {cookie_name}",
                    severity="MEDIUM",
                    category="Cookies",
                    description="A cookie was observed without the Secure attribute.",
                    target=target,
                    evidence=cookie
                )
            )

        if "HttpOnly" not in cookie:
            findings.append(
                Finding(
                    name=f"Cookie missing HttpOnly flag: {cookie_name}",
                    severity="MEDIUM",
                    category="Cookies",
                    description="A cookie was observed without the HttpOnly attribute.",
                    target=target,
                    evidence=cookie
                )
            )

        if "SameSite" not in cookie:
            findings.append(
                Finding(
                    name=f"Cookie missing SameSite attribute: {cookie_name}",
                    severity="LOW",
                    category="Cookies",
                    description="A cookie was observed without an explicit SameSite attribute.",
                    target=target,
                    evidence=cookie
                )
            )

    return findings

