import ipaddress

import requests


def get_client_ip(request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    if request.client:
        return request.client.host

    return None


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def lookup_ip_location(ip: str | None) -> dict:
    if not _is_public_ip(ip):
        return {}

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
    except Exception:
        return {}

    if data.get("status") != "success":
        return {}

    return {
        "country_code": data.get("countryCode"),
        "country_name": data.get("country"),
        "city": data.get("city"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
    }
