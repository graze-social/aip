from typing import Dict
from urllib.parse import urlparse

def get_cors_headers(
    origin_value: Optional[str], path: str, debug: bool
) -> Dict[str, str]:
    """Return appropriate CORS headers based on origin and path."""
    allowed_origins = {
        "https://graze.social",
        "https://www.graze.social",
        "https://sky-feeder-git-astro-graze.vercel.app",
    }

    allowed_debug_hosts = {
        "localhost",
        "127.0.0.1",
    }

    headers = {
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": (
            "Keep-Alive, User-Agent, X-Requested-With, "
            "If-Modified-Since, Cache-Control, Content-Type, "
            "Authorization, X-Subject, X-Service"
        ),
        "Vary": "Origin"
    }

    if path.startswith("/auth/"):
        headers["Access-Control-Allow-Origin"] = "*"
    elif origin_value:
        parsed = urlparse(origin_value)
        base = f"{parsed.scheme}://{parsed.hostname}" if parsed.scheme and parsed.hostname else origin_value

        if base in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin_value
        elif debug and parsed.hostname in allowed_debug_hosts:
            headers["Access-Control-Allow-Origin"] = origin_value

    return headers
