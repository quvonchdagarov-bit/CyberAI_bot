"""Google Safe Browsing API v4 integratsiyasi."""

from typing import Any

import aiohttp

from bot.config import settings


async def google_safe_browsing_check(
    session: aiohttp.ClientSession, url_value: str
) -> dict[str, Any]:
    """URLni Google Safe Browsing orqali tekshirish."""
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return {"enabled": False, "matches": []}

    endpoint = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
    )
    body = {
        "client": {"clientId": "camcyber-pro", "clientVersion": "4.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_value}],
        },
    }

    try:
        async with session.post(endpoint, json=body, timeout=30) as resp:
            data = await resp.json(content_type=None)
            return {"enabled": True, "matches": data.get("matches", [])}
    except Exception as e:
        return {"enabled": True, "matches": [], "error": str(e)}
