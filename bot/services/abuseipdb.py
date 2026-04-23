"""AbuseIPDB — IP manzil reputatsiyasini tekshirish.

AbuseIPDB xalqaro bazasida 5 milliondan ortiq xavfli IP manzillar ro'yxati mavjud.
Bepul API: 1000 so'rov/kun (https://www.abuseipdb.com/api)
"""

import socket
from typing import Any
from urllib.parse import urlparse

import aiohttp

from bot.config import settings
from bot.loader import logger


def _extract_ip_from_url(url: str) -> str | None:
    """URL dan IP manzilni ajratib olish yoki domenni resolve qilish."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return None

        # Agar host allaqachon IP bo'lsa
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return host

        # Domen nomini IP ga aylantirish
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror:
            return None
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    """Mahalliy (private) IP ekanligini tekshirish."""
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except Exception:
        return False


async def check_abuseipdb(
    session: aiohttp.ClientSession,
    url: str,
) -> dict[str, Any]:
    """AbuseIPDB orqali URL ning IP manzilini tekshirish.

    Returns:
        dict: {
            "enabled": bool,
            "ip": str,
            "abuse_score": int (0-100),
            "country": str,
            "isp": str,
            "total_reports": int,
            "is_whitelisted": bool,
            "threat": bool,
        }
    """
    result: dict[str, Any] = {
        "enabled": False,
        "ip": None,
        "abuse_score": 0,
        "country": None,
        "isp": None,
        "total_reports": 0,
        "is_whitelisted": False,
        "threat": False,
    }

    if not settings.ABUSEIPDB_API_KEY:
        return result

    ip = _extract_ip_from_url(url)
    if not ip:
        return result

    if _is_private_ip(ip):
        return result  # Mahalliy IP — tekshirishning hojati yo'q

    result["ip"] = ip
    result["enabled"] = True

    try:
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "",
        }

        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                logger.warning("AbuseIPDB HTTP %d: %s", resp.status, ip)
                return result

            data = await resp.json()
            d = data.get("data", {})

            result["abuse_score"] = int(d.get("abuseConfidenceScore", 0))
            result["country"] = d.get("countryCode", "")
            result["isp"] = d.get("isp", "")
            result["total_reports"] = int(d.get("totalReports", 0))
            result["is_whitelisted"] = bool(d.get("isWhitelisted", False))
            result["threat"] = result["abuse_score"] >= 25 or result["total_reports"] >= 5

            if result["threat"]:
                logger.info(
                    "🚨 AbuseIPDB: %s — Abuse Score: %d%%, Hisobotlar: %d (%s)",
                    ip, result["abuse_score"], result["total_reports"], result["isp"],
                )

    except aiohttp.ClientError as exc:
        logger.warning("AbuseIPDB so'rovida tarmoq xatosi: %s", exc)
    except Exception as exc:
        logger.warning("AbuseIPDB umumiy xato: %s", exc)

    return result
