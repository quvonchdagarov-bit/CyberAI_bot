"""VirusTotal API v3 integratsiyasi."""

import asyncio
from pathlib import Path
from typing import Any

import aiohttp

from bot.config import settings
from bot.utils.helpers import vt_headers, vt_url_id


async def vt_get_analysis(
    session: aiohttp.ClientSession, analysis_id: str
) -> dict[str, Any]:
    """Tahlil natijasini olish."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    async with session.get(url, headers=vt_headers(), timeout=40) as resp:
        data = await resp.json(content_type=None)
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "status": attrs.get("status"),
            "stats": attrs.get("stats", {}),
        }


async def vt_poll_analysis(
    session: aiohttp.ClientSession,
    analysis_id: str,
    tries: int = 5,
    delay: int = 8,
) -> dict[str, Any]:
    """Tahlil yakunlanguncha kutish."""
    last = {}
    for _ in range(tries):
        last = await vt_get_analysis(session, analysis_id)
        if last.get("status") == "completed":
            return last
        await asyncio.sleep(delay)
    return last


async def vt_get_file_report(
    session: aiohttp.ClientSession, sha256: str
) -> dict[str, Any]:
    """SHA256 bo'yicha fayl hisobotini olish."""
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    async with session.get(url, headers=vt_headers(), timeout=40) as resp:
        if resp.status == 404:
            return {"found": False}
        data = await resp.json(content_type=None)
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "found": True,
            "stats": attrs.get("last_analysis_stats", {}),
            "meaningful_name": attrs.get("meaningful_name"),
            "type_description": attrs.get("type_description"),
        }


async def vt_get_upload_url(session: aiohttp.ClientSession) -> str | None:
    """Katta fayllar uchun maxsus yuklash URLini olish."""
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    async with session.get(url, headers=vt_headers(), timeout=30) as resp:
        if resp.status != 200:
            return None
        data = await resp.json(content_type=None)
        return data.get("data")


async def vt_upload_file(
    session: aiohttp.ClientSession, path: Path, filename: str
) -> str | None:
    """Faylni VirusTotal ga yuklash."""
    upload_url = "https://www.virustotal.com/api/v3/files"

    if path.stat().st_size > 32 * 1024 * 1024:
        custom_url = await vt_get_upload_url(session)
        if not custom_url:
            return None
        upload_url = custom_url

    form = aiohttp.FormData()
    with open(path, "rb") as f:
        form.add_field("file", f, filename=filename)
        async with session.post(
            upload_url, headers=vt_headers(), data=form, timeout=180
        ) as resp:
            data = await resp.json(content_type=None)
            return data.get("data", {}).get("id")


async def vt_scan_url(
    session: aiohttp.ClientSession, url_value: str
) -> str | None:
    """URLni VirusTotal ga yuborish."""
    url = "https://www.virustotal.com/api/v3/urls"
    async with session.post(
        url, headers=vt_headers(), data={"url": url_value}, timeout=40
    ) as resp:
        data = await resp.json(content_type=None)
        return data.get("data", {}).get("id")


async def vt_get_url_report(
    session: aiohttp.ClientSession, url_value: str
) -> dict[str, Any]:
    """URL bo'yicha VirusTotal hisobotini olish."""
    url_id = vt_url_id(url_value)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    async with session.get(url, headers=vt_headers(), timeout=40) as resp:
        if resp.status == 404:
            return {"found": False}
        data = await resp.json(content_type=None)
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "found": True,
            "stats": attrs.get("last_analysis_stats", {}),
            "reputation": attrs.get("reputation"),
        }
