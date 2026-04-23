"""URLScan.io integratsiyasi — havolalarni vizual skanerlash.

URLScan.io xizmati havolani real brauzerda ochib, skrinshotlaydi,
resurslarni yig'adi va xavfsizlik bahosi beradi.
Bepul API: 100 skan/kun (https://urlscan.io/docs/)
"""

import asyncio
from typing import Any

import aiohttp

from bot.config import settings
from bot.loader import logger


async def urlscan_submit_and_wait(
    session: aiohttp.ClientSession,
    url: str,
    max_wait: int = 30,
) -> dict[str, Any]:
    """URLScan.io ga URL yuborish va natijani kutish.

    Args:
        session: aiohttp ClientSession
        url: Tekshiriladigan URL
        max_wait: Natijani kutish vaqti (soniya)

    Returns:
        dict: {
            "enabled": bool,
            "scan_id": str,
            "result_url": str,
            "screenshot_url": str,
            "score": int,
            "categories": list[str],
            "malicious": bool,
            "verdicts": dict,
            "page_title": str,
            "country": str,
            "ip": str,
        }
    """
    result: dict[str, Any] = {
        "enabled": False,
        "scan_id": None,
        "result_url": None,
        "screenshot_url": None,
        "score": 0,
        "categories": [],
        "malicious": False,
        "verdicts": {},
        "page_title": None,
        "country": None,
        "ip": None,
    }

    if not settings.URLSCAN_API_KEY:
        # API kalit yo'q bo'lsa ham bepul (public) tekshirish qilish mumkin
        # lekin limit juda past
        return result

    result["enabled"] = True

    try:
        headers = {
            "API-Key": settings.URLSCAN_API_KEY,
            "Content-Type": "application/json",
        }
        payload = {
            "url": url,
            "visibility": "unlisted",  # Ommaga ko'rsatilmaydi
        }

        # 1. Skanerni boshlash
        async with session.post(
            "https://urlscan.io/api/v1/scan/",
            json=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status not in (200, 201):
                body = await resp.text()
                logger.warning("URLScan submit xatosi HTTP %d: %s", resp.status, body[:200])
                return result

            data = await resp.json()
            scan_uuid = data.get("uuid")
            if not scan_uuid:
                return result

            result["scan_id"] = scan_uuid
            result["result_url"] = f"https://urlscan.io/result/{scan_uuid}/"
            result["screenshot_url"] = f"https://urlscan.io/screenshots/{scan_uuid}.png"

        # 2. Natijani kutish (URLScan skan qilishi uchun 10-20 soniya kerak)
        await asyncio.sleep(15)

        for attempt in range(3):
            try:
                async with session.get(
                    f"https://urlscan.io/api/v1/result/{scan_uuid}/",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        res_data = await resp.json()

                        # Verdicts (hukm)
                        verdicts = res_data.get("verdicts", {}).get("overall", {})
                        result["verdicts"] = verdicts
                        result["malicious"] = bool(verdicts.get("malicious", False))
                        result["score"] = int(verdicts.get("score", 0))
                        result["categories"] = verdicts.get("categories", [])

                        # Sahifa ma'lumotlari
                        page = res_data.get("page", {})
                        result["page_title"] = page.get("title", "")
                        result["country"] = page.get("country", "")
                        result["ip"] = page.get("ip", "")

                        if result["malicious"]:
                            logger.info(
                                "🚨 URLScan: %s — Zararli! Score: %d, Kategoriyalar: %s",
                                url[:60], result["score"], result["categories"],
                            )
                        break
                    elif resp.status == 404:
                        # Hali tayyor emas
                        await asyncio.sleep(10)
            except Exception:
                await asyncio.sleep(5)

    except aiohttp.ClientError as exc:
        logger.warning("URLScan tarmoq xatosi: %s", exc)
    except Exception as exc:
        logger.warning("URLScan umumiy xato: %s", exc)

    return result
