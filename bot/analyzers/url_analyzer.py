"""URL xavfsizlik tahlili — phishing, shortener, VirusTotal, Safe Browsing."""

from typing import Any

import aiohttp

from bot.config import settings
from bot.utils.constants import (
    ADULT_WORDS,
    PHISHING_HINTS,
    SHORTENERS,
)
from bot.utils.helpers import url_domain
from bot.analyzers.scoring import calculate_final_risk
from bot.services.virustotal import vt_get_url_report, vt_poll_analysis, vt_scan_url
from bot.services.safebrowsing import google_safe_browsing_check


async def analyze_url(
    session: aiohttp.ClientSession, url_value: str
) -> dict[str, Any]:
    """URLni xavfsizlik nuqtai nazaridan to'liq tahlil qilish."""
    domain = url_domain(url_value)
    lowered = url_value.lower()
    result: dict[str, Any] = {
        "url": url_value,
        "domain": domain,
        "base_score": 0,
        "reasons": [],
    }

    # Qisqartirilgan havola
    if domain in SHORTENERS:
        result["base_score"] += 20
        result["reasons"].append("qisqartirilgan havola")

    # Domen ichida raqam
    if any(ch.isdigit() for ch in domain):
        result["base_score"] += 8
        result["reasons"].append("domen ichida raqamlar bor")

    # G'ayrioddiy domen
    if domain.count("-") >= 2:
        result["base_score"] += 8
        result["reasons"].append("domen g'ayrioddiy ko'rinadi")

    # Phishing belgilari
    phishing_hits = [w for w in PHISHING_HINTS if w in lowered]
    if phishing_hits:
        result["base_score"] += 12
        result["reasons"].append(f"phishing belgisi: {phishing_hits[0]}")

    # Shubhali yuklama
    if any(x in lowered for x in [".apk", ".exe", ".zip", ".msi", ".jar"]):
        result["base_score"] += 20
        result["reasons"].append("havolada shubhali yuklama bor")

    # 18+ belgilar
    if any(w in lowered for w in ADULT_WORDS):
        result["base_score"] = max(result["base_score"], 75)
        result["reasons"].append("18+ belgilar topildi")

    # VirusTotal tekshiruv
    if settings.VT_API_KEY:
        vt_report = await vt_get_url_report(session, url_value)
        if vt_report.get("found") and vt_report.get("stats"):
            result["vt_stats"] = vt_report["stats"]
        else:
            analysis_id = await vt_scan_url(session, url_value)
            if analysis_id:
                analysis = await vt_poll_analysis(session, analysis_id, tries=4, delay=6)
                result["vt_stats"] = analysis.get("stats", {})

    # Google Safe Browsing
    result["safe_browsing"] = await google_safe_browsing_check(session, url_value)

    return calculate_final_risk(result)
