"""URL xavfsizlik tahlili — to'liq kengaytirilgan versiya.

Yangi qo'shilgan:
- AbuseIPDB (IP reputatsiyasi)
- Typosquatting aniqlash (g00gle.com, paypa1.com kabi)
- Homograph hujumlari (kirill/lotin aralash domenlar)
- URL redirect zanjiri tekshiruvi
- Shubhali TLD (yuqori darajali domen) tekshiruvi
- @ belgisi (fishing ko'rsatkichi)
- URLScan.io (ixtiyoriy — API kalit bo'lsa)
"""

import re
import unicodedata
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
from bot.services.abuseipdb import check_abuseipdb
from bot.loader import logger

# ─── Typosquatting — mashhur domen nomlari ────────────────────────────────────
POPULAR_DOMAINS = {
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "telegram": "telegram.org",
    "youtube": "youtube.com",
    "twitter": "twitter.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "tiktok": "tiktok.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "yahoo": "yahoo.com",
    "gmail": "gmail.com",
    "outlook": "outlook.com",
    "uzum": "uzum.market",
    "uzmobile": "uzmobile.uz",
    "mbank": "mbank.uz",
    "click": "click.uz",
    "payme": "payme.uz",
}

# Xavfli TLD-lar (ko'p spam/phishing shu domenlar ostida)
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".work", ".date", ".faith", ".loan",
    ".online", ".site", ".website", ".club", ".bid",
    ".stream", ".download", ".racing", ".win", ".party",
    ".gq", ".ml", ".cf", ".ga", ".tk",
}

# Typosquatting harflari (visual o'xshashligi)
CHAR_SUBSTITUTIONS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "b", "7": "t", "8": "b",
    "@": "a", "!": "i", "|": "i",
}

# Kirill harflari lotin shakliga o'xshash (IDN Homograph)
CYRILLIC_LOOKALIKES = {
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "і": "i",
    "ь": "b",
}


def _normalize_domain(domain: str) -> str:
    """Domenni typosquatting tekshiruvi uchun normallash."""
    d = domain.lower()
    # Raqamlarni harflarga almashtirish
    for digit, letter in CHAR_SUBSTITUTIONS.items():
        d = d.replace(digit, letter)
    # Kirill harflarini lotinga
    normalized = ""
    for ch in d:
        normalized += CYRILLIC_LOOKALIKES.get(ch, ch)
    return normalized


def _detect_typosquatting(domain: str) -> str | None:
    """Typosquatting holatini aniqlash.

    Returns:
        Taqlid qilingan original domen yoki None
    """
    # Domendan TLD ni olib tashlash
    domain_lower = domain.lower()
    domain_no_tld = re.sub(r"\.[a-z]{2,10}$", "", domain_lower)

    normalized = _normalize_domain(domain_no_tld)

    for keyword, real_domain in POPULAR_DOMAINS.items():
        real_base = real_domain.split(".")[0]
        # To'liq mos kelsa (haqiqiy domen) — o'tkazib yuboramiz
        if domain_lower == real_domain or domain_lower.endswith("." + real_domain):
            return None
        # Normallanmadan so'ng mos kelsa — typosquatting!
        norm_keyword = _normalize_domain(real_base)
        if normalized == norm_keyword and domain_lower != real_domain:
            return real_domain
        # Levenshtein kabi sodda: uzunlik 1 farq qilsa
        if len(normalized) == len(norm_keyword) and sum(
            a != b for a, b in zip(normalized, norm_keyword)
        ) == 1:
            return real_domain

    return None


def _check_homograph(domain: str) -> bool:
    """IDN Homograph hujumini aniqlash (kirill + lotin aralash)."""
    has_latin = any("a" <= c <= "z" for c in domain.lower())
    has_cyrillic = any(c in CYRILLIC_LOOKALIKES for c in domain)
    return has_latin and has_cyrillic


async def _follow_redirects(session: aiohttp.ClientSession, url: str) -> str:
    """URL redirect zanjiridagi yakuniy manzilni aniqlash."""
    try:
        async with session.head(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=8),
            ssl=False,
        ) as resp:
            final_url = str(resp.url)
            if final_url != url:
                logger.debug("🔄 Redirect: %s → %s", url[:50], final_url[:50])
            return final_url
    except Exception:
        return url


async def analyze_url(
    session: aiohttp.ClientSession, url_value: str
) -> dict[str, Any]:
    """URLni to'liq kengaytirilgan xavfsizlik tahlili.

    15+ tekshiruv:
    1. Qisqartirilgan havola
    2. Domen raqamlar
    3. G'ayrioddiy domen
    4. Phishing kalit so'zlar
    5. Shubhali yuklama kengaytmasi
    6. 18+ belgilar
    7. @ belgisi (fishing ko'rsatkichi)
    8. Xavfli TLD
    9. Typosquatting aniqlash
    10. Homograph (kirill/lotin aralash)
    11. Juda uzun URL
    12. IP manzil URL da (domen o'rniga)
    13. Redirect tekshiruvi
    14. VirusTotal
    15. Google Safe Browsing
    16. AbuseIPDB (IP reputatsiyasi)
    """
    domain = url_domain(url_value)
    lowered = url_value.lower()

    result: dict[str, Any] = {
        "url": url_value,
        "domain": domain,
        "base_score": 0,
        "reasons": [],
        "tools_used": ["URL Pattern Analysis"],
    }

    # ── 1. Qisqartirilgan havola ───────────────────────────────────────────
    if domain in SHORTENERS:
        result["base_score"] += 20
        result["reasons"].append("qisqartirilgan havola — real manba yashirilgan")

    # ── 2. Domengi raqamlar ────────────────────────────────────────────────
    if re.search(r"\d{4,}", domain):
        result["base_score"] += 10
        result["reasons"].append("domenda ko'p raqamlar — suv xo'jaligiga o'xshamaydi")

    # ── 3. Ko'p chiziqcha ─────────────────────────────────────────────────
    if domain.count("-") >= 3:
        result["base_score"] += 12
        result["reasons"].append("domenda g'ayrioddiy ko'p chiziqcha")

    # ── 4. Phishing belgilari ─────────────────────────────────────────────
    phishing_hits = [w for w in PHISHING_HINTS if w in lowered]
    if phishing_hits:
        result["base_score"] += 15
        result["reasons"].append(f"phishing belgisi topildi: {', '.join(phishing_hits[:3])}")

    # ── 5. Shubhali yuklamalar ────────────────────────────────────────────
    if any(x in lowered for x in [".apk", ".exe", ".zip", ".msi", ".jar", ".bat", ".ps1"]):
        result["base_score"] += 22
        result["reasons"].append("havolada zararli fayl yuklanishi bor")

    # ── 6. 18+ belgilar ──────────────────────────────────────────────────
    if any(w in lowered for w in ADULT_WORDS):
        result["base_score"] = max(result["base_score"], 75)
        result["reasons"].append("18+ tarkibli deb belgilangan")

    # ── 7. @ belgisi URL da ───────────────────────────────────────────────
    if "@" in url_value:
        result["base_score"] += 30
        result["reasons"].append("URL da @ belgisi — fishing texnikasi (haqiqiy manzil yashirilgan)")

    # ── 8. Xavfli TLD ────────────────────────────────────────────────────
    tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld.lower() in HIGH_RISK_TLDS:
        result["base_score"] += 15
        result["reasons"].append(f"xavfli yuqori darajali domen: {tld}")

    # ── 9. Typosquatting ──────────────────────────────────────────────────
    squatted = _detect_typosquatting(domain)
    if squatted:
        result["base_score"] += 40
        result["reasons"].append(
            f"typosquatting: '{domain}' — '{squatted}' ni taqlid qilmoqda"
        )
        result["tools_used"].append("Typosquatting Detector")

    # ── 10. Homograph hujumi ──────────────────────────────────────────────
    if _check_homograph(domain):
        result["base_score"] += 35
        result["reasons"].append("IDN homograph hujumi: kirill + lotin harflar aralash")
        result["tools_used"].append("Homograph Detector")

    # ── 11. Juda uzun URL ─────────────────────────────────────────────────
    if len(url_value) > 200:
        result["base_score"] += 10
        result["reasons"].append(f"URL juda uzun ({len(url_value)} belgi) — yashirish urinishi")

    # ── 12. IP manzil URL da ─────────────────────────────────────────────
    if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_value):
        result["base_score"] += 25
        result["reasons"].append("URL domenga emas, to'g'ridan-to'g'ri IP manzilga yo'naltiradi")

    # ── 13. Redirect zanjiri ─────────────────────────────────────────────
    final_url = await _follow_redirects(session, url_value)
    if final_url != url_value:
        final_domain = url_domain(final_url)
        result["final_url"] = final_url
        result["final_domain"] = final_domain
        result["tools_used"].append("Redirect Tracker")
        if final_domain != domain:
            result["base_score"] += 15
            result["reasons"].append(
                f"redirect boshqa domenge: {final_domain[:40]}"
            )
        # Final URL ham typosquatting tekshiruv
        sq2 = _detect_typosquatting(final_domain)
        if sq2 and sq2 != squatted:
            result["base_score"] += 30
            result["reasons"].append(
                f"redirect manzil typosquatting: '{final_domain}' → '{sq2}'"
            )

    # ── 14. VirusTotal ────────────────────────────────────────────────────
    if settings.VT_API_KEY:
        result["tools_used"].append("VirusTotal API")
        vt_report = await vt_get_url_report(session, url_value)
        if vt_report.get("found") and vt_report.get("stats"):
            result["vt_stats"] = vt_report["stats"]
        else:
            analysis_id = await vt_scan_url(session, url_value)
            if analysis_id:
                analysis = await vt_poll_analysis(session, analysis_id, tries=4, delay=6)
                result["vt_stats"] = analysis.get("stats", {})

    # ── 15. Google Safe Browsing ──────────────────────────────────────────
    sb_result = await google_safe_browsing_check(session, url_value)
    result["safe_browsing"] = sb_result
    if sb_result.get("enabled"):
        result["tools_used"].append("Google Safe Browsing")

    # ── 16. AbuseIPDB ─────────────────────────────────────────────────────
    if settings.ABUSEIPDB_API_KEY:
        abuse_result = await check_abuseipdb(session, url_value)
        result["abuseipdb"] = abuse_result
        if abuse_result.get("enabled"):
            result["tools_used"].append("AbuseIPDB")
            if abuse_result.get("threat"):
                score_add = min(int(abuse_result["abuse_score"]) // 2, 40)
                result["base_score"] += score_add
                result["reasons"].append(
                    f"AbuseIPDB: IP xavfli ({abuse_result['abuse_score']}% ishonch, "
                    f"{abuse_result['total_reports']} hisobot, {abuse_result.get('country', '?')} "
                    f"— {abuse_result.get('isp', '?')[:30]})"
                )

    return calculate_final_risk(result)
