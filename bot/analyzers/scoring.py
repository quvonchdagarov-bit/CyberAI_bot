"""Risk skori hisoblash va risk darajasini aniqlash."""

from typing import Any

from bot.utils.constants import RISK_LEVELS
from bot.utils.helpers import dedupe_keep_order


def stats_to_score(stats: dict[str, Any]) -> tuple[int, str]:
    """VirusTotal statistikasidan risk skori hisoblash."""
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    score = min(malicious * 25 + suspicious * 12, 100)
    summary = (
        f"malicious={malicious}, suspicious={suspicious}, "
        f"harmless={harmless}, undetected={undetected}"
    )
    return score, summary


def classify_risk_level(score: int) -> str:
    """Risk skori bo'yicha daraja nomini qaytarish."""
    for min_score, label in RISK_LEVELS:
        if score >= min_score:
            return label
    return "🟢 PAST"


def calculate_final_risk(result: dict[str, Any]) -> dict[str, Any]:
    """Barcha manbalardan olingan ballarni birlashtirish."""
    score = int(result.get("base_score", 0))
    reasons = list(result.get("reasons", []))

    # VirusTotal natijalari
    vt_stats = result.get("vt_stats") or {}
    if vt_stats:
        vt_score, vt_summary = stats_to_score(vt_stats)
        score = max(score, vt_score)
        result["vt_summary"] = vt_summary
        if vt_score >= 50:
            reasons.append("VirusTotal xavfli yoki shubhali natija qaytardi")

    # ClamAV natijalari
    clamav = result.get("clamav") or {}
    if clamav.get("found"):
        score = max(score, 92)
        reasons.append(f"ClamAV tahdid topdi: {clamav.get('signature', 'unknown')}")

    # YARA natijalari (severity bo'yicha ball berish)
    yara_info = result.get("yara") or {}
    yara_matches = yara_info.get("matches", [])
    yara_details = yara_info.get("details", [])
    if yara_matches:
        yara_score = 40
        for d in yara_details:
            severity = d.get("severity", "").lower()
            if severity == "critical":
                yara_score = max(yara_score, 88)
            elif severity == "high":
                yara_score = max(yara_score, 72)
            elif severity == "medium":
                yara_score = max(yara_score, 55)
        # Ko'p match bo'lsa, skorni oshirish
        yara_score = min(yara_score + len(yara_matches) * 5, 95)
        score = max(score, yara_score)
        reasons.append(f"YARA: {len(yara_matches)} ta moslik topdi")

    # Google Safe Browsing natijalari
    safe_browsing = result.get("safe_browsing") or {}
    if safe_browsing.get("matches"):
        score = max(score, 88)
        reasons.append("Google Safe Browsing match topdi")

    result["score"] = min(score, 100)
    result["reasons"] = dedupe_keep_order(reasons)
    return result
