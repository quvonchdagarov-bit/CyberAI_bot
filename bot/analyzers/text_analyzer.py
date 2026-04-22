"""Matn xavfsizlik tahlili — fishing, haqorat, 18+ aniqlash."""

from typing import Any

from bot.utils.constants import (
    ADULT_WORDS,
    BAD_WORDS,
    EMAIL_RE,
    IP_RE,
    PHISHING_HINTS,
)
from bot.analyzers.scoring import calculate_final_risk


async def analyze_text(text: str) -> dict[str, Any]:
    """Matnni xavfsizlik nuqtai nazaridan tahlil qilish."""
    lowered = text.lower()
    result: dict[str, Any] = {
        "text": text[:1000],
        "base_score": 0,
        "reasons": [],
        "tag": None,
    }

    # 18+ kontentni aniqlash
    if any(w in lowered for w in ADULT_WORDS):
        result["base_score"] = max(result["base_score"], 75)
        result["reasons"].append("nomaqbul 18+ kalit so'z topildi")
        result["tag"] = "adult"

    # Haqoratli iboralar
    if any(w in lowered for w in BAD_WORDS):
        result["base_score"] = max(result["base_score"], 55)
        result["reasons"].append("haqoratli ibora topildi")
        result["tag"] = result["tag"] or "bad_words"

    # Fishing/scam belgilari
    phishing_count = sum(1 for w in PHISHING_HINTS if w in lowered)
    if phishing_count >= 2:
        result["base_score"] = max(result["base_score"], 60)
        result["reasons"].append("fishing yoki scamga o'xshash iboralar bor")
        result["tag"] = result["tag"] or "text"

    # Email + parol so'rovi
    if EMAIL_RE.search(text) and any(
        x in lowered for x in ["parol", "password", "verify", "kod", "otp"]
    ):
        result["base_score"] = max(result["base_score"], 68)
        result["reasons"].append("ma'lumot yig'ishga o'xshash so'rov bor")

    # IP + login kombinatsiya
    if IP_RE.search(text) and "login" in lowered:
        result["base_score"] = max(result["base_score"], 50)
        result["reasons"].append("IP asosidagi shubhali login yo'naltirish")

    return calculate_final_risk(result)
