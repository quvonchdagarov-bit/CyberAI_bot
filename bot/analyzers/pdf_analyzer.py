"""PDF fayl tahlili — shubhali elementlarni aniqlash."""

from pathlib import Path
from typing import Any


def analyze_pdf(path: Path) -> dict[str, Any]:
    """PDF ichidagi xavfli elementlarni aniqlash."""
    reasons = []
    score = 0

    try:
        raw = path.read_bytes()
        text = raw.decode(errors="ignore").lower()

        suspicious_keywords = [
            "/javascript", "/js", "/launch", "/openaction",
            "/richmedia", "/embeddedfile", "/aa", "/submitform",
        ]

        hits = [k for k in suspicious_keywords if k in text]
        if hits:
            reasons.append("PDF ichida script yoki embedded obyekt belgisi bor")
            score += 35

        if text.count("obj") > 120:
            reasons.append("PDF ichida obyektlar soni g'ayrioddiy ko'p")
            score += 10

        return {
            "ok": True,
            "score": min(score, 100),
            "reasons": reasons,
            "hits": hits,
        }
    except Exception as e:
        return {
            "ok": False,
            "score": 0,
            "reasons": [f"PDF tahlilida xato: {e}"],
            "hits": [],
        }
