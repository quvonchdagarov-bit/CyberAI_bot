"""Arxiv (ZIP) fayl tahlili — ichidagi xavfli fayllarni aniqlash."""

import zipfile
from pathlib import Path
from typing import Any

from bot.utils.constants import INNER_DANGEROUS_EXTS
from bot.utils.helpers import dedupe_keep_order


def inspect_zip(path: Path) -> dict[str, Any]:
    """ZIP arxiv ichidagi xavfli fayllarni aniqlash."""
    found = []
    reasons = []
    score = 0

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()

            if len(names) > 250:
                score += 15
                reasons.append("arxiv ichida juda ko'p fayl bor")

            for name in names[:200]:
                lower = name.lower()
                if any(lower.endswith(ext) for ext in INNER_DANGEROUS_EXTS):
                    found.append(name)
                    score += 18
                if any(
                    token in lower
                    for token in [".mp4.apk", ".jpg.exe", ".png.apk", ".pdf.exe"]
                ):
                    score += 25
                    found.append(name)
                if "crack" in lower or "keygen" in lower or "patch" in lower:
                    score += 15
                    found.append(name)

        if found:
            reasons.append("arxiv ichida shubhali fayllar topildi")

        return {
            "ok": True,
            "score": min(score, 100),
            "found_files": dedupe_keep_order(found)[:12],
            "reasons": reasons,
        }
    except Exception as e:
        return {
            "ok": False,
            "score": 0,
            "found_files": [],
            "reasons": [f"arxivni tekshirishda xato: {e}"],
        }
