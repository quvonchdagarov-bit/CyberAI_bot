"""YARA qoidalar asosida fayl skanerlash."""

from pathlib import Path
from typing import Any

try:
    import yara

    _yara_available = True
except ImportError:
    yara = None
    _yara_available = False

from bot.config import settings
from bot.loader import logger

_yara_rules_cache = None


def load_yara_rules():
    """YARA qoidalarini yuklab keshlash."""
    global _yara_rules_cache
    if _yara_rules_cache is not None:
        return _yara_rules_cache
    if not _yara_available:
        return None
    try:
        rules_path = settings.YARA_RULES_PATH
        if not rules_path.exists():
            logger.warning("YARA qoidalar fayli topilmadi: %s", rules_path)
            return None
        _yara_rules_cache = yara.compile(filepath=str(rules_path))
        logger.info("✅ YARA qoidalari yuklandi: %s", rules_path)
        return _yara_rules_cache
    except Exception as e:
        logger.warning("YARA yuklanmadi: %s", e)
        return None


def scan_with_yara(file_path: Path) -> dict[str, Any]:
    """Faylni YARA qoidalari bilan skanerlash.

    Har bir moslik uchun qoida nomi, tavsif va jiddiylik darajasi qaytariladi.
    """
    rules = load_yara_rules()
    if rules is None:
        return {
            "enabled": _yara_available,
            "matches": [],
            "details": [],
            "note": "YARA qoidalari yuklanmadi" if _yara_available else "yara-python o'rnatilmagan",
        }
    try:
        matches = rules.match(str(file_path))
        match_names = []
        match_details = []

        for m in matches:
            match_names.append(m.rule)
            detail = {
                "rule": m.rule,
                "tags": list(m.tags) if m.tags else [],
            }
            # Metadata mavjud bo'lsa
            if hasattr(m, "meta") and m.meta:
                detail["description"] = m.meta.get("description", "")
                detail["severity"] = m.meta.get("severity", "unknown")
            match_details.append(detail)

        if match_names:
            logger.info(
                "🔴 YARA: %d ta moslik — %s",
                len(match_names),
                ", ".join(match_names[:5]),
            )

        return {
            "enabled": True,
            "matches": match_names,
            "details": match_details,
            "match_count": len(match_names),
        }
    except Exception as e:
        logger.warning("YARA skanerlash xatosi: %s", e)
        return {"enabled": True, "matches": [], "details": [], "error": str(e)}
