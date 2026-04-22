"""ClamAV antivirus skanerlash xizmati."""

from pathlib import Path
from typing import Any

try:
    import pyclamd

    _clamav_available = True
except ImportError:
    pyclamd = None
    _clamav_available = False

from bot.config import settings
from bot.loader import logger


def _get_clamav_connection():
    """ClamAV daemonga ulanish — Network yoki Unix socket."""
    if not _clamav_available:
        return None

    # 1. Network socket (Windows va Linux uchun universal)
    try:
        cd = pyclamd.ClamdNetworkSocket(
            host=settings.CLAMAV_HOST, port=settings.CLAMAV_PORT
        )
        if cd.ping():
            return cd
    except Exception:
        pass

    # 2. Unix socket (Linux uchun)
    try:
        cd = pyclamd.ClamdUnixSocket()
        if cd.ping():
            return cd
    except Exception:
        pass

    return None


def scan_with_clamav(file_path: Path) -> dict[str, Any]:
    """Faylni ClamAV orqali skanerlash.

    ClamAV daemon (clamd) ishga tushirilgan bo'lishi kerak.
    Network yoki Unix socket orqali ulanadi.
    """
    if not _clamav_available:
        return {
            "enabled": False,
            "found": False,
            "note": "pyclamd o'rnatilmagan",
        }

    try:
        cd = _get_clamav_connection()
        if cd is None:
            return {
                "enabled": False,
                "found": False,
                "note": "ClamAV daemon ulanib bo'lmadi",
            }

        result = cd.scan_file(str(file_path))

        if result:
            file_result = result.get(str(file_path))
            if file_result:
                status, signature = file_result
                is_found = status == "FOUND"

                if is_found:
                    logger.info("🔴 ClamAV: virus topildi — %s", signature)

                return {
                    "enabled": True,
                    "found": is_found,
                    "signature": signature if is_found else None,
                    "status": status,
                }

        return {"enabled": True, "found": False}
    except Exception as e:
        logger.warning("ClamAV skanerlash xatosi: %s", e)
        return {"enabled": True, "found": False, "error": str(e)}
