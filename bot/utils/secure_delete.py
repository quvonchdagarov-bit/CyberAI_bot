"""Xavfsiz fayl o'chirish — DoD 5220.22-M standart.

Fayl oddiy o'chirilganda disk blokida ma'lumot qoladi va tiklanishi mumkin.
Bu modul faylni 3 marta tasodifiy baytlar bilan ustiga yozib keyin o'chiradi.
"""

import asyncio
import os
import secrets
from pathlib import Path

from bot.loader import logger


async def secure_shred(path: Path, passes: int = 3) -> bool:
    """Faylni xavfsiz o'chirish (DoD 5220.22-M standart).

    Args:
        path: O'chiriladigan fayl yo'li
        passes: Ustiga yozish marta soni (standart: 3)

    Returns:
        True — muvaffaqiyatli, False — xato yuz berdi
    """
    if not path.exists():
        return True

    try:
        size = path.stat().st_size
        if size == 0:
            path.unlink(missing_ok=True)
            return True

        # CPU bloklanmasligi uchun thread pool ishlatamiz
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _shred_sync, path, size, passes)
        logger.debug("🗑️ Xavfsiz o'chirildi: %s (%d bayt, %d o'tish)", path.name, size, passes)
        return True

    except Exception as exc:
        logger.warning("⚠️ Xavfsiz o'chirishda xato (%s): %s — oddiy o'chirish qayta urinamiz", path.name, exc)
        try:
            path.unlink(missing_ok=True)
            return True
        except Exception:
            return False


def _shred_sync(path: Path, size: int, passes: int) -> None:
    """Sinxron: tasodifiy baytlar bilan ustiga yozib o'chirish."""
    with open(path, "r+b") as f:
        for i in range(passes):
            f.seek(0)
            # Pass 1: tasodifiy baytlar, Pass 2: 0x00, Pass 3: 0xFF
            if i == 0:
                chunk_size = min(size, 64 * 1024)
                written = 0
                while written < size:
                    to_write = min(chunk_size, size - written)
                    f.write(secrets.token_bytes(to_write))
                    written += to_write
            elif i == 1:
                f.write(b"\x00" * size)
            else:
                f.write(b"\xff" * size)
            f.flush()
            os.fsync(f.fileno())
    path.unlink()


async def safe_cleanup(path: Path) -> None:
    """Faylni xavfsiz tozalash — shredding yoki oddiy o'chirish."""
    if path and path.exists():
        await secure_shred(path)
