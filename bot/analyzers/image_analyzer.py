"""Rasm tahlili — OCR (matn ajratish) va QR kod o'qish."""

from pathlib import Path
from typing import Any

from bot.loader import logger

# =============================================
# OCR — pytesseract + Pillow
# =============================================
try:
    from PIL import Image
    import pytesseract

    _ocr_available = True
except ImportError:
    Image = None
    pytesseract = None
    _ocr_available = False

# =============================================
# QR — pyzbar + Pillow
# =============================================
try:
    from pyzbar.pyzbar import decode as zbar_decode

    _qr_available = True
except Exception:
    zbar_decode = None
    _qr_available = False

from bot.utils.helpers import dedupe_keep_order


def extract_image_text(file_path: Path) -> dict[str, Any]:
    """Rasmdan matn ajratib olish (OCR).

    Pytesseract va Pillow o'rnatilgan bo'lishi kerak.
    Tesseract OCR dasturi tizimda bo'lishi shart.
    """
    if not _ocr_available:
        return {"enabled": False, "text": "", "note": "pytesseract yoki Pillow o'rnatilmagan"}
    try:
        img = Image.open(file_path)

        # Rasmni kichiklashtirish (katta fayllar uchun)
        max_dim = 4000
        if img.width > max_dim or img.height > max_dim:
            img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

        # OCR — ko'p tilli rejimda
        text = pytesseract.image_to_string(img, lang="eng+rus+uzb")
        text = text.strip()

        if text:
            logger.info("🔍 OCR: %d belgi ajratildi", len(text))

        return {"enabled": True, "text": text}
    except Exception as e:
        logger.warning("OCR xatosi: %s", e)
        return {"enabled": True, "text": "", "error": str(e)}


def extract_qr_data(file_path: Path) -> dict[str, Any]:
    """Rasm ichidagi QR kodlardan ma'lumot o'qish.

    Pyzbar va Pillow o'rnatilgan bo'lishi kerak.
    """
    if not _qr_available:
        return {"enabled": False, "values": [], "note": "pyzbar o'rnatilmagan"}
    try:
        img = Image.open(file_path)

        # QR kodlarni aniqlash
        decoded_objects = zbar_decode(img)
        values = []
        for obj in decoded_objects:
            try:
                data = obj.data.decode("utf-8", errors="ignore")
                if data:
                    values.append(data)
            except Exception:
                continue

        unique_values = dedupe_keep_order(values)

        if unique_values:
            logger.info("📱 QR: %d ta kod topildi", len(unique_values))

        return {"enabled": True, "values": unique_values}
    except Exception as e:
        logger.warning("QR skan xatosi: %s", e)
        return {"enabled": True, "values": [], "error": str(e)}
