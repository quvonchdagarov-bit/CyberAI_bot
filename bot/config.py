"""Loyiha sozlamalari — .env fayldan yuklanadi."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Barcha konfiguratsiya qiymatlari."""

    # Telegram
    BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    ADMIN_IDS: list[int] = [
        int(x.strip())
        for x in os.getenv("ADMIN_IDS", "").split(",")
        if x.strip().isdigit()
    ]

    # Tashqi API kalitlari
    VT_API_KEY: str = os.getenv("VT_API_KEY", "").strip()
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip()

    # Bot xulqi
    DELETE_BAD_MESSAGES: bool = os.getenv("DELETE_BAD_MESSAGES", "false").lower() == "true"
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "40"))
    URL_ANALYSIS_LIMIT: int = int(os.getenv("URL_ANALYSIS_LIMIT", "3"))

    # Papkalar
    DOWNLOAD_DIR: Path = Path(os.getenv("DOWNLOAD_DIR", "downloads"))
    QUARANTINE_DIR: Path = Path(os.getenv("QUARANTINE_DIR", "quarantine"))
    YARA_RULES_PATH: Path = Path(os.getenv("YARA_RULES_PATH", "rules/basic_rules.yar"))
    DB_PATH: Path = Path(os.getenv("DB_PATH", "data/camcyber.db"))

    # ClamAV
    CLAMAV_HOST: str = os.getenv("CLAMAV_HOST", "127.0.0.1")
    CLAMAV_PORT: int = int(os.getenv("CLAMAV_PORT", "3310"))

    # Tesseract OCR
    TESSERACT_CMD: str = os.getenv("TESSERACT_CMD", "").strip()

    # Gemini AI modeli
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")


settings = Settings()

# Tekshirish
if not settings.BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN topilmadi. .env ichiga token yozing.")

# Kerakli papkalarni yaratish
for directory in [
    settings.DOWNLOAD_DIR,
    settings.QUARANTINE_DIR,
    settings.DB_PATH.parent,
    Path("rules"),
]:
    directory.mkdir(parents=True, exist_ok=True)
