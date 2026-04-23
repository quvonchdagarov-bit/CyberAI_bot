"""Loyiha sozlamalari — .env fayldan yuklanadi."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Barcha konfiguratsiya qiymatlari."""

    # ─── Telegram ───────────────────────────────────────────────────────────
    BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    ADMIN_IDS: list[int] = [
        int(x.strip())
        for x in os.getenv("ADMIN_IDS", "").split(",")
        if x.strip().isdigit()
    ]

    # ─── Bot versiyasi va muhit ──────────────────────────────────────────────
    BOT_VERSION: str = os.getenv("BOT_VERSION", "2.1.0")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")  # production | staging | development

    # ─── Tashqi API kalitlari ────────────────────────────────────────────────
    VT_API_KEY: str = os.getenv("VT_API_KEY", "").strip()
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip()
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "").strip()
    SENTRY_DSN: str = os.getenv("SENTRY_DSN", "").strip()

    # ─── Bot xulqi ───────────────────────────────────────────────────────────
    DELETE_BAD_MESSAGES: bool = os.getenv("DELETE_BAD_MESSAGES", "false").lower() == "true"
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "50"))
    URL_ANALYSIS_LIMIT: int = int(os.getenv("URL_ANALYSIS_LIMIT", "5"))
    GLOBAL_RISK_THRESHOLD: int = int(os.getenv("GLOBAL_RISK_THRESHOLD", "65"))

    # ─── Rate Limiting ────────────────────────────────────────────────────────
    THROTTLE_RATE: float = float(os.getenv("THROTTLE_RATE", "1.5"))
    MAX_FILES_PER_MINUTE: int = int(os.getenv("MAX_FILES_PER_MINUTE", "5"))
    MAX_MESSAGES_PER_10S: int = int(os.getenv("MAX_MESSAGES_PER_10S", "8"))

    # ─── Papkalar ────────────────────────────────────────────────────────────
    DOWNLOAD_DIR: Path = Path(os.getenv("DOWNLOAD_DIR", "downloads"))
    QUARANTINE_DIR: Path = Path(os.getenv("QUARANTINE_DIR", "quarantine"))
    YARA_RULES_PATH: Path = Path(os.getenv("YARA_RULES_PATH", "rules/basic_rules.yar"))
    DB_PATH: Path = Path(os.getenv("DB_PATH", "data/camcyber.db"))

    # ─── ClamAV ──────────────────────────────────────────────────────────────
    CLAMAV_HOST: str = os.getenv("CLAMAV_HOST", "127.0.0.1")
    CLAMAV_PORT: int = int(os.getenv("CLAMAV_PORT", "3310"))

    # ─── Tesseract OCR ───────────────────────────────────────────────────────
    TESSERACT_CMD: str = os.getenv("TESSERACT_CMD", "").strip()

    # ─── AI Modeli ───────────────────────────────────────────────────────────
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    # ─── URLScan ─────────────────────────────────────────────────────────────
    # URLScan tahlilini kutish vaqti (soniya) — ayrim serverlar sekin
    URLSCAN_WAIT_SEC: int = int(os.getenv("URLSCAN_WAIT_SEC", "20"))

    # ─── Xavfsizlik ──────────────────────────────────────────────────────────
    # Fayllarni xavfsiz o'chirish (DoD 5220.22-M)
    SECURE_DELETE: bool = os.getenv("SECURE_DELETE", "true").lower() == "true"
    # Tahlildan keyin faylni karantinda necha kun saqlash (0 = darhol o'chirish)
    QUARANTINE_DAYS: int = int(os.getenv("QUARANTINE_DAYS", "7"))


settings = Settings()

# ─── Tekshirishlar ───────────────────────────────────────────────────────────
if not settings.BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN topilmadi. .env ichiga token yozing.")

# ─── Kerakli papkalarni yaratish ─────────────────────────────────────────────
for _directory in [
    settings.DOWNLOAD_DIR,
    settings.QUARANTINE_DIR,
    settings.DB_PATH.parent,
    Path("rules"),
    Path("logs"),
]:
    _directory.mkdir(parents=True, exist_ok=True)
