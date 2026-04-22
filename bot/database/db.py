"""SQLite ma'lumotlar bazasi boshqaruvi."""

import aiosqlite

from bot.config import settings
from bot.loader import logger

_db: aiosqlite.Connection | None = None


async def init_db():
    """Ma'lumotlar bazasini ishga tushirish va jadvallar yaratish."""
    global _db
    _db = await aiosqlite.connect(str(settings.DB_PATH))
    _db.row_factory = aiosqlite.Row
    await _create_tables()
    logger.info("Ma'lumotlar bazasi tayyor: %s", settings.DB_PATH)


async def get_db() -> aiosqlite.Connection:
    """Aktiv DB connectionni olish."""
    if _db is None:
        await init_db()
    return _db


async def close_db():
    """DB connectionni yopish."""
    global _db
    if _db:
        await _db.close()
        _db = None


async def _create_tables():
    """Jadvallar yaratish."""
    await _db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            full_name TEXT,
            auto_delete INTEGER DEFAULT 0,
            notify INTEGER DEFAULT 1,
            detail_mode INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            chat_id INTEGER,
            scan_type TEXT,
            target TEXT,
            score INTEGER DEFAULT 0,
            risk_level TEXT,
            result_json TEXT,
            short_report TEXT,
            full_report TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS group_settings (
            chat_id INTEGER PRIMARY KEY,
            auto_delete INTEGER DEFAULT 0,
            scan_enabled INTEGER DEFAULT 1,
            min_alert_score INTEGER DEFAULT 40,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    await _db.commit()
