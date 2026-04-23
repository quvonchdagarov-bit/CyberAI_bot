"""SQLite ma'lumotlar bazasi boshqaruvi — WAL rejim va indekslar bilan."""

import aiosqlite

from bot.config import settings
from bot.loader import logger

_db: aiosqlite.Connection | None = None


async def init_db():
    """Ma'lumotlar bazasini ishga tushirish va jadvallar yaratish."""
    global _db
    _db = await aiosqlite.connect(str(settings.DB_PATH))
    _db.row_factory = aiosqlite.Row

    # WAL (Write-Ahead Logging) — parallel yozishlarda xatolarni kamaytiradi
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA synchronous=NORMAL")
    await _db.execute("PRAGMA cache_size=10000")
    await _db.execute("PRAGMA foreign_keys=ON")
    await _db.execute("PRAGMA temp_store=MEMORY")

    await _create_tables()
    await _migrate_existing_db()  # Eski bazaga yangi ustunlar
    await _create_indexes()
    logger.info("✅ Ma'lumotlar bazasi tayyor (WAL rejim): %s", settings.DB_PATH)


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
    """Jadvallar yaratish — yangi ustunlar qo'shilgan."""
    await _db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id    INTEGER PRIMARY KEY,
            username   TEXT,
            full_name  TEXT,
            language   TEXT DEFAULT 'uz',
            is_banned  INTEGER DEFAULT 0,
            auto_delete INTEGER DEFAULT 0,
            notify     INTEGER DEFAULT 1,
            detail_mode INTEGER DEFAULT 0,
            total_scans INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            chat_id     INTEGER,
            scan_type   TEXT,
            target      TEXT,
            score       INTEGER DEFAULT 0,
            risk_level  TEXT,
            result_json TEXT,
            short_report TEXT,
            full_report TEXT,
            tools_count INTEGER DEFAULT 0,
            scan_time_ms INTEGER DEFAULT 0,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS group_settings (
            chat_id         INTEGER PRIMARY KEY,
            chat_title      TEXT,
            auto_delete     INTEGER DEFAULT 0,
            scan_enabled    INTEGER DEFAULT 1,
            min_alert_score INTEGER DEFAULT 65,
            profanity_enabled INTEGER DEFAULT 1,
            added_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS broadcasts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            message    TEXT,
            sent_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    await _db.commit()


async def _migrate_existing_db():
    """Eski bazaga yangi ustunlarni xavfsiz qo'shish (idempotent)."""
    migrations = [
        ("users", "language", "TEXT DEFAULT 'uz'"),
        ("users", "is_banned", "INTEGER DEFAULT 0"),
        ("users", "total_scans", "INTEGER DEFAULT 0"),
        ("scans", "tools_count", "INTEGER DEFAULT 0"),
        ("scans", "scan_time_ms", "INTEGER DEFAULT 0"),
        ("group_settings", "chat_title", "TEXT"),
        ("group_settings", "profanity_enabled", "INTEGER DEFAULT 1"),
        ("group_settings", "updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]
    for table, column, col_def in migrations:
        try:
            await _db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
            logger.info("✅ Migratsiya: %s.%s qo'shildi", table, column)
        except Exception:
            pass  # Ustun allaqachon mavjud — o'tkazib yuboramiz
    await _db.commit()


async def _create_indexes():
    """Tezlikni oshirish uchun indekslar yaratish."""
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_scans_score ON scans(score)",
        "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type)",
        "CREATE INDEX IF NOT EXISTS idx_users_banned ON users(is_banned)",
        "CREATE INDEX IF NOT EXISTS idx_users_active ON users(last_active DESC)",
    ]
    for sql in indexes:
        await _db.execute(sql)
    await _db.commit()
