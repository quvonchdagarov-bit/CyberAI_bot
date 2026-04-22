"""
Profanity (haqoratli so'z) ogohlantirish ma'lumotlar bazasi.

Har bir foydalanuvchining har bir chatdagi ogohlantirish sonini saqlaydi.
"""

from datetime import datetime

from bot.database.db import get_db


async def init_profanity_table():
    """Profanity jadvalini yaratish."""
    db = await get_db()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS profanity_warnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,
            bad_words TEXT,
            warned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_profanity_user_chat
        ON profanity_warnings(user_id, chat_id);
    """)
    await db.commit()


async def get_user_warnings(user_id: int, chat_id: int) -> int:
    """Foydalanuvchining joriy chatdagi ogohlantirish sonini olish."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT COUNT(*) FROM profanity_warnings WHERE user_id = ? AND chat_id = ?",
        (user_id, chat_id),
    )
    row = await cursor.fetchone()
    return row[0] if row else 0


async def add_warning(user_id: int, chat_id: int, bad_words: str) -> int:
    """Yangi ogohlantirish qo'shish. Yangi count qaytaradi."""
    db = await get_db()
    await db.execute(
        """
        INSERT INTO profanity_warnings (user_id, chat_id, bad_words, warned_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, chat_id, bad_words, datetime.now()),
    )
    await db.commit()
    return await get_user_warnings(user_id, chat_id)


async def reset_warnings(user_id: int, chat_id: int):
    """Foydalanuvchining ogohlantirishlarini tozalash (chiqarilgandan keyin)."""
    db = await get_db()
    await db.execute(
        "DELETE FROM profanity_warnings WHERE user_id = ? AND chat_id = ?",
        (user_id, chat_id),
    )
    await db.commit()


async def get_all_warnings(chat_id: int) -> list[dict]:
    """Guruhning barcha ogohlantirishlarini olish."""
    db = await get_db()
    cursor = await db.execute(
        """
        SELECT user_id, COUNT(*) as warning_count,
               MAX(warned_at) as last_warning
        FROM profanity_warnings
        WHERE chat_id = ?
        GROUP BY user_id
        ORDER BY warning_count DESC
        """,
        (chat_id,),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_warning_history(user_id: int, chat_id: int) -> list[dict]:
    """Foydalanuvchining ogohlantirish tarixini olish."""
    db = await get_db()
    cursor = await db.execute(
        """
        SELECT bad_words, warned_at
        FROM profanity_warnings
        WHERE user_id = ? AND chat_id = ?
        ORDER BY warned_at DESC
        """,
        (user_id, chat_id),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]
