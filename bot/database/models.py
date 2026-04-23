"""Ma'lumotlar bazasi so'rovlari — yangi funksiyalar qo'shilgan."""

import json
from datetime import datetime
from typing import Any

from bot.database.db import get_db


# ═══════════════════════════════════════════
# Foydalanuvchilar
# ═══════════════════════════════════════════

async def upsert_user(user_id: int, username: str | None, full_name: str | None):
    """Foydalanuvchini qo'shish yoki yangilash."""
    db = await get_db()
    await db.execute(
        """
        INSERT INTO users (user_id, username, full_name, last_active)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id)
        DO UPDATE SET username=?, full_name=?, last_active=?
        """,
        (
            user_id, username, full_name, datetime.now(),
            username, full_name, datetime.now(),
        ),
    )
    await db.commit()


async def get_user(user_id: int) -> dict | None:
    """Foydalanuvchi ma'lumotlarini olish."""
    db = await get_db()
    cursor = await db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def get_user_setting(user_id: int, key: str) -> Any:
    """Foydalanuvchi sozlamasini olish."""
    user = await get_user(user_id)
    if user:
        return user.get(key)
    return None


async def toggle_user_setting(user_id: int, key: str) -> bool:
    """Foydalanuvchi sozlamasini toggle qilish (0<->1)."""
    db = await get_db()
    current = await get_user_setting(user_id, key)
    new_value = 0 if current else 1
    await db.execute(
        f"UPDATE users SET {key} = ? WHERE user_id = ?",
        (new_value, user_id),
    )
    await db.commit()
    return bool(new_value)


async def get_total_users() -> int:
    """Umumiy foydalanuvchilar soni."""
    db = await get_db()
    cursor = await db.execute("SELECT COUNT(*) FROM users")
    row = await cursor.fetchone()
    return row[0] if row else 0


async def get_all_users() -> list[dict]:
    """Barcha foydalanuvchilarni olish (broadcast uchun)."""
    db = await get_db()
    cursor = await db.execute("SELECT user_id, username, is_banned FROM users")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def ban_user(user_id: int) -> None:
    """Foydalanuvchini bloklash."""
    db = await get_db()
    await db.execute("UPDATE users SET is_banned = 1 WHERE user_id = ?", (user_id,))
    await db.commit()


async def unban_user(user_id: int) -> None:
    """Foydalanuvchini blokdan chiqarish."""
    db = await get_db()
    await db.execute("UPDATE users SET is_banned = 0 WHERE user_id = ?", (user_id,))
    await db.commit()


async def is_user_banned(user_id: int) -> bool:
    """Foydalanuvchi bloklangan-bloklamamganini tekshirish."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT is_banned FROM users WHERE user_id = ?", (user_id,)
    )
    row = await cursor.fetchone()
    return bool(row and row["is_banned"])


async def increment_user_scan_count(user_id: int) -> None:
    """Foydalanuvchi tekshiruv sonini oshirish."""
    db = await get_db()
    await db.execute(
        "UPDATE users SET total_scans = total_scans + 1 WHERE user_id = ?",
        (user_id,),
    )
    await db.commit()


# ═══════════════════════════════════════════
# Tekshiruv tarixi
# ═══════════════════════════════════════════

async def save_scan(
    user_id: int,
    chat_id: int,
    scan_type: str,
    target: str,
    score: int,
    risk_level: str,
    result_data: dict[str, Any],
    short_report: str,
    full_report: str,
    tools_count: int = 0,
    scan_time_ms: int = 0,
) -> int:
    """Tekshiruv natijasini saqlash."""
    db = await get_db()
    cursor = await db.execute(
        """
        INSERT INTO scans
            (user_id, chat_id, scan_type, target, score,
             risk_level, result_json, short_report, full_report,
             tools_count, scan_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id, chat_id, scan_type, target[:200], score,
            risk_level, json.dumps(result_data, ensure_ascii=False),
            short_report, full_report, tools_count, scan_time_ms,
        ),
    )
    await db.commit()
    return cursor.lastrowid


async def get_scan(scan_id: int) -> dict | None:
    """Tekshiruv natijasini olish."""
    db = await get_db()
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = await cursor.fetchone()
    if row:
        data = dict(row)
        if data.get("result_json"):
            data["result_data"] = json.loads(data["result_json"])
        return data
    return None


async def get_user_scans(user_id: int, page: int = 1, per_page: int = 5) -> list[dict]:
    """Foydalanuvchining tekshiruv tarixini olish (pagination bilan)."""
    db = await get_db()
    offset = (page - 1) * per_page
    cursor = await db.execute(
        """
        SELECT id, scan_type, target, score, risk_level, created_at, scan_time_ms
        FROM scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, per_page, offset),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_user_scan_count(user_id: int) -> int:
    """Foydalanuvchining umumiy tekshiruvlari soni."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)
    )
    row = await cursor.fetchone()
    return row[0] if row else 0


async def clear_user_history(user_id: int):
    """Foydalanuvchi tarixini tozalash."""
    db = await get_db()
    await db.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
    await db.commit()


async def get_recent_dangerous_scans(limit: int = 10) -> list[dict]:
    """Oxirgi xavfli (75+) skanlarni olish (admin uchun)."""
    db = await get_db()
    cursor = await db.execute(
        """
        SELECT id, user_id, scan_type, target, score, risk_level, created_at
        FROM scans
        WHERE score >= 75
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════
# Statistika
# ═══════════════════════════════════════════

async def get_user_stats(user_id: int) -> dict[str, Any]:
    """Foydalanuvchi statistikasi."""
    db = await get_db()

    cursor = await db.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)
    )
    total = (await cursor.fetchone())[0]

    cursor = await db.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id = ? AND score >= 40", (user_id,)
    )
    dangerous = (await cursor.fetchone())[0]

    cursor = await db.execute(
        "SELECT scan_type, COUNT(*) as cnt FROM scans WHERE user_id = ? GROUP BY scan_type",
        (user_id,),
    )
    by_type = {row["scan_type"]: row["cnt"] for row in await cursor.fetchall()}

    cursor = await db.execute(
        "SELECT created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    )
    last_row = await cursor.fetchone()
    last_scan = last_row["created_at"] if last_row else None

    cursor = await db.execute(
        "SELECT AVG(score) FROM scans WHERE user_id = ? AND score > 0", (user_id,)
    )
    avg_row = await cursor.fetchone()
    avg_score = round(avg_row[0] or 0, 1)

    return {
        "total": total,
        "dangerous": dangerous,
        "by_type": by_type,
        "last_scan": last_scan,
        "avg_score": avg_score,
    }


async def get_global_stats() -> dict[str, Any]:
    """Global statistika (admin uchun)."""
    db = await get_db()

    cursor = await db.execute("SELECT COUNT(*) FROM users")
    users = (await cursor.fetchone())[0]

    cursor = await db.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1")
    banned = (await cursor.fetchone())[0]

    cursor = await db.execute("SELECT COUNT(*) FROM scans")
    total_scans = (await cursor.fetchone())[0]

    cursor = await db.execute("SELECT COUNT(*) FROM scans WHERE score >= 40")
    dangerous = (await cursor.fetchone())[0]

    cursor = await db.execute("SELECT COUNT(*) FROM scans WHERE score >= 75")
    critical = (await cursor.fetchone())[0]

    cursor = await db.execute(
        "SELECT COUNT(*) FROM scans WHERE date(created_at) = date('now')"
    )
    today_scans = (await cursor.fetchone())[0]

    return {
        "users": users,
        "banned": banned,
        "total_scans": total_scans,
        "dangerous": dangerous,
        "critical": critical,
        "today_scans": today_scans,
    }
