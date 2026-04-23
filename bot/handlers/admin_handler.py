"""Admin handler — to'liq kengaytirilgan admin panel.

Yangi funksiyalar:
- /broadcast — barcha foydalanuvchilarga xabar yuborish
- /ban <user_id> — foydalanuvchini bloklash
- /unban <user_id> — blokdan chiqarish
- /tools — barcha vositalar holati
- /scan_log — oxirgi xavfli scanlar
- /users — foydalanuvchilar ro'yxati
"""

import asyncio

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, Message

from bot.config import settings
from bot.database.models import (
    get_global_stats,
    get_all_users,
    get_recent_dangerous_scans,
    ban_user,
    unban_user,
)
from bot.keyboards.callback_data import AdminAction
from bot.keyboards.inline_kb import get_admin_keyboard, get_back_to_menu_keyboard
from bot.loader import bot, logger, tools_status

router = Router(name="admin_handler")


def is_admin(user_id: int) -> bool:
    """Foydalanuvchi admin ekanligini tekshirish."""
    return user_id in settings.ADMIN_IDS


# ─── /admin ────────────────────────────────────────────────────────────────
@router.message(Command("admin"))
async def cmd_admin(message: Message):
    """Admin panel."""
    if not message.from_user or not is_admin(message.from_user.id):
        await message.reply("⛔ Bu buyruq faqat adminlar uchun.")
        return

    stats = await get_global_stats()
    active_tools = sum(1 for v in tools_status.values() if v)
    total_tools = len(tools_status)

    await message.answer(
        f"👮 <b>CyberAI Admin Panel</b>\n"
        f"━━━━━━━━━━━━━━━━━\n"
        f"👥 Foydalanuvchilar: <b>{stats['users']}</b>\n"
        f"📊 Jami skanlar: <b>{stats['total_scans']}</b>\n"
        f"🟡 Shubhali: <b>{stats['dangerous']}</b>\n"
        f"🔴 Kritik: <b>{stats['critical']}</b>\n"
        f"🔧 Vositalar: <b>{active_tools}/{total_tools}</b> faol\n"
        f"🤖 Bot: <b>v{settings.BOT_VERSION}</b> | {settings.ENVIRONMENT}",
        reply_markup=get_admin_keyboard(),
    )


# ─── /broadcast ───────────────────────────────────────────────────────────
@router.message(Command("broadcast"))
async def cmd_broadcast(message: Message):
    """Barcha foydalanuvchilarga xabar yuborish."""
    if not message.from_user or not is_admin(message.from_user.id):
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply(
            "📢 <b>Foydalanish:</b>\n"
            "<code>/broadcast Xabar matni</code>"
        )
        return

    broadcast_text = (
        f"📢 <b>CyberAI Bot xabari:</b>\n\n"
        f"{args[1]}"
    )

    status = await message.reply("⏳ Xabar yuborilmoqda...")
    users = await get_all_users()
    sent, failed = 0, 0

    for user in users:
        if user.get("is_banned"):
            continue
        try:
            await bot.send_message(user["user_id"], broadcast_text)
            sent += 1
            await asyncio.sleep(0.05)  # Flood limit oldini olish
        except Exception:
            failed += 1

    await status.edit_text(
        f"✅ <b>Broadcast yakunlandi</b>\n\n"
        f"📤 Yuborildi: <b>{sent}</b>\n"
        f"❌ Xato: <b>{failed}</b>\n"
        f"👥 Jami: <b>{len(users)}</b>"
    )
    logger.info("Broadcast: %d yuborildi, %d xato", sent, failed)


# ─── /ban ──────────────────────────────────────────────────────────────────
@router.message(Command("ban"))
async def cmd_ban(message: Message):
    """Foydalanuvchini botdan bloklash."""
    if not message.from_user or not is_admin(message.from_user.id):
        return

    args = message.text.split()
    if len(args) < 2 or not args[1].isdigit():
        await message.reply("🚫 <b>Foydalanish:</b> <code>/ban 123456789</code>")
        return

    target_id = int(args[1])
    reason = " ".join(args[2:]) if len(args) > 2 else "Admin qarori"

    await ban_user(target_id)
    await message.reply(
        f"🚫 <b>Foydalanuvchi bloklandi</b>\n"
        f"🆔 ID: <code>{target_id}</code>\n"
        f"📝 Sabab: {reason}"
    )

    # Foydalanuvchiga xabar
    try:
        await bot.send_message(
            target_id,
            f"🚫 <b>Siz botdan bloklangansiz.</b>\n"
            f"📝 Sabab: {reason}\n"
            f"📞 Murojaat: @Hamidullayevich_03"
        )
    except Exception:
        pass

    logger.warning("Admin ban: user_id=%d, sabab=%s", target_id, reason)


# ─── /unban ────────────────────────────────────────────────────────────────
@router.message(Command("unban"))
async def cmd_unban(message: Message):
    """Foydalanuvchini blokdan chiqarish."""
    if not message.from_user or not is_admin(message.from_user.id):
        return

    args = message.text.split()
    if len(args) < 2 or not args[1].isdigit():
        await message.reply("✅ <b>Foydalanish:</b> <code>/unban 123456789</code>")
        return

    target_id = int(args[1])
    await unban_user(target_id)
    await message.reply(
        f"✅ <b>Foydalanuvchi blokdan chiqarildi</b>\n"
        f"🆔 ID: <code>{target_id}</code>"
    )

    try:
        await bot.send_message(
            target_id,
            "✅ <b>Botdan bloklangiz olib tashlandi!</b>\n"
            "CyberAI botdan yana foydalanishingiz mumkin."
        )
    except Exception:
        pass


# ─── /tools ────────────────────────────────────────────────────────────────
@router.message(Command("tools"))
async def cmd_tools(message: Message):
    """Barcha xavfsizlik vositalarining holati."""
    if not message.from_user or not is_admin(message.from_user.id):
        return

    lines = ["🔧 <b>Vositalar holati:</b>\n"]
    tool_icons = {
        "VirusTotal": "🔬",
        "YARA": "🧬",
        "ClamAV": "🦠",
        "Androguard": "📱",
        "Entropy": "📈",
        "Hash": "🔐",
        "SafeBrowsing": "🌐",
        "URLAnalysis": "🔗",
        "OCR": "📷",
        "QR": "📱",
        "Archive": "🗜️",
        "AI": "🤖",
        "TelegramBot": "💬",
        "AbuseIPDB": "🛡",
        "URLScan": "🔍",
    }

    for tool, status in tools_status.items():
        icon = tool_icons.get(tool, "🔧")
        s = "✅ Faol" if status else "❌ O'chirilgan"
        lines.append(f"{icon} {tool}: {s}")

    active = sum(1 for v in tools_status.values() if v)
    total = len(tools_status)
    lines.append(f"\n📊 Holat: <b>{active}/{total}</b> vosita faol")

    await message.reply("\n".join(lines))


# ─── /scan_log ─────────────────────────────────────────────────────────────
@router.message(Command("scan_log"))
async def cmd_scan_log(message: Message):
    """Oxirgi 10 ta xavfli skan hisoboti."""
    if not message.from_user or not is_admin(message.from_user.id):
        return

    scans = await get_recent_dangerous_scans(limit=10)
    if not scans:
        await message.reply("📋 Hozircha xavfli skan aniqlanmagan.")
        return

    lines = ["🔴 <b>Oxirgi xavfli skanlar:</b>\n"]
    for i, scan in enumerate(scans, 1):
        score = scan.get("score", 0)
        risk = scan.get("risk_level", "?")
        stype = scan.get("scan_type", "?")
        target = (scan.get("target") or "")[:30]
        created = str(scan.get("created_at", ""))[:16]
        user_id = scan.get("user_id", "?")
        lines.append(
            f"{i}. [{score}/100] {risk}\n"
            f"   📋 {stype}: <code>{target}</code>\n"
            f"   👤 User: {user_id} | 📅 {created}\n"
        )

    await message.reply("\n".join(lines))


# ─── Callback handlers ───────────────────────────────────────────────────
@router.callback_query(AdminAction.filter(F.action == "stats"))
async def callback_admin_stats(callback: CallbackQuery):
    """Global statistika (admin)."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Ruxsat yo'q.", show_alert=True)
        return

    stats = await get_global_stats()
    active_tools = sum(1 for v in tools_status.values() if v)

    text = (
        "📊 <b>Global Statistika</b>\n"
        "━━━━━━━━━━━━━━━━━\n"
        f"👥 Foydalanuvchilar: <b>{stats['users']}</b>\n"
        f"📌 Jami tekshiruvlar: <b>{stats['total_scans']}</b>\n"
        f"🟡 Shubhali (40+): <b>{stats['dangerous']}</b>\n"
        f"🔴 Kritik (75+): <b>{stats['critical']}</b>\n"
        f"🔧 Faol vositalar: <b>{active_tools}/{len(tools_status)}</b>\n"
        f"🤖 Versiya: <b>v{settings.BOT_VERSION}</b>"
    )

    try:
        await callback.message.edit_text(text, reply_markup=get_admin_keyboard())
    except Exception:
        await callback.message.answer(text, reply_markup=get_admin_keyboard())

    await callback.answer()


@router.callback_query(AdminAction.filter(F.action == "back"))
async def callback_admin_back(callback: CallbackQuery):
    """Admin paneldan ortga."""
    from bot.keyboards.inline_kb import get_main_menu_inline
    try:
        await callback.message.edit_text(
            "⬇️ Quyidagi menyudan foydalaning yoki to'g'ridan-to'g'ri fayl/link yuboring:",
            reply_markup=get_main_menu_inline(),
        )
    except Exception:
        pass
    await callback.answer()
