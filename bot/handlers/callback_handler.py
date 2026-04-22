"""Callback handler — inline tugma bosilgandagi amallar."""

import json

from aiogram import F, Router
from aiogram.types import CallbackQuery

from bot.database.models import (
    get_scan,
    get_user_scan_count,
    get_user_scans,
    get_user_stats,
    clear_user_history,
)
from bot.keyboards.callback_data import (
    HistoryAction,
    MenuAction,
    ResultAction,
)
from bot.keyboards.inline_kb import (
    get_ai_back_keyboard,
    get_back_to_menu_keyboard,
    get_detail_back_keyboard,
    get_history_keyboard,
    get_main_menu_inline,
    get_stats_keyboard,
)
from bot.loader import logger
from bot.reports.builder import build_plain_expert_warning
from bot.reports.formatter import format_detailed_report
from bot.services.ai_reporter import ai_expand_security_report

router = Router(name="callback_handler")


# =========================
# Natija tugmalari
# =========================
@router.callback_query(ResultAction.filter(F.action == "detail"))
async def callback_detail(callback: CallbackQuery, callback_data: ResultAction):
    """Batafsil hisobot ko'rsatish."""
    scan = await get_scan(callback_data.scan_id)
    if not scan:
        await callback.answer("❌ Natija topilmadi.", show_alert=True)
        return

    full_report = scan.get("full_report", "Hisobot mavjud emas.")

    try:
        await callback.message.edit_text(
            full_report[:4096],
            reply_markup=get_detail_back_keyboard(callback_data.scan_id),
        )
    except Exception:
        await callback.message.answer(
            full_report[:4096],
            reply_markup=get_detail_back_keyboard(callback_data.scan_id),
        )

    await callback.answer()


@router.callback_query(ResultAction.filter(F.action == "ai"))
async def callback_ai_analysis(callback: CallbackQuery, callback_data: ResultAction):
    """AI kengaytirilgan tahlil."""
    scan = await get_scan(callback_data.scan_id)
    if not scan:
        await callback.answer("❌ Natija topilmadi.", show_alert=True)
        return

    await callback.answer("🤖 AI tahlil boshlanmoqda...", show_alert=False)

    try:
        await callback.message.edit_text(
            "🤖 <b>AI tahlil qilinmoqda...</b>\n⏳ Bu 5-15 soniya vaqt olishi mumkin."
        )
    except Exception:
        pass

    result_data = scan.get("result_data", {})
    scan_type = scan.get("scan_type", "file")
    warning = build_plain_expert_warning(result_data, scan_type)
    full_report = scan.get("full_report", "")

    ai_text = await ai_expand_security_report(
        warning, full_report, result_data, scan_type
    )

    try:
        await callback.message.edit_text(
            ai_text[:4096],
            reply_markup=get_ai_back_keyboard(),
        )
    except Exception:
        await callback.message.answer(
            ai_text[:4096],
            reply_markup=get_ai_back_keyboard(),
        )


@router.callback_query(ResultAction.filter(F.action == "share"))
async def callback_share(callback: CallbackQuery, callback_data: ResultAction):
    """Natijani ulashish."""
    scan = await get_scan(callback_data.scan_id)
    if not scan:
        await callback.answer("❌ Natija topilmadi.", show_alert=True)
        return

    share_text = scan.get("short_report", "Natija mavjud emas.")
    share_text += "\n\n🛡 CamCyber Pro bilan tekshirilgan."

    # Forward qilish uchun alohida xabar sifatida yuborish
    await callback.message.answer(
        f"📤 <b>Ulashish uchun nusxa:</b>\n\n{share_text[:3800]}"
    )
    await callback.answer("✅ Nusxa tayyorlandi!")


# =========================
# Statistika
# =========================
@router.callback_query(MenuAction.filter(F.action == "stats"))
async def callback_stats(callback: CallbackQuery):
    """Statistika sahifasi."""
    user_id = callback.from_user.id
    stats = await get_user_stats(user_id)
    by_type = stats.get("by_type", {})

    stats_text = (
        "📊 <b>Sizning statistikangiz</b>\n"
        "\n"
        f"📌 Jami tekshiruvlar: <b>{stats['total']}</b>\n"
        f"🔴 Xavfli topilgan: <b>{stats['dangerous']}</b>\n"
        f"📄 Fayllar: <b>{by_type.get('file', 0)}</b>\n"
        f"🔗 Havolalar: <b>{by_type.get('link', 0)}</b>\n"
        f"📝 Matnlar: <b>{by_type.get('text', 0)}</b>\n"
    )
    if stats.get("last_scan"):
        stats_text += f"\n🕐 Oxirgi: {stats['last_scan']}"

    try:
        await callback.message.edit_text(stats_text, reply_markup=get_stats_keyboard())
    except Exception:
        await callback.message.answer(stats_text, reply_markup=get_stats_keyboard())

    await callback.answer()


# =========================
# Tarix
# =========================
@router.callback_query(MenuAction.filter(F.action == "history"))
async def callback_history(callback: CallbackQuery):
    """Tarix sahifasi."""
    user_id = callback.from_user.id
    total = await get_user_scan_count(user_id)
    scans = await get_user_scans(user_id, page=1)

    if not scans:
        try:
            await callback.message.edit_text(
                "📋 <b>Tekshiruv tarixi</b>\n\nHali hech qanday tekshiruv bajarilmagan.",
                reply_markup=get_back_to_menu_keyboard(),
            )
        except Exception:
            await callback.message.answer(
                "📋 <b>Tekshiruv tarixi</b>\n\nHali hech qanday tekshiruv bajarilmagan.",
                reply_markup=get_back_to_menu_keyboard(),
            )
        await callback.answer()
        return

    try:
        await callback.message.edit_text(
            f"📋 <b>Tekshiruv tarixi</b> ({total} ta)",
            reply_markup=get_history_keyboard(scans, 1, total),
        )
    except Exception:
        await callback.message.answer(
            f"📋 <b>Tekshiruv tarixi</b> ({total} ta)",
            reply_markup=get_history_keyboard(scans, 1, total),
        )

    await callback.answer()


@router.callback_query(HistoryAction.filter(F.action == "page"))
async def callback_history_page(callback: CallbackQuery, callback_data: HistoryAction):
    """Tarix sahifasi — pagination."""
    user_id = callback.from_user.id
    page = callback_data.page
    total = await get_user_scan_count(user_id)
    scans = await get_user_scans(user_id, page=page)

    try:
        await callback.message.edit_text(
            f"📋 <b>Tekshiruv tarixi</b> ({total} ta)",
            reply_markup=get_history_keyboard(scans, page, total),
        )
    except Exception:
        pass

    await callback.answer()


@router.callback_query(HistoryAction.filter(F.action == "view"))
async def callback_history_view(callback: CallbackQuery, callback_data: HistoryAction):
    """Tarixdan bitta natijani ko'rish."""
    scan = await get_scan(callback_data.scan_id)
    if not scan:
        await callback.answer("❌ Natija topilmadi.", show_alert=True)
        return

    short_report = scan.get("short_report", "Ma'lumot mavjud emas.")
    scan_id = scan["id"]
    score = scan.get("score", 0)

    try:
        await callback.message.edit_text(
            short_report[:4096],
            reply_markup=get_detail_back_keyboard(scan_id),
        )
    except Exception:
        await callback.message.answer(
            short_report[:4096],
            reply_markup=get_detail_back_keyboard(scan_id),
        )

    await callback.answer()


@router.callback_query(HistoryAction.filter(F.action == "clear"))
async def callback_history_clear(callback: CallbackQuery):
    """Tarixni tozalash."""
    user_id = callback.from_user.id
    await clear_user_history(user_id)

    try:
        await callback.message.edit_text(
            "🗑 <b>Tarix tozalandi!</b>\n\nBarcha tekshiruv natijalari o'chirildi.",
            reply_markup=get_back_to_menu_keyboard(),
        )
    except Exception:
        pass

    await callback.answer("✅ Tarix tozalandi!")


# =========================
# Noop callback (pagination info uchun)
# =========================
@router.callback_query(lambda c: c.data == "noop")
async def callback_noop(callback: CallbackQuery):
    """Bo'sh callback — hech narsa qilmaydi."""
    await callback.answer()
