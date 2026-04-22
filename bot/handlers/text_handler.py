"""Matn xabar handler — matn tahlili va URL tekshiruvi."""

import asyncio

import aiohttp
from aiogram import F, Router
from aiogram.types import Message

from bot.config import settings
from bot.analyzers.scoring import classify_risk_level
from bot.analyzers.text_analyzer import analyze_text
from bot.analyzers.url_analyzer import analyze_url
from bot.database.models import save_scan
from bot.keyboards.inline_kb import get_result_keyboard
from bot.reports.builder import build_plain_expert_warning
from bot.reports.formatter import format_detailed_report, format_short_result
from bot.services.ai_reporter import ai_expand_security_report
from bot.utils.helpers import extract_urls, normalize_url
from bot.utils.telegram import maybe_delete

router = Router(name="text_handler")

# Reply keyboard tugmalarini ushlab, tegishli handlerlarga yo'naltirish
MENU_BUTTONS = {"🔍 Tekshirish", "📊 Statistika", "📋 Tarix", "⚙️ Sozlamalar", "ℹ️ Yordam", "📞 Aloqa"}


@router.message(F.text)
async def handle_text_message(message: Message):
    """Matnli xabarlarni tahlil qilish — matn va URL tekshiruvi."""
    if not message.text:
        return

    text = message.text.strip()

    # Menu button bosilgan bo'lsa — handlers/start yoki handlers/settings ga yo'naltirish
    if text in MENU_BUTTONS:
        await _handle_menu_button(message, text)
        return

    user_id = message.from_user.id if message.from_user else 0
    chat_id = message.chat.id

    # 1. Matn tahlili
    text_result = await analyze_text(message.text)
    text_score = int(text_result.get("score", 0))

    if text_score > settings.GLOBAL_RISK_THRESHOLD:
        await _send_analysis_result(
            message, text_result, "text", user_id, chat_id,
            tag=text_result.get("tag"),
        )

    # 2. URL tahlili
    urls = extract_urls(message.text)
    if not urls:
        # Agar matn ham xavfsiz bo'lsa va URL yo'q bo'lsa — jimlik
        return

    # URL topilsa — status xabari yuborish
    status_msg = await message.reply(
        "🔍 <b>Havola tekshirilmoqda...</b>\n"
        f"📎 {len(urls)} ta havola topildi. Tahlil qilinmoqda..."
    )

    async with aiohttp.ClientSession() as session:
        results = []
        for url_value in urls[:settings.URL_ANALYSIS_LIMIT]:
            results.append(await analyze_url(session, url_value))
            await asyncio.sleep(0.4)

    if results:
        best = max(results, key=lambda x: x["score"])
        best_score = int(best.get("score", 0))

        # Natijani databse ga saqlash
        short_text = format_short_result(best, "link")
        full_text = format_detailed_report(best, "link")
        scan_id = await save_scan(
            user_id=user_id,
            chat_id=chat_id,
            scan_type="link",
            target=best.get("url", "")[:200],
            score=best_score,
            risk_level=classify_risk_level(best_score),
            result_data=best,
            short_report=short_text,
            full_report=full_text,
        )

        keyboard = get_result_keyboard(scan_id, best_score)

        if best_score >= 70:
            from bot.database.models import get_user_setting
            auto_delete = await get_user_setting(user_id, "auto_delete")
            if auto_delete or settings.DELETE_BAD_MESSAGES:
                try:
                    await message.delete()
                except Exception:
                    pass

        # Faqat risk belgilangan darajadan yuqori bo'lsa xabar berish
        if best_score <= settings.GLOBAL_RISK_THRESHOLD:
            logger.info("Low risk URL score (%d <= %d). Silencing alert.", best_score, settings.GLOBAL_RISK_THRESHOLD)
            try:
                await status_msg.delete()
            except Exception:
                pass
            return

        # Status xabarni natija bilan almashtirish
        try:
            await status_msg.edit_text(short_text, reply_markup=keyboard)
        except Exception:
            await status_msg.delete()
            await message.answer(short_text, reply_markup=keyboard)


async def _send_analysis_result(
    message: Message,
    result: dict,
    content_type: str,
    user_id: int,
    chat_id: int,
    tag: str | None = None,
):
    """Tahlil natijasini saqlash va foydalanuvchiga yuborish."""
    score = int(result.get("score", 0))

    short_text = format_short_result(result, content_type)
    full_text = format_detailed_report(result, content_type, tag)

    scan_id = await save_scan(
        user_id=user_id,
        chat_id=chat_id,
        scan_type=content_type,
        target=result.get("text", "")[:200],
        score=score,
        risk_level=classify_risk_level(score),
        result_data=result,
        short_report=short_text,
        full_report=full_text,
    )

    keyboard = get_result_keyboard(scan_id, score)

    if score >= 70:
        from bot.database.models import get_user_setting
        auto_delete = await get_user_setting(user_id, "auto_delete")
        if auto_delete or settings.DELETE_BAD_MESSAGES:
            try:
                await message.delete()
            except Exception:
                pass

    if score <= settings.GLOBAL_RISK_THRESHOLD:
        logger.info("Low risk content score (%d <= %d). Silencing alert.", score, settings.GLOBAL_RISK_THRESHOLD)
        return

    await message.reply(short_text, reply_markup=keyboard)


async def _handle_menu_button(message: Message, text: str):
    """Reply keyboard menu tugmalari uchun yo'naltirish."""
    from bot.keyboards.inline_kb import (
        get_main_menu_inline,
        get_scan_type_keyboard,
        get_settings_keyboard,
        get_stats_keyboard,
        get_history_keyboard,
    )
    from bot.database.models import get_user, get_user_stats, get_user_scans, get_user_scan_count

    user_id = message.from_user.id if message.from_user else 0

    if text == "🔍 Tekshirish":
        await message.answer(
            "🔍 <b>Tekshirish turini tanlang</b>\n\n"
            "Yoki to'g'ridan-to'g'ri fayl/link yuboring:",
            reply_markup=get_scan_type_keyboard(),
        )

    elif text == "📊 Statistika":
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

        await message.answer(stats_text, reply_markup=get_stats_keyboard())

    elif text == "📋 Tarix":
        total = await get_user_scan_count(user_id)
        scans = await get_user_scans(user_id, page=1)

        if not scans:
            await message.answer(
                "📋 <b>Tekshiruv tarixi</b>\n\nHali hech qanday tekshiruv bajarilmagan.",
                reply_markup=get_main_menu_inline(),
            )
            return

        await message.answer(
            f"📋 <b>Tekshiruv tarixi</b> ({total} ta)",
            reply_markup=get_history_keyboard(scans, 1, total),
        )

    elif text == "⚙️ Sozlamalar":
        user = await get_user(user_id)
        auto_delete = bool(user.get("auto_delete", 0)) if user else False
        notify = bool(user.get("notify", 1)) if user else True
        detail_mode = bool(user.get("detail_mode", 0)) if user else False

        await message.answer(
            "⚙️ <b>Bot Sozlamalari</b>\n\nTugmalarni bosib sozlamalarni o'zgartiring:",
            reply_markup=get_settings_keyboard(auto_delete, notify, detail_mode),
        )

    elif text == "ℹ️ Yordam":
        from bot.handlers.help import HELP_TEXT
        await message.answer(HELP_TEXT, reply_markup=get_main_menu_inline())

    elif text == "📞 Aloqa":
        await message.answer(
            "📞 <b>Biz bilan bog'lanish va hamkorlik uchun:</b>\n\n"
            "📱 Telefon: +998942686903\n"
            "💬 Telegram: @Hamidullayevich_03\n"
            "\n"
            "Murojaatlaringizni kutamiz!"
        )
