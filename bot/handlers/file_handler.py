"""Fayl/media handler — fayllarni yuklab tahlil qilish."""

import time
from pathlib import Path

from aiogram import F, Router
from aiogram.types import Message

from bot.config import settings
from bot.loader import bot, logger
from bot.analyzers.file_analyzer import analyze_saved_file
from bot.analyzers.scoring import classify_risk_level
from bot.database.models import save_scan
from bot.keyboards.inline_kb import get_result_keyboard
from bot.reports.formatter import format_detailed_report, format_short_result
from bot.utils.constants import ARCHIVE_EXTS
from bot.utils.telegram import resolve_telegram_file

router = Router(name="file_handler")


@router.message(F.document | F.video | F.animation | F.audio | F.voice | F.photo)
async def handle_file_message(message: Message):
    """Fayl/media kelganda — yuklab tahlil qilish."""
    file_id, filename, file_size, mime_type = await resolve_telegram_file(message)
    if not file_id or not filename:
        return

    user_id = message.from_user.id if message.from_user else 0
    chat_id = message.chat.id

    # Hajm tekshiruvi
    if file_size and file_size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        await message.reply(
            f"⚠️ Fayl juda katta. Maksimal hajm: <b>{settings.MAX_FILE_SIZE_MB} MB</b>."
        )
        return

    # Status xabari — "tahlil qilinmoqda..."
    status_msg = await message.reply(
        "⏳ <b>Fayl qabul qilindi</b>\n"
        f"📄 {filename}\n"
        "🔄 Tahlil boshlanmoqda..."
    )

    temp_path = settings.DOWNLOAD_DIR / f"{int(time.time())}_{filename}"

    try:
        # Faylni yuklash
        try:
            await status_msg.edit_text(
                "📥 <b>Fayl yuklab olinmoqda...</b>\n"
                f"📄 {filename}"
            )
        except Exception:
            pass

        tg_file = await bot.get_file(file_id)
        await bot.download_file(tg_file.file_path, destination=temp_path, timeout=300)

        # Tahlil bosqichi
        try:
            await status_msg.edit_text(
                "🔍 <b>Fayl tahlil qilinmoqda...</b>\n"
                f"📄 {filename}\n"
                "⏳ Bu biroz vaqt olishi mumkin..."
            )
        except Exception:
            pass

        result = await analyze_saved_file(temp_path, filename, mime_type)
        tag = "archive" if Path(filename).suffix.lower() in ARCHIVE_EXTS else "file"
        score = int(result.get("score", 0))

        # Xavfli faylni karantinga ko'chirish
        if score >= 75:
            try:
                quarantine_path = settings.QUARANTINE_DIR / f"{int(time.time())}_{filename}"
                temp_path.replace(quarantine_path)
                temp_path = quarantine_path
            except Exception:
                pass

        # Natijani DB ga saqlash
        short_text = format_short_result(result, "file")
        full_text = format_detailed_report(result, "file", tag)
        scan_id = await save_scan(
            user_id=user_id,
            chat_id=chat_id,
            scan_type="file",
            target=filename[:200],
            score=score,
            risk_level=classify_risk_level(score),
            result_data=result,
            short_report=short_text,
            full_report=full_text,
        )

        keyboard = get_result_keyboard(scan_id, score)

        # Xavfli xabarni o'chirish
        if score >= 70:
            from bot.database.models import get_user_setting
            auto_delete = await get_user_setting(user_id, "auto_delete")
            
            # Agar foydalanuvchi yoqgan bo'lsa (yoki settings.DELETE_BAD_MESSAGES global yoqilgan bo'lsa yordamchi)
            if auto_delete or settings.DELETE_BAD_MESSAGES:
                try:
                    await message.delete()
                except Exception as e:
                    logger.warning("Xabarni o'chirishda xato (admin huquqi yo'q bo'lishi mumkin): %s", e)

        # Status xabarni natija bilan almashtirish
        try:
            await status_msg.edit_text(short_text, reply_markup=keyboard)
        except Exception:
            await status_msg.delete()
            await message.answer(short_text, reply_markup=keyboard)

    except Exception as e:
        logger.exception("Fayl tahlilida xato")
        try:
            await status_msg.edit_text(
                f"⚠️ Faylni tekshirishda xatolik yuz berdi:\n<code>{e}</code>"
            )
        except Exception:
            await message.reply(
                f"⚠️ Faylni tekshirishda xatolik yuz berdi:\n<code>{e}</code>"
            )
    finally:
        try:
            if temp_path.exists() and temp_path.parent == settings.DOWNLOAD_DIR:
                temp_path.unlink()
        except Exception:
            pass


@router.message(F.caption)
async def handle_caption_message(message: Message):
    """Fayl bilan kelgan caption ichidagi URLlarni tekshirish."""
    from bot.analyzers.url_analyzer import analyze_url
    from bot.utils.helpers import extract_urls
    from bot.utils.telegram import maybe_delete
    import aiohttp
    import asyncio

    caption = message.caption or ""
    urls = extract_urls(caption)
    if not urls:
        return

    user_id = message.from_user.id if message.from_user else 0
    chat_id = message.chat.id

    async with aiohttp.ClientSession() as session:
        results = []
        for url_value in urls[:settings.URL_ANALYSIS_LIMIT]:
            results.append(await analyze_url(session, url_value))
            await asyncio.sleep(0.4)

    if results:
        best = max(results, key=lambda x: x["score"])
        score = int(best.get("score", 0))

        short_text = format_short_result(best, "link")
        full_text = format_detailed_report(best, "link")
        scan_id = await save_scan(
            user_id=user_id,
            chat_id=chat_id,
            scan_type="link",
            target=best.get("url", "")[:200],
            score=score,
            risk_level=classify_risk_level(score),
            result_data=best,
            short_report=short_text,
            full_report=full_text,
        )

        keyboard = get_result_keyboard(scan_id, score)

        if score >= 70:
            await maybe_delete(message)

        await message.reply(short_text, reply_markup=keyboard)
