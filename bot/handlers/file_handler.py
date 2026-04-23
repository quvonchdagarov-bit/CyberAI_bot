"""Fayl/media handler — fayllarni yuklab tahlil qilish.

Yangilangan:
- Xavfsiz fayl o'chirish (DoD 5220.22-M)
- Skanerlash vaqtini ko'rsatish
- Karantin siyosati
"""

import time
from pathlib import Path

from aiogram import F, Router
from aiogram.types import Message

from bot.config import settings
from bot.loader import bot, logger
from bot.analyzers.file_analyzer import analyze_saved_file
from bot.analyzers.scoring import classify_risk_level
from bot.database.models import save_scan, increment_user_scan_count
from bot.keyboards.inline_kb import get_result_keyboard
from bot.reports.formatter import format_detailed_report, format_short_result
from bot.utils.constants import ARCHIVE_EXTS
from bot.utils.telegram import resolve_telegram_file
from bot.utils.secure_delete import secure_shred

router = Router(name="file_handler")


@router.message(F.document | F.video | F.animation | F.audio | F.voice | F.photo)
async def handle_file_message(message: Message):
    """Fayl/media kelganda — yuklab tahlil qilish."""
    file_id, filename, file_size, mime_type = await resolve_telegram_file(message)
    if not file_id or not filename:
        return

    user_id = message.from_user.id if message.from_user else 0
    chat_id = message.chat.id

    # ── Hajm tekshiruvi ──────────────────────────────────────────────────
    if file_size and file_size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        await message.reply(
            f"⚠️ <b>Fayl juda katta!</b>\n"
            f"📏 Fayl hajmi: <b>{file_size / (1024*1024):.1f} MB</b>\n"
            f"📌 Maksimal: <b>{settings.MAX_FILE_SIZE_MB} MB</b>\n\n"
            f"💡 Katta fayllarni VirusTotal.com saytida tekshiring."
        )
        return

    # ── Status xabari ─────────────────────────────────────────────────────
    status_msg = await message.reply(
        "⏳ <b>Fayl qabul qilindi</b>\n"
        f"📄 <code>{filename}</code>\n"
        "🔄 Tahlil tayyorlanmoqda..."
    )

    temp_path = settings.DOWNLOAD_DIR / f"{int(time.time())}_{filename}"
    scan_start = time.monotonic()

    try:
        # ── Yuklash ───────────────────────────────────────────────────────
        try:
            await status_msg.edit_text(
                "📥 <b>Fayl yuklab olinmoqda...</b>\n"
                f"📄 <code>{filename}</code>"
            )
        except Exception:
            pass

        tg_file = await bot.get_file(file_id)
        await bot.download_file(tg_file.file_path, destination=temp_path, timeout=300)

        # ── Tahlil ───────────────────────────────────────────────────────
        try:
            await status_msg.edit_text(
                "🔍 <b>Xavfsizlik tahlili boshlanmoqda...</b>\n"
                f"📄 <code>{filename}</code>\n"
                "🛡 16 ta vosita faol — biroz kuting..."
            )
        except Exception:
            pass

        result = await analyze_saved_file(temp_path, filename, mime_type)
        tag = "archive" if Path(filename).suffix.lower() in ARCHIVE_EXTS else "file"
        score = int(result.get("score", 0))
        scan_ms = int((time.monotonic() - scan_start) * 1000)

        # ── Xavfli faylni karantinga ko'chirish ───────────────────────────
        if score >= 75:
            try:
                quarantine_path = settings.QUARANTINE_DIR / f"{int(time.time())}_{filename}"
                temp_path.replace(quarantine_path)
                temp_path = quarantine_path
                logger.warning(
                    "🚨 Karantinga ko'chirildi: %s (score=%d)", filename, score
                )
            except Exception:
                pass

        # ── DB ga saqlash ─────────────────────────────────────────────────
        short_text = format_short_result(result, "file", scan_ms)
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
            tools_count=len(result.get("tools_used", [])),
            scan_time_ms=scan_ms,
        )

        # ── Foydalanuvchi statistikasini yangilash ────────────────────────
        await increment_user_scan_count(user_id)

        keyboard = get_result_keyboard(scan_id, score)

        # ── Xavfli xabarni o'chirish ──────────────────────────────────────
        if score >= 70:
            from bot.database.models import get_user_setting
            auto_delete = await get_user_setting(user_id, "auto_delete")
            if auto_delete or settings.DELETE_BAD_MESSAGES:
                try:
                    await message.delete()
                except Exception as e:
                    logger.warning("Xabarni o'chirishda xato: %s", e)

        # ── Threshold tekshiruvi ──────────────────────────────────────────
        if score <= settings.GLOBAL_RISK_THRESHOLD:
            logger.info(
                "✅ Past xavf (%d <= %d): %s — ogohlantirish yuborilmadi",
                score, settings.GLOBAL_RISK_THRESHOLD, filename,
            )
            try:
                await status_msg.delete()
            except Exception:
                pass
            return

        # ── Natijani ko'rsatish ───────────────────────────────────────────
        try:
            await status_msg.edit_text(short_text, reply_markup=keyboard)
        except Exception:
            await status_msg.delete()
            await message.answer(short_text, reply_markup=keyboard)

    except Exception as e:
        logger.exception("Fayl tahlilida xato: %s", filename)
        try:
            await status_msg.edit_text(
                f"⚠️ <b>Tahlilda xatolik yuz berdi</b>\n"
                f"📄 <code>{filename}</code>\n"
                f"<code>{str(e)[:200]}</code>"
            )
        except Exception:
            await message.reply(f"⚠️ Xatolik: <code>{str(e)[:200]}</code>")
    finally:
        # ── Faylni xavfsiz o'chirish (DoD 5220.22-M) ──────────────────────
        if temp_path.exists() and temp_path.parent == settings.DOWNLOAD_DIR:
            if settings.SECURE_DELETE:
                await secure_shred(temp_path)
            else:
                try:
                    temp_path.unlink()
                except Exception:
                    pass


@router.message(F.caption)
async def handle_caption_message(message: Message):
    """Fayl bilan kelgan caption ichidagi URLlarni tekshirish."""
    from bot.analyzers.url_analyzer import analyze_url
    from bot.utils.helpers import extract_urls
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

        if score <= settings.GLOBAL_RISK_THRESHOLD:
            return

        await message.reply(short_text, reply_markup=keyboard)
