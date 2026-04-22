"""Telegram yordamchi funksiyalar — xabar yuborish, o'chirish, fayl aniqlash."""

import asyncio
import time

from aiogram.exceptions import TelegramRetryAfter
from aiogram.types import Message

from bot.config import settings

# Chat-ga xos locklar va oxirgi yuborish vaqtlari
_send_locks: dict[int, asyncio.Lock] = {}
_last_sent_time: dict[int, float] = {}


async def safe_send(message: Message, text: str, reply_markup=None):
    """Xavfsiz xabar yuborish — rate limiting va flood himoya bilan."""
    if not text.strip():
        return None

    chat_id = message.chat.id
    if chat_id not in _send_locks:
        _send_locks[chat_id] = asyncio.Lock()

    async with _send_locks[chat_id]:
        now = time.time()
        wait_time = max(0, 1.4 - (now - _last_sent_time.get(chat_id, 0)))
        if wait_time > 0:
            await asyncio.sleep(wait_time)

        try:
            result = await message.reply(
                text[:4096],
                reply_markup=reply_markup,
            )
            _last_sent_time[chat_id] = time.time()
            return result
        except TelegramRetryAfter as e:
            await asyncio.sleep(float(e.retry_after) + 1)
            result = await message.reply(
                text[:4096],
                reply_markup=reply_markup,
            )
            _last_sent_time[chat_id] = time.time()
            return result


async def safe_answer(message: Message, text: str, reply_markup=None):
    """Xavfsiz javob yuborish — reply qilmasdan."""
    if not text.strip():
        return None

    try:
        return await message.answer(text[:4096], reply_markup=reply_markup)
    except TelegramRetryAfter as e:
        await asyncio.sleep(float(e.retry_after) + 1)
        return await message.answer(text[:4096], reply_markup=reply_markup)


async def maybe_delete(message: Message):
    """Agar sozlama yoqilgan bo'lsa, xabarni o'chirish."""
    if not settings.DELETE_BAD_MESSAGES:
        return
    try:
        await message.delete()
    except Exception:
        pass


async def resolve_telegram_file(
    message: Message,
) -> tuple[str | None, str | None, int | None, str | None]:
    """Telegram xabardan fayl ma'lumotlarini ajratish."""
    if message.document:
        return (
            message.document.file_id,
            message.document.file_name or "file.bin",
            message.document.file_size,
            message.document.mime_type,
        )
    if message.video:
        return (
            message.video.file_id,
            message.video.file_name or "video.mp4",
            message.video.file_size,
            message.video.mime_type,
        )
    if message.animation:
        return (
            message.animation.file_id,
            message.animation.file_name or "animation.mp4",
            message.animation.file_size,
            message.animation.mime_type,
        )
    if message.audio:
        return (
            message.audio.file_id,
            message.audio.file_name or "audio.bin",
            message.audio.file_size,
            message.audio.mime_type,
        )
    if message.voice:
        return (
            message.voice.file_id,
            "voice.ogg",
            message.voice.file_size,
            message.voice.mime_type,
        )
    if message.photo:
        biggest = message.photo[-1]
        return (biggest.file_id, "photo.jpg", biggest.file_size, "image/jpeg")
    return (None, None, None, None)
