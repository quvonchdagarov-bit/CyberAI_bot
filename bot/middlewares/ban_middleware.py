"""Bloklangan foydalanuvchilarni tekshiruvchi middleware."""

from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import Message

from bot.database.models import is_user_banned, upsert_user


class BanCheckMiddleware(BaseMiddleware):
    """Har bir xabarda foydalanuvchi bloklangan-bloklamamganini tekshiradi."""

    async def __call__(
        self,
        handler: Callable[[Message, dict[str, Any]], Awaitable[Any]],
        event: Message,
        data: dict[str, Any],
    ) -> Any:
        if not event.from_user or event.from_user.is_bot:
            return await handler(event, data)

        user = event.from_user

        # Foydalanuvchini DBga qo'shish/yangilash
        await upsert_user(user.id, user.username, user.full_name)

        # Ban tekshiruvi
        if await is_user_banned(user.id):
            try:
                await event.answer(
                    "🚫 <b>Siz botdan bloklangansiz.</b>\n"
                    "Murojaat uchun: @Hamidullayevich_03"
                )
            except Exception:
                pass
            return  # Handler ga o'tkazmaymiz

        return await handler(event, data)
