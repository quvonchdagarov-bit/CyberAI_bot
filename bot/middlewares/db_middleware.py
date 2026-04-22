"""Database middleware — har bir xabar uchun foydalanuvchini DB ga yozish."""

from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import Message

from bot.database.models import upsert_user


class DatabaseMiddleware(BaseMiddleware):
    """Har bir xabar kelganda foydalanuvchini avtomatik ro'yxatdan o'tkazish."""

    async def __call__(
        self,
        handler: Callable[[Message, dict[str, Any]], Awaitable[Any]],
        event: Message,
        data: dict[str, Any],
    ) -> Any:
        if event.from_user:
            await upsert_user(
                user_id=event.from_user.id,
                username=event.from_user.username,
                full_name=event.from_user.full_name,
            )

        return await handler(event, data)
