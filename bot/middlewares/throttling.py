"""Throttling middleware — rate limiting."""

import time
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import Message


class ThrottlingMiddleware(BaseMiddleware):
    """Har bir foydalanuvchi uchun rate limiting."""

    def __init__(self, rate_limit: float = 1.5):
        self.rate_limit = rate_limit
        self._last_time: dict[int, float] = {}

    async def __call__(
        self,
        handler: Callable[[Message, dict[str, Any]], Awaitable[Any]],
        event: Message,
        data: dict[str, Any],
    ) -> Any:
        user_id = event.from_user.id if event.from_user else 0

        now = time.time()
        last = self._last_time.get(user_id, 0)

        if now - last < self.rate_limit:
            return  # Xabarni o'tkazib yuborish (throttle)

        self._last_time[user_id] = now
        return await handler(event, data)
