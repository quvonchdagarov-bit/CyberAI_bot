"""Handlers paketi — barcha router-larni ro'yxatdan o'tkazish."""

from aiogram import Dispatcher

from bot.handlers.start import router as start_router
from bot.handlers.help import router as help_router
from bot.handlers.admin_handler import router as admin_router
from bot.handlers.settings_handler import router as settings_router
from bot.handlers.callback_handler import router as callback_router
from bot.handlers.file_handler import router as file_router
from bot.handlers.text_handler import router as text_router


def register_all_handlers(dp: Dispatcher):
    """Barcha handler router-larni Dispatcher ga qo'shish."""
    dp.include_routers(
        start_router,
        help_router,
        admin_router,
        settings_router,
        callback_router,
        file_router,
        text_router,  # oxirida — barcha matnli xabarlarni ushlaydi
    )
