"""Reply keyboard (menu buttonlar) — doimiy pastki tugmalar."""

from aiogram.types import (
    KeyboardButton,
    ReplyKeyboardMarkup,
)


def get_main_menu_kb() -> ReplyKeyboardMarkup:
    """Asosiy menyu reply keyboard."""
    return ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(text="🔍 Tekshirish"),
                KeyboardButton(text="📊 Statistika"),
            ],
            [
                KeyboardButton(text="📋 Tarix"),
                KeyboardButton(text="⚙️ Sozlamalar"),
            ],
            [
                KeyboardButton(text="ℹ️ Yordam"),
                KeyboardButton(text="📞 Aloqa"),
            ],
        ],
        resize_keyboard=True,
        input_field_placeholder="Fayl, havola yoki matn yuboring...",
    )
