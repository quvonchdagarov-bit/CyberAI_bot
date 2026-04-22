"""Admin handler — admin panel va buyruqlar."""

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import CallbackQuery, Message

from bot.config import settings
from bot.database.models import get_global_stats
from bot.keyboards.callback_data import AdminAction
from bot.keyboards.inline_kb import get_admin_keyboard, get_back_to_menu_keyboard

router = Router(name="admin_handler")


def is_admin(user_id: int) -> bool:
    """Foydalanuvchi admin ekanligini tekshirish."""
    return user_id in settings.ADMIN_IDS


@router.message(Command("admin"))
async def cmd_admin(message: Message):
    """Admin panel."""
    if not message.from_user or not is_admin(message.from_user.id):
        await message.reply("⛔ Bu buyruq faqat adminlar uchun.")
        return

    await message.answer(
        "👮 <b>Admin Panel</b>\n"
        "\n"
        "Quyidagi tugmalardan foydalaning:",
        reply_markup=get_admin_keyboard(),
    )


@router.callback_query(AdminAction.filter(F.action == "stats"))
async def callback_admin_stats(callback: CallbackQuery):
    """Global statistika (admin)."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Ruxsat yo'q.", show_alert=True)
        return

    stats = await get_global_stats()

    text = (
        "📊 <b>Global Statistika</b>\n"
        "\n"
        f"👥 Foydalanuvchilar: <b>{stats['users']}</b>\n"
        f"📌 Jami tekshiruvlar: <b>{stats['total_scans']}</b>\n"
        f"🟡 Shubhali: <b>{stats['dangerous']}</b>\n"
        f"🔴 Kritik: <b>{stats['critical']}</b>\n"
    )

    try:
        await callback.message.edit_text(
            text, reply_markup=get_admin_keyboard()
        )
    except Exception:
        await callback.message.answer(text, reply_markup=get_admin_keyboard())

    await callback.answer()


@router.callback_query(AdminAction.filter(F.action == "back"))
async def callback_admin_back(callback: CallbackQuery):
    """Admin paneldan ortga."""
    from bot.keyboards.inline_kb import get_main_menu_inline

    try:
        await callback.message.edit_text(
            "⬇️ Quyidagi menyudan foydalaning yoki to'g'ridan-to'g'ri fayl/link yuboring:",
            reply_markup=get_main_menu_inline(),
        )
    except Exception:
        pass

    await callback.answer()
