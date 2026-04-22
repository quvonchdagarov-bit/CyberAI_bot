"""Sozlamalar handler — foydalanuvchi sozlamalarini boshqarish."""

from aiogram import F, Router
from aiogram.types import CallbackQuery

from bot.database.models import get_user, toggle_user_setting, upsert_user
from bot.keyboards.callback_data import MenuAction, SettingsAction
from bot.keyboards.inline_kb import get_main_menu_inline, get_settings_keyboard

router = Router(name="settings_handler")


@router.callback_query(MenuAction.filter(F.action == "settings"))
async def callback_settings(callback: CallbackQuery):
    """Sozlamalar sahifasi."""
    user_id = callback.from_user.id
    user = await get_user(user_id)

    if not user:
        await upsert_user(user_id, callback.from_user.username, callback.from_user.full_name)
        user = await get_user(user_id)

    auto_delete = bool(user.get("auto_delete", 0)) if user else False
    notify = bool(user.get("notify", 1)) if user else True
    detail_mode = bool(user.get("detail_mode", 0)) if user else False

    try:
        await callback.message.edit_text(
            "⚙️ <b>Bot Sozlamalari</b>\n"
            "\n"
            "Tugmalarni bosib sozlamalarni o'zgartiring:\n"
            "\n"
            "🗑 <b>Auto-o'chirish</b> — xavfli xabarni avtomatik o'chirish\n"
            "🔔 <b>Bildirishnoma</b> — past xavfli natijalarni ham ko'rsatish\n"
            "📊 <b>Batafsil rejim</b> — har doim to'liq hisobot ko'rsatish",
            reply_markup=get_settings_keyboard(auto_delete, notify, detail_mode),
        )
    except Exception:
        await callback.message.answer(
            "⚙️ <b>Bot Sozlamalari</b>",
            reply_markup=get_settings_keyboard(auto_delete, notify, detail_mode),
        )

    await callback.answer()


@router.callback_query(SettingsAction.filter(F.action.in_({"auto_delete", "notify", "detail_mode"})))
async def callback_toggle_setting(callback: CallbackQuery, callback_data: SettingsAction):
    """Sozlamani toggle qilish."""
    user_id = callback.from_user.id

    # Avval foydalanuvchi mavjudligini tekshirish
    user = await get_user(user_id)
    if not user:
        await upsert_user(user_id, callback.from_user.username, callback.from_user.full_name)

    new_value = await toggle_user_setting(user_id, callback_data.action)

    # Yangilangan sozlamalarni olish
    user = await get_user(user_id)
    auto_delete = bool(user.get("auto_delete", 0)) if user else False
    notify = bool(user.get("notify", 1)) if user else True
    detail_mode = bool(user.get("detail_mode", 0)) if user else False

    status_emoji = "✅ Yoqildi" if new_value else "❌ O'chirildi"
    setting_names = {
        "auto_delete": "Auto-o'chirish",
        "notify": "Bildirishnoma",
        "detail_mode": "Batafsil rejim",
    }
    setting_name = setting_names.get(callback_data.action, "Sozlama")

    try:
        await callback.message.edit_text(
            "⚙️ <b>Bot Sozlamalari</b>\n"
            "\n"
            "Tugmalarni bosib sozlamalarni o'zgartiring:\n"
            "\n"
            "🗑 <b>Auto-o'chirish</b> — xavfli xabarni avtomatik o'chirish\n"
            "🔔 <b>Bildirishnoma</b> — past xavfli natijalarni ham ko'rsatish\n"
            "📊 <b>Batafsil rejim</b> — har doim to'liq hisobot ko'rsatish",
            reply_markup=get_settings_keyboard(auto_delete, notify, detail_mode),
        )
    except Exception:
        pass

    await callback.answer(f"{setting_name}: {status_emoji}")


@router.callback_query(SettingsAction.filter(F.action == "back"))
async def callback_settings_back(callback: CallbackQuery):
    """Sozlamalardan asosiy menyuga qaytish."""
    try:
        await callback.message.edit_text(
            "⬇️ Quyidagi menyudan foydalaning yoki to'g'ridan-to'g'ri fayl/link yuboring:",
            reply_markup=get_main_menu_inline(),
        )
    except Exception:
        pass
    await callback.answer()
