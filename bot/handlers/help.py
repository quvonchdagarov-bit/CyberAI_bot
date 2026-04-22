"""/help buyrug'i — yordam sahifasi."""

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from bot.keyboards.inline_kb import get_main_menu_inline

router = Router(name="help")

HELP_TEXT = (
    "ℹ️ <b>CamCyber Pro — Yordam</b>\n"
    "\n"
    "<b>Buyruqlar:</b>\n"
    "/start — Botni ishga tushirish\n"
    "/help — Yordam sahifasi\n"
    "/admin — Admin panel (faqat adminlar uchun)\n"
    "\n"
    "<b>Yuborish mumkin:</b>\n"
    "📄 <b>Fayllar</b> — APK, EXE, ZIP, RAR, 7Z, PDF, rasm\n"
    "🔗 <b>Havolalar</b> — Xabar ichiga URL yozing\n"
    "📝 <b>Matn</b> — Shubhali xabar matnini yuboring\n"
    "📷 <b>QR rasm</b> — QR kod mavjud rasm yuboring\n"
    "\n"
    "<b>Menu tugmalari:</b>\n"
    "🔍 Tekshirish — yangi skanerlash boshlash\n"
    "📊 Statistika — shaxsiy statistikangiz\n"
    "📋 Tarix — oldingi tekshiruvlar ro'yxati\n"
    "⚙️ Sozlamalar — bot sozlamalarini boshqarish\n"
    "\n"
    "<b>Natija tugmalari:</b>\n"
    "📋 Batafsil — to'liq texnik hisobot\n"
    "🤖 AI Tahlil — AI kengaytirilgan tahlil\n"
    "📤 Ulashish — natijani boshqalarga yuborish"
)


@router.message(Command("help"))
async def cmd_help(message: Message):
    """Yordam xabari."""
    await message.answer(HELP_TEXT, reply_markup=get_main_menu_inline())
