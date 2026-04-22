"""/start buyrug'i — salomlash va asosiy menyu."""

from aiogram import F, Router
from aiogram.filters import CommandStart

from aiogram.types import CallbackQuery, Message

from bot.keyboards.callback_data import MenuAction, ScanAction
from bot.keyboards.inline_kb import (
    get_main_menu_inline,
    get_scan_type_keyboard,
    get_back_to_menu_keyboard,
)
from bot.keyboards.reply_kb import get_main_menu_kb

router = Router(name="start")

START_TEXT = (
    "🛡 <b>CamCyber Pro</b> ga xush kelibsiz!\n"
    "\n"
    "Men professional kiberxavfsizlik yordamchisiman.\n"
    "Quyidagi xizmatlarni taqdim etaman:\n"
    "\n"
    "🔍 <b>Fayl tekshirish</b> — APK, EXE, ZIP, PDF\n"
    "🔗 <b>Havola tekshirish</b> — URL, domen tahlili\n"
    "📝 <b>Matn tahlili</b> — Fishing, scam aniqlash\n"
    "📷 <b>QR skanerlash</b> — Rasm ichidagi QR kodlar\n"
    "\n"
    "📎 Menga fayl, havola yoki shubhali matn yuboring!"
)

ABOUT_TEXT = (
    "🛡 <b>CamCyber Pro v2.0</b>\n"
    "\n"
    "Professional kiberxavfsizlik Telegram boti.\n"
    "\n"
    "🔧 <b>Texnologiyalar:</b>\n"
    "  • VirusTotal API v3\n"
    "  • Google Safe Browsing v4\n"
    "  • ClamAV antivirus\n"
    "  • YARA qoidalar\n"
    "  • OpenAI GPT — AI tahlil\n"
    "  • Tesseract OCR — rasm tahlili\n"
    "\n"
    "👨‍💻 <b>Ishlab chiquvchi:</b> Dagarov Quvonchbek\n"
    "📊 Barcha tahlillar real vaqtda amalga oshiriladi."
)


@router.message(CommandStart())
async def cmd_start(message: Message):
    """Bot ishga tushganda asosiy menyu ko'rsatish."""
    await message.answer(
        START_TEXT,
        reply_markup=get_main_menu_kb(),
    )
    await message.answer(
        "⬇️ Quyidagi menyudan foydalaning yoki to'g'ridan-to'g'ri fayl/link yuboring:",
        reply_markup=get_main_menu_inline(),
    )


@router.callback_query(MenuAction.filter(F.action == "main"))
async def callback_main_menu(callback: CallbackQuery):
    """Asosiy menyuga qaytish."""
    await callback.message.edit_text(
        "⬇️ Quyidagi menyudan foydalaning yoki to'g'ridan-to'g'ri fayl/link yuboring:",
        reply_markup=get_main_menu_inline(),
    )
    await callback.answer()


@router.callback_query(ScanAction.filter())
async def callback_scan_type(callback: CallbackQuery, callback_data: ScanAction):
    """Skanerlash turi tanlanganda."""
    messages = {
        "file": "📄 Tekshirmoqchi bo'lgan faylni menga yuboring.\n\n"
                "Qo'llab-quvvatlanadigan formatlar: APK, EXE, ZIP, RAR, PDF, rasm va boshqalar.",
        "url": "🔗 Tekshirmoqchi bo'lgan URL manzilni yozing.\n\n"
               "Misol: https://example.com",
        "text": "📝 Shubhali matnni menga yuboring.\n\n"
                "Men fishing, scam va zararli iboralarni aniqlashga harakat qilaman.",
        "qr": "📷 QR kod mavjud bo'lgan rasmni menga yuboring.\n\n"
              "Men QR ichidagi havolani avtomatik tahlil qilaman.",
    }

    text = messages.get(callback_data.action, "Noma'lum amal.")

    await callback.message.edit_text(
        text,
        reply_markup=get_back_to_menu_keyboard(),
    )
    await callback.answer()


@router.callback_query(MenuAction.filter(F.action == "about"))
async def callback_about(callback: CallbackQuery):
    """Bot haqida ma'lumot."""
    await callback.message.edit_text(
        ABOUT_TEXT,
        reply_markup=get_back_to_menu_keyboard(),
    )
    await callback.answer()
