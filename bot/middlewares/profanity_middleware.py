"""
Profanity (haqoratli so'z) middleware.

Xabarlarni haqoratli so'zlar uchun tekshiradi.
- Topilsa: ogohlantirish beradi
- 3 marta ogohlantirilgandan keyin, 4-chi safar guruhdan chiqarib yuboradi
"""

import logging
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware, Bot
from aiogram.types import Message

from bot.filters.bad_words import check_message_for_bad_words
from bot.database.profanity_db import (
    get_user_warnings,
    add_warning,
    reset_warnings,
)

logger = logging.getLogger("camcyber_pro")

# Ogohlantirish xabarlari
WARNING_MESSAGES = {
    1: (
        "⚠️ <b>1-OGOHLANTIRISH!</b>\n\n"
        "👤 {mention}, siz haqoratli so'z ishlatdingiz!\n"
        "❌ Topilgan so'z(lar): <code>{words}</code>\n\n"
        "📌 Bu sizning <b>1-chi</b> ogohlantirish.\n"
        "🚫 <b>3 marta</b> ogohlantirishdan keyin guruhdan chiqarilasiz!\n"
        "✅ Iltimos, hurmatli bo'ling."
    ),
    2: (
        "⚠️⚠️ <b>2-OGOHLANTIRISH!</b>\n\n"
        "👤 {mention}, yana haqoratli so'z ishlatdingiz!\n"
        "❌ Topilgan so'z(lar): <code>{words}</code>\n\n"
        "📌 Bu sizning <b>2-chi</b> ogohlantirish.\n"
        "🔴 Yana <b>1 marta</b> — oxirgi ogohlantirish!\n"
        "⛔ Keyingisida guruhdan <b>chiqarilasiz</b>!"
    ),
    3: (
        "🔴🔴🔴 <b>3-OGOHLANTIRISH — OXIRGI!</b>\n\n"
        "👤 {mention}, bu sizning <b>OXIRGI</b> ogohlantirish!\n"
        "❌ Topilgan so'z(lar): <code>{words}</code>\n\n"
        "⛔ <b>Yana 1 marta</b> haqoratli so'z ishlatsangiz,\n"
        "guruhdan <b>CHIQARIB YUBORILASIZ</b>!\n"
        "🙏 Iltimos, o'zingizni tutib turing!"
    ),
}

KICK_MESSAGE = (
    "🚫 <b>GURUHDAN CHIQARILDI!</b>\n\n"
    "👤 {mention} ({user_id}) guruhdan chiqarib yuborildi.\n\n"
    "📊 Sabab: <b>4 marta</b> haqoratli so'z ishlatdi.\n"
    "❌ Oxirgi topilgan so'z(lar): <code>{words}</code>\n\n"
    "⚖️ Qoidalar hamma uchun barobar!"
)


class ProfanityMiddleware(BaseMiddleware):
    """Haqoratli so'zlarni tekshiruvchi middleware."""

    async def __call__(
        self,
        handler: Callable[[Message, dict[str, Any]], Awaitable[Any]],
        event: Message,
        data: dict[str, Any],
    ) -> Any:
        # Faqat matnli xabarlarni tekshiramiz
        if not event.text and not event.caption:
            return await handler(event, data)

        # Foydalanuvchi bo'lmasa o'tkazib yuboramiz
        if not event.from_user:
            return await handler(event, data)

        # Bot xabarlarini tekshirmaymiz
        if event.from_user.is_bot:
            return await handler(event, data)

        text = event.text or event.caption or ""
        user_id = event.from_user.id
        chat_id = event.chat.id

        # Shaxsiy chatda ham tekshiramiz, lekin chiqarish faqat guruhda
        is_group = event.chat.type in ("group", "supergroup")

        # Haqoratli so'zlarni tekshirish
        found_words = check_message_for_bad_words(text)

        if not found_words:
            # Haqoratli so'z topilmadi — davom etamiz
            return await handler(event, data)

        # Haqoratli so'z topildi!
        words_str = ", ".join(found_words[:5])  # Ko'pi bilan 5 tasini ko'rsatamiz

        # Foydalanuvchi mention
        if event.from_user.username:
            mention = f"@{event.from_user.username}"
        else:
            mention = f'<a href="tg://user?id={user_id}">{event.from_user.full_name}</a>'

        bot: Bot = data.get("bot") or event.bot

        # Ogohlantirish sonini olish va oshirish
        current_warnings = await get_user_warnings(user_id, chat_id)
        new_count = current_warnings + 1

        # Ogohlantirishni bazaga yozish
        await add_warning(user_id, chat_id, words_str)

        logger.warning(
            "Haqoratli so'z topildi! User=%s Chat=%s Words=%s Count=%d",
            user_id, chat_id, words_str, new_count,
        )

        try:
            # Haqoratli xabarni o'chirishga harakat qilamiz
            try:
                await event.delete()
            except Exception:
                pass  # O'chirish huquqi yo'q bo'lsa davom etamiz

            if new_count >= 4:
                # 4-chi yoki undan ortiq — guruhdan chiqarish
                if is_group:
                    # Avval xabar yuboramiz
                    await bot.send_message(
                        chat_id,
                        KICK_MESSAGE.format(
                            mention=mention,
                            user_id=user_id,
                            words=words_str,
                        ),
                    )
                    # Foydalanuvchini guruhdan chiqaramiz
                    try:
                        await bot.ban_chat_member(chat_id, user_id)
                        # Ban qildik, lekin qayta qo'shilishi uchun unban qilamiz
                        await bot.unban_chat_member(chat_id, user_id, only_if_banned=True)
                        logger.info(
                            "Foydalanuvchi guruhdan chiqarildi: User=%s Chat=%s",
                            user_id, chat_id,
                        )
                    except Exception as e:
                        logger.error("Foydalanuvchini chiqarishda xato: %s", e)
                        await bot.send_message(
                            chat_id,
                            f"⚠️ Foydalanuvchini chiqarib bo'lmadi. "
                            f"Bot admin huquqlariga ega ekanligini tekshiring.\n"
                            f"Xato: {e}",
                        )

                    # Ogohlantirishlarni tozalaymiz
                    await reset_warnings(user_id, chat_id)
                else:
                    # Shaxsiy chatda chiqarish mumkin emas
                    await bot.send_message(
                        chat_id,
                        f"🚫 {mention}, siz 4 marta haqoratli so'z ishlatdingiz!\n"
                        f"Guruhda bo'lganingizda chiqarib yuborilgan bo'lardingiz.",
                    )
                    await reset_warnings(user_id, chat_id)

                return  # Handler ga o'tkazmaymiz

            else:
                # 1, 2 yoki 3-chi ogohlantirish
                template = WARNING_MESSAGES.get(new_count, WARNING_MESSAGES[1])
                await bot.send_message(
                    chat_id,
                    template.format(mention=mention, words=words_str),
                )
                return  # Handler ga o'tkazmaymiz

        except Exception as e:
            logger.error("Profanity middleware xatosi: %s", e)
            # Xatolik bo'lsa ham handler ga o'tkazamiz
            return await handler(event, data)
