"""CamCyber Pro — Entry Point."""

import asyncio

from bot.loader import bot, dp, logger
from bot.database.db import init_db, close_db
from bot.handlers import register_all_handlers
from bot.middlewares.throttling import ThrottlingMiddleware
from bot.middlewares.db_middleware import DatabaseMiddleware
from bot.middlewares.profanity_middleware import ProfanityMiddleware
from bot.database.profanity_db import init_profanity_table


async def on_startup():
    """Bot ishga tushganda bajariladigan amallar."""
    await init_db()
    await init_profanity_table()
    logger.info("Ma'lumotlar bazasi tayyor (profanity jadvali ham).")


async def on_shutdown():
    """Bot to'xtaganda bajariladigan amallar."""
    await close_db()
    logger.info("Ma'lumotlar bazasi yopildi.")


async def main():
    """Asosiy ishga tushirish funksiyasi."""
    logger.info("=" * 50)
    logger.info("🛡 CamCyber Pro v2.0 ishga tushmoqda...")
    logger.info("=" * 50)

    # Middleware-larni ro'yxatdan o'tkazish
    dp.message.middleware(ThrottlingMiddleware(rate_limit=1.5))
    dp.message.middleware(DatabaseMiddleware())
    dp.message.middleware(ProfanityMiddleware())

    # Handler-larni ro'yxatdan o'tkazish
    register_all_handlers(dp)

    # Lifecycle hook-lar
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    # Polling boshlash
    logger.info("🚀 Bot polling rejimida ishga tushdi!")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
