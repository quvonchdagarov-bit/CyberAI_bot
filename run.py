"""CyberAI Pro v2.1 — Entry Point.

Yangilangan:
- Sentry monitoring ishga tushiriladi
- AbuseIPDB, URLScan vositalari tekshiriladi
- Banned user middleware qo'shildi
"""

import asyncio

from bot.loader import bot, dp, logger
from bot.database.db import init_db, close_db
from bot.handlers import register_all_handlers
from bot.middlewares.throttling import ThrottlingMiddleware
from bot.middlewares.db_middleware import DatabaseMiddleware
from bot.middlewares.profanity_middleware import ProfanityMiddleware
from bot.middlewares.ban_middleware import BanCheckMiddleware
from bot.database.profanity_db import init_profanity_table
from bot.services.sentry_init import init_sentry
from bot.config import settings


async def on_startup():
    """Bot ishga tushganda bajariladigan amallar."""
    await init_db()
    await init_profanity_table()
    logger.info("✅ Ma'lumotlar bazasi tayyor (WAL rejim + indekslar)")


async def on_shutdown():
    """Bot to'xtaganda bajariladigan amallar."""
    await close_db()
    logger.info("🔴 Ma'lumotlar bazasi yopildi")


async def main():
    """Asosiy ishga tushirish funksiyasi."""
    logger.info("=" * 60)
    logger.info("🛡  CyberAI Pro v%s ishga tushmoqda...", settings.BOT_VERSION)
    logger.info("🌍 Muhit: %s", settings.ENVIRONMENT)
    logger.info("=" * 60)

    # ── Sentry monitoring ──────────────────────────────────────────────────
    sentry_ok = init_sentry()
    if sentry_ok:
        logger.info("📡 Sentry monitoring faol")

    # ── Middleware-larni ro'yxatdan o'tkazish ──────────────────────────────
    dp.message.middleware(BanCheckMiddleware())
    dp.message.middleware(ThrottlingMiddleware(rate_limit=settings.THROTTLE_RATE))
    dp.message.middleware(DatabaseMiddleware())
    dp.message.middleware(ProfanityMiddleware())

    # ── Handler-larni ro'yxatdan o'tkazish ────────────────────────────────
    register_all_handlers(dp)

    # ── Lifecycle hook-lar ────────────────────────────────────────────────
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    # ── Polling boshlash ──────────────────────────────────────────────────
    logger.info("🚀 Bot polling rejimida ishga tushdi!")
    logger.info("📊 Risk threshold: %d+", settings.GLOBAL_RISK_THRESHOLD)
    logger.info("🗑 Xavfsiz o'chirish: %s", "Faol" if settings.SECURE_DELETE else "O'chirilgan")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
