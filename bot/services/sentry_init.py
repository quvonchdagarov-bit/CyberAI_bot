"""Sentry — real vaqtda xatolik kuzatuvi va monitoring.

Sentry xizmati botda har qanday xato yuz berganda:
- Xatoning aniq joyi (fayl, qator)
- Stack trace (chaqiruv zanjiri)
- Foydalanuvchi ma'lumotlari
- Qo'shimcha kontekst
ni saqlaydi va email/Telegram orqali xabar beradi.
"""

import logging

from bot.config import settings
from bot.loader import logger


def init_sentry() -> bool:
    """Sentry SDK ni ishga tushirish.

    Returns:
        True — Sentry faol, False — DSN yo'q yoki xato
    """
    if not settings.SENTRY_DSN:
        logger.info("ℹ️ Sentry: SENTRY_DSN topilmadi, monitoring o'chirilgan")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration

        sentry_logging = LoggingIntegration(
            level=logging.WARNING,       # WARNING va undan yuqori loglar capture qilinadi
            event_level=logging.ERROR,   # ERROR va undan yuqori — Sentry event bo'ladi
        )

        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            integrations=[sentry_logging],
            traces_sample_rate=0.1,      # Performance tracing uchun 10% so'rovlar
            profiles_sample_rate=0.05,   # Profiling uchun 5%
            environment=settings.ENVIRONMENT,
            release=settings.BOT_VERSION,
            # PII (shaxsiy ma'lumotlar) yuborilmasin
            send_default_pii=False,
            # Bot tokeni va API kalitlari yuborilmasin
            before_send=_before_send_filter,
        )

        logger.info("✅ Sentry monitoring faol: %s muhit, v%s", settings.ENVIRONMENT, settings.BOT_VERSION)
        return True

    except ImportError:
        logger.warning("⚠️ sentry-sdk o'rnatilmagan. pip install sentry-sdk")
        return False
    except Exception as exc:
        logger.warning("⚠️ Sentry ishga tushirishda xato: %s", exc)
        return False


def _before_send_filter(event: dict, hint: dict) -> dict | None:
    """Sentry ga yuborishdan oldin ma'lumotlarni filtrlash.

    Maxfiy ma'lumotlarni (token, API key) tozalaydi.
    """
    sensitive_keys = {
        "token", "api_key", "apikey", "password", "secret",
        "authorization", "api-key", "x-apikey", "bot_token",
    }

    def _clean(obj):
        if isinstance(obj, dict):
            return {
                k: "***FILTERED***" if k.lower() in sensitive_keys else _clean(v)
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [_clean(i) for i in obj]
        return obj

    event = _clean(event)
    return event


def capture_exception(exc: Exception, context: dict | None = None) -> None:
    """Xatoni Sentry ga yuborish."""
    try:
        import sentry_sdk
        with sentry_sdk.push_scope() as scope:
            if context:
                for key, value in context.items():
                    scope.set_extra(key, value)
            sentry_sdk.capture_exception(exc)
    except Exception:
        pass  # Sentry o'zi xato bersa, botni to'xtatmaymiz


def set_user_context(user_id: int, username: str | None = None) -> None:
    """Sentry kontekstiga foydalanuvchi ID ni qo'shish (maxfiy emas)."""
    try:
        import sentry_sdk
        sentry_sdk.set_user({"id": str(user_id), "username": username or "unknown"})
    except Exception:
        pass
