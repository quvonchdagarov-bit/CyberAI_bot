"""Bot, Dispatcher va tashqi xizmat instance-lari — CyberAI Pro v2.1."""

import logging
import shutil

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

from bot.config import settings

# Logging sozlash
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("camcyber_pro")

# Bot va Dispatcher
bot = Bot(
    token=settings.BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)
dp = Dispatcher()


# =============================================
# Vositalar holatini tekshirish va sozlash
# =============================================
def _setup_tesseract():
    """Tesseract OCR ni sozlash."""
    try:
        import pytesseract

        # 1. .env da ko'rsatilgan yo'l
        if settings.TESSERACT_CMD:
            pytesseract.pytesseract.tesseract_cmd = settings.TESSERACT_CMD
            logger.info("✅ Tesseract OCR: %s", settings.TESSERACT_CMD)
            return True

        # 2. PATH dan topish (Windows va Linux)
        tesseract_path = shutil.which("tesseract")
        if tesseract_path:
            pytesseract.pytesseract.tesseract_cmd = tesseract_path
            logger.info("✅ Tesseract OCR: %s (avtomatik topildi)", tesseract_path)
            return True

        # 3. Windows standart yo'llari
        import os
        import platform
        if platform.system() == "Windows":
            win_paths = [
                r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
            ]
            for wp in win_paths:
                if os.path.isfile(wp):
                    pytesseract.pytesseract.tesseract_cmd = wp
                    logger.info("✅ Tesseract OCR: %s (Windows yo'l)", wp)
                    return True

        logger.warning("⚠️ Tesseract OCR: tesseract topilmadi, OCR ishlamaydi")
        return False
    except ImportError:
        logger.warning("⚠️ pytesseract o'rnatilmagan — OCR ishlamaydi")
        return False


def check_tools_status():
    """Barcha xavfsizlik vositalarining holatini tekshirish."""
    tools_status = {}

    # 1. VirusTotal
    tools_status["VirusTotal"] = bool(settings.VT_API_KEY)
    if settings.VT_API_KEY:
        logger.info("✅ VirusTotal API: faol")
    else:
        logger.warning("⚠️ VirusTotal API: VT_API_KEY topilmadi")

    # 2. YARA
    try:
        import yara
        if settings.YARA_RULES_PATH.exists():
            try:
                yara.compile(filepath=str(settings.YARA_RULES_PATH))
                tools_status["YARA"] = True
                logger.info("✅ YARA Scanner: faol (%s)", settings.YARA_RULES_PATH)
            except Exception as e:
                tools_status["YARA"] = False
                logger.warning("⚠️ YARA qoidalari noto'g'ri: %s", e)
        else:
            tools_status["YARA"] = False
            logger.warning("⚠️ YARA: qoidalar fayli topilmadi: %s", settings.YARA_RULES_PATH)
    except ImportError:
        tools_status["YARA"] = False
        logger.warning("⚠️ yara-python o'rnatilmagan")

    # 3. ClamAV
    try:
        import pyclamd
        try:
            cd = pyclamd.ClamdNetworkSocket(
                host=settings.CLAMAV_HOST, port=settings.CLAMAV_PORT
            )
            if cd.ping():
                tools_status["ClamAV"] = True
                logger.info("✅ ClamAV: faol (%s:%s)", settings.CLAMAV_HOST, settings.CLAMAV_PORT)
            else:
                tools_status["ClamAV"] = False
                logger.warning("⚠️ ClamAV: daemon javob bermayapti")
        except Exception:
            tools_status["ClamAV"] = False
            logger.warning("⚠️ ClamAV: daemon ulanib bo'lmadi (%s:%s)", settings.CLAMAV_HOST, settings.CLAMAV_PORT)
    except ImportError:
        tools_status["ClamAV"] = False
        logger.warning("⚠️ pyclamd o'rnatilmagan")

    # 4. Androguard
    try:
        from androguard.misc import AnalyzeAPK
        tools_status["Androguard"] = True
        logger.info("✅ Androguard: faol (APK tahlili tayyor)")
    except ImportError:
        tools_status["Androguard"] = False
        logger.warning("⚠️ androguard o'rnatilmagan — APK tahlili cheklangan")

    # 5. Entropy — har doim ishlaydi
    tools_status["Entropy"] = True
    logger.info("✅ Entropy Analysis: faol")

    # 6. Hash — har doim ishlaydi
    tools_status["Hash"] = True
    logger.info("✅ Hash (MD5/SHA256): faol")

    # 7. Google Safe Browsing
    tools_status["SafeBrowsing"] = bool(settings.GOOGLE_SAFE_BROWSING_API_KEY)
    if settings.GOOGLE_SAFE_BROWSING_API_KEY:
        logger.info("✅ Google Safe Browsing: faol")
    else:
        logger.warning("⚠️ Google Safe Browsing: API kalit topilmadi")

    # 8. URL/Phishing — har doim ishlaydi
    tools_status["URLAnalysis"] = True
    logger.info("✅ URL/Phishing Detection: faol")

    # 9. OCR (Tesseract)
    tools_status["OCR"] = _setup_tesseract()

    # 10. QR kod
    try:
        from pyzbar.pyzbar import decode as zbar_decode
        tools_status["QR"] = True
        logger.info("✅ QR Scanner (pyzbar): faol")
    except Exception as e:
        tools_status["QR"] = False
        logger.warning("⚠️ QR Scanner (pyzbar) yuklanmadi (DLL hato yoki o'rnatilmagan): %s", e)

    # 11. ZIP/Archive — har doim ishlaydi
    tools_status["Archive"] = True
    logger.info("✅ ZIP/Archive Analyzer: faol")

    # 12. AI (Gemini)
    tools_status["AI"] = bool(settings.GEMINI_API_KEY)
    if settings.GEMINI_API_KEY:
        logger.info("✅ Gemini AI Reporter: faol (%s)", settings.GEMINI_MODEL)
    else:
        logger.warning("⚠️ Gemini AI: API kalit topilmadi")

    # 13. Telegram Bot — har doim ishlaydi
    tools_status["TelegramBot"] = True
    logger.info("✅ Telegram Bot (aiogram): faol")

    # 14. AbuseIPDB
    tools_status["AbuseIPDB"] = bool(settings.ABUSEIPDB_API_KEY)
    if settings.ABUSEIPDB_API_KEY:
        logger.info("✅ AbuseIPDB IP Reputation: faol")
    else:
        logger.warning("⚠️ AbuseIPDB: API kalit topilmadi (ixtiyoriy)")

    # 15. URLScan.io
    tools_status["URLScan"] = bool(settings.URLSCAN_API_KEY)
    if settings.URLSCAN_API_KEY:
        logger.info("✅ URLScan.io: faol")
    else:
        logger.warning("⚠️ URLScan.io: API kalit topilmadi (ixtiyoriy)")

    # 16. Xavfsiz o'chirish
    tools_status["SecureDelete"] = settings.SECURE_DELETE
    if settings.SECURE_DELETE:
        logger.info("✅ Secure Delete (DoD 5220.22-M): faol")
    else:
        logger.info("ℹ️ Secure Delete: o'chirilgan (SECURE_DELETE=false)")

    # Umumiy natija
    active = sum(1 for v in tools_status.values() if v)
    total = len(tools_status)
    logger.info("=" * 50)
    logger.info("🛡 Vositalar holati: %d/%d faol", active, total)
    logger.info("=" * 50)

    return tools_status


# Bot ishga tushganda vositalarni tekshirish
tools_status = check_tools_status()
