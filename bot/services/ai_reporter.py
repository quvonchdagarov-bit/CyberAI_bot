"""Gemini AI bilan kengaytirilgan xavfsizlik hisoboti generatori."""

from typing import Any

from bot.config import settings
from bot.loader import logger

# Gemini client yaratish
_gemini_model = None


def _get_gemini_model():
    """Gemini modelini yuklash (lazy init)."""
    global _gemini_model
    if _gemini_model is not None:
        return _gemini_model

    if not settings.GEMINI_API_KEY:
        return None

    try:
        from google import genai

        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        _gemini_model = client
        logger.info("Gemini AI client tayyor.")
        return client
    except Exception as e:
        logger.warning("Gemini yuklashda xato: %s", e)
        return None


async def ai_expand_security_report(
    warning_text: str,
    detailed_report: str,
    result: dict[str, Any],
    content_type: str,
) -> str:
    """Gemini AI yordamida professional xavfsizlik hisoboti yaratish.

    Barcha 13 ta vosita natijalarini birlashtirib,
    professional va tushunarli xulosa beradi.
    """
    client = _get_gemini_model()

    if client is None:
        return f"{warning_text}\n\n{detailed_report}"

    # Ishlatilgan vositalar ro'yxati
    tools_used = result.get("tools_used", [])
    tools_text = ", ".join(tools_used) if tools_used else "Nomaʼlum"

    # YARA detallari
    yara_info = result.get("yara", {})
    yara_details = ""
    if yara_info.get("matches"):
        yara_details = f"\nYARA mosliklari: {', '.join(yara_info['matches'])}"
        details = yara_info.get("details", [])
        for d in details[:5]:
            desc = d.get("description", "")
            sev = d.get("severity", "")
            if desc:
                yara_details += f"\n  - {d['rule']}: {desc} (jiddiylik: {sev})"

    # APK detallari
    apk_info = result.get("apk_info", {})
    apk_details = ""
    if apk_info.get("ok"):
        apk_details = (
            f"\nAPK: {apk_info.get('app_name', '?')} ({apk_info.get('package_name', '?')})"
            f"\n  Jami ruxsatlar: {apk_info.get('permission_count', 0)}"
            f"\n  Xavfli ruxsatlar: {', '.join(apk_info.get('permissions', [])[:8])}"
            f"\n  Activities: {apk_info.get('activities_count', 0)}"
            f"\n  Services: {apk_info.get('services_count', 0)}"
            f"\n  Receivers: {apk_info.get('receivers_count', 0)}"
        )
        if apk_info.get("suspicious_apis"):
            apk_details += f"\n  Shubhali API: {', '.join(apk_info['suspicious_apis'][:5])}"

    # OCR detallari
    ocr_info = result.get("ocr_info", {})
    ocr_text = ""
    if ocr_info.get("text"):
        ocr_text = f"\nOCR matn (rasm ichidan): {ocr_info['text'][:500]}"

    # QR detallari
    qr_info = result.get("qr_info", {})
    qr_text = ""
    if qr_info.get("values"):
        qr_text = f"\nQR kod qiymatlari: {', '.join(qr_info['values'][:3])}"

    # Archive detallari
    archive_info = result.get("archive_info", {})
    archive_text = ""
    if archive_info.get("found_files"):
        archive_text = f"\nArxiv ichidagi shubhali fayllar: {', '.join(archive_info['found_files'][:8])}"

    # PDF detallari
    pdf_info = result.get("pdf_info", {})
    pdf_text = ""
    if pdf_info.get("hits"):
        pdf_text = f"\nPDF shubhali elementlar: {', '.join(pdf_info['hits'][:6])}"

    # Safe Browsing
    safe_browsing = result.get("safe_browsing", {})
    sb_text = ""
    if safe_browsing.get("matches"):
        sb_text = f"\nGoogle Safe Browsing: {len(safe_browsing['matches'])} ta xavfli match topildi"

    prompt = f"""
Siz professional cyber security tahlilchi botsiz.
Quyidagi ma'lumotlar asosida zamonaviy, aniq, real va professional o'zbek tilida yakuniy javob yozing.

Qoidalar:
- Vahima uyg'otmang.
- Asossiz da'vo qilmang.
- Faqat mavjud evidence asosida yozing.
- 4 bo'limli formatda yozing:
  1) Yakuniy hukm
  2) Ishlatilgan vositalar va natijalari
  3) Nega shunday baho berildi
  4) Foydalanuvchi nima qilishi kerak
- Agar evidence kuchli bo'lsa, "ma'lumotlar o'g'irlanishi mumkin", "akkaunt xavf ostida qolishi mumkin" kabi iboralarni ishlating.
- Agar evidence kuchsiz bo'lsa, ehtimol shaklida yozing.
- Natija 900 belgidan 2500 belgigacha bo'lsin.
- Til: lotin yozuvidagi o'zbekcha.

Content type: {content_type}
Score: {result.get("score", 0)}
Reasons: {result.get("reasons", [])}

ISHLATILGAN VOSITALAR: {tools_text}

VT stats: {result.get("vt_stats", {})}
ClamAV: {result.get("clamav", {})}
{yara_details}
{apk_details}
{ocr_text}
{qr_text}
{archive_text}
{pdf_text}
{sb_text}

Entropiya: {result.get("entropy", "N/A")}
SHA256: {result.get("sha256", "N/A")}
Fayl hajmi: {result.get("size_human", "N/A")}

Qisqa warning:
{warning_text}

Batafsil hisobot:
{detailed_report}
""".strip()

    import asyncio

    max_retries = 3
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            # Asinxron chaqiruvdan foydalanamiz (bot qotib qolmasligi uchun)
            response = await client.aio.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=prompt,
            )
            text = (response.text or "").strip()
            return text or f"{warning_text}\n\n{detailed_report}"
        except Exception as e:
            error_str = str(e)
            if "429" in error_str and attempt < max_retries - 1:
                logger.warning(f"Gemini API limitiga yetildi (429). {retry_delay} soniyadan keyin qayta urinib ko'rilmoqda... (Urinish {attempt + 1}/{max_retries})")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.warning("Gemini AI report xatosi: %s", e)
                return f"{warning_text}\n\n{detailed_report}"
    
    return f"{warning_text}\n\n{detailed_report}"
