"""Gemini AI — kengaytirilgan professional xavfsizlik hisoboti.

Yangilangan:
- MITRE ATT&CK framework terminologiyasi
- AbuseIPDB, URLScan, Metadata natijalari
- Aniq tavsiyalar (nima qilish, nima qilmaslik)
- Yanada professional va batafsil prompt
- Token limitni boshqarish
"""

from typing import Any

from bot.config import settings
from bot.loader import logger

_gemini_client = None


def _get_gemini_client():
    """Gemini modelini yuklash (lazy init)."""
    global _gemini_client
    if _gemini_client is not None:
        return _gemini_client

    if not settings.GEMINI_API_KEY:
        return None

    try:
        from google import genai
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        _gemini_client = client
        logger.info("✅ Gemini AI client tayyor (%s)", settings.GEMINI_MODEL)
        return client
    except Exception as e:
        logger.warning("Gemini yuklashda xato: %s", e)
        return None


def _truncate(text: str, max_len: int = 500) -> str:
    """Matnni belgilangan uzunlikda kesish."""
    if not text:
        return ""
    return text[:max_len] + ("..." if len(text) > max_len else "")


async def ai_expand_security_report(
    warning_text: str,
    detailed_report: str,
    result: dict[str, Any],
    content_type: str,
) -> str:
    """Gemini AI yordamida professional xavfsizlik hisoboti yaratish.

    MITRE ATT&CK terminologiyasi va professional tahlil bilan.
    """
    client = _get_gemini_client()
    if client is None:
        return f"{warning_text}\n\n{detailed_report}"

    score = result.get("score", 0)
    tools_used = result.get("tools_used", [])

    # ── Tahlil natijalarini yig'ish ────────────────────────────────────────
    sections = []

    # YARA
    yara_info = result.get("yara", {})
    if yara_info.get("matches"):
        details = yara_info.get("details", [])
        yara_text = f"YARA mosliklari: {len(yara_info['matches'])} ta"
        for d in details[:3]:
            yara_text += f"\n  - {d.get('rule')}: {_truncate(d.get('description',''), 100)} (Jiddiylik: {d.get('severity','')})"
        sections.append(("YARA Scanner", yara_text))

    # APK
    apk_info = result.get("apk_info", {})
    if apk_info.get("ok"):
        apk_text = (
            f"Ilova: {apk_info.get('app_name', '?')} | "
            f"Paket: {apk_info.get('package_name', '?')}\n"
            f"Xavfli ruxsatlar: {', '.join(apk_info.get('permissions', [])[:6])}\n"
            f"Shubhali API: {', '.join(apk_info.get('suspicious_apis', [])[:3])}"
        )
        sections.append(("APK Tahlili (Androguard)", apk_text))

    # Metadata
    meta = result.get("metadata", {})
    if meta.get("enabled") and meta.get("score", 0) > 0:
        _unknown = "noma'lum"
        meta_text = f"Muallif: {meta.get('author', _unknown)} | Yaratuvchi: {meta.get('creator', _unknown)}"
        if meta.get("gps_found"):
            meta_text += " | GPS koordinatlar mavjud"
        if meta.get("reasons"):
            meta_text += f"\nSabab: {'; '.join(meta['reasons'][:3])}"
        sections.append(("Metadata Tahlili", meta_text))

    # ClamAV
    clamav = result.get("clamav", {})
    if clamav.get("found"):
        _sig = clamav.get("signature", "noma'lum")
        sections.append(("ClamAV Antivirus", f"Virus topildi: {_sig}"))

    # VirusTotal
    vt_stats = result.get("vt_stats") or {}
    if vt_stats:
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        total = sum(vt_stats.values())
        sections.append(("VirusTotal", f"{total} dvijok: {malicious} zararli, {suspicious} shubhali"))

    # AbuseIPDB
    abuse = result.get("abuseipdb", {})
    if abuse.get("enabled") and abuse.get("threat"):
        sections.append((
            "AbuseIPDB",
            f"IP: {abuse.get('ip')} | Xavf: {abuse.get('abuse_score')}% | "
            f"{abuse.get('total_reports')} hisobot | {abuse.get('country', '?')} | "
            f"ISP: {_truncate(abuse.get('isp', '?'), 40)}"
        ))

    # Safe Browsing
    sb = result.get("safe_browsing", {})
    if sb.get("matches"):
        sections.append(("Google Safe Browsing", f"{len(sb['matches'])} ta xavfli match"))

    # OCR
    ocr_info = result.get("ocr_info", {})
    if ocr_info.get("text"):
        sections.append(("OCR (Rasm ichidagi matn)", _truncate(ocr_info["text"], 300)))

    # QR
    qr_info = result.get("qr_info", {})
    if qr_info.get("values"):
        sections.append(("QR Kod", ", ".join(qr_info["values"][:2])))

    # Archive
    archive = result.get("archive_info", {})
    if archive.get("found_files"):
        sections.append(("Arxiv", ", ".join(archive["found_files"][:5])))

    # PDF
    pdf_info = result.get("pdf_info", {})
    if pdf_info.get("hits"):
        sections.append(("PDF Tahlili", ", ".join(pdf_info["hits"][:4])))

    # Typosquatting
    reasons = result.get("reasons", [])
    typo_reasons = [r for r in reasons if "typosquatting" in r or "homograph" in r]
    if typo_reasons:
        sections.append(("Typosquatting/Homograph", typo_reasons[0]))

    # ── Prompt yaratish ────────────────────────────────────────────────────
    sections_text = ""
    for title, content in sections:
        sections_text += f"\n\n### {title}\n{content}"

    file_info = ""
    if result.get("filename"):
        file_info = (
            f"Fayl: {result['filename']}\n"
            f"SHA256: {result.get('sha256', 'N/A')}\n"
            f"Hajm: {result.get('size_human', 'N/A')}\n"
            f"Entropiya: {result.get('entropy', 'N/A')}\n"
        )
    elif result.get("url"):
        file_info = f"URL: {result['url'][:100]}\n"

    prompt = f"""Siz dunyo darajasidagi professional kiberxavfsizlik tahlilchisisiz.
Quyidagi REAL tahlil natijalarini ko'rib, foydalanuvchi uchun aniq, professional va harakatga yo'naltiruvchi xavfsizlik hisoboti yozing.

---
## TAHLIL MA'LUMOTLARI

Content turi: {content_type}
Risk skori: {score}/100
Skanerlash vaqti: {result.get('scan_time_ms', 0)}ms
Ishlatilgan vositalar: {', '.join(tools_used)}
{file_info}
Aniqlangan sabablar: {'; '.join(reasons[:6])}
{sections_text}

---
## YOZISH QOIDALARI

1. **Til:** O'zbek tili (lotin yozuvi) — sodda va aniq
2. **Format:** Quyidagi 4 bo'limda yozilsin:
   - 🔴 **YAKUNIY HUKM** — xavf darajasini bir jumlada aniq ayt
   - 🔍 **NIMA ANIQLANDI** — konkret evidence va texnik tushuntirish (MITRE ATT&CK terminlariga mos agar kerak bo'lsa)
   - ⚠️ **XAVF NIMA** — real oqibatlar (ma'lumot o'g'irlanishi, akkaunt buzilishi va h.k.) faqat mavjud evidence asosida
   - ✅ **NIMA QILISH KERAK** — aniq va amaliy 3-5 ta qadam
3. **Muhim:** Asossiz da'vo qilmang. Faqat mavjud evidence asosida yozing.
4. **Uzunlik:** 600-1200 belgi. Juda qisqa yoki juda uzun bo'lmasin.
5. **Agar xavf past bo'lsa:** Xotirjam izohlang, vahima uyg'otmang.
""".strip()

    import asyncio
    max_retries = 3
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            response = await client.aio.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=prompt,
            )
            text = (response.text or "").strip()
            if text:
                return text
            return f"{warning_text}\n\n{detailed_report}"
        except Exception as e:
            error_str = str(e)
            if "429" in error_str and attempt < max_retries - 1:
                logger.warning(
                    "Gemini API limit (429). %ds da qayta urinish... (%d/%d)",
                    retry_delay, attempt + 1, max_retries,
                )
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
            else:
                logger.warning("Gemini AI xatosi: %s", e)
                return f"{warning_text}\n\n{detailed_report}"

    return f"{warning_text}\n\n{detailed_report}"
