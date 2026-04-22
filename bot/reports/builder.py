"""Hisobot tuzish — dalillar, oqibatlar, tavsiyalar, ogohlantirish."""

from typing import Any

from bot.utils.helpers import dedupe_keep_order


def build_evidence_list(result: dict[str, Any]) -> list[str]:
    """Tahlil dalillarini ro'yxat shaklida yig'ish."""
    evidence = []
    reasons = result.get("reasons", []) or []

    for r in reasons[:8]:
        evidence.append(r)

    # Entropiya
    entropy = result.get("entropy")
    if entropy is not None and entropy > 6.8:
        evidence.append(f"Entropiya: {entropy} (yuqori — shifrlangan/packed)")

    # VirusTotal
    vt_stats = result.get("vt_stats") or {}
    if vt_stats:
        malicious = int(vt_stats.get("malicious", 0))
        suspicious = int(vt_stats.get("suspicious", 0))
        harmless = int(vt_stats.get("harmless", 0))
        undetected = int(vt_stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        evidence.append(
            f"VirusTotal ({total} dvijok): zararli={malicious}, shubhali={suspicious}, "
            f"xavfsiz={harmless}, aniqlanmadi={undetected}"
        )

    # ClamAV
    clamav = result.get("clamav") or {}
    if clamav.get("found"):
        evidence.append(
            f"ClamAV imzosi mos tushdi: {clamav.get('signature', 'unknown')}"
        )
    elif clamav.get("enabled"):
        evidence.append("ClamAV: virus topilmadi")

    # YARA (batafsil)
    yara_info = result.get("yara") or {}
    yara_matches = yara_info.get("matches", []) or []
    yara_details = yara_info.get("details", []) or []
    if yara_matches:
        evidence.append("YARA mosliklari: " + ", ".join(yara_matches[:6]))
        for d in yara_details[:3]:
            desc = d.get("description", "")
            sev = d.get("severity", "")
            if desc:
                evidence.append(f"  → {d['rule']}: {desc} (jiddiylik: {sev})")

    # APK (batafsil)
    apk_info = result.get("apk_info") or {}
    if apk_info.get("ok"):
        app_name = apk_info.get("app_name", "?")
        pkg = apk_info.get("package_name", "?")
        evidence.append(f"APK ilova: {app_name} ({pkg})")
    if apk_info.get("permissions"):
        evidence.append(
            "Shubhali APK permissionlar: " + ", ".join(apk_info["permissions"][:8])
        )
    if apk_info.get("suspicious_apis"):
        evidence.append(
            "Shubhali API chaqiruvlar: " + ", ".join(apk_info["suspicious_apis"][:5])
        )

    # Arxiv
    archive_info = result.get("archive_info") or {}
    if archive_info.get("found_files"):
        evidence.append(
            "Arxiv ichidagi xavfli fayllar: "
            + ", ".join(archive_info["found_files"][:8])
        )

    # PDF
    pdf_info = result.get("pdf_info") or {}
    if pdf_info.get("hits"):
        evidence.append(
            "PDF ichidagi shubhali elementlar: " + ", ".join(pdf_info["hits"][:6])
        )

    # OCR
    ocr_info = result.get("ocr_info") or {}
    if ocr_info.get("text"):
        evidence.append(f"OCR matn topildi: {ocr_info['text'][:100]}...")

    # QR
    qr_info = result.get("qr_info") or {}
    if qr_info.get("values"):
        evidence.append(f"QR kodlardan topildi: {', '.join(qr_info['values'][:3])}")
    qr_url_best = result.get("qr_url_best") or {}
    if qr_url_best.get("url"):
        evidence.append(
            f"QR ichida tekshirilgan havola bor: {qr_url_best.get('url')}"
        )

    # Google Safe Browsing
    safe_browsing = result.get("safe_browsing") or {}
    if safe_browsing.get("matches"):
        evidence.append(f"Google Safe Browsing: {len(safe_browsing['matches'])} ta xavfli match")

    return evidence[:15]


def infer_possible_impacts(
    result: dict[str, Any], content_type: str, tag: str | None = None
) -> list[str]:
    """Mumkin bo'lgan oqibatlarni aniqlash."""
    impacts = []
    score = int(result.get("score", 0))
    filename = (result.get("filename") or "").lower()
    reasons = " ".join(result.get("reasons", [])).lower()

    if content_type == "link":
        impacts.extend([
            "akkaunt paroli yoki tasdiqlash kodi kiritilsa, hisob nazoratdan chiqishi mumkin",
            "bank karta yoki to'lov ma'lumotlari kiritilsa, moliyaviy zarar yuz berishi mumkin",
            "soxta sahifa orqali shaxsiy ma'lumotlar yig'ilishi mumkin",
        ])

    if content_type == "file":
        if filename.endswith(".apk"):
            impacts.extend([
                "telefon ichidagi SMS, kontaktlar yoki qo'ng'iroq ma'lumotlari so'ralishi mumkin",
                "fon rejimida zararli ruxsatlar orqali qurilma kuzatilishi mumkin",
                "banking yoki akkaunt ma'lumotlarini o'g'irlash xavfi paydo bo'lishi mumkin",
            ])
        elif filename.endswith(
            (".exe", ".msi", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".scr", ".dll")
        ):
            impacts.extend([
                "kompyuterda yashirin jarayon ishga tushishi mumkin",
                "brauzerda saqlangan parollar yoki sessiyalar xavf ostida qolishi mumkin",
                "fayllar buzilishi, o'chishi yoki tashqi serverga uzatilishi mumkin",
            ])
        elif filename.endswith((".zip", ".rar", ".7z")) or tag == "archive":
            impacts.extend([
                "arxiv ichidagi fayl ochilgandan keyin zararli kod ishga tushishi mumkin",
                "foydalanuvchi ko'rmagan ichki fayl orqali tizim zararlanishi mumkin",
            ])
        elif filename.endswith(".pdf"):
            impacts.extend([
                "zararli link yoki soxta yo'naltirish orqali ma'lumot yig'ilishi mumkin",
                "ichidagi script yoki embedded obyektlar xavf tug'dirishi mumkin",
            ])
        else:
            if score >= 75:
                impacts.extend([
                    "faylni ochish yoki ishga tushirish ma'lumotlar xavfsizligiga tahdid solishi mumkin",
                    "qurilmadagi shaxsiy fayllar, akkauntlar yoki sessiyalar xavf ostida qolishi mumkin",
                ])

    # Maxsus permissionlar bo'yicha
    if "read_sms" in reasons or "send_sms" in reasons or "receive_sms" in reasons:
        impacts.append("SMS tasdiqlash kodlari ushlanishi xavfi bor")

    if "read_contacts" in reasons or "write_contacts" in reasons:
        impacts.append("kontaktlar ro'yxati olinishi yoki o'zgartirilishi mumkin")

    if "record_audio" in reasons:
        impacts.append("mikrofon bilan bog'liq maxfiylik xavfi mavjud")

    if "system_alert_window" in reasons or "accessibility" in reasons:
        impacts.append(
            "ekran ustida soxta oynalar ko'rsatilib, foydalanuvchi aldanishi mumkin"
        )

    # Dublikatlarni olib tashlash
    deduped = []
    seen = set()
    for item in impacts:
        if item not in seen:
            seen.add(item)
            deduped.append(item)

    return deduped[:5]


def build_recommendations(
    result: dict[str, Any], content_type: str
) -> list[str]:
    """Foydalanuvchiga tavsiyalar berish."""
    score = int(result.get("score", 0))
    recs = []

    if content_type == "file":
        if score >= 75:
            recs.extend([
                "bu faylni ochmang, ishga tushirmang va o'rnatmang",
                "uni boshqa foydalanuvchilarga ham yubormang",
                "agar allaqachon ishga tushirilgan bo'lsa, qurilmani to'liq tekshiruvdan o'tkazing",
            ])
        elif score >= 40:
            recs.extend([
                "faylni faqat ishonchli manbadan kelganini tasdiqlagandan keyin ko'rib chiqing",
                "ishlatishdan oldin qo'shimcha antivirus tekshiruv o'tkazing",
            ])

    elif content_type == "link":
        if score >= 75:
            recs.extend([
                "linkni bosmang va hech qanday ma'lumot kiritmang",
                "agar sayt ochilgan bo'lsa, login qilmagan holda darhol yoping",
                "parol kiritilgan bo'lsa, darhol almashtiring",
            ])
        elif score >= 40:
            recs.extend([
                "link manbasini tekshirmasdan ochmang",
                "domen nomini va HTTPS sertifikatini alohida tekshiring",
            ])

    elif content_type == "text":
        recs.extend([
            "xabar ichidagi so'rovlarni mustaqil tekshirib ko'ring",
            "noma'lum manbaga parol, kod yoki karta ma'lumoti bermang",
        ])

    return recs[:4]


def build_plain_expert_warning(
    result: dict[str, Any], content_type: str, tag: str | None = None
) -> str:
    """Qisqa professional ogohlantirish xabari."""
    score = int(result.get("score", 0))
    filename = (result.get("filename") or "obyekt").strip()
    impacts = infer_possible_impacts(result, content_type, tag)
    primary_impact = (
        impacts[0]
        if impacts
        else "qurilma va ma'lumotlar xavfsizligiga tahdid tug'dirishi mumkin"
    )

    if score >= 90:
        return (
            f"⛔ {filename} bo'yicha kritik darajadagi xavf belgilari aniqlandi. "
            f"Bu obyekt ishga tushirilsa yoki ochilsa, {primary_impact}. "
            f"Uni darhol bloklash va ishlatmaslik tavsiya etiladi."
        )
    if score >= 75:
        return (
            f"🚨 {filename} yuqori xavfli deb baholandi. "
            f"Tahlilga ko'ra bu obyekt zararli faoliyat bilan bog'liq bo'lishi mumkin va {primary_impact}. "
            f"Ochish, o'rnatish yoki ishlatish tavsiya etilmaydi."
        )
    if score >= 60:
        return (
            f"⚠️ {filename} xavfli yoki kuchli shubhali obyekt sifatida baholandi. "
            f"Unda foydalanuvchini aldash, zararli ruxsat olish yoki ma'lumot yig'ish "
            f"bilan bog'liq belgilar mavjud. Qo'shimcha tekshiruvsiz ishlatmang."
        )
    if score >= 40:
        return (
            f"⚠️ {filename} bo'yicha shubhali belgilar topildi. "
            f"Hozircha to'liq zararli deb tasdiqlanmagan, lekin ehtiyotkorlik bilan yondashish kerak."
        )
    return ""
