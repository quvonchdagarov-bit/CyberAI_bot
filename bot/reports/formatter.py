"""Hisobot formatlash — chiroyli ko'rsatish uchun."""

from typing import Any

from bot.analyzers.scoring import classify_risk_level
from bot.reports.builder import (
    build_evidence_list,
    build_recommendations,
    infer_possible_impacts,
)


def format_pct(value: int) -> str:
    """Foiz formatlash."""
    return f"{max(0, min(100, int(value)))}%"


def format_short_result(result: dict[str, Any], content_type: str) -> str:
    """Qisqa natija xabari — dastlabki ko'rsatish uchun."""
    score = int(result.get("score", 0))
    level = classify_risk_level(score)
    filename = result.get("filename") or result.get("url") or result.get("text", "")[:50]

    lines = []

    if score >= 40:
        lines.append("🛡 <b>XAVFSIZLIK NATIJASI</b>")
    else:
        lines.append("✅ <b>XAVFSIZ</b>")

    lines.append("")

    if content_type == "file":
        lines.append(f"📄 <b>Fayl:</b> {filename}")
        if result.get("size_human"):
            lines.append(f"📏 <b>Hajm:</b> {result['size_human']}")
    elif content_type == "link":
        url = result.get("url", "")
        lines.append(f"🔗 <b>Havola:</b> {url[:80]}")
    elif content_type == "text":
        lines.append(f"📝 <b>Matn:</b> {str(filename)[:60]}...")

    lines.append(f"📊 <b>Risk:</b> {score}/100 — {level}")
    lines.append("")

    if score >= 90:
        lines.append(
            "⛔ Bu obyekt juda yuqori xavfli deb baholandi. "
            "Uni ishonchsiz deb qabul qilish kerak."
        )
    elif score >= 75:
        lines.append(
            "🚨 Yuqori xavf toifasiga kiradi. "
            "Ochish, o'rnatish yoki ishlatish tavsiya etilmaydi."
        )
    elif score >= 60:
        lines.append(
            "⚠️ Xavfli bo'lishi mumkin. "
            "Qo'shimcha tekshiruvsiz ishlatish tavsiya etilmaydi."
        )
    elif score >= 40:
        lines.append(
            "⚠️ Shubhali belgilar ko'rsatdi. "
            "Ehtiyotkorlik bilan yondashish kerak."
        )
    else:
        lines.append("Aniq yuqori xavfli belgi topilmadi.")

    # Eng muhim dalillar (qisqa)
    reasons = result.get("reasons", [])[:3]
    if reasons and score >= 40:
        lines.append("")
        lines.append("🔎 <b>Asosiy belgilar:</b>")
        for r in reasons:
            lines.append(f"  • {r}")

    # Ishlatilgan vositalar (qisqa)
    tools_used = result.get("tools_used", [])
    if tools_used:
        lines.append("")
        lines.append(f"🔧 <b>Tekshiruvlar:</b> {len(tools_used)} ta vosita")

    return "\n".join(lines)


def format_detailed_report(
    result: dict[str, Any], content_type: str, tag: str | None = None
) -> str:
    """To'liq batafsil hisobot — barcha dalillar bilan."""
    score = int(result.get("score", 0))
    level = classify_risk_level(score)
    confidence = min(95, max(35, score))
    filename = result.get("filename")
    sha256 = result.get("sha256")
    md5 = result.get("md5")
    mime_type = result.get("mime_type") or "unknown"

    evidence = build_evidence_list(result)
    impacts = infer_possible_impacts(result, content_type, tag)
    recs = build_recommendations(result, content_type)

    lines = []
    lines.append("🛡 <b>KENGAYTIRILGAN XAVFSIZLIK HISOBOTI</b>")
    lines.append("")
    lines.append(f"📊 <b>Xavf darajasi:</b> {level}")
    lines.append(f"📈 <b>Risk skori:</b> {score}/100")
    lines.append(f"🎯 <b>Ishonchliligi:</b> {format_pct(confidence)}")

    if filename:
        lines.append(f"📄 <b>Fayl:</b> {filename}")
        lines.append(f"📂 <b>MIME:</b> {mime_type}")
    if result.get("url"):
        lines.append(f"🔗 <b>URL:</b> {result['url'][:80]}")
    if result.get("size_human"):
        lines.append(f"📏 <b>Hajm:</b> {result['size_human']}")
    if result.get("entropy") is not None:
        lines.append(f"🔢 <b>Entropiya:</b> {result['entropy']}")
    if sha256:
        lines.append(f"🔐 <b>SHA256:</b> <code>{sha256[:32]}...</code>")
    if md5:
        lines.append(f"🔐 <b>MD5:</b> <code>{md5}</code>")

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━")

    # Ishlatilgan vositalar
    tools_used = result.get("tools_used", [])
    if tools_used:
        lines.append("")
        lines.append(f"🔧 <b>Ishlatilgan vositalar ({len(tools_used)}):</b>")
        for tool in tools_used:
            lines.append(f"  ✅ {tool}")

    # Xulosa
    lines.append("")
    lines.append("📌 <b>Qisqa xulosa:</b>")
    if score >= 90:
        lines.append(
            "Bu obyekt juda yuqori xavfli deb baholandi. "
            "Uni ishonchsiz deb qabul qilish kerak."
        )
    elif score >= 75:
        lines.append(
            "Yuqori xavf toifasiga kiradi. "
            "Ochish, o'rnatish yoki ishlatish tavsiya etilmaydi."
        )
    elif score >= 60:
        lines.append(
            "Xavfli bo'lishi mumkin. "
            "Qo'shimcha tekshiruvsiz ishlatish tavsiya etilmaydi."
        )
    elif score >= 40:
        lines.append(
            "Shubhali belgilar ko'rsatdi. Ehtiyotkorlik bilan yondashish kerak."
        )
    else:
        lines.append("Aniq yuqori xavfli belgi topilmadi.")

    # Dalillar
    if evidence:
        lines.append("")
        lines.append("🔎 <b>Aniqlangan belgilar:</b>")
        for item in evidence:
            lines.append(f"  • {item}")

    # APK batafsil
    apk_info = result.get("apk_info") or {}
    if apk_info.get("ok"):
        lines.append("")
        lines.append("📱 <b>APK tahlili:</b>")
        lines.append(f"  📦 Ilova: {apk_info.get('app_name', '?')}")
        lines.append(f"  📋 Paket: {apk_info.get('package_name', '?')}")
        lines.append(f"  🔑 Jami ruxsatlar: {apk_info.get('permission_count', 0)}")
        if apk_info.get("min_sdk"):
            lines.append(f"  📱 Min SDK: {apk_info['min_sdk']}")
        if apk_info.get("target_sdk"):
            lines.append(f"  🎯 Target SDK: {apk_info['target_sdk']}")

    # YARA batafsil
    yara_info = result.get("yara") or {}
    yara_details = yara_info.get("details", [])
    if yara_details:
        lines.append("")
        lines.append("🧬 <b>YARA mosliklari:</b>")
        for d in yara_details[:5]:
            desc = d.get("description", "")
            sev = d.get("severity", "")
            if desc:
                lines.append(f"  🔴 {d['rule']}: {desc} ({sev})")
            else:
                lines.append(f"  🔴 {d['rule']}")

    # ClamAV batafsil
    clamav = result.get("clamav") or {}
    if clamav.get("enabled"):
        lines.append("")
        if clamav.get("found"):
            lines.append(f"🦠 <b>ClamAV:</b> Virus topildi — {clamav.get('signature', 'unknown')}")
        else:
            lines.append("🦠 <b>ClamAV:</b> Virus topilmadi ✅")

    # VirusTotal batafsil
    vt_stats = result.get("vt_stats") or {}
    if vt_stats:
        malicious = int(vt_stats.get("malicious", 0))
        suspicious = int(vt_stats.get("suspicious", 0))
        harmless = int(vt_stats.get("harmless", 0))
        undetected = int(vt_stats.get("undetected", 0))
        total_engines = malicious + suspicious + harmless + undetected
        lines.append("")
        lines.append(f"🔬 <b>VirusTotal ({total_engines} dvijok):</b>")
        lines.append(f"  🔴 Zararli: {malicious}")
        lines.append(f"  🟡 Shubhali: {suspicious}")
        lines.append(f"  🟢 Xavfsiz: {harmless}")
        lines.append(f"  ⚪ Aniqlanmadi: {undetected}")

    # Google Safe Browsing
    safe_browsing = result.get("safe_browsing") or {}
    if safe_browsing.get("enabled"):
        lines.append("")
        if safe_browsing.get("matches"):
            lines.append(f"🌐 <b>Google Safe Browsing:</b> ⚠️ {len(safe_browsing['matches'])} ta xavfli match")
        else:
            lines.append("🌐 <b>Google Safe Browsing:</b> Xavfsiz ✅")

    # OCR natijasi
    ocr_info = result.get("ocr_info") or {}
    if ocr_info.get("enabled") and ocr_info.get("text"):
        lines.append("")
        lines.append("📷 <b>OCR (rasm ichidagi matn):</b>")
        lines.append(f"  {ocr_info['text'][:200]}...")

    # QR natijasi
    qr_info = result.get("qr_info") or {}
    if qr_info.get("values"):
        lines.append("")
        lines.append("📱 <b>QR kod natijalari:</b>")
        for v in qr_info["values"][:3]:
            lines.append(f"  🔗 {v[:80]}")

    # Oqibatlar
    if impacts:
        lines.append("")
        lines.append("⚠️ <b>Mumkin bo'lgan oqibatlar:</b>")
        for item in impacts:
            lines.append(f"  • {item}")

    # Tavsiyalar
    if recs:
        lines.append("")
        lines.append("✅ <b>Tavsiya etilgan harakatlar:</b>")
        for item in recs:
            lines.append(f"  • {item}")

    return "\n".join(lines)
