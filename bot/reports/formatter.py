"""Hisobot formatlash — professional vizual ko'rsatish.

Yangi:
- Visual risk progress bar: [████████░░] 80%
- VirusTotal SHA256 to'g'ridan-to'g'ri havolasi
- Skanerlash vaqtini ko'rsatish
- AbuseIPDB natijasi
- Metadata tahlili natijasi
- Yaxshilangan ko'rinish
"""

from typing import Any

from bot.analyzers.scoring import classify_risk_level
from bot.reports.builder import (
    build_evidence_list,
    build_recommendations,
    infer_possible_impacts,
)


def _risk_progress_bar(score: int) -> str:
    """Visual progress bar yasash.

    Misol: [████████░░] 80%
    """
    total_blocks = 10
    filled = round(score / 10)
    filled = max(0, min(total_blocks, filled))
    empty = total_blocks - filled

    if score >= 75:
        bar_char = "█"
    elif score >= 50:
        bar_char = "▓"
    else:
        bar_char = "▒"

    bar = bar_char * filled + "░" * empty
    return f"[{bar}] {score}%"


def _format_scan_time(scan_ms: int) -> str:
    """Skanerlash vaqtini formatlash."""
    if scan_ms < 1000:
        return f"{scan_ms}ms"
    return f"{scan_ms / 1000:.1f}s"


def format_pct(value: int) -> str:
    """Foiz formatlash."""
    return f"{max(0, min(100, int(value)))}%"


def format_short_result(
    result: dict[str, Any],
    content_type: str,
    scan_ms: int = 0,
) -> str:
    """Qisqa natija xabari — dastlabki ko'rsatish uchun."""
    score = int(result.get("score", 0))
    level = classify_risk_level(score)
    filename = result.get("filename") or result.get("url") or result.get("text", "")[:50]

    lines = []

    # ── Sarlavha ──────────────────────────────────────────────────────────
    if score >= 75:
        lines.append("🚨 <b>XAVFSIZLIK OGOHLANTIRISHI</b>")
    elif score >= 40:
        lines.append("⚠️ <b>SHUBHALI KONTENT ANIQLANDI</b>")
    else:
        lines.append("✅ <b>XAVFSIZ</b>")

    lines.append("")

    # ── Fayl/URL/Matn info ────────────────────────────────────────────────
    if content_type == "file":
        lines.append(f"📄 <b>Fayl:</b> <code>{filename}</code>")
        if result.get("size_human"):
            lines.append(f"📏 <b>Hajm:</b> {result['size_human']}")
        if result.get("mime_type"):
            lines.append(f"🗂 <b>Tur:</b> {result['mime_type']}")
    elif content_type == "link":
        url = result.get("url", "")
        lines.append(f"🔗 <b>Havola:</b> {url[:80]}")
        if result.get("final_url") and result["final_url"] != url:
            lines.append(f"↪️ <b>Final:</b> {result['final_url'][:60]}")
    elif content_type == "text":
        lines.append(f"📝 <b>Matn:</b> {str(filename)[:60]}...")

    # ── Risk darajasi (Visual progress bar) ───────────────────────────────
    lines.append("")
    lines.append(f"📊 <b>Risk:</b> {_risk_progress_bar(score)}")
    lines.append(f"🎯 <b>Daraja:</b> {level}")

    # ── Xulosa ───────────────────────────────────────────────────────────
    lines.append("")
    if score >= 90:
        lines.append(
            "⛔ <b>KRITIK XAVF!</b> Bu obyekt juda xavfli. "
            "Darhol bloklang va hech kim bilan ulashmang."
        )
    elif score >= 75:
        lines.append(
            "🚨 Bu obyekt yuqori xavfli. "
            "Ochish, o'rnatish yoki ishlatish <b>tavsiya etilmaydi</b>."
        )
    elif score >= 60:
        lines.append(
            "⚠️ Xavfli bo'lishi mumkin. "
            "Qo'shimcha tekshiruvsiz ishlatmang."
        )
    elif score >= 40:
        lines.append("⚠️ Shubhali belgilar topildi. Ehtiyotkorlik zarur.")
    else:
        lines.append("✅ Aniq yuqori xavfli belgi topilmadi.")

    # ── Asosiy dalillar ───────────────────────────────────────────────────
    reasons = result.get("reasons", [])[:3]
    if reasons and score >= 40:
        lines.append("")
        lines.append("🔎 <b>Asosiy belgilar:</b>")
        for r in reasons:
            lines.append(f"  • {r}")

    # ── Vositalar soni va vaqt ────────────────────────────────────────────
    tools_used = result.get("tools_used", [])
    lines.append("")
    info_line = f"🔧 <b>Tekshiruvlar:</b> {len(tools_used)} ta vosita"
    if scan_ms > 0:
        info_line += f" | ⏱ {_format_scan_time(scan_ms)}"
    lines.append(info_line)

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
    mime_type = result.get("mime_type") or "noma'lum"
    scan_ms = result.get("scan_time_ms", 0)

    evidence = build_evidence_list(result)
    impacts = infer_possible_impacts(result, content_type, tag)
    recs = build_recommendations(result, content_type)

    lines = []
    lines.append("🛡 <b>KENGAYTIRILGAN XAVFSIZLIK HISOBOTI</b>")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("")

    # ── Risk darajasi ─────────────────────────────────────────────────────
    lines.append(f"📊 <b>Xavf darajasi:</b> {level}")
    lines.append(f"📈 <b>Risk skori:</b> {_risk_progress_bar(score)}")
    lines.append(f"🎯 <b>Ishonchliligi:</b> {format_pct(confidence)}")
    if scan_ms > 0:
        lines.append(f"⏱ <b>Tahlil vaqti:</b> {_format_scan_time(scan_ms)}")

    lines.append("")

    # ── Fayl ma'lumotlari ─────────────────────────────────────────────────
    if filename:
        lines.append(f"📄 <b>Fayl:</b> <code>{filename}</code>")
        lines.append(f"🗂 <b>MIME:</b> {mime_type}")
    if result.get("url"):
        lines.append(f"🔗 <b>URL:</b> {result['url'][:80]}")
        if result.get("final_url") and result["final_url"] != result.get("url"):
            lines.append(f"↪️ <b>Final URL:</b> {result['final_url'][:60]}")
    if result.get("size_human"):
        lines.append(f"📏 <b>Hajm:</b> {result['size_human']}")
    if result.get("entropy") is not None:
        lines.append(f"🔢 <b>Entropiya:</b> {result['entropy']}")

    # ── Hash va VT havolasi ───────────────────────────────────────────────
    if sha256:
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}"
        lines.append(
            f"🔐 <b>SHA256:</b> <a href=\"{vt_link}\"><code>{sha256[:20]}...</code></a>"
        )
    if md5:
        lines.append(f"🔐 <b>MD5:</b> <code>{md5}</code>")

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━")

    # ── Ishlatilgan vositalar ─────────────────────────────────────────────
    tools_used = result.get("tools_used", [])
    if tools_used:
        lines.append("")
        lines.append(f"🔧 <b>Ishlatilgan vositalar ({len(tools_used)}):</b>")
        for tool in tools_used:
            lines.append(f"  ✅ {tool}")

    # ── Xulosa ───────────────────────────────────────────────────────────
    lines.append("")
    lines.append("📌 <b>Qisqa xulosa:</b>")
    if score >= 90:
        lines.append(
            "Bu obyekt KRITIK darajada xavfli. Darhol bloklash zarur."
        )
    elif score >= 75:
        lines.append(
            "Yuqori xavf toifasiga kiradi. Ochish yoki ishlatish tavsiya etilmaydi."
        )
    elif score >= 60:
        lines.append(
            "Xavfli bo'lishi mumkin. Qo'shimcha tekshiruvsiz ishlatmang."
        )
    elif score >= 40:
        lines.append("Shubhali belgilar topildi. Ehtiyotkorlik zarur.")
    else:
        lines.append("Aniq yuqori xavfli belgi topilmadi.")

    # ── Dalillar ─────────────────────────────────────────────────────────
    if evidence:
        lines.append("")
        lines.append("🔎 <b>Aniqlangan belgilar:</b>")
        for item in evidence:
            lines.append(f"  • {item}")

    # ── Metadata ─────────────────────────────────────────────────────────
    meta = result.get("metadata") or {}
    if meta.get("enabled"):
        lines.append("")
        lines.append("🗃 <b>Metadata tahlili:</b>")
        if meta.get("author"):
            lines.append(f"  👤 Muallif: {meta['author']}")
        if meta.get("creator"):
            lines.append(f"  💻 Yaratuvchi: {meta['creator']}")
        if meta.get("created"):
            lines.append(f"  📅 Yaratilgan: {meta['created'][:19]}")
        if meta.get("company"):
            lines.append(f"  🏢 Kompaniya: {meta['company']}")
        if meta.get("gps_found"):
            lines.append("  📍 GPS koordinatlar mavjud!")

    # ── APK batafsil ─────────────────────────────────────────────────────
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

    # ── YARA batafsil ────────────────────────────────────────────────────
    yara_info = result.get("yara") or {}
    yara_details = yara_info.get("details", [])
    if yara_details:
        lines.append("")
        lines.append("🧬 <b>YARA mosliklari:</b>")
        for d in yara_details[:5]:
            desc = d.get("description", "")
            sev = d.get("severity", "")
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "🔵")
            if desc:
                lines.append(f"  {sev_icon} {d['rule']}: {desc} ({sev})")
            else:
                lines.append(f"  {sev_icon} {d['rule']}")

    # ── ClamAV ───────────────────────────────────────────────────────────
    clamav = result.get("clamav") or {}
    if clamav.get("enabled"):
        lines.append("")
        if clamav.get("found"):
            lines.append(f"🦠 <b>ClamAV:</b> ⚠️ Virus topildi — <code>{clamav.get('signature', 'unknown')}</code>")
        else:
            lines.append("🦠 <b>ClamAV:</b> ✅ Virus topilmadi")

    # ── VirusTotal ────────────────────────────────────────────────────────
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

    # ── AbuseIPDB ─────────────────────────────────────────────────────────
    abuseipdb = result.get("abuseipdb") or {}
    if abuseipdb.get("enabled"):
        lines.append("")
        if abuseipdb.get("threat"):
            lines.append(
                f"🌐 <b>AbuseIPDB:</b> ⚠️ IP xavfli\n"
                f"  🔢 Abuse Score: {abuseipdb['abuse_score']}%\n"
                f"  📊 Hisobotlar: {abuseipdb['total_reports']}\n"
                f"  🌍 Mamlakat: {abuseipdb.get('country', '?')}\n"
                f"  🏢 ISP: {(abuseipdb.get('isp', '?'))[:30]}"
            )
        else:
            lines.append(f"🌐 <b>AbuseIPDB:</b> ✅ IP reputatsiyasi yaxshi")

    # ── Google Safe Browsing ───────────────────────────────────────────────
    safe_browsing = result.get("safe_browsing") or {}
    if safe_browsing.get("enabled"):
        lines.append("")
        if safe_browsing.get("matches"):
            lines.append(f"🛡 <b>Google Safe Browsing:</b> ⚠️ {len(safe_browsing['matches'])} ta xavfli match")
        else:
            lines.append("🛡 <b>Google Safe Browsing:</b> ✅ Xavfsiz")

    # ── OCR natijasi ──────────────────────────────────────────────────────
    ocr_info = result.get("ocr_info") or {}
    if ocr_info.get("enabled") and ocr_info.get("text"):
        lines.append("")
        lines.append("📷 <b>OCR (rasm ichidagi matn):</b>")
        lines.append(f"  {ocr_info['text'][:200]}...")

    # ── QR natijasi ───────────────────────────────────────────────────────
    qr_info = result.get("qr_info") or {}
    if qr_info.get("values"):
        lines.append("")
        lines.append("📱 <b>QR kod natijalari:</b>")
        for v in qr_info["values"][:3]:
            lines.append(f"  🔗 {v[:80]}")

    # ── Oqibatlar ─────────────────────────────────────────────────────────
    if impacts:
        lines.append("")
        lines.append("⚠️ <b>Mumkin bo'lgan oqibatlar:</b>")
        for item in impacts:
            lines.append(f"  • {item}")

    # ── Tavsiyalar ─────────────────────────────────────────────────────────
    if recs:
        lines.append("")
        lines.append("✅ <b>Tavsiya etilgan harakatlar:</b>")
        for item in recs:
            lines.append(f"  • {item}")

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("🤖 <i>CyberAI Bot v2.1 | 16 ta xavfsizlik vositasi</i>")

    return "\n".join(lines)
