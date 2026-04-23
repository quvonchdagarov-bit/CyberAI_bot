"""Umumiy fayl tahlili — 16 ta xavfsizlik vositasi bilan.

Qo'shimcha (yangi):
- Metadata tahlili (PDF, DOCX, XLSX, rasm EXIF)
- Xavfsiz fayl o'chirish (DoD standart)
- Skanerlash vaqtini qayd etish
"""

import time
import zipfile
from pathlib import Path
from typing import Any

import aiohttp

from bot.config import settings
from bot.utils.constants import (
    ARCHIVE_EXTS,
    IMAGE_EXTS,
    SUSPICIOUS_EXTS,
)
from bot.utils.helpers import (
    calculate_entropy,
    file_md5,
    file_sha256,
    get_mime_type,
    human_size,
    is_double_extension,
    normalize_url,
    safe_lower,
)
from bot.analyzers.apk_analyzer import analyze_apk_permissions
from bot.analyzers.archive_analyzer import inspect_zip
from bot.analyzers.image_analyzer import extract_image_text, extract_qr_data
from bot.analyzers.pdf_analyzer import analyze_pdf
from bot.analyzers.metadata_analyzer import analyze_metadata
from bot.analyzers.scoring import calculate_final_risk
from bot.analyzers.text_analyzer import analyze_text
from bot.analyzers.url_analyzer import analyze_url
from bot.services.clamav import scan_with_clamav
from bot.services.virustotal import vt_get_file_report, vt_poll_analysis, vt_upload_file
from bot.services.yara_scanner import scan_with_yara
from bot.loader import logger


async def analyze_saved_file(
    path: Path, filename: str, mime_type: str | None = None
) -> dict[str, Any]:
    """Faylni to'liq 16 ta xavfsizlik vositasi bilan tahlil qilish.

    1.  Hash (SHA256, MD5)
    2.  Entropy tahlili
    3.  Fayl kengaytma tekshiruvi
    4.  Double extension aniqlash
    5.  Kalit so'z tekshiruvi
    6.  Metadata tahlili (PDF, DOCX, EXIF) ← YANGI
    7.  Arxiv (ZIP) tahlili
    8.  APK (Androguard) tahlili
    9.  PDF tahlili
    10. OCR (pytesseract) — rasm ichidagi matn
    11. QR kod (pyzbar) — rasm ichidagi QR
    12. ClamAV antivirus skan
    13. YARA qoidalar skan
    14. VirusTotal API tekshiruvi
    """
    scan_start = time.monotonic()
    ext = Path(filename).suffix.lower()
    lower_name = filename.lower()
    size_bytes = path.stat().st_size
    sha256 = file_sha256(path)
    md5 = file_md5(path)
    entropy = calculate_entropy(path)

    logger.info(
        "📂 Fayl tahlili boshlandi: %s (%.2f KB, entropy=%.3f)",
        filename, size_bytes / 1024, entropy,
    )

    result: dict[str, Any] = {
        "filename": filename,
        "sha256": sha256,
        "md5": md5,
        "size_bytes": size_bytes,
        "size_human": human_size(size_bytes),
        "mime_type": mime_type or get_mime_type(path),
        "entropy": entropy,
        "base_score": 0,
        "reasons": [],
        "tools_used": ["Hash (SHA256/MD5)", "Entropy Analysis"],
        "scan_time_ms": 0,
    }

    # ── Shubhali kengaytma ─────────────────────────────────────────────────
    if ext in SUSPICIOUS_EXTS:
        result["base_score"] += 18
        result["reasons"].append(f"shubhali kengaytma: {ext}")

    # ── Ikki qavatli kengaytma ─────────────────────────────────────────────
    if is_double_extension(filename):
        result["base_score"] += 35
        result["reasons"].append("soxta ikki qavatli nom (maskan: fayl.pdf.exe)")

    # ── Xavfli kalit so'zlar ───────────────────────────────────────────────
    dangerous_keywords = ["crack", "mod", "premium", "keygen", "patch", "unlock", "cheat", "hack"]
    found_kw = [kw for kw in dangerous_keywords if kw in lower_name]
    if found_kw:
        result["base_score"] += 12
        result["reasons"].append(f"fayl nomida xavfli so'z: {', '.join(found_kw)}")

    # ── Entropiya tahlili ──────────────────────────────────────────────────
    if entropy > 7.4:
        result["base_score"] += 20
        result["reasons"].append(
            f"entropiya juda yuqori ({entropy}) — qadoqlangan yoki shifrlangan"
        )
    elif entropy > 6.8:
        result["base_score"] += 8
        result["reasons"].append(f"entropiya biroz yuqori ({entropy})")

    # ── Metadata tahlili ───────────────────────────────────────────────────
    meta_result = analyze_metadata(path)
    if meta_result.get("enabled"):
        result["metadata"] = meta_result
        result["tools_used"].append("Metadata Analyzer")
        if meta_result.get("score", 0) > 0:
            result["base_score"] = max(result["base_score"], meta_result["score"])
            result["reasons"].extend(meta_result.get("reasons", []))

    # ── Arxiv tekshiruvi ───────────────────────────────────────────────────
    if ext in ARCHIVE_EXTS or zipfile.is_zipfile(path):
        archive_info = inspect_zip(path)
        result["archive_info"] = archive_info
        result["base_score"] = max(result["base_score"], archive_info.get("score", 0))
        result["reasons"].extend(archive_info.get("reasons", []))
        result["tools_used"].append("ZIP/Archive Analyzer")

    # ── APK tekshiruvi ─────────────────────────────────────────────────────
    if ext == ".apk":
        apk_info = analyze_apk_permissions(path)
        result["apk_info"] = apk_info
        result["base_score"] = max(result["base_score"], apk_info.get("score", 0))
        result["reasons"].extend(apk_info.get("reasons", []))
        result["tools_used"].append(
            "Androguard (APK Analyzer)" if apk_info.get("ok") else "Androguard (cheklangan)"
        )

    # ── PDF tekshiruvi ─────────────────────────────────────────────────────
    if ext == ".pdf":
        pdf_info = analyze_pdf(path)
        result["pdf_info"] = pdf_info
        result["base_score"] = max(result["base_score"], pdf_info.get("score", 0))
        result["reasons"].extend(pdf_info.get("reasons", []))
        result["tools_used"].append("PDF Analyzer")

    # ── Rasm tekshiruvi (OCR + QR) ─────────────────────────────────────────
    if ext in IMAGE_EXTS or safe_lower(mime_type).startswith("image/"):
        ocr_info = extract_image_text(path)
        qr_info = extract_qr_data(path)
        result["ocr_info"] = ocr_info
        result["qr_info"] = qr_info

        if ocr_info.get("enabled"):
            result["tools_used"].append("OCR (Tesseract)")
        if qr_info.get("enabled"):
            result["tools_used"].append("QR Scanner (pyzbar)")

        ocr_text = ocr_info.get("text", "")
        if ocr_text:
            text_result = await analyze_text(ocr_text[:3000])
            result["ocr_text_result"] = text_result
            result["base_score"] = max(
                result["base_score"], min(text_result.get("score", 0), 70)
            )
            result["reasons"].append("rasm ichidagi matn tahlil qilindi")

        qr_values = qr_info.get("values", [])
        if qr_values:
            result["reasons"].append(f"QR kod topildi ({len(qr_values)} ta)")
            async with aiohttp.ClientSession() as session:
                qr_url_results = []
                for value in qr_values[:2]:
                    if value.startswith(("http://", "https://", "www.")):
                        qr_url_results.append(
                            await analyze_url(session, normalize_url(value))
                        )
                if qr_url_results:
                    best = max(qr_url_results, key=lambda x: x["score"])
                    result["qr_url_best"] = best
                    result["base_score"] = max(result["base_score"], best["score"])
                    result["reasons"].append("QR ichidagi havola tahlil qilindi")

    # ── ClamAV skanerlash ──────────────────────────────────────────────────
    clamav_result = scan_with_clamav(path)
    result["clamav"] = clamav_result
    if clamav_result.get("enabled"):
        result["tools_used"].append("ClamAV Antivirus")

    # ── YARA skanerlash ────────────────────────────────────────────────────
    yara_result = scan_with_yara(path)
    result["yara"] = yara_result
    if yara_result.get("enabled"):
        result["tools_used"].append("YARA Scanner")

    # ── VirusTotal tekshiruvi ──────────────────────────────────────────────
    if settings.VT_API_KEY:
        result["tools_used"].append("VirusTotal API")
        async with aiohttp.ClientSession() as session:
            report = await vt_get_file_report(session, sha256)
            if report.get("found") and report.get("stats"):
                result["vt_stats"] = report["stats"]
            else:
                analysis_id = await vt_upload_file(session, path, filename)
                if analysis_id:
                    analysis = await vt_poll_analysis(
                        session, analysis_id, tries=5, delay=8
                    )
                    result["vt_stats"] = analysis.get("stats", {})

    # ── Skanerlash vaqtini qayd etish ────────────────────────────────────
    elapsed_ms = int((time.monotonic() - scan_start) * 1000)
    result["scan_time_ms"] = elapsed_ms

    logger.info(
        "✅ Tahlil yakunlandi: %s — %d ta vosita, %d ms",
        filename, len(result["tools_used"]), elapsed_ms,
    )

    return calculate_final_risk(result)
