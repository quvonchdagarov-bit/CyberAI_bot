"""Fayl metadata tahlilchisi — PDF, DOCX, XLSX, rasm uchun.

Metadata (yashirin ma'lumotlar) fayllar ichida ko'plab sir ma'lumotlarni saqlaydi:
- Muallif ismi va kompyuter nomi
- Yaratilgan va o'zgartirilgan sana
- GPS koordinatalar (rasmlarda)
- Dastur nomi va versiyasi
- Korxona nomi

Bu ma'lumotlar josuslik va zararli fayl aniqlashda juda muhim.
"""

import re
from pathlib import Path
from typing import Any

from bot.loader import logger

# Shubhali muallif/korxona nomlar (ko'p zararli dasturlarda shu nomlar uchraydi)
SUSPICIOUS_AUTHORS = {
    "admin", "user", "test", "hacker", "h4cker", "attacker",
    "malware", "trojan", "virus", "exploit", "payload",
    "anonymous", "anon", "root", "superuser",
}

# Shubhali yaratilish joylari (VM/sandbox muhitlar)
SUSPICIOUS_COMPUTERS = {
    "sandbox", "cuckoo", "analysis", "virus", "malware",
    "honeypot", "anyrun", "hybrid", "vmware", "virtualbox",
}


def analyze_metadata(path: Path) -> dict[str, Any]:
    """Fayl metadatasini tahlil qilish.

    Returns:
        dict: {
            "enabled": bool,
            "author": str | None,
            "creator": str | None,
            "created": str | None,
            "modified": str | None,
            "company": str | None,
            "subject": str | None,
            "keywords": str | None,
            "gps_found": bool,
            "score": int,
            "reasons": list[str],
            "raw": dict,
        }
    """
    result: dict[str, Any] = {
        "enabled": False,
        "author": None,
        "creator": None,
        "created": None,
        "modified": None,
        "company": None,
        "subject": None,
        "keywords": None,
        "gps_found": False,
        "score": 0,
        "reasons": [],
        "raw": {},
    }

    ext = path.suffix.lower()

    try:
        if ext == ".pdf":
            _analyze_pdf_meta(path, result)
        elif ext in (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"):
            _analyze_office_meta(path, result)
        elif ext in (".jpg", ".jpeg", ".png", ".tiff", ".webp", ".bmp"):
            _analyze_image_exif(path, result)
        else:
            return result

        result["enabled"] = True
        _score_metadata(result)

    except Exception as exc:
        logger.debug("Metadata tahlil xatosi (%s): %s", path.name, exc)

    return result


def _analyze_pdf_meta(path: Path, result: dict[str, Any]) -> None:
    """PDF metadata tahlili."""
    try:
        import pypdf

        with open(path, "rb") as f:
            reader = pypdf.PdfReader(f)
            meta = reader.metadata or {}
            raw = {k: str(v) for k, v in meta.items()}
            result["raw"] = raw
            result["author"] = raw.get("/Author") or raw.get("/Creator")
            result["creator"] = raw.get("/Producer")
            result["created"] = raw.get("/CreationDate")
            result["modified"] = raw.get("/ModDate")
            result["subject"] = raw.get("/Subject")
            result["keywords"] = raw.get("/Keywords")
    except ImportError:
        # pypdf yo'q bo'lsa, oddiy binary qidiruv
        _extract_pdf_meta_raw(path, result)
    except Exception as exc:
        logger.debug("PDF meta xatosi: %s", exc)
        _extract_pdf_meta_raw(path, result)


def _extract_pdf_meta_raw(path: Path, result: dict[str, Any]) -> None:
    """PDF dan xom binary ma'lumot olish."""
    try:
        content = path.read_bytes()[:8192].decode("latin-1", errors="ignore")
        author_match = re.search(r"/Author\s*\(([^)]+)\)", content)
        creator_match = re.search(r"/Creator\s*\(([^)]+)\)", content)
        if author_match:
            result["author"] = author_match.group(1).strip()
        if creator_match:
            result["creator"] = creator_match.group(1).strip()
    except Exception:
        pass


def _analyze_office_meta(path: Path, result: dict[str, Any]) -> None:
    """DOCX/XLSX/PPTX metadata tahlili (ZIP ichidagi XML)."""
    try:
        import zipfile
        import xml.etree.ElementTree as ET

        with zipfile.ZipFile(path, "r") as z:
            # docProps/core.xml — asosiy metadata
            core_xml_names = [n for n in z.namelist() if "core.xml" in n]
            if core_xml_names:
                with z.open(core_xml_names[0]) as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns = {
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                        "dcterms": "http://purl.org/dc/terms/",
                    }
                    creator = root.find("dc:creator", ns)
                    modified_by = root.find("cp:lastModifiedBy", ns)
                    created = root.find("dcterms:created", ns)
                    modified = root.find("dcterms:modified", ns)
                    subject = root.find("dc:subject", ns)
                    keywords = root.find("cp:keywords", ns)

                    result["author"] = creator.text if creator is not None else None
                    result["creator"] = modified_by.text if modified_by is not None else None
                    result["created"] = created.text if created is not None else None
                    result["modified"] = modified.text if modified is not None else None
                    result["subject"] = subject.text if subject is not None else None
                    result["keywords"] = keywords.text if keywords is not None else None

            # docProps/app.xml — korxona nomi
            app_xml_names = [n for n in z.namelist() if "app.xml" in n]
            if app_xml_names:
                with z.open(app_xml_names[0]) as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns_app = {"ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
                    company = root.find("ep:Company", ns_app)
                    result["company"] = company.text if company is not None else None

    except Exception as exc:
        logger.debug("Office meta xatosi: %s", exc)


def _analyze_image_exif(path: Path, result: dict[str, Any]) -> None:
    """Rasm EXIF metadata tahlili (GPS, kamera, sana)."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        with Image.open(path) as img:
            exif_data = img._getexif()  # type: ignore
            if not exif_data:
                return

            raw = {}
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))
                raw[tag] = str(value)[:100]

            result["raw"] = raw
            result["creator"] = raw.get("Software", None)
            result["created"] = raw.get("DateTimeOriginal", raw.get("DateTime", None))
            result["author"] = raw.get("Artist", None)

            # GPS ma'lumotlar bor bo'lsa
            if "GPSInfo" in raw or any("GPS" in k for k in raw):
                result["gps_found"] = True

    except ImportError:
        pass
    except Exception as exc:
        logger.debug("EXIF xatosi: %s", exc)


def _score_metadata(result: dict[str, Any]) -> None:
    """Metadata asosida risk skori hisoblash."""
    score = 0
    reasons = []

    author = (result.get("author") or "").lower().strip()
    creator = (result.get("creator") or "").lower().strip()
    company = (result.get("company") or "").lower().strip()

    # Shubhali muallif
    for sus in SUSPICIOUS_AUTHORS:
        if sus in author or sus in creator:
            score += 20
            reasons.append(f"Shubhali muallif ismi: '{result.get('author') or result.get('creator')}'")
            break

    # Shubhali kompyuter nomi
    for sus in SUSPICIOUS_COMPUTERS:
        if sus in author or sus in creator or sus in company:
            score += 25
            reasons.append(f"Fayl sandbox/VM muhitida yaratilgan belgisi: '{sus}'")
            break

    # GPS koordinatlar (maxfiylik xavfi)
    if result.get("gps_found"):
        score += 10
        reasons.append("Rasm ichida GPS joylashuv ma'lumotlari mavjud")

    # Muallif yo'q (ba'zan zararli fayllar metadatani o'chiradi)
    if not author and not creator and not result.get("created"):
        score += 8
        reasons.append("Metadata bo'sh — muallif va sana ma'lumotlari yo'q")

    result["score"] = min(score, 50)  # Metadata yolg'iz 50 dan oshmasin
    result["reasons"] = reasons
