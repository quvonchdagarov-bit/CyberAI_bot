"""Umumiy yordamchi funksiyalar."""

import base64
import hashlib
import math
import mimetypes
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from bot.utils.constants import (
    DOUBLE_EXT_PATTERNS,
    URL_RE,
)


def normalize_url(url: str) -> str:
    """URLni normallash — ortiqcha belgilarni olib tashlash."""
    url = url.strip().rstrip(").,]>")
    if url.startswith("www."):
        url = "http://" + url
    return url


def extract_urls(text: str) -> list[str]:
    """Matn ichidan barcha URLlarni ajratib olish."""
    if not text:
        return []
    urls = []
    for item in URL_RE.findall(text):
        value = normalize_url(item)
        if value not in urls:
            urls.append(value)
    return urls


def url_domain(url: str) -> str:
    """URLdan domen nomini ajratish."""
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


def safe_lower(value: str | None) -> str:
    """None-safe lowercase."""
    return (value or "").lower()


def dedupe_keep_order(items: list[str]) -> list[str]:
    """Ro'yxatdan dublikatlarni olib tashlash, tartibni saqlash."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def file_sha256(path: Path) -> str:
    """Fayl SHA256 xeshini hisoblash."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_md5(path: Path) -> str:
    """Fayl MD5 xeshini hisoblash."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def human_size(size_bytes: int) -> str:
    """Baytlarni inson o'qiy oladigan formatga o'tkazish."""
    units = ["B", "KB", "MB", "GB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def get_mime_type(path: Path) -> str:
    """Fayl MIME turini aniqlash."""
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


def calculate_entropy(path: Path) -> float:
    """Fayl entropiyasini hisoblash (shifrlangan/packed aniqlash uchun)."""
    try:
        data = path.read_bytes()
        if not data:
            return 0.0
        counter = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return 0.0


def is_double_extension(filename: str) -> bool:
    """Ikki qavatli kengaytma mavjudligini tekshirish (.jpg.exe kabi)."""
    lowered = filename.lower()
    return any(x in lowered for x in DOUBLE_EXT_PATTERNS)


def vt_headers() -> dict[str, str]:
    """VirusTotal API header-larini qaytarish."""
    from bot.config import settings
    return {"x-apikey": settings.VT_API_KEY}


def vt_url_id(url: str) -> str:
    """URL uchun VirusTotal ID yaratish."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
