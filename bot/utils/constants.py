"""Loyiha konstantalari — regex, kalit so'zlar, kengaytmalar."""

import re

# =========================
# Regex patternlar
# =========================
URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# =========================
# Nomaqbul va xavfli so'zlar
# =========================
ADULT_WORDS = {
    "porn", "xxx", "adult", "sex", "cam", "nude", "onlyfans", "escort",
    "erotik", "yalang", "yalangoch",
}

BAD_WORDS = {
    "ahmoq", "tentak", "lanati", "iflos", "nodon",
}

PHISHING_HINTS = {
    "login", "verify", "secure", "bank", "bonus", "free", "gift", "payment",
    "confirm", "update", "wallet", "account", "reset-password", "premium",
    "claim", "click", "parol", "tasdiqlang", "kirish", "to'lov", "karta",
    "hisob", "bloklanadi", "sovg'a", "mukofot", "promo", "otp", "sms code",
    "kodni kiriting", "tasdiq kodi", "refund", "withdraw",
}

# =========================
# URL / domen
# =========================
SHORTENERS = {
    "bit.ly", "cutt.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy",
    "shorturl.at", "clck.ru", "goo.su",
}

# =========================
# Fayl kengaytmalari
# =========================
SUSPICIOUS_EXTS = {
    ".apk", ".exe", ".msi", ".bat", ".cmd", ".js", ".vbs", ".scr",
    ".ps1", ".jar", ".zip", ".rar", ".7z", ".lnk", ".hta", ".dll", ".pdf",
}

ARCHIVE_EXTS = {".zip", ".rar", ".7z"}

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}

INNER_DANGEROUS_EXTS = {
    ".exe", ".bat", ".cmd", ".js", ".vbs", ".scr", ".ps1",
    ".apk", ".jar", ".lnk", ".hta", ".dll",
}

# =========================
# APK xavfli ruxsatlar (ball bilan)
# =========================
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": 18,
    "android.permission.SEND_SMS": 22,
    "android.permission.RECEIVE_SMS": 18,
    "android.permission.RECORD_AUDIO": 14,
    "android.permission.CAMERA": 10,
    "android.permission.READ_CONTACTS": 14,
    "android.permission.WRITE_CONTACTS": 14,
    "android.permission.READ_CALL_LOG": 18,
    "android.permission.WRITE_CALL_LOG": 18,
    "android.permission.READ_PHONE_STATE": 10,
    "android.permission.CALL_PHONE": 14,
    "android.permission.REQUEST_INSTALL_PACKAGES": 20,
    "android.permission.QUERY_ALL_PACKAGES": 16,
    "android.permission.SYSTEM_ALERT_WINDOW": 22,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.ACCESS_COARSE_LOCATION": 8,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 28,
}

# =========================
# Risk darajalari
# =========================
RISK_LEVELS = [
    (90, "🔴 KRITIK"),
    (75, "🟠 JUDA YUQORI"),
    (60, "🟡 YUQORI"),
    (40, "🟡 O'RTA"),
    (0, "🟢 PAST"),
]

# =========================
# Ikki qavatli kengaytma patternlar
# =========================
DOUBLE_EXT_PATTERNS = [
    ".jpg.exe", ".png.exe", ".pdf.exe", ".doc.exe", ".docx.exe",
    ".mp4.apk", ".jpg.apk", ".png.apk", ".pdf.apk", ".txt.exe",
]
