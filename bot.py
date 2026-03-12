import asyncio
import base64
import hashlib
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
from aiogram import Bot, Dispatcher
from aiogram.exceptions import TelegramRetryAfter
from aiogram.types import Message
from dotenv import load_dotenv
from androguard.misc import AnalyzeAPK

load_dotenv()

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
DELETE_BAD_MESSAGES = os.getenv("DELETE_BAD_MESSAGES", "false").lower() == "true"

if not TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN topilmadi. .env faylga token qo'ying.")

bot = Bot(token=TOKEN)
dp = Dispatcher()

DOWNLOAD_DIR = Path("downloads")
DOWNLOAD_DIR.mkdir(exist_ok=True)

URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

ADULT_WORDS = {
    "porn", "xxx", "adult", "sex", "cam", "nude", "onlyfans", "escort",
    "erotik", "yalang", "yalangoch"
}

BAD_WORDS = {
    "ahmoq", "tentak", "lanati", "so'kinish"
}

PHISHING_HINTS = {
    "login", "verify", "secure", "bank", "bonus", "free",
    "gift", "payment", "confirm", "update", "wallet",
    "account", "reset-password"
}

SUSPICIOUS_EXTS = {
    ".apk", ".exe", ".msi", ".bat", ".cmd", ".js", ".vbs", ".scr",
    ".ps1", ".jar", ".zip", ".rar", ".7z"
}

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
    "android.permission.READ_EXTERNAL_STORAGE": 6,
    "android.permission.WRITE_EXTERNAL_STORAGE": 8,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 28,
}

send_locks = {}
last_sent_time = {}


def normalize_url(url: str) -> str:
    url = url.strip()
    if url.startswith("www."):
        url = "http://" + url
    return url


def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    urls = []
    for item in URL_RE.findall(text):
        u = normalize_url(item)
        if u not in urls:
            urls.append(u)
    return urls


def url_domain(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


def vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY}


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stats_to_score(stats: dict) -> tuple[int, str]:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    score = min(malicious * 25 + suspicious * 12, 100)
    summary = (
        f"malicious={malicious}, suspicious={suspicious}, "
        f"harmless={harmless}, undetected={undetected}"
    )
    return score, summary


def band(score: int) -> str:
    if score >= 80:
        return "YUQORI"
    if score >= 50:
        return "O‘RTA"
    return "PAST"


async def safe_send(message: Message, text: str, parse_mode: str | None = None):
    chat_id = message.chat.id

    if chat_id not in send_locks:
        send_locks[chat_id] = asyncio.Lock()

    async with send_locks[chat_id]:
        now = time.time()
        last_time = last_sent_time.get(chat_id, 0)
        wait_time = max(0, 2 - (now - last_time))
        if wait_time > 0:
            await asyncio.sleep(wait_time)

        try:
            await message.reply(text, parse_mode=parse_mode)
            last_sent_time[chat_id] = time.time()
        except TelegramRetryAfter as e:
            await asyncio.sleep(float(e.retry_after) + 1)
            await message.reply(text, parse_mode=parse_mode)
            last_sent_time[chat_id] = time.time()


async def maybe_delete(message: Message):
    if not DELETE_BAD_MESSAGES:
        return
    try:
        await message.delete()
    except Exception:
        pass


async def vt_get_analysis(session: aiohttp.ClientSession, analysis_id: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    async with session.get(url, headers=vt_headers(), timeout=40) as resp:
        data = await resp.json(content_type=None)
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "status": attrs.get("status"),
            "stats": attrs.get("stats", {}),
        }


async def vt_poll_analysis(
    session: aiohttp.ClientSession,
    analysis_id: str,
    tries: int = 6,
    delay: int = 10
) -> dict:
    last = {}
    for _ in range(tries):
        last = await vt_get_analysis(session, analysis_id)
        if last.get("status") == "completed":
            return last
        await asyncio.sleep(delay)
    return last


async def vt_get_file_report(session: aiohttp.ClientSession, sha256: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    async with session.get(url, headers=vt_headers(), timeout=40) as resp:
        if resp.status == 404:
            return {"found": False}
        data = await resp.json(content_type=None)
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "found": True,
            "stats": attrs.get("last_analysis_stats", {}),
            "meaningful_name": attrs.get("meaningful_name"),
            "type_description": attrs.get("type_description"),
        }


async def vt_get_upload_url(session: aiohttp.ClientSession) -> str | None:
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    async with session.get(url, headers=vt_headers(), timeout=30) as resp:
        if resp.status != 200:
            return None
        data = await resp.json(content_type=None)
        return data.get("data")


async def vt_upload_file(
    session: aiohttp.ClientSession,
    path: Path,
    filename: str
) -> str | None:
    upload_url = "https://www.virustotal.com/api/v3/files"

    if path.stat().st_size > 32 * 1024 * 1024:
        custom_url = await vt_get_upload_url(session)
        if not custom_url:
            return None
        upload_url = custom_url

    form = aiohttp.FormData()
    with open(path, "rb") as f:
        form.add_field("file", f, filename=filename)
        async with session.post(upload_url, headers=vt_headers(), data=form, timeout=180) as resp:
            data = await resp.json(content_type=None)
            return data.get("data", {}).get("id")


async def vt_scan_url(session: aiohttp.ClientSession, url_value: str) -> str | None:
    url = "https://www.virustotal.com/api/v3/urls"
    async with session.post(url, headers=vt_headers(), data={"url": url_value}, timeout=40) as resp:
        data = await resp.json(content_type=None)
        return data.get("data", {}).get("id")


async def vt_get_url_report(session: aiohttp.ClientSession, url_value: str) -> dict:
    url_id = vt_url_id(url_value)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    async with session.get(url, headers=vt_headers(), timeout=40) as resp:
        if resp.status == 404:
            return {"found": False}
        data = await resp.json(content_type=None)
        attrs = data.get("data", {}).get("attributes", {})
        return {
            "found": True,
            "stats": attrs.get("last_analysis_stats", {}),
            "reputation": attrs.get("reputation"),
        }


async def analyze_url(session: aiohttp.ClientSession, url_value: str) -> dict:
    domain = url_domain(url_value)
    reasons = []
    local_score = 0
    lowered = url_value.lower()

    for word in PHISHING_HINTS:
        if word in lowered:
            local_score += 10
            reasons.append(f"shubhali so‘z: {word}")
            break

    if ".apk" in lowered or ".exe" in lowered or ".zip" in lowered:
        local_score += 20
        reasons.append("havolada shubhali fayl ko‘rinishi bor")

    vt_report = await vt_get_url_report(session, url_value)
    vt_summary = None
    score = local_score

    if vt_report.get("found") and vt_report.get("stats"):
        score, vt_summary = stats_to_score(vt_report["stats"])
        if score >= 50:
            reasons.append("VirusTotal zararli yoki shubhali dedi")
    else:
        analysis_id = await vt_scan_url(session, url_value)
        if analysis_id:
            analysis = await vt_poll_analysis(session, analysis_id, tries=4, delay=8)
            if analysis.get("stats"):
                score, vt_summary = stats_to_score(analysis["stats"])
                if score >= 50:
                    reasons.append("VirusTotal zararli yoki shubhali dedi")
            else:
                reasons.append("VirusTotal tahlili hali tugamadi")

    if any(w in lowered for w in ADULT_WORDS):
        score = max(score, 75)
        reasons.append("18+ belgilar URL ichida topildi")

    return {
        "url": url_value,
        "domain": domain,
        "score": min(score, 100),
        "band": band(min(score, 100)),
        "reasons": reasons,
        "vt_summary": vt_summary,
    }


def analyze_apk_permissions(path: Path) -> dict:
    try:
        a, d, dx = AnalyzeAPK(str(path))
        permissions = a.get_permissions() or []

        score = 0
        reasons = []
        found_permissions = []

        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                score += DANGEROUS_PERMISSIONS[perm]
                found_permissions.append(perm)

        if found_permissions:
            reasons.append("shubhali permissionlar topildi")

        return {
            "ok": True,
            "score": min(score, 100),
            "permissions": found_permissions[:15],
            "permission_count": len(permissions),
            "package_name": a.get_package(),
            "app_name": a.get_app_name(),
            "target_sdk": a.get_target_sdk_version(),
            "min_sdk": a.get_min_sdk_version(),
            "reasons": reasons,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "score": 0,
            "permissions": [],
            "permission_count": 0,
            "package_name": None,
            "app_name": None,
            "target_sdk": None,
            "min_sdk": None,
            "reasons": [],
        }


async def analyze_saved_file(path: Path, filename: str, mime_type: str | None = None) -> dict:
    ext = Path(filename).suffix.lower()
    sha256 = file_sha256(path)

    reasons = []
    local_score = 0
    lower_name = filename.lower()
    apk_info = None

    if ext in SUSPICIOUS_EXTS:
        local_score += 20
        reasons.append(f"shubhali kengaytma: {ext}")

    if (
        ".mp4.apk" in lower_name
        or ".jpg.apk" in lower_name
        or ".png.apk" in lower_name
        or ".pdf.exe" in lower_name
    ):
        local_score += 35
        reasons.append("soxta ikki qavatli nom")

    if "crack" in lower_name or "mod" in lower_name or "premium" in lower_name:
        local_score += 10
        reasons.append("fayl nomida xavfli kalit so‘z bor")

    if ext == ".apk":
        apk_info = analyze_apk_permissions(path)
        if apk_info.get("ok"):
            local_score = max(local_score, apk_info.get("score", 0))
            if apk_info.get("reasons"):
                reasons.extend(apk_info["reasons"])
        else:
            reasons.append("APK ichki tahlili bajarilmadi")

    if not VT_API_KEY:
        return {
            "filename": filename,
            "sha256": sha256,
            "score": local_score,
            "band": band(local_score),
            "reasons": reasons + ["VirusTotal API kalit qo‘yilmagan"],
            "vt_summary": None,
            "apk_info": apk_info,
        }

    async with aiohttp.ClientSession() as session:
        report = await vt_get_file_report(session, sha256)

        if report.get("found") and report.get("stats"):
            vt_score, vt_summary = stats_to_score(report["stats"])
            score = max(local_score, vt_score)
            reasons.append("VirusTotal hash bo‘yicha natija topdi")
            return {
                "filename": filename,
                "sha256": sha256,
                "score": min(score, 100),
                "band": band(min(score, 100)),
                "reasons": reasons,
                "vt_summary": vt_summary,
                "apk_info": apk_info,
            }

        analysis_id = await vt_upload_file(session, path, filename)
        if not analysis_id:
            reasons.append("VirusTotal’ga yuklab bo‘lmadi")
            return {
                "filename": filename,
                "sha256": sha256,
                "score": min(local_score, 100),
                "band": band(min(local_score, 100)),
                "reasons": reasons,
                "vt_summary": None,
                "apk_info": apk_info,
            }

        analysis = await vt_poll_analysis(session, analysis_id, tries=6, delay=10)
        if analysis.get("stats"):
            vt_score, vt_summary = stats_to_score(analysis["stats"])
            score = max(local_score, vt_score)
            reasons.append("VirusTotal yuklangan faylni tahlil qildi")
            return {
                "filename": filename,
                "sha256": sha256,
                "score": min(score, 100),
                "band": band(min(score, 100)),
                "reasons": reasons,
                "vt_summary": vt_summary,
                "apk_info": apk_info,
            }

        reasons.append("VirusTotal tahlili hali tugamadi")
        return {
            "filename": filename,
            "sha256": sha256,
            "score": min(max(local_score, 25), 100),
            "band": band(min(max(local_score, 25), 100)),
            "reasons": reasons,
            "vt_summary": None,
            "apk_info": apk_info,
        }


async def process_file_message(
    message: Message,
    file_id: str,
    filename: str,
    file_size: int | None = None,
    mime_type: str | None = None
):
    tg_file = await bot.get_file(file_id)
    temp_path = DOWNLOAD_DIR / f"{int(time.time())}_{filename}"

    try:
        await bot.download_file(tg_file.file_path, destination=temp_path)
        result = await analyze_saved_file(temp_path, filename, mime_type)

        lines = []
        lines.append("📦 *CyberAI fayl tahlili*")
        lines.append("")
        lines.append(f"• Nomi: `{result['filename']}`")
        lines.append(f"• SHA256: `{result['sha256']}`")
        if file_size:
            lines.append(f"• Hajmi: `{file_size}` bayt")
        lines.append(f"• Risk: *{result['score']}/100* ({result['band']})")

        if result["reasons"]:
            lines.append("")
            lines.append("*Sabablar:*")
            for r in result["reasons"][:6]:
                lines.append(f"• {r}")

        if result["vt_summary"]:
            lines.append("")
            lines.append(f"*VirusTotal:* `{result['vt_summary']}`")

        apk_info = result.get("apk_info")
        if apk_info and apk_info.get("ok"):
            lines.append("")
            lines.append("*APK ichki tahlili:*")
            if apk_info.get("app_name"):
                lines.append(f"• App: `{apk_info['app_name']}`")
            if apk_info.get("package_name"):
                lines.append(f"• Package: `{apk_info['package_name']}`")
            if apk_info.get("min_sdk"):
                lines.append(f"• Min SDK: `{apk_info['min_sdk']}`")
            if apk_info.get("target_sdk"):
                lines.append(f"• Target SDK: `{apk_info['target_sdk']}`")
            lines.append(f"• Permissionlar soni: `{apk_info['permission_count']}`")
            perms = apk_info.get("permissions", [])
            if perms:
                lines.append("• Shubhali permissionlar:")
                for p in perms[:8]:
                    lines.append(f"  - `{p}`")

        lines.append("")
        lines.append("_Eslatma: bu avtomatik xavfsizlik tahlili._")

        if result["score"] >= 70:
            await maybe_delete(message)

        await safe_send(message, "\n".join(lines), parse_mode="Markdown")

    except Exception as e:
        await safe_send(
            message,
            f"⚠️ Faylni tekshirishda xatolik yuz berdi:\n`{str(e)}`",
            parse_mode="Markdown"
        )
    finally:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass


async def handle_text_logic(message: Message):
    text = message.text or ""
    urls = extract_urls(text)

    alerts = []
    reasons = []

    adult_hits = [w for w in ADULT_WORDS if w in text.lower()]
    bad_hits = [w for w in BAD_WORDS if w in text.lower()]
    phishing_hits = [w for w in PHISHING_HINTS if w in text.lower()]

    if adult_hits:
        alerts.append("18+ yoki nomaqbul matn aniqlandi")
        reasons.append(", ".join(adult_hits[:5]))

    if bad_hits:
        alerts.append("haqoratli yoki nomaqbul so‘z aniqlandi")
        reasons.append(", ".join(bad_hits[:5]))

    if phishing_hits and not urls:
        alerts.append("shubhali scam/phishing iboralari aniqlandi")
        reasons.append(", ".join(phishing_hits[:5]))

    url_results = []
    if urls:
        async with aiohttp.ClientSession() as session:
            for u in urls[:2]:
                url_results.append(await analyze_url(session, u))
                await asyncio.sleep(1)

    risky = [x for x in url_results if x["score"] >= 50]
    if risky:
        alerts.append("shubhali yoki fishing havola aniqlandi")

    if not alerts and not urls:
        return

    lines = []
    lines.append("🚨 *CyberAI ogohlantirish*" if risky or adult_hits else "⚠️ *CyberAI natija*")
    lines.append("")

    for a in alerts:
        lines.append(f"• {a}")

    if reasons:
        lines.append("")
        lines.append("*Matn sabablari:*")
        for r in reasons:
            lines.append(f"• {r}")

    if url_results:
        lines.append("")
        lines.append("*Havola tahlili:*")
        for item in url_results:
            lines.append(f"• Domen: `{item['domain'] or 'noma’lum'}`")
            lines.append(f"  Risk: *{item['score']}/100* ({item['band']})")
            if item["reasons"]:
                lines.append(f"  Sabab: {', '.join(item['reasons'][:3])}")
            if item["vt_summary"]:
                lines.append(f"  VT: `{item['vt_summary']}`")

    if risky or adult_hits:
        await maybe_delete(message)

    await safe_send(message, "\n".join(lines), parse_mode="Markdown")


async def handle_caption_logic(message: Message):
    caption = message.caption or ""
    urls = extract_urls(caption)
    if not urls:
        return

    async with aiohttp.ClientSession() as session:
        url_results = []
        for u in urls[:2]:
            url_results.append(await analyze_url(session, u))
            await asyncio.sleep(1)

    lines = []
    lines.append("⚠️ *CyberAI caption tahlili*")
    lines.append("")

    for item in url_results:
        lines.append(f"• Domen: `{item['domain'] or 'noma’lum'}`")
        lines.append(f"  Risk: *{item['score']}/100* ({item['band']})")
        if item["reasons"]:
            lines.append(f"  Sabab: {', '.join(item['reasons'][:3])}")
        if item["vt_summary"]:
            lines.append(f"  VT: `{item['vt_summary']}`")

    await safe_send(message, "\n".join(lines), parse_mode="Markdown")


@dp.message()
async def handle_everything(message: Message):
    try:
        if message.text == "/start":
            await safe_send(
                message,
                "Assalomu alaykum.\n\n"
                "Men CyberAI botiman.\n"
                "Men quyidagilarni tekshiraman:\n"
                "• APK, EXE, ZIP, JAR va boshqa fayllar\n"
                "• video/audio/document ko‘rinishida yuborilgan fayllar\n"
                "• shubhali havolalar\n"
                "• 18+ matn va haqoratli so‘zlar"
            )
            return

        if message.text:
            await handle_text_logic(message)

        if message.caption:
            await handle_caption_logic(message)

        file_id = None
        filename = None
        file_size = None
        mime_type = None

        if message.document:
            file_id = message.document.file_id
            filename = message.document.file_name or "file.bin"
            file_size = message.document.file_size
            mime_type = message.document.mime_type

        elif message.video:
            file_id = message.video.file_id
            filename = message.video.file_name or "video.mp4"
            file_size = message.video.file_size
            mime_type = message.video.mime_type

        elif message.animation:
            file_id = message.animation.file_id
            filename = message.animation.file_name or "animation.mp4"
            file_size = message.animation.file_size
            mime_type = message.animation.mime_type

        elif message.audio:
            file_id = message.audio.file_id
            filename = message.audio.file_name or "audio.bin"
            file_size = message.audio.file_size
            mime_type = message.audio.mime_type

        elif message.voice:
            file_id = message.voice.file_id
            filename = "voice.ogg"
            file_size = message.voice.file_size
            mime_type = message.voice.mime_type

        elif message.photo:
            biggest = message.photo[-1]
            file_id = biggest.file_id
            filename = "photo.jpg"
            file_size = biggest.file_size
            mime_type = "image/jpeg"

        if file_id:
            print("DEBUG FILE:", filename, mime_type, file_size)
            await process_file_message(message, file_id, filename, file_size, mime_type)

    except Exception as e:
        print("DEBUG ERROR:", str(e))
        await safe_send(
            message,
            f"⚠️ Xatolik yuz berdi:\n`{str(e)}`",
            parse_mode="Markdown"
        )


async def main():
    print("CyberAI bot ishga tushdi...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())