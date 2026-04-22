"""APK fayl tahlili — Android permissionlar va dastur ma'lumotlari tekshiruvi."""

from pathlib import Path
from typing import Any

try:
    from androguard.misc import AnalyzeAPK

    _androguard_available = True
except ImportError:
    AnalyzeAPK = None
    _androguard_available = False

from bot.utils.constants import DANGEROUS_PERMISSIONS
from bot.loader import logger


def analyze_apk_permissions(path: Path) -> dict[str, Any]:
    """APK faylning xavfli ruxsatlarini va ichki ma'lumotlarini tahlil qilish.

    Androguard kutubxonasi o'rnatilgan bo'lishi kerak.
    """
    if not _androguard_available:
        return {
            "ok": False,
            "score": 0,
            "permissions": [],
            "reasons": ["androguard o'rnatilmagan — APK tahlili bajarilmadi"],
            "note": "pip install androguard buyrug'ini bajaring",
        }

    try:
        a, d, dx = AnalyzeAPK(str(path))
        all_permissions = a.get_permissions() or []
        score = 0
        found_permissions = []
        reasons = []

        # Xavfli ruxsatlarni tekshirish
        for perm in all_permissions:
            if perm in DANGEROUS_PERMISSIONS:
                score += DANGEROUS_PERMISSIONS[perm]
                found_permissions.append(perm)

        if found_permissions:
            reasons.append(f"{len(found_permissions)} ta shubhali permission topildi")

        # Ilova ma'lumotlari
        package_name = a.get_package() or "noma'lum"
        app_name = a.get_app_name() or "noma'lum"
        min_sdk = a.get_min_sdk_version()
        target_sdk = a.get_target_sdk_version()

        # Activities, services, receivers analizi
        activities = a.get_activities() or []
        services = a.get_services() or []
        receivers = a.get_receivers() or []

        # Xavfli belgilarni qo'shimcha tekshirish
        if len(all_permissions) > 15:
            score += 10
            reasons.append(f"juda ko'p permission so'ralgan ({len(all_permissions)} ta)")

        if len(services) > 8:
            score += 8
            reasons.append(f"ko'p background service topildi ({len(services)} ta)")

        if len(receivers) > 6:
            score += 5
            reasons.append(f"ko'p broadcast receiver topildi ({len(receivers)} ta)")

        # DEX analiz — shubhali API chaqiruvlarni qidirish
        suspicious_apis = []
        try:
            for cls in dx.get_classes():
                cls_name = str(cls.name).lower()
                if any(x in cls_name for x in [
                    "crypto", "cipher", "base64", "dexclassloader",
                    "runtime", "processbuilder", "reflection"
                ]):
                    suspicious_apis.append(str(cls.name))
        except Exception:
            pass

        if suspicious_apis:
            score += 12
            reasons.append("shubhali API chaqiruvlar aniqlandi")

        if score > 0:
            logger.info(
                "📱 APK tahlili: %s — %d ball, %d xavfli permission",
                package_name, score, len(found_permissions),
            )

        return {
            "ok": True,
            "score": min(score, 100),
            "permissions": found_permissions[:15],
            "permission_count": len(all_permissions),
            "package_name": package_name,
            "app_name": app_name,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "activities_count": len(activities),
            "services_count": len(services),
            "receivers_count": len(receivers),
            "suspicious_apis": suspicious_apis[:10],
            "reasons": reasons,
        }
    except Exception as e:
        logger.warning("APK tahlili xatosi: %s", e)
        return {
            "ok": False,
            "score": 0,
            "permissions": [],
            "permission_count": 0,
            "package_name": None,
            "app_name": None,
            "reasons": [f"APK ichki tahlili bajarilmadi: {e}"],
        }
