"""Inline keyboard builder — chiroyli inline tugmalar."""

import math

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from bot.keyboards.callback_data import (
    AdminAction,
    HistoryAction,
    MenuAction,
    ResultAction,
    ScanAction,
    SettingsAction,
)


def get_main_menu_inline() -> InlineKeyboardMarkup:
    """Asosiy menyu inline keyboard — /start uchun."""
    builder = InlineKeyboardBuilder()

    builder.row(
        InlineKeyboardButton(
            text="🔍 Fayl tekshirish",
            callback_data=ScanAction(action="file").pack(),
        ),
        InlineKeyboardButton(
            text="🔗 URL tekshirish",
            callback_data=ScanAction(action="url").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="📝 Matn tahlili",
            callback_data=ScanAction(action="text").pack(),
        ),
        InlineKeyboardButton(
            text="📷 QR skanerlash",
            callback_data=ScanAction(action="qr").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="📊 Statistika",
            callback_data=MenuAction(action="stats").pack(),
        ),
        InlineKeyboardButton(
            text="📋 Tarix",
            callback_data=MenuAction(action="history").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="⚙️ Sozlamalar",
            callback_data=MenuAction(action="settings").pack(),
        ),
        InlineKeyboardButton(
            text="ℹ️ Bot haqida",
            callback_data=MenuAction(action="about").pack(),
        ),
    )

    return builder.as_markup()


def get_result_keyboard(scan_id: int, score: int) -> InlineKeyboardMarkup:
    """Natija sahifasi inline keyboard."""
    builder = InlineKeyboardBuilder()

    builder.row(
        InlineKeyboardButton(
            text="📋 Batafsil hisobot",
            callback_data=ResultAction(action="detail", scan_id=scan_id).pack(),
        ),
    )

    if score >= 40:
        builder.row(
            InlineKeyboardButton(
                text="🤖 AI Tahlil",
                callback_data=ResultAction(action="ai", scan_id=scan_id).pack(),
            ),
        )

    builder.row(
        InlineKeyboardButton(
            text="📤 Ulashish",
            callback_data=ResultAction(action="share", scan_id=scan_id).pack(),
        ),
    )

    return builder.as_markup()


def get_detail_back_keyboard(scan_id: int) -> InlineKeyboardMarkup:
    """Batafsil hisobotdan ortga qaytish tugmasi."""
    builder = InlineKeyboardBuilder()

    builder.row(
        InlineKeyboardButton(
            text="🤖 AI Tahlil",
            callback_data=ResultAction(action="ai", scan_id=scan_id).pack(),
        ),
        InlineKeyboardButton(
            text="📤 Ulashish",
            callback_data=ResultAction(action="share", scan_id=scan_id).pack(),
        ),
    )

    return builder.as_markup()


def get_ai_back_keyboard() -> InlineKeyboardMarkup:
    """AI hisobotdan ortga qaytish."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text="◀️ Asosiy menyu",
            callback_data=MenuAction(action="main").pack(),
        ),
    )
    return builder.as_markup()


def get_scan_type_keyboard() -> InlineKeyboardMarkup:
    """Skanerlash turi tanlash keyboard."""
    builder = InlineKeyboardBuilder()

    builder.row(
        InlineKeyboardButton(
            text="📄 Fayl yuboring",
            callback_data=ScanAction(action="file").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="🔗 URL yozing",
            callback_data=ScanAction(action="url").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="📝 Matn yozing",
            callback_data=ScanAction(action="text").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="📷 QR rasm yuboring",
            callback_data=ScanAction(action="qr").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="◀️ Ortga",
            callback_data=MenuAction(action="main").pack(),
        ),
    )

    return builder.as_markup()


def get_settings_keyboard(
    auto_delete: bool, notify: bool, detail_mode: bool
) -> InlineKeyboardMarkup:
    """Sozlamalar sahifasi keyboard."""
    builder = InlineKeyboardBuilder()

    ad_icon = "✅" if auto_delete else "❌"
    n_icon = "✅" if notify else "❌"
    dm_icon = "✅" if detail_mode else "❌"

    builder.row(
        InlineKeyboardButton(
            text=f"🗑 Auto-o'chirish: {ad_icon}",
            callback_data=SettingsAction(action="auto_delete").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text=f"🔔 Bildirishnoma: {n_icon}",
            callback_data=SettingsAction(action="notify").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text=f"📊 Batafsil rejim: {dm_icon}",
            callback_data=SettingsAction(action="detail_mode").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="◀️ Asosiy menyu",
            callback_data=SettingsAction(action="back").pack(),
        ),
    )

    return builder.as_markup()


def get_stats_keyboard() -> InlineKeyboardMarkup:
    """Statistika sahifasi keyboard."""
    builder = InlineKeyboardBuilder()

    builder.row(
        InlineKeyboardButton(
            text="📋 Tarixni ko'rish",
            callback_data=MenuAction(action="history").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="◀️ Asosiy menyu",
            callback_data=MenuAction(action="main").pack(),
        ),
    )

    return builder.as_markup()


def get_history_keyboard(
    scans: list[dict],
    current_page: int,
    total_count: int,
    per_page: int = 5,
) -> InlineKeyboardMarkup:
    """Tarix sahifasi keyboard (pagination bilan)."""
    builder = InlineKeyboardBuilder()
    total_pages = max(1, math.ceil(total_count / per_page))

    # Har bir scan uchun tugma
    for scan in scans:
        scan_id = scan["id"]
        score = scan.get("score", 0)
        target = scan.get("target", "???")[:25]
        scan_type = scan.get("scan_type", "?")

        # Risk rangini emoji bilan ko'rsatish
        if score >= 75:
            icon = "🔴"
        elif score >= 40:
            icon = "🟡"
        else:
            icon = "🟢"

        type_icons = {"file": "📄", "link": "🔗", "text": "📝"}
        t_icon = type_icons.get(scan_type, "📎")

        builder.row(
            InlineKeyboardButton(
                text=f"{icon} {t_icon} {target} — {score}/100",
                callback_data=HistoryAction(
                    action="view", scan_id=scan_id
                ).pack(),
            ),
        )

    # Pagination
    nav_buttons = []
    if current_page > 1:
        nav_buttons.append(
            InlineKeyboardButton(
                text="◀️ Oldingi",
                callback_data=HistoryAction(
                    action="page", page=current_page - 1
                ).pack(),
            )
        )

    nav_buttons.append(
        InlineKeyboardButton(
            text=f"📄 {current_page}/{total_pages}",
            callback_data="noop",
        )
    )

    if current_page < total_pages:
        nav_buttons.append(
            InlineKeyboardButton(
                text="Keyingi ▶️",
                callback_data=HistoryAction(
                    action="page", page=current_page + 1
                ).pack(),
            )
        )

    if nav_buttons:
        builder.row(*nav_buttons)

    # Clear va back
    builder.row(
        InlineKeyboardButton(
            text="🗑 Tarixni tozalash",
            callback_data=HistoryAction(action="clear").pack(),
        ),
        InlineKeyboardButton(
            text="◀️ Ortga",
            callback_data=MenuAction(action="main").pack(),
        ),
    )

    return builder.as_markup()


def get_back_to_menu_keyboard() -> InlineKeyboardMarkup:
    """Faqat ortga tugmasi."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text="◀️ Asosiy menyu",
            callback_data=MenuAction(action="main").pack(),
        ),
    )
    return builder.as_markup()


def get_admin_keyboard() -> InlineKeyboardMarkup:
    """Admin panel keyboard."""
    builder = InlineKeyboardBuilder()

    builder.row(
        InlineKeyboardButton(
            text="📊 Global statistika",
            callback_data=AdminAction(action="stats").pack(),
        ),
    )
    builder.row(
        InlineKeyboardButton(
            text="◀️ Ortga",
            callback_data=AdminAction(action="back").pack(),
        ),
    )

    return builder.as_markup()
