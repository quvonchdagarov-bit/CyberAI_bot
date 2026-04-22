"""CallbackData factory-lar — inline buttonlar uchun strukturalangan ma'lumot."""

from aiogram.filters.callback_data import CallbackData


class MenuAction(CallbackData, prefix="menu"):
    """Asosiy menyu tugmalari."""
    action: str  # scan, history, stats, settings, help, about


class ScanAction(CallbackData, prefix="scan"):
    """Skanerlash turi tanlash."""
    action: str  # text, url, file, qr


class ResultAction(CallbackData, prefix="res"):
    """Natija sahifasi tugmalari."""
    action: str  # detail, ai, rescan, share
    scan_id: int


class SettingsAction(CallbackData, prefix="set"):
    """Sozlamalar toggle tugmalari."""
    action: str  # auto_delete, notify, detail_mode, back


class HistoryAction(CallbackData, prefix="hist"):
    """Tarix sahifasi tugmalari."""
    action: str  # page, clear, back, view
    page: int = 1
    scan_id: int = 0


class AdminAction(CallbackData, prefix="adm"):
    """Admin panel tugmalari."""
    action: str  # stats, broadcast, back
