from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from system_repair import __version__ as VERSION


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="system-repair",
        description="Локальная утилита проверки и восстановления настроек Windows.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="запустить безопасную демонстрацию на синтетических данных",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="каталог манифестов и резервных копий",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--smoke-test", action="store_true", help="проверить запуск интерфейса и выйти (только с --demo)")
    return parser


def _default_backup_dir(*, demo: bool) -> Path:
    if demo:
        return Path.home() / ".local" / "share" / "system-repair-demo" / "backups"
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
        return base / "SystemRepair" / "Backups"
    return Path.home() / ".local" / "share" / "system-repair-demo" / "backups"


def _startup_error(message: str) -> int:
    if sys.stderr is not None:
        print(message, file=sys.stderr)
    elif os.name == "nt":
        import ctypes

        show = ctypes.WinDLL("user32").MessageBoxW
        show.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        show.restype = ctypes.c_int
        show(None, message, "System Repair", 0x10)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.smoke_test and not args.demo:
        return _startup_error("--smoke-test разрешён только вместе с --demo.")

    if not args.demo and sys.platform != "win32":
        return _startup_error(
            "System Repair выполняет системные операции только в Windows. "
            "Запустите `system-repair --demo` для безопасной демонстрации."
        )

    if args.demo:
        from system_repair.demo import DemoPlatform

        platform = DemoPlatform()
    else:
        try:
            from system_repair.windows import WindowsPlatform

            platform = WindowsPlatform()
        except Exception as exc:
            return _startup_error(f"Не удалось инициализировать платформу Windows: {type(exc).__name__}: {exc}")

    try:
        from PySide6.QtWidgets import QApplication

        from system_repair.engine import RepairEngine
        from system_repair.ui import MainWindow

        backup_root = args.backup_dir or _default_backup_dir(demo=args.demo)
        engine = RepairEngine(platform, backup_root)
    except Exception as exc:
        return _startup_error(f"Не удалось запустить System Repair: {type(exc).__name__}: {exc}")

    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setStyle("Fusion")
    app.setApplicationName("System Repair & Remediation Tool")
    app.setApplicationVersion(VERSION)
    window = MainWindow(engine)
    window.show()
    if args.smoke_test:
        from PySide6.QtCore import QTimer

        timer = QTimer(window)
        deadline = time.monotonic() + 10

        def check_started() -> None:
            if not window._busy and (window._scan_result is not None or window._operation_failed):
                timer.stop()
                ok = window._scan_result is not None and not window._operation_failed
                ok = ok and window.demo_banner.isVisible() and window.process_table.rowCount() > 0
                window.close()
                app.exit(0 if ok else 1)
            elif time.monotonic() > deadline:
                timer.stop()
                app.exit(1)

        timer.timeout.connect(check_started)
        timer.start(50)
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
