from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QColor, QFont, QFontDatabase, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from system_repair import __version__ as VERSION
from system_repair.catalog import BY_ID, REPAIRS
from system_repair.model import Finding, ProcessInfo, RepairResult, ScanResult

_COLOR_TEXT = "#d8dadd"
_COLOR_MUTED = "#a8adb2"
_COLOR_GREEN = "#82c891"
_COLOR_YELLOW = "#e0bd63"
_COLOR_RED = "#e17b75"


class _TaskWorker(QObject):
    log = Signal(str, str)
    outcome = Signal(str, object, str)
    completed = Signal()

    def __init__(
        self,
        operation: str,
        function: Callable[..., object],
        arguments: tuple[Any, ...],
    ):
        super().__init__()
        self._operation = operation
        self._function = function
        self._arguments = arguments

    @Slot()
    def run(self) -> None:
        try:
            result = self._function(*self._arguments, self.log.emit)
            self.outcome.emit(self._operation, result, "")
        except Exception as exc:
            self.outcome.emit(self._operation, None, f"{type(exc).__name__}: {exc}")
        finally:
            self.completed.emit()


class _UiRelay(QObject):
    def __init__(self, window: Any):
        super().__init__(window)
        self._window = window

    @Slot(str, str)
    def append_log(self, level: str, message: str) -> None:
        self._window._append_log(level, message)

    @Slot(str, object, str)
    def handle_outcome(self, operation: str, result: object, error: str) -> None:
        self._window._handle_outcome(operation, result, error)

    @Slot()
    def task_thread_finished(self) -> None:
        self._window._task_thread_finished()


def _write_log_file(path: Path, contents: str, log: Callable[[str, str], None]) -> Path:
    path.write_text(contents, encoding="utf-8", newline="\n")
    log("INFO", f"Журнал сохранён: {path}")
    return path


class MainWindow(QMainWindow):
    """Compact read/repair interface; all engine calls are serialized in a QThread."""

    def __init__(
        self,
        engine: Any,
        *,
        auto_scan: bool = True,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.engine = engine
        self.platform = engine.platform
        self._ui_relay = _UiRelay(self)
        self._is_demo = bool(getattr(self.platform, "is_demo", False))
        self._thread: QThread | None = None
        self._worker: _TaskWorker | None = None
        self._active_operation = ""
        self._operation_failed = False
        self._busy = False
        self._scan_result: ScanResult | None = None
        self._processes: list[ProcessInfo] = []

        try:
            self._is_admin = bool(self.platform.is_admin())
            self._admin_probe_failed = False
        except Exception:
            self._is_admin = False
            self._admin_probe_failed = True

        self.setWindowTitle(f"System Repair & Remediation Tool {VERSION}")
        self.setMinimumSize(960, 620)
        self.resize(1180, 790)
        self._apply_style()
        self._build_ui()
        self._refresh_action_controls()

        if self._is_demo:
            self._append_log("WARN", "ДЕМО: используются синтетические данные; Windows и реальные процессы не изменяются.")
        self._append_log("INFO", "Готово. Нажмите «Проверить» для чтения текущего состояния.")
        if self._admin_probe_failed:
            self._append_log("ERROR", "Не удалось проверить права администратора; изменения отключены.")
        if auto_scan:
            QTimer.singleShot(0, self._start_scan)

    def _apply_style(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setFont(QFont("Segoe UI", 9))
        self.setStyleSheet(
            "QWidget { background: #242628; color: #d8dadd; font-size: 9pt; }"
            "QTabWidget::pane { border: 1px solid #4a4d50; top: -1px; }"
            "QTabBar::tab { background: #303234; border: 1px solid #4a4d50;"
            " padding: 5px 11px; margin-right: 2px; }"
            "QTabBar::tab:selected { background: #3a3d40; color: #ffffff; }"
            "QTabBar::tab:!selected:hover { background: #393c3e; }"
            "QTableWidget { background: #1d1f21; alternate-background-color: #252729;"
            " gridline-color: #3c3f42; selection-background-color: #405367;"
            " selection-color: #ffffff; border: 1px solid #414447; }"
            "QHeaderView::section { background: #303234; color: #d8dadd;"
            " border: 0; border-right: 1px solid #45484b;"
            " border-bottom: 1px solid #45484b; padding: 4px 6px; }"
            "QPushButton { background: #36393b; border: 1px solid #565a5d;"
            " padding: 4px 9px; min-height: 21px; }"
            "QPushButton:hover { background: #414548; }"
            "QPushButton:pressed { background: #292c2e; }"
            "QPushButton:disabled { color: #777c80; background: #2a2c2e;"
            " border-color: #3b3e40; }"
            "QLineEdit, QPlainTextEdit { background: #191b1d; border: 1px solid #45484b;"
            " selection-background-color: #405367; }"
            "QLineEdit { padding: 4px 6px; }"
            "QPlainTextEdit { padding: 4px; }"
            "QLabel#demoBanner { background: #40391f; color: #f0d174;"
            " border: 1px solid #6a5d32; padding: 3px 6px; font-weight: 600; }"
            "QLabel#warningNote { color: #e0bd63; }"
            "QLabel#mutedLabel { color: #a8adb2; }"
            "QStatusBar { background: #202224; border-top: 1px solid #3b3e40; }"
        )

    def _build_ui(self) -> None:
        central = QWidget(self)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 7, 8, 5)
        layout.setSpacing(5)
        self.setCentralWidget(central)

        header = QHBoxLayout()
        title = QLabel("System Repair & Remediation Tool")
        title_font = QFont("Segoe UI", 11)
        title_font.setBold(True)
        title.setFont(title_font)
        self.version_label = QLabel(f"v{VERSION}")
        self.version_label.setObjectName("mutedLabel")
        self.platform_label = QLabel(str(getattr(self.platform, "platform_label", "Windows")))
        self.platform_label.setObjectName("mutedLabel")
        self.platform_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        header.addWidget(title)
        header.addWidget(self.version_label)
        header.addStretch(1)
        header.addWidget(self.platform_label)
        layout.addLayout(header)

        self.demo_banner = QLabel(
            "ДЕМО · синтетические данные · реальные настройки Windows и процессы не изменяются"
        )
        self.demo_banner.setObjectName("demoBanner")
        self.demo_banner.setVisible(self._is_demo)
        layout.addWidget(self.demo_banner)

        self.access_label = QLabel(self._access_text())
        self.access_label.setObjectName("mutedLabel")
        layout.addWidget(self.access_label)

        self.policy_note = QLabel(
            "HKCU относится к профилю текущего токена: UAC с учётными данными другой учётной "
            "записи не исправляет HKCU исходного пользователя. Доменные/MDM-политики изменяйте "
            "только с разрешения их владельца."
        )
        self.policy_note.setObjectName("warningNote")
        self.policy_note.setWordWrap(True)
        self.policy_note.setMaximumHeight(38)
        layout.addWidget(self.policy_note)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(5)
        self.scan_button = QPushButton("Проверить")
        self.apply_button = QPushButton("Исправить выбранное")
        self.backup_button = QPushButton("Создать бэкап")
        self.restore_button = QPushButton("Восстановить бэкап…")
        self.save_logs_button = QPushButton("Сохранить журнал…")
        toolbar.addWidget(self.scan_button)
        toolbar.addWidget(self.apply_button)
        toolbar.addWidget(self.backup_button)
        toolbar.addWidget(self.restore_button)
        toolbar.addStretch(1)
        toolbar.addWidget(self.save_logs_button)
        layout.addLayout(toolbar)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self._build_repairs_tab()
        self._build_findings_tab()
        self._build_services_tab()
        self._build_processes_tab()

        log_header = QHBoxLayout()
        log_title = QLabel("Журнал операций")
        log_title_font = QFont()
        log_title_font.setBold(True)
        log_title.setFont(log_title_font)
        self.log_state_label = QLabel("ожидание")
        self.log_state_label.setObjectName("mutedLabel")
        log_header.addWidget(log_title)
        log_header.addStretch(1)
        log_header.addWidget(self.log_state_label)
        layout.addLayout(log_header)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setUndoRedoEnabled(False)
        self.log_view.setMinimumHeight(145)
        self.log_view.setMaximumBlockCount(10000)
        mono_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        mono_font.setStyleHint(QFont.StyleHint.Monospace)
        mono_font.setPointSize(9)
        self.log_view.setFont(mono_font)
        layout.addWidget(self.log_view)

        self.scan_button.clicked.connect(self._start_scan)
        self.apply_button.clicked.connect(self._confirm_and_apply)
        self.backup_button.clicked.connect(self._confirm_and_backup)
        self.restore_button.clicked.connect(self._choose_restore)
        self.save_logs_button.clicked.connect(self._choose_log_destination)
        self.repair_table.itemChanged.connect(self._repair_item_changed)
        self.process_table.itemSelectionChanged.connect(self._refresh_action_controls)
        self.terminate_process_button.clicked.connect(self._confirm_and_terminate)
        self.process_filter.textChanged.connect(self._render_processes)

    def _access_text(self) -> str:
        if self._is_demo:
            return "Режим: ДЕМО (операции имитируются)"
        if self._admin_probe_failed:
            return "Права: проверить не удалось; изменение системы отключено"
        if self._is_admin:
            return "Права: администратор"
        return "Права: без повышения. Для исправлений перезапустите приложение от имени администратора под тем же пользователем."

    @staticmethod
    def _make_table(headers: tuple[str, ...], name: str) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setObjectName(name)
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setSortingEnabled(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(24)
        table.horizontalHeader().setHighlightSections(False)
        table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        return table

    def _build_repairs_tab(self) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(5, 5, 5, 5)
        page_layout.setSpacing(4)
        note = QLabel(
            "Отметьте конкретные операции. Флажки только формируют план; изменения применяются "
            "после отдельного подтверждения."
        )
        note.setObjectName("mutedLabel")
        page_layout.addWidget(note)
        self.repair_table = self._make_table(
            ("Исправление", "Раздел", "Описание и ограничения", "Состояние"),
            "repairTable",
        )
        self.repair_items: dict[str, QTableWidgetItem] = {}
        for repair in REPAIRS:
            row = self.repair_table.rowCount()
            self.repair_table.insertRow(row)
            title_item = QTableWidgetItem(repair.title)
            title_item.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsUserCheckable
            )
            title_item.setCheckState(Qt.CheckState.Unchecked)
            title_item.setData(Qt.ItemDataRole.UserRole, repair.id)
            title_item.setToolTip(repair.title)
            self.repair_items[repair.id] = title_item
            self.repair_table.setItem(row, 0, title_item)
            self.repair_table.setItem(row, 1, self._item(repair.category))
            self.repair_table.setItem(row, 2, self._item(repair.detail, tooltip=repair.detail))
            state_item = self._item("Не проверено")
            state_item.setForeground(QColor(_COLOR_MUTED))
            self.repair_table.setItem(row, 3, state_item)
        header = self.repair_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.repair_table.setColumnWidth(0, 285)
        self.repair_table.setColumnWidth(1, 98)
        self.repair_table.setColumnWidth(3, 155)
        page_layout.addWidget(self.repair_table, 1)
        self.tabs.addTab(page, "Исправления")

    def _build_findings_tab(self) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(5, 5, 5, 5)
        page_layout.setSpacing(4)
        note = QLabel(
            "Run, RunOnce, Winlogon и IFEO: каждое совпадение — повод для ручной проверки, "
            "не доказательство заражения. Сканирование ничего не удаляет."
        )
        note.setObjectName("mutedLabel")
        page_layout.addWidget(note)
        self.findings_table = self._make_table(
            ("Категория", "Имя", "Расположение", "Значение", "Статус"), "findingsTable"
        )
        self._set_finding_columns(self.findings_table)
        page_layout.addWidget(self.findings_table, 1)
        self.tabs.addTab(page, "Автозагрузка / IFEO")

    def _build_services_tab(self) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(5, 5, 5, 5)
        page_layout.setSpacing(4)
        note = QLabel("Службы показаны для ручной проверки; автоматическое отключение не выполняется.")
        note.setObjectName("mutedLabel")
        page_layout.addWidget(note)
        self.services_table = self._make_table(
            ("Категория", "Имя", "Расположение", "Конфигурация", "Статус"), "servicesTable"
        )
        self._set_finding_columns(self.services_table)
        page_layout.addWidget(self.services_table, 1)
        self.tabs.addTab(page, "Службы")

    def _build_processes_tab(self) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(5, 5, 5, 5)
        page_layout.setSpacing(4)
        controls = QHBoxLayout()
        self.process_filter = QLineEdit()
        self.process_filter.setPlaceholderText("Фильтр по PID, имени, пути или пользователю")
        self.process_filter.setClearButtonEnabled(True)
        self.terminate_process_button = QPushButton("Завершить выбранный процесс…")
        self.terminate_process_button.setToolTip(
            "Завершение только вручную выбранного процесса после подтверждения PID и пути."
        )
        controls.addWidget(self.process_filter, 1)
        controls.addWidget(self.terminate_process_button)
        page_layout.addLayout(controls)
        self.process_note = QLabel(
            "Список не оценивает вредоносность. Выберите ровно один PID и проверьте полный путь."
        )
        self.process_note.setObjectName("mutedLabel")
        page_layout.addWidget(self.process_note)
        self.process_table = self._make_table(
            ("PID", "Имя", "Путь образа", "Пользователь", "Запущен", "Статус"),
            "processTable",
        )
        self.processes_table = self.process_table
        header = self.process_table.horizontalHeader()
        for column in (0, 1, 3, 4, 5):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.process_table.setColumnWidth(0, 75)
        self.process_table.setColumnWidth(1, 165)
        self.process_table.setColumnWidth(3, 150)
        self.process_table.setColumnWidth(4, 150)
        self.process_table.setColumnWidth(5, 120)
        page_layout.addWidget(self.process_table, 1)
        self.tabs.addTab(page, "Процессы")

    @staticmethod
    def _set_finding_columns(table: QTableWidget) -> None:
        header = table.horizontalHeader()
        for column in (0, 1, 3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        table.setColumnWidth(0, 100)
        table.setColumnWidth(1, 170)
        table.setColumnWidth(3, 320)
        table.setColumnWidth(4, 110)

    @staticmethod
    def _item(text: str, *, mono: bool = False, tooltip: str | None = None) -> QTableWidgetItem:
        item = QTableWidgetItem(str(text))
        item.setToolTip(str(text) if tooltip is None else tooltip)
        item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        if mono:
            font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
            font.setStyleHint(QFont.StyleHint.Monospace)
            item.setFont(font)
        return item

    @staticmethod
    def _status_color(status: str) -> QColor:
        text = status.casefold()
        if any(word in text for word in ("ошиб", "сбой", "запрещ", "отказ", "не удалось")):
            return QColor(_COLOR_RED)
        if any(word in text for word in ("норма", "типовое", "успеш", "восстановлен", "исправлен", "готово")):
            return QColor(_COLOR_GREEN)
        if any(word in text for word in ("отлич", "провер", "обнаруж", "предупреж", "небезопас")):
            return QColor(_COLOR_YELLOW)
        return QColor(_COLOR_TEXT)

    @staticmethod
    def _timestamp(value: float) -> str:
        try:
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, TypeError, ValueError):
            return str(value)

    @Slot(str, str)
    def _append_log(self, level: str, message: str) -> None:
        severity = str(level).upper()
        color = {
            "ERROR": _COLOR_RED,
            "CRITICAL": _COLOR_RED,
            "WARN": _COLOR_YELLOW,
            "WARNING": _COLOR_YELLOW,
            "SUCCESS": _COLOR_GREEN,
            "OK": _COLOR_GREEN,
        }.get(severity, _COLOR_TEXT)
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} [{severity}] {message}"
        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        text_format = QTextCharFormat()
        text_format.setForeground(QColor(color))
        cursor.insertText(line + "\n", text_format)
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()
        self.log_state_label.setText(severity or "INFO")
        self.log_state_label.setStyleSheet(f"color: {color};")

    def _selected_repair_ids(self) -> list[str]:
        return [
            repair.id
            for repair in REPAIRS
            if self.repair_items[repair.id].checkState() == Qt.CheckState.Checked
        ]

    def _selected_process(self) -> ProcessInfo | None:
        selected = self.process_table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        row = selected[0].row()
        item = self.process_table.item(row, 0)
        if item is None:
            return None
        process = item.data(Qt.ItemDataRole.UserRole)
        return process if isinstance(process, ProcessInfo) else None

    def _refresh_action_controls(self, *_args: object) -> None:
        mutable = self._is_admin and not self._busy
        self.scan_button.setEnabled(not self._busy)
        self.apply_button.setEnabled(mutable and bool(self._selected_repair_ids()))
        self.backup_button.setEnabled(mutable and bool(self._selected_repair_ids()))
        self.restore_button.setEnabled(mutable)
        self.save_logs_button.setEnabled(not self._busy)
        self.terminate_process_button.setEnabled(mutable and self._selected_process() is not None)
        self.repair_table.setEnabled(not self._busy)
        self.process_filter.setEnabled(not self._busy)

    def _repair_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() == 0:
            self._refresh_action_controls()

    def _render_scan(self, result: ScanResult) -> None:
        self._scan_result = result
        for repair in REPAIRS:
            row = REPAIRS.index(repair)
            state = result.states.get(repair.id)
            item = self._item("Не проверено" if state is None else state.status)
            if state is not None:
                item.setToolTip(f"{state.status}\n{state.detail}")
                item.setForeground(self._status_color(state.status))
            else:
                item.setForeground(QColor(_COLOR_MUTED))
            self.repair_table.setItem(row, 3, item)

        self.findings_table.setRowCount(0)
        for finding in result.findings:
            self._append_finding(self.findings_table, finding)

        self.services_table.setRowCount(0)
        for service in result.services:
            self._append_finding(self.services_table, service)

        self._processes = list(result.processes)
        self._render_processes()
        errors = sum(state.status == "Ошибка" for state in result.states.values())
        errors += sum(finding.status == "Ошибка" for finding in result.findings + result.services)
        self._operation_failed = bool(errors)
        self._append_log(
            "WARN" if errors else "SUCCESS",
            f"Проверка завершена: {len(result.findings)} записей для ручной проверки, "
            f"{len(result.services)} служб, {len(result.processes)} процессов. Ошибок чтения: {errors}.",
        )
        self.statusBar().showMessage("Проверка завершена; обнаруженные записи требуют ручной оценки.", 8000)

    def _append_finding(self, table: QTableWidget, finding: Finding) -> None:
        row = table.rowCount()
        table.insertRow(row)
        location = str(finding.location)
        value = str(finding.value)
        value_is_path = "\\" in value or "/" in value or value.casefold().endswith(".exe")
        entries = (
            self._item(finding.category),
            self._item(finding.name),
            self._item(location, mono=True, tooltip=location),
            self._item(value, mono=value_is_path, tooltip=value),
            self._item(finding.status),
        )
        for column, item in enumerate(entries):
            if column == 4:
                item.setForeground(self._status_color(finding.status))
            table.setItem(row, column, item)

    def _render_processes(self, _text: str = "") -> None:
        if not hasattr(self, "process_table"):
            return
        query = self.process_filter.text().strip().casefold()
        filtered = [
            process
            for process in self._processes
            if not query
            or query
            in " ".join(
                (str(process.pid), process.name, process.path, process.user, process.status)
            ).casefold()
        ]
        self.process_table.setRowCount(0)
        for process in filtered:
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)
            pid_item = self._item(str(process.pid), mono=True)
            pid_item.setData(Qt.ItemDataRole.UserRole, process)
            items = (
                pid_item,
                self._item(process.name),
                self._item(process.path, mono=True, tooltip=process.path),
                self._item(process.user, mono=True, tooltip=process.user),
                self._item(self._timestamp(process.created), mono=True),
                self._item(process.status),
            )
            items[-1].setForeground(self._status_color(process.status))
            for column, item in enumerate(items):
                self.process_table.setItem(row, column, item)
        self._refresh_action_controls()

    def _start_scan(self) -> None:
        if self._busy:
            return
        self.log_state_label.setText("проверка")
        self.log_state_label.setStyleSheet(f"color: {_COLOR_YELLOW};")
        self._start_task("scan", "Проверка", self.engine.scan)

    def _confirm_and_apply(self) -> None:
        ids = self._selected_repair_ids()
        if not ids or not self._authorize_mutation():
            return
        selected = [BY_ID[item] for item in ids]
        lines = ["Будут выполнены выбранные операции:"]
        for repair in selected:
            lines.append(f"- [{repair.category}] {repair.title}")
            lines.append(f"  {repair.detail}")
        lines.extend(
            (
                "",
                "Перед изменениями будет создана и проверена новая резервная копия. "
                "При ошибке резервирования исправление не начнётся.",
            )
        )
        if any(repair.kind in ("winsock", "tcpip") for repair in selected):
            lines.extend(
                (
                    "",
                    "ДОПОЛНИТЕЛЬНОЕ ПРЕДУПРЕЖДЕНИЕ: сброс сети может нарушить связь, "
                    "сбросить статические IP/DNS и повлиять на VPN. RDP-соединение может "
                    "оборваться; не запускайте сброс по RDP. После операции потребуется "
                    "перезагрузка. До сброса обязательны проверенная копия и точка восстановления.",
                )
            )
        if any(repair.reboot for repair in selected) and not any(
            repair.kind in ("winsock", "tcpip") for repair in selected
        ):
            lines.append("После выбранной операции может потребоваться перезагрузка.")
        if not self._confirm("Подтвердите исправление", "\n".join(lines)):
            self._append_log("INFO", "Применение отменено пользователем.")
            return
        self._start_task("apply", "Исправление выбранных пунктов", self.engine.apply, ids)

    def _confirm_and_backup(self) -> None:
        ids = self._selected_repair_ids()
        if not ids or not self._authorize_mutation():
            return
        selected = [BY_ID[item] for item in ids]
        lines = ["Будет создана резервная копия для выбранных пунктов:"]
        lines.extend(f"- [{repair.category}] {repair.title}" for repair in selected)
        lines.extend(
            (
                "",
                "Копия сохраняет исходное состояние; она сама по себе не исправляет настройки.",
                "Для сетевых операций сейчас сохраняется конфигурация без создания точки Windows. "
                "Новая точка восстановления будет обязательна непосредственно перед сбросом.",
            )
        )
        if not self._confirm("Создать бэкап", "\n".join(lines)):
            self._append_log("INFO", "Создание бэкапа отменено пользователем.")
            return
        self._start_task("backup", "Создание бэкапа", self.engine.create_backup, ids)

    def _choose_restore(self) -> None:
        if not self._authorize_mutation():
            return
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Выберите манифест резервной копии",
            str(self.engine.backup_root),
            "Манифесты System Repair (*.json);;Все файлы (*)",
        )
        if not path:
            return
        manifest = Path(path)
        message = (
            "Будет восстановлено состояние из манифеста:\n"
            f"{manifest}\n\n"
            "Не выбирайте файл из неизвестного источника. Движок проверит манифест и "
            "доступность резервирования текущего состояния до записи."
        )
        if not self._confirm("Подтвердите восстановление", message):
            self._append_log("INFO", "Восстановление отменено пользователем.")
            return
        self._start_task("restore", "Восстановление бэкапа", self.engine.restore, manifest)

    def _choose_log_destination(self) -> None:
        if self._busy:
            return
        default_path = Path.home() / f"system-repair-{datetime.now():%Y%m%d-%H%M%S}.log"
        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Сохранить журнал",
            str(default_path),
            "Текстовые журналы (*.log *.txt);;Все файлы (*)",
        )
        if not path:
            return
        destination = Path(path)
        contents = self.log_view.toPlainText()
        self._start_task(
            "save_logs",
            "Сохранение журнала",
            _write_log_file,
            destination,
            contents,
        )

    def _confirm_and_terminate(self) -> None:
        process = self._selected_process()
        if process is None or not self._authorize_mutation():
            return
        message = (
            "Запрошено завершение выбранного процесса:\n"
            f"PID: {process.pid}\n"
            f"Имя: {process.name}\n"
            f"Пользователь: {process.user}\n"
            f"Путь: {process.path}\n"
            f"Время запуска: {self._timestamp(process.created)}\n\n"
            "Несохранённые данные процесса будут потеряны. Эту операцию нельзя отменить бэкапом.\n\n"
            "Интерфейс не определяет вредоносность процесса. Продолжайте только после "
            "ручной проверки пути и назначения. Движок перепроверит идентичность процесса; "
            "при завершении процесса, недоступности или повторном использовании PID "
            "операция должна завершиться ошибкой, а не завершать другой процесс."
        )
        if not self._confirm("Подтвердите завершение процесса", message):
            self._append_log("INFO", f"Завершение PID {process.pid} отменено пользователем.")
            return
        self._start_task("terminate", f"Завершение PID {process.pid}", self.engine.terminate, process)

    def _authorize_mutation(self) -> bool:
        if self._busy:
            return False
        if not self._is_admin:
            self._append_log("ERROR", "Изменение отклонено: требуются права администратора.")
            return False
        return True

    def _confirm(self, title: str, text: str) -> bool:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(text)
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        box.setEscapeButton(QMessageBox.StandardButton.No)
        box.setStyleSheet(
            "QLabel { min-width: 430px; max-width: 690px; }"
            "QPushButton { min-width: 78px; }"
        )
        return box.exec() == QMessageBox.StandardButton.Yes

    def _start_task(self, operation: str, label: str, function: Callable[..., object], *args: Any) -> bool:
        if self._busy:
            return False
        thread = QThread(self)
        worker = _TaskWorker(operation, function, tuple(args))
        worker.moveToThread(thread)
        worker.log.connect(self._ui_relay.append_log, Qt.ConnectionType.QueuedConnection)
        worker.outcome.connect(self._ui_relay.handle_outcome, Qt.ConnectionType.QueuedConnection)
        worker.completed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        thread.started.connect(worker.run)
        thread.finished.connect(self._ui_relay.task_thread_finished, Qt.ConnectionType.QueuedConnection)
        thread.finished.connect(thread.deleteLater)

        self._thread = thread
        self._worker = worker
        self._active_operation = label
        self._operation_failed = False
        self._busy = True
        self.log_state_label.setText("выполняется")
        self.log_state_label.setStyleSheet(f"color: {_COLOR_YELLOW};")
        self._append_log("INFO", f"Начата операция: {label}.")
        self._refresh_action_controls()
        thread.start()
        return True

    @Slot(str, object, str)
    def _handle_outcome(self, operation: str, result: object, error: str) -> None:
        if operation in ("apply", "restore", "terminate"):
            self._invalidate_scan()
        if error:
            self._operation_failed = True
            self._append_log("ERROR", f"{operation}: {error}")
            self.log_state_label.setText("ошибка")
            self.log_state_label.setStyleSheet(f"color: {_COLOR_RED};")
            self.statusBar().showMessage(f"Ошибка: {error}", 12000)
            return
        try:
            if operation == "scan":
                if not isinstance(result, ScanResult):
                    raise TypeError("Сканер вернул неподдерживаемый результат.")
                self._render_scan(result)
            elif operation in ("apply", "restore"):
                self._report_repair_result(operation, result)
            elif operation == "backup":
                self._append_log("SUCCESS", f"Бэкап создан: {result}")
                self.statusBar().showMessage(f"Бэкап создан: {result}", 10000)
            elif operation == "terminate":
                self._append_log("SUCCESS", "Запрошенный процесс завершён.")
                self.statusBar().showMessage("Операция завершена.", 8000)
            elif operation == "save_logs":
                self.statusBar().showMessage(f"Журнал сохранён: {result}", 10000)
        except Exception as exc:
            self._operation_failed = True
            message = f"Ошибка отображения результата: {type(exc).__name__}: {exc}"
            self._append_log("ERROR", message)
            self.log_state_label.setText("ошибка")
            self.log_state_label.setStyleSheet(f"color: {_COLOR_RED};")
            self.statusBar().showMessage(message, 12000)

    def _invalidate_scan(self) -> None:
        self._scan_result = None
        for row in range(self.repair_table.rowCount()):
            item = self._item("Нужно проверить", tooltip="После операции состояние могло измениться. Нажмите «Проверить».")
            item.setForeground(QColor(_COLOR_YELLOW))
            self.repair_table.setItem(row, 3, item)
        self.findings_table.setRowCount(0)
        self.services_table.setRowCount(0)
        self._processes = []
        self._render_processes()
        self._append_log("INFO", "Предыдущий снимок устарел. Нажмите «Проверить», чтобы обновить таблицы.")

    def _report_repair_result(self, operation: str, value: object) -> None:
        if not isinstance(value, RepairResult):
            raise TypeError("Движок вернул неподдерживаемый результат исправления.")
        action = "восстановлено" if operation == "restore" else "выполнено"
        completed = ", ".join(value.completed) or "без изменений"
        self._append_log(
            "SUCCESS",
            f"Операция {action}; резервная копия: {value.backup}; пункты: {completed}; "
            f"перезагрузка: {'да' if value.reboot else 'нет'}.",
        )
        if value.reboot:
            self._append_log("WARN", "Для завершения сетевого сброса требуется перезагрузка Windows.")
        self._append_log("INFO", "Состояние не пересканировано; выполните «Проверить» повторно.")
        self.statusBar().showMessage("Операция завершена; рекомендуется повторная проверка.", 10000)

    @Slot()
    def _task_thread_finished(self) -> None:
        label = self._active_operation
        self._thread = None
        self._worker = None
        self._active_operation = ""
        self._busy = False
        if not self._operation_failed:
            self.log_state_label.setText("готово")
            self.log_state_label.setStyleSheet(f"color: {_COLOR_GREEN};")
            if label:
                self.statusBar().showMessage(f"Завершено: {label}.", 5000)
        self._refresh_action_controls()

    def closeEvent(self, event: Any) -> None:
        if self._busy:
            self.statusBar().showMessage(
                f"Операция «{self._active_operation}» выполняется; закрытие запрещено до её завершения."
            )
            self._append_log("WARN", "Закрытие отклонено: фоновая операция ещё выполняется.")
            event.ignore()
            return
        super().closeEvent(event)
