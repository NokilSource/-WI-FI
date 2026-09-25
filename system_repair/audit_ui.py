from __future__ import annotations

import os
import re
import tempfile
from dataclasses import replace
from datetime import datetime
from typing import Any

from PyQt6.QtCore import QSignalBlocker, Qt, QTimer
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from system_repair.audit_model import (
    FileEntry,
    FileScan,
    HiveMount,
    RegistryListing,
    ServiceInfo,
    StartupEntry,
    TaskInfo,
)
from system_repair.model import ProcessInfo, RegistryAddress, RegistryValue

_RED = "#e17b75"
_AUDIT_READ_OPERATIONS = frozenset(
    {
        "audit_process_scan",
        "audit_startup_scan",
        "audit_services_scan",
        "audit_tasks_scan",
        "audit_registry_scan",
        "audit_files_scan",
        "audit_duplicates",
    }
)

_REGISTRY_TYPES = (
    ("Строка (REG_SZ)", 1),
    ("Расширяемая строка (REG_EXPAND_SZ)", 2),
    ("Двоичные данные (REG_BINARY)", 3),
    ("DWORD (32 бит)", 4),
    ("Многострочная строка (REG_MULTI_SZ)", 7),
    ("QWORD (64 бит)", 11),
)
_REGISTRY_TYPE_NAMES = {value: label for label, value in _REGISTRY_TYPES}


class AuditUiMixin:
    """Composable audit pages for a host that owns the worker and authorization APIs."""

    def _build_audit_ui(self) -> None:
        self._audit_processes: list[ProcessInfo] | None = None
        self._audit_startup_entries: list[StartupEntry] = []
        self._audit_services: list[ServiceInfo] = []
        self._audit_tasks: list[TaskInfo] = []
        self._audit_task_folder = ""
        self._audit_task_change: tuple[TaskInfo, str] | None = None
        self._audit_registry_listing: RegistryListing | None = None
        self._audit_mounts: dict[str, HiveMount] = {}
        self._audit_unmounting: HiveMount | None = None
        self._audit_file_scan: FileScan | None = None
        self._audit_file_scan_kind = "scan"
        self._audit_deferred_tree: tuple[ProcessInfo, ...] | None = None
        self._audit_worker_read_errors: list[str] = []

        self._audit_deferred_timer = QTimer(self)
        self._audit_deferred_timer.setSingleShot(True)
        self._audit_deferred_timer.timeout.connect(self._start_deferred_tree_kill)

        self._extend_process_page()
        self._extend_service_page()
        self._build_startup_audit_page()
        self._build_service_audit_page()
        self._build_registry_page()
        self._build_scheduler_page()
        self._build_files_page()
        self._build_system_page()
        if getattr(self, "_is_demo", False):
            self.registry_mount_button.setEnabled(False)
            self.registry_mount_button.setToolTip("Монтирование реальных кустов отключено в демо-режиме.")
            self.registry_note.setText(
                "ДЕМО: монтирование offline-корней отключено; реальные кусты не имитируются. "
                "В обычном режиме открывается только резервная рабочая копия куста."
            )
        self._refresh_audit_controls()

    @staticmethod
    def _audit_cell(text: object, *, tooltip: str | None = None, mono: bool = False) -> QTableWidgetItem:
        value = str(text)
        item = QTableWidgetItem(value)
        item.setToolTip(value if tooltip is None else str(tooltip))
        item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        if mono:
            font = item.font()
            font.setFamily("Consolas")
            item.setFont(font)
        return item

    @staticmethod
    def _audit_table(
        headers: tuple[str, ...],
        name: str,
        *,
        multi_select: bool = False,
    ) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setObjectName(name)
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
            if multi_select
            else QAbstractItemView.SelectionMode.SingleSelection
        )
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setSortingEnabled(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(24)
        table.horizontalHeader().setHighlightSections(False)
        table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        return table

    @staticmethod
    def _audit_page(tabs: Any, title: str, note_text: str) -> tuple[QWidget, QVBoxLayout, QLabel]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(4)
        note = QLabel(note_text, page)
        note.setObjectName("mutedLabel")
        note.setTextFormat(Qt.TextFormat.PlainText)
        note.setWordWrap(True)
        layout.addWidget(note)
        tabs.addTab(page, title)
        return page, layout, note

    def _extend_process_page(self) -> None:
        page = self.process_table.parentWidget()
        layout = page.layout() if page is not None else None
        if layout is None:
            return

        wanted = (
            "Critical",
            "Company",
            "Command line",
            "Signature",
            "Parent PID",
            "Hidden",
            "Trusted",
            "Same path",
        )
        existing = {
            self.process_table.horizontalHeaderItem(index).text().casefold(): index
            for index in range(self.process_table.columnCount())
            if self.process_table.horizontalHeaderItem(index) is not None
        }
        for label in wanted:
            column = existing.get(label.casefold())
            if column is None:
                column = self.process_table.columnCount()
                self.process_table.setColumnCount(column + 1)
                self.process_table.setHorizontalHeaderItem(column, QTableWidgetItem(label))
                existing[label.casefold()] = column
            else:
                self.process_table.setHorizontalHeaderItem(column, QTableWidgetItem(label))
        self._audit_process_columns = existing
        header = self.process_table.horizontalHeader()
        for column in range(self.process_table.columnCount()):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        for label, width in (
            ("pid", 75),
            ("имя", 165),
            ("путь образа", 360),
            ("пользователь", 150),
            ("запущен", 150),
            ("статус", 120),
            ("Critical", 78),
            ("Company", 190),
            ("Command line", 380),
            ("Signature", 120),
            ("Parent PID", 90),
            ("Hidden", 75),
            ("Trusted", 75),
            ("Same path", 100),
        ):
            column = existing.get(label.casefold())
            if column is not None:
                self.process_table.setColumnWidth(column, width)
        legacy_kill = getattr(self, "terminate_process_button", None)
        if isinstance(legacy_kill, QPushButton):
            layout.removeWidget(legacy_kill)
            legacy_kill.hide()
        self.process_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self._show_process_context_menu)
        self.process_table.itemSelectionChanged.connect(self._refresh_audit_controls)

        self.hide_trusted_processes = QCheckBox("Скрыть доверенные системные")
        self.hide_trusted_processes.setChecked(True)
        self.suspicious_processes_only = QCheckBox("Подозрительные")
        self.signed_processes_only = QCheckBox("С цифровой подписью")
        self.group_duplicate_processes = QCheckBox("Группировать одинаковые пути")
        self.group_duplicate_processes.setChecked(True)
        filters = QHBoxLayout()
        filters.addWidget(self.hide_trusted_processes)
        filters.addWidget(self.suspicious_processes_only)
        filters.addWidget(self.signed_processes_only)
        filters.addWidget(self.group_duplicate_processes)
        filters.addStretch(1)

        self.audit_process_scan_button = QPushButton("Обновить аудит")
        self.audit_process_kill_button = QPushButton("Завершить…")
        self.audit_process_tree_button = QPushButton("Завершить дерево…")
        self.audit_process_suspend_button = QPushButton("Приостановить…")
        self.audit_process_resume_button = QPushButton("Возобновить…")
        self.audit_process_open_button = QPushButton("Открыть расположение")
        self.audit_process_duplicates_button = QPushButton("Искать дубликаты…")
        actions = QHBoxLayout()
        for button in (
            self.audit_process_scan_button,
            self.audit_process_kill_button,
            self.audit_process_tree_button,
            self.audit_process_suspend_button,
            self.audit_process_resume_button,
            self.audit_process_open_button,
            self.audit_process_duplicates_button,
        ):
            actions.addWidget(button)
        actions.addStretch(1)
        layout.insertLayout(1, filters)
        layout.insertLayout(2, actions)

        self.hide_trusted_processes.toggled.connect(self._render_audit_processes)
        self.suspicious_processes_only.toggled.connect(self._render_audit_processes)
        self.signed_processes_only.toggled.connect(self._render_audit_processes)
        self.group_duplicate_processes.toggled.connect(self._render_audit_processes)
        if hasattr(self, "process_filter"):
            self.process_filter.textChanged.connect(self._render_audit_processes)
        self.audit_process_scan_button.clicked.connect(self._scan_audit_processes)
        self.audit_process_kill_button.clicked.connect(lambda: self._audit_process_action("kill"))
        self.audit_process_tree_button.clicked.connect(self._plan_process_tree_kill)
        self.audit_process_suspend_button.clicked.connect(lambda: self._audit_process_action("suspend"))
        self.audit_process_resume_button.clicked.connect(lambda: self._audit_process_action("resume"))
        self.audit_process_open_button.clicked.connect(self._open_selected_process)
        self.audit_process_duplicates_button.clicked.connect(self._find_process_duplicates)

        note = getattr(self, "process_note", None)
        if isinstance(note, QLabel):
            note.setText(
                "Проверяйте полный путь и командную строку вручную. Company Name не доказывает "
                "доверие; цифровая подпись отображается только по результату проверки. "
                "Флаг Critical доступен только для чтения."
            )
            note.setTextFormat(Qt.TextFormat.PlainText)
            note.setWordWrap(True)

    def _extend_service_page(self) -> None:
        self.service_audit_button = QPushButton("Обновить аудит служб")
        self.service_suspicious_only = QCheckBox("Только подозрительные")
        page = self.services_table.parentWidget()
        layout = page.layout() if page is not None else None
        if layout is not None:
            controls = QHBoxLayout()
            controls.addWidget(self.service_audit_button)
            controls.addWidget(self.service_suspicious_only)
            controls.addStretch(1)
            layout.insertLayout(1, controls)
            note = layout.itemAt(0).widget()
            if isinstance(note, QLabel):
                note.setText(
                    "Сводка первичной проверки. Полный управляемый перечень служб находится на "
                    "вкладке «Аудит служб»; подозрительность не является доказательством заражения."
                )
                note.setTextFormat(Qt.TextFormat.PlainText)
                note.setWordWrap(True)
        self.service_audit_button.clicked.connect(self._scan_audit_services)
        self.service_suspicious_only.toggled.connect(self._render_audit_services)

    def _build_startup_audit_page(self) -> None:
        page, layout, self.startup_note = self._audit_page(
            self.tabs,
            "Аудит автозагрузки",
            "Run/RunOnce, Winlogon, BootShell и физические Startup-папки. Сканирование только "
            "читает данные; удаление файловых записей выполняется движком через карантин.",
        )
        controls = QHBoxLayout()
        self.startup_scan_button = QPushButton("Сканировать")
        self.startup_edit_button = QPushButton("Изменить значение…")
        self.startup_remove_button = QPushButton("Удалить / карантин…")
        self.startup_registry_button = QPushButton("Открыть ключ в Regedit")
        self.startup_location_button = QPushButton("Открыть расположение")
        for button in (
            self.startup_scan_button,
            self.startup_edit_button,
            self.startup_remove_button,
            self.startup_registry_button,
            self.startup_location_button,
        ):
            controls.addWidget(button)
        controls.addStretch(1)
        layout.addLayout(controls)
        self.startup_table = self._audit_table(
            ("Категория", "Имя", "Расположение", "Команда", "Статус"), "auditStartupTable"
        )
        self._set_audit_columns(self.startup_table, (110, 190, 290, 430, 120))
        layout.addWidget(self.startup_table, 1)
        self.startup_table.itemSelectionChanged.connect(self._refresh_audit_controls)
        self.startup_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.startup_table.customContextMenuRequested.connect(self._show_startup_context_menu)
        self.startup_scan_button.clicked.connect(self._scan_startup)
        self.startup_edit_button.clicked.connect(self._edit_selected_startup)
        self.startup_remove_button.clicked.connect(self._remove_selected_startup)
        self.startup_registry_button.clicked.connect(self._open_selected_startup_registry)
        self.startup_location_button.clicked.connect(self._open_selected_startup_location)

    def _build_service_audit_page(self) -> None:
        _page, layout, self.service_audit_note = self._audit_page(
            self.tabs,
            "Аудит служб",
            "Отображаются имя службы, PID, режим запуска, состояние, описание, команда и "
            "результат подписи. Отсутствие описания или подписи — повод проверить источник, "
            "а не автоматический вердикт.",
        )
        controls = QHBoxLayout()
        self.service_scan_button = QPushButton("Сканировать")
        self.service_start_button = QPushButton("Запустить…")
        self.service_stop_button = QPushButton("Остановить…")
        self.service_start_type_button = QPushButton("Режим запуска…")
        self.service_delete_button = QPushButton("Удалить службу…")
        self.service_open_button = QPushButton("Открыть расположение")
        for button in (
            self.service_scan_button,
            self.service_start_button,
            self.service_stop_button,
            self.service_start_type_button,
            self.service_delete_button,
            self.service_open_button,
        ):
            controls.addWidget(button)
        controls.addStretch(1)
        layout.addLayout(controls)
        self.audit_services_table = self._audit_table(
            (
                "Системное имя",
                "Отображаемое имя",
                "PID",
                "Запуск",
                "Состояние",
                "Описание",
                "Команда",
                "Подпись",
                "Подозрительная",
            ),
            "auditServicesTable",
        )
        self._set_audit_columns(self.audit_services_table, (145, 190, 65, 105, 105, 230, 390, 115, 115))
        layout.addWidget(self.audit_services_table, 1)
        self.audit_services_table.itemSelectionChanged.connect(self._refresh_audit_controls)
        self.audit_services_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.audit_services_table.customContextMenuRequested.connect(self._show_service_context_menu)
        self.service_scan_button.clicked.connect(self._scan_audit_services)
        self.service_start_button.clicked.connect(lambda: self._change_selected_service("start"))
        self.service_stop_button.clicked.connect(lambda: self._change_selected_service("stop"))
        self.service_start_type_button.clicked.connect(self._choose_service_start_type)
        self.service_delete_button.clicked.connect(self._delete_selected_service)
        self.service_open_button.clicked.connect(self._open_selected_service_location)

    def _build_registry_page(self) -> None:
        _page, layout, self.registry_note = self._audit_page(
            self.tabs,
            "Реестр",
            "Изменения разрешены только после отдельного подтверждения и авторизации. Offline "
            "кусты открываются как рабочая копия с сохранением пути и резервной копии; это не "
            "обещание доступа к WinRE или живому системному кусту.",
        )
        controls = QHBoxLayout()
        self.registry_hive = QComboBox()
        self.registry_hive.addItem("HKCU", "HKCU")
        self.registry_hive.addItem("HKLM", "HKLM")
        self.registry_key = QLineEdit()
        self.registry_key.setPlaceholderText("Путь ключа, например Software\\Microsoft")
        self.registry_view = QComboBox()
        self.registry_view.addItem("64-bit", 64)
        self.registry_view.addItem("32-bit", 32)
        self.registry_up_button = QPushButton("↑")
        self.registry_browse_button = QPushButton("Открыть ключ")
        self.registry_mount_button = QPushButton("Подключить offline hive…")
        self.registry_unmount_button = QPushButton("Выгрузить рабочую копию…")
        self.registry_restore_button = QPushButton("Восстановить action.json…")
        for widget in (
            self.registry_hive,
            self.registry_key,
            self.registry_view,
            self.registry_up_button,
            self.registry_browse_button,
            self.registry_mount_button,
            self.registry_unmount_button,
            self.registry_restore_button,
        ):
            controls.addWidget(widget)
        layout.addLayout(controls)
        self.registry_current_label = QLabel("Ключ не загружен")
        self.registry_current_label.setObjectName("mutedLabel")
        self.registry_current_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.registry_current_label)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.registry_subkeys_table = self._audit_table(("Подразделы",), "registrySubkeysTable")
        self.registry_values_table = self._audit_table(
            ("Имя значения", "Тип", "Данные"), "registryValuesTable"
        )
        self._set_audit_columns(self.registry_values_table, (190, 210, 530))
        split.addWidget(self.registry_subkeys_table)
        split.addWidget(self.registry_values_table)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)

        edit_controls = QHBoxLayout()
        self.registry_add_value_button = QPushButton("Создать значение…")
        self.registry_edit_value_button = QPushButton("Изменить…")
        self.registry_delete_value_button = QPushButton("Удалить значение…")
        self.registry_open_button = QPushButton("Открыть ключ в Regedit")
        for button in (
            self.registry_add_value_button,
            self.registry_edit_value_button,
            self.registry_delete_value_button,
            self.registry_open_button,
        ):
            edit_controls.addWidget(button)
        edit_controls.addStretch(1)
        layout.addLayout(edit_controls)

        self.registry_subkeys_table.itemDoubleClicked.connect(self._enter_registry_subkey)
        self.registry_values_table.itemSelectionChanged.connect(self._refresh_audit_controls)
        self.registry_hive.currentIndexChanged.connect(self._registry_hive_changed)
        self.registry_view.currentIndexChanged.connect(self._registry_key_edited)
        self.registry_key.textEdited.connect(self._registry_key_edited)
        self.registry_subkeys_table.itemSelectionChanged.connect(self._refresh_audit_controls)
        self.registry_browse_button.clicked.connect(self._browse_registry)
        self.registry_key.returnPressed.connect(self._browse_registry)
        self.registry_up_button.clicked.connect(self._registry_parent_key)
        self.registry_mount_button.clicked.connect(self._choose_hive_to_mount)
        self.registry_unmount_button.clicked.connect(self._unmount_selected_hive)
        self.registry_restore_button.clicked.connect(self._choose_registry_restore)
        self.registry_add_value_button.clicked.connect(self._create_registry_value)
        self.registry_edit_value_button.clicked.connect(self._edit_registry_value)
        self.registry_delete_value_button.clicked.connect(self._delete_registry_value)
        self.registry_open_button.clicked.connect(self._open_registry_key)

    def _build_scheduler_page(self) -> None:
        _page, layout, self.scheduler_note = self._audit_page(
            self.tabs,
            "Планировщик",
            "Дерево папок строится по найденным задачам. Переключение флажка включения "
            "всегда требует подтверждения; новое состояние отображается только после ответа "
            "движка. Удаление задачи не запускается автоматически.",
        )
        controls = QHBoxLayout()
        self.task_scan_button = QPushButton("Сканировать задачи")
        self.task_delete_button = QPushButton("Удалить выбранную…")
        self.task_details_button = QPushButton("Подробности / XML")
        controls.addWidget(self.task_scan_button)
        controls.addWidget(self.task_delete_button)
        controls.addWidget(self.task_details_button)
        controls.addStretch(1)
        layout.addLayout(controls)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.task_tree = QTreeWidget()
        self.task_tree.setObjectName("auditTaskTree")
        self.task_tree.setHeaderHidden(True)
        self.task_table = self._audit_table(
            ("Имя", "Папка", "Включена", "Создана", "Следующий запуск", "Автор", "Описание", "Команда"),
            "auditTaskTable",
        )
        self.task_table.setColumnWidth(0, 190)
        self.task_table.setColumnWidth(1, 190)
        self.task_table.setColumnWidth(2, 85)
        self.task_table.setColumnWidth(3, 145)
        self.task_table.setColumnWidth(4, 145)
        self.task_table.setColumnWidth(5, 150)
        self.task_table.setColumnWidth(6, 260)
        self.task_table.setColumnWidth(7, 370)
        split.addWidget(self.task_tree)
        split.addWidget(self.task_table)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 4)
        layout.addWidget(split, 1)
        self.task_scan_button.clicked.connect(self._scan_tasks)
        self.task_delete_button.clicked.connect(self._delete_selected_task)
        self.task_details_button.clicked.connect(self._show_selected_task_details)
        self.task_tree.currentItemChanged.connect(lambda *_: self._render_audit_tasks())
        self.task_table.itemChanged.connect(self._task_enabled_changed)
        self.task_table.itemSelectionChanged.connect(self._refresh_audit_controls)
        self.task_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.task_table.customContextMenuRequested.connect(self._show_task_context_menu)

    def _build_files_page(self) -> None:
        _page, layout, self.files_note = self._audit_page(
            self.tabs,
            "Файлы",
            "Выберите корневую папку явно. Интервал в минутах равен нулю — без временного "
            "ограничения (движок всё равно применяет лимиты). Пакетные действия относятся "
            "только к выделенным строкам; удаление с обходом блокировок не предоставляется.",
        )
        controls = QHBoxLayout()
        self.files_root = QLineEdit()
        self.files_root.setPlaceholderText("Выберите корневую папку для сканирования")
        self.files_choose_root_button = QPushButton("Выбрать папку…")
        self.files_minutes = QSpinBox()
        self.files_minutes.setRange(0, 525600)
        self.files_minutes.setValue(60)
        self.files_minutes.setToolTip("0 — без ограничения по времени")
        self.files_scan_button = QPushButton("Сканировать")
        controls.addWidget(self.files_root, 1)
        controls.addWidget(self.files_choose_root_button)
        controls.addWidget(QLabel("Минут:"))
        controls.addWidget(self.files_minutes)
        controls.addWidget(self.files_scan_button)
        layout.addLayout(controls)

        actions = QHBoxLayout()
        self.files_copy_button = QPushButton("Копировать выбранные…")
        self.files_quarantine_button = QPushButton("В карантин…")
        self.files_restore_quarantine_button = QPushButton("Восстановить из карантина…")
        self.files_open_button = QPushButton("Открыть расположение")
        for button in (
            self.files_copy_button,
            self.files_quarantine_button,
            self.files_restore_quarantine_button,
            self.files_open_button,
        ):
            actions.addWidget(button)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.files_status = QLabel("Сканирование ещё не выполнялось")
        self.files_status.setObjectName("mutedLabel")
        self.files_status.setTextFormat(Qt.TextFormat.PlainText)
        self.files_status.setWordWrap(True)
        layout.addWidget(self.files_status)
        self.files_table = self._audit_table(
            ("Путь", "Размер", "Изменён", "Создан", "Атрибут"),
            "auditFilesTable",
            multi_select=True,
        )
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._set_audit_columns(self.files_table, (620, 100, 165, 165, 90))
        layout.addWidget(self.files_table, 1)
        self.files_table.itemSelectionChanged.connect(self._refresh_audit_controls)
        self.files_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(self._show_file_context_menu)
        self.files_root.textChanged.connect(self._refresh_audit_controls)
        self.files_choose_root_button.clicked.connect(self._choose_files_root)
        self.files_scan_button.clicked.connect(self._scan_files)
        self.files_copy_button.clicked.connect(lambda: self._file_action("copy"))
        self.files_quarantine_button.clicked.connect(lambda: self._file_action("quarantine"))
        self.files_restore_quarantine_button.clicked.connect(self._restore_quarantine)
        self.files_open_button.clicked.connect(self._open_selected_file_location)

    def _build_system_page(self) -> None:
        _page, layout, self.system_note = self._audit_page(
            self.tabs,
            "Система",
            "Потенциально disruptive действия показывают последствия и требуют явного "
            "подтверждения. Сканирование SFC и запуск штатных средств выполняются через "
            "AuditEngine, не напрямую из интерфейса.",
        )
        rows = (
            ("sfc", "Запустить SFC /scannow…"),
            ("diskmgmt", "Управление дисками"),
            ("recovery", "Перезагрузка в WinRE…"),
            ("safe", "Параметры запуска / Safe Mode…"),
            ("uefi", "Перезагрузка в UEFI / BIOS…"),
            ("cancel_restart", "Отменить запланированную перезагрузку…"),
            ("appearance", "Настройки темы Windows…"),
        )
        self.system_action_buttons: dict[str, QPushButton] = {}
        for action, title in rows:
            button = QPushButton(title)
            button.setMinimumHeight(34)
            button.clicked.connect(lambda _checked=False, code=action: self._run_system_action(code))
            layout.addWidget(button)
            self.system_action_buttons[action] = button
        layout.addStretch(1)

    @staticmethod
    def _set_audit_columns(table: QTableWidget, widths: tuple[int, ...]) -> None:
        for column, width in enumerate(widths):
            if column < table.columnCount():
                table.setColumnWidth(column, width)
                table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)

    def _audit_engine_method(self, name: str) -> Any | None:
        audit = getattr(self, "audit", None)
        method = getattr(audit, name, None) if audit is not None else None
        if not callable(method):
            self._audit_message("ERROR", f"Модуль аудита не предоставляет операцию {name}.")
            return None
        return method

    def _start_audit_task(
        self,
        operation: str,
        label: str,
        method_name: str,
        *args: Any,
    ) -> bool:
        method = self._audit_engine_method(method_name)
        if method is None:
            return False
        if getattr(self, "_busy", False):
            return False
        self._audit_worker_read_errors.clear()
        function = method
        if operation in _AUDIT_READ_OPERATIONS:
            def scan_with_error_capture(*worker_args: Any) -> object:
                if not worker_args or not callable(worker_args[-1]):
                    raise TypeError("Для сканирования не передан обработчик журнала.")
                arguments, log = worker_args[:-1], worker_args[-1]

                def capture(level: str, message: str) -> None:
                    if str(level).upper() in {"ERROR", "CRITICAL"}:
                        self._audit_worker_read_errors.append(str(message))
                    log(level, message)

                return method(*arguments, capture)

            function = scan_with_error_capture
        return bool(self._start_task(operation, label, function, *args))

    def _audit_message(self, level: str, text: str) -> None:
        self._append_log(level, text)
        if level.upper() in ("ERROR", "CRITICAL"):
            self._operation_failed = True
        status = getattr(self, "statusBar", None)
        if callable(status):
            status().showMessage(str(text), 10000)

    def _audit_confirmation(self, title: str, text: str) -> bool:
        if not self._authorize_mutation():
            return False
        if self._confirm(title, text):
            return True
        self._append_log("INFO", f"Операция «{title}» отменена пользователем.")
        return False

    @staticmethod
    def _audit_signed(status: str) -> bool:
        normalized = str(status).strip().casefold()
        return normalized in {
            "valid",
            "signed",
            "verified",
            "действительна",
            "действительный",
            "подписан",
            "подписана",
            "подписано",
        }

    @staticmethod
    def _audit_read_status_is_partial(status: object) -> bool:
        value = str(status or "").strip().casefold()
        return any(
            marker in value
            for marker in (
                "ошиб",
                "error",
                "failed",
                "недоступ",
                "не удалось",
                "unknown",
                "неизвест",
                "не провер",
            )
        )

    @classmethod
    def _audit_items_have_read_errors(cls, entries: Any) -> bool:
        for entry in entries:
            if str(getattr(entry, "error", "") or "").strip():
                return True
            if cls._audit_read_status_is_partial(getattr(entry, "status", "")):
                return True
            if isinstance(entry, ProcessInfo) and (
                not entry.path or str(entry.signature).casefold() == "unknownerror"
            ):
                return True
        return False

    def _report_audit_read(self, label: str, count: int, partial: bool) -> None:
        self._operation_failed = partial
        suffix = " Результат может быть неполным; проверьте ошибки журнала и повторите сканирование." if partial else ""
        self._audit_message("WARN" if partial else "SUCCESS", f"{label}: {count}.{suffix}")

    @staticmethod
    def _normalized_path(path: str) -> str:
        return os.path.normcase(str(path).replace("/", "\\")).casefold().rstrip("\\")

    @classmethod
    def _process_is_suspicious(cls, process: ProcessInfo) -> bool:
        path = cls._normalized_path(process.path)
        parts = tuple(part for part in path.split("\\") if part)
        if process.hidden or any(part.startswith(".") for part in parts):
            return True
        if any(part in {"$recycle.bin", "recycler"} for part in parts):
            return True
        temp_paths = [os.environ.get("TEMP", ""), os.environ.get("TMP", ""), tempfile.gettempdir()]
        for temp_path in temp_paths:
            normalized = cls._normalized_path(temp_path)
            if normalized and (path == normalized or path.startswith(normalized + "\\")):
                return True
        return any(part == "temp" for part in parts)

    def _render_audit_processes(self, *_args: object) -> None:
        processes = self._audit_processes
        if processes is None or not hasattr(self, "process_table"):
            return
        query = self.process_filter.text().strip().casefold() if hasattr(self, "process_filter") else ""
        filtered = [
            process
            for process in processes
            if not (self.hide_trusted_processes.isChecked() and process.trusted)
            and not (self.suspicious_processes_only.isChecked() and not self._process_is_suspicious(process))
            and not (self.signed_processes_only.isChecked() and not self._audit_signed(process.signature))
            and (
                not query
                or query
                in " ".join(
                    (
                        str(process.pid),
                        process.name,
                        process.path,
                        process.user,
                        process.status,
                        process.company,
                        process.command_line,
                        process.signature,
                    )
                ).casefold()
            )
        ]
        normalized_paths = [self._normalized_path(process.path) for process in filtered]
        counts: dict[str, int] = {}
        for path in normalized_paths:
            if path:
                counts[path] = counts.get(path, 0) + 1
        if self.group_duplicate_processes.isChecked():
            filtered.sort(key=lambda process: (self._normalized_path(process.path), process.pid))

        table = self.process_table
        blocker = QSignalBlocker(table)
        table.setRowCount(0)
        for process in filtered:
            row = table.rowCount()
            table.insertRow(row)
            pid_item = self._audit_cell(process.pid, mono=True)
            pid_item.setData(Qt.ItemDataRole.UserRole, process)
            critical = "Да" if process.critical is True else "Нет" if process.critical is False else "?"
            duplicate_count = counts.get(self._normalized_path(process.path), 1)
            values = {
                0: pid_item,
                1: self._audit_cell(process.name),
                2: self._audit_cell(process.path, tooltip=process.path, mono=True),
                3: self._audit_cell(process.user, mono=True),
                4: self._audit_cell(self._audit_time(process.created)),
                5: self._audit_cell(process.status),
                self._audit_process_columns["critical"]: self._audit_cell(critical),
                self._audit_process_columns["company"]: self._audit_cell(process.company),
                self._audit_process_columns["command line"]: self._audit_cell(
                    process.command_line, tooltip=process.command_line, mono=True
                ),
                self._audit_process_columns["signature"]: self._audit_cell(process.signature),
                self._audit_process_columns["parent pid"]: self._audit_cell(process.parent_pid),
                self._audit_process_columns["hidden"]: self._audit_cell("Да" if process.hidden else "Нет"),
                self._audit_process_columns["trusted"]: self._audit_cell("Да" if process.trusted else "Нет"),
                self._audit_process_columns["same path"]: self._audit_cell(
                    f"x{duplicate_count}" if duplicate_count > 1 else "—"
                ),
            }
            for column, item in values.items():
                if column < table.columnCount():
                    table.setItem(row, column, item)
        del blocker
        self._refresh_audit_controls()

    @staticmethod
    def _audit_time(value: float | int | None) -> str:
        if value is None:
            return "—"
        try:
            return datetime.fromtimestamp(float(value)).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, TypeError, ValueError):
            return str(value)

    @staticmethod
    def _audit_ns_time(value: int) -> str:
        if not value:
            return "—"
        try:
            return datetime.fromtimestamp(value / 1_000_000_000).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, TypeError, ValueError):
            return str(value)

    def _selected_audit_process(self) -> ProcessInfo | None:
        selected = self.process_table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        item = self.process_table.item(selected[0].row(), 0)
        process = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return process if isinstance(process, ProcessInfo) else None

    def _scan_audit_processes(self) -> None:
        self._start_audit_task("audit_process_scan", "Аудит процессов", "processes")

    def _audit_process_action(self, action: str) -> None:
        process = self._selected_audit_process()
        if process is None:
            return
        if action not in {"kill", "suspend", "resume"}:
            self._audit_message("ERROR", "Запрошено неподдерживаемое действие над процессом.")
            return
        verbs = {
            "kill": ("Подтвердите завершение процесса", "Завершить процесс"),
            "suspend": ("Подтвердите приостановку процесса", "Приостановить процесс"),
            "resume": ("Подтвердите возобновление процесса", "Возобновить процесс"),
        }
        title, verb = verbs[action]
        message = (
            f"Действие: {verb}\nPID: {process.pid}\nИмя: {process.name}\n"
            f"Путь: {process.path}\nВремя запуска: {self._audit_time(process.created)}\n\n"
            "Проверьте идентичность процесса и возможные последствия вручную. Для завершения "
            "несохранённые данные будут потеряны; интерфейс не определяет вредоносность."
        )
        if not self._audit_confirmation(title, message):
            return
        self._start_audit_task(
            "audit_process_action",
            f"{verb}: PID {process.pid}",
            "process_action",
            process,
            action,
        )

    def _confirm_and_terminate(self) -> None:
        self._audit_process_action("kill")

    def _plan_process_tree_kill(self) -> None:
        process = self._selected_audit_process()
        if process is None or not self._authorize_mutation():
            return
        self._start_audit_task(
            "audit_tree_plan",
            f"Построение плана дерева PID {process.pid}",
            "process_tree",
            process,
        )

    def _review_process_tree_plan(self, result: object) -> None:
        if not isinstance(result, (tuple, list)) or any(not isinstance(item, ProcessInfo) for item in result):
            raise TypeError("План дерева процессов имеет неподдерживаемый формат.")
        plan = tuple(result)
        if not plan:
            self._audit_message("WARN", "Движок вернул пустой план дерева; процессы не изменены.")
            return
        lines = ["Будет передан движку фиксированный план процессов:", ""]
        lines.extend(
            f"PID {item.pid} | {item.name} | {item.path} | запуск {self._audit_time(item.created)}"
            for item in plan
        )
        lines.extend(
            (
                "",
                "Это именно снимок PID/пути/времени запуска, а не динамический поиск новых "
                "потомков. Несохранённые данные будут потеряны. Операция необратима.",
            )
        )
        if not self._confirm("Подтвердите завершение дерева", "\n".join(lines)):
            self._append_log("INFO", "Завершение дерева процессов отменено; план не выполнен.")
            return
        self._audit_deferred_tree = plan
        self._audit_deferred_timer.start(0)

    def _start_deferred_tree_kill(self) -> None:
        plan = self._audit_deferred_tree
        if plan is None:
            return
        if self._busy:
            self._audit_deferred_timer.start(40)
            return
        if not self._authorize_mutation():
            self._audit_deferred_tree = None
            return
        self._audit_deferred_tree = None
        if not self._start_audit_task(
            "audit_tree_kill",
            f"Завершение фиксированного дерева ({len(plan)} процессов)",
            "kill_tree",
            plan,
        ):
            if self._busy:
                self._audit_deferred_tree = plan
                self._audit_deferred_timer.start(40)

    def _open_selected_process(self) -> None:
        process = self._selected_audit_process()
        if process is not None and process.path:
            self._start_audit_task(
                "audit_open_location", "Открытие расположения процесса", "open_location", process.path
            )

    def _find_process_duplicates(self) -> None:
        process = self._selected_audit_process()
        if process is None or not process.path:
            return
        root = self.files_root.text().strip() if hasattr(self, "files_root") else ""
        if not root:
            root = QFileDialog.getExistingDirectory(self, "Корневая папка для поиска дубликатов", "")
        if not root:
            return
        self._audit_file_scan_kind = "duplicates"
        self.tabs.setCurrentWidget(self.files_table.parentWidget())
        self._start_audit_task(
            "audit_duplicates", "Поиск файлов-дубликатов", "duplicates", process.path, root
        )

    def _show_process_context_menu(self, position: Any) -> None:
        item = self.process_table.itemAt(position)
        if item is not None:
            self.process_table.selectRow(item.row())
        if self._selected_audit_process() is None:
            return
        menu = QMenu(self)
        for label, slot in (
            ("Завершить…", lambda: self._audit_process_action("kill")),
            ("Завершить дерево…", self._plan_process_tree_kill),
            ("Приостановить…", lambda: self._audit_process_action("suspend")),
            ("Возобновить…", lambda: self._audit_process_action("resume")),
            ("Открыть расположение", self._open_selected_process),
            ("Искать дубликаты…", self._find_process_duplicates),
            ("Флаг Critical (только чтение)…", self._explain_critical_flag),
        ):
            action = menu.addAction(label)
            action.triggered.connect(slot)
        menu.exec(self.process_table.viewport().mapToGlobal(position))

    def _explain_critical_flag(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle("Флаг Critical")
        box.setIcon(QMessageBox.Icon.Information)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(
            "Флаг критичности процесса отображается только для чтения. Изменение защитного "
            "состояния ядра из этой утилиты не поддерживается: такая попытка может вызвать "
            "аварийное завершение Windows или потерю данных."
        )
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.exec()

    def _scan_startup(self) -> None:
        self._start_audit_task("audit_startup_scan", "Аудит автозагрузки", "startup")

    def _render_startup(self, entries: list[StartupEntry]) -> None:
        self._audit_startup_entries = list(entries)
        table = self.startup_table
        blocker = QSignalBlocker(table)
        table.setRowCount(0)
        for entry in self._audit_startup_entries:
            row = table.rowCount()
            table.insertRow(row)
            first = self._audit_cell(entry.category)
            first.setData(Qt.ItemDataRole.UserRole, entry)
            values = (
                first,
                self._audit_cell(entry.name),
                self._audit_cell(entry.location, tooltip=entry.location, mono=True),
                self._audit_cell(entry.command, tooltip=entry.command, mono=True),
                self._audit_cell(entry.status),
            )
            for column, cell in enumerate(values):
                table.setItem(row, column, cell)
        del blocker
        self.startup_note.setText(
            f"Найдено записей: {len(entries)}. Сканирование ничего не удаляет; отсутствие подписи "
            "или необычный путь требуют ручной проверки."
        )
        self._refresh_audit_controls()

    def _selected_startup(self) -> StartupEntry | None:
        selected = self.startup_table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        item = self.startup_table.item(selected[0].row(), 0)
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return value if isinstance(value, StartupEntry) else None

    def _edit_selected_startup(self) -> None:
        entry = self._selected_startup()
        if entry is None or entry.address is None:
            return
        value = self._registry_value_dialog(entry.value)
        if value is None:
            return
        message = (
            f"Изменить параметр автозагрузки?\nИмя: {entry.name}\nКлюч: {entry.address.label}\n"
            f"Команда: {entry.command}\n\nБудет записано значение типа "
            f"{_REGISTRY_TYPE_NAMES.get(value.type, value.type)}."
        )
        if not self._audit_confirmation("Изменение автозапуска", message):
            return
        self._start_audit_task(
            "audit_startup_edit", "Изменение записи автозагрузки", "edit_startup", entry, value
        )

    def _remove_selected_startup(self) -> None:
        entry = self._selected_startup()
        if entry is None:
            return
        target = entry.address.label if entry.address is not None else entry.path or entry.location
        action = "Запись реестра будет удалена." if entry.address is not None else (
            "Файл Startup будет перемещён в карантин движком; принудительное удаление не выполняется."
        )
        message = (
            f"Запрошено удаление записи автозагрузки:\n{entry.name}\n{target}\n{entry.command}\n\n"
            f"{action} Проверьте путь и источник вручную."
        )
        if not self._audit_confirmation("Подтвердите изменение автозагрузки", message):
            return
        self._start_audit_task(
            "audit_startup_edit", "Удаление записи автозагрузки", "edit_startup", entry, None
        )

    def _open_selected_startup_registry(self) -> None:
        entry = self._selected_startup()
        if entry is not None and entry.address is not None:
            self._start_audit_task(
                "audit_open_registry", "Открытие ключа автозагрузки", "open_registry", entry.address
            )

    def _open_selected_startup_location(self) -> None:
        entry = self._selected_startup()
        path = entry.path if entry is not None else ""
        if path:
            self._start_audit_task(
                "audit_open_location", "Открытие Startup-расположения", "open_location", path
            )

    def _show_startup_context_menu(self, position: Any) -> None:
        item = self.startup_table.itemAt(position)
        if item is not None:
            self.startup_table.selectRow(item.row())
        if self._selected_startup() is None:
            return
        menu = QMenu(self)
        for title, slot in (
            ("Изменить значение…", self._edit_selected_startup),
            ("Удалить / карантин…", self._remove_selected_startup),
            ("Открыть ключ в Regedit", self._open_selected_startup_registry),
            ("Открыть расположение", self._open_selected_startup_location),
        ):
            action = menu.addAction(title)
            action.triggered.connect(slot)
        menu.exec(self.startup_table.viewport().mapToGlobal(position))

    def _scan_audit_services(self) -> None:
        self._start_audit_task("audit_services_scan", "Аудит служб", "services")

    @classmethod
    def _service_is_suspicious(cls, service: ServiceInfo) -> bool:
        command = cls._normalized_path(service.command)
        user_path = any(
            marker in command
            for marker in ("\\users\\", "\\appdata\\", "\\temp\\", "\\public\\")
        )
        return bool(
            service.suspicious
            or not service.description.strip()
            or not cls._audit_signed(service.signature)
            or user_path
        )

    def _render_audit_services(self, *_args: object) -> None:
        if not hasattr(self, "audit_services_table"):
            return
        services = self._audit_services
        if self.service_suspicious_only.isChecked():
            services = [service for service in services if self._service_is_suspicious(service)]
        table = self.audit_services_table
        blocker = QSignalBlocker(table)
        table.setRowCount(0)
        for service in services:
            row = table.rowCount()
            table.insertRow(row)
            name_item = self._audit_cell(service.name, tooltip=service.name, mono=True)
            name_item.setData(Qt.ItemDataRole.UserRole, service)
            values = (
                name_item,
                self._audit_cell(service.display_name),
                self._audit_cell(service.pid),
                self._audit_cell(service.start_type),
                self._audit_cell(service.state, tooltip=service.error or service.state),
                self._audit_cell(service.description, tooltip=service.description),
                self._audit_cell(service.command, tooltip=service.command, mono=True),
                self._audit_cell(service.signature),
                self._audit_cell("Да" if self._service_is_suspicious(service) else "Нет"),
            )
            for column, cell in enumerate(values):
                table.setItem(row, column, cell)
        del blocker
        self._refresh_audit_controls()

    def _selected_service(self) -> ServiceInfo | None:
        selected = self.audit_services_table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        item = self.audit_services_table.item(selected[0].row(), 0)
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return value if isinstance(value, ServiceInfo) else None

    def _change_selected_service(self, action: str) -> None:
        service = self._selected_service()
        if service is None or action not in {"start", "stop", "auto", "manual", "disabled"}:
            return
        labels = {
            "start": "Запустить",
            "stop": "Остановить",
            "auto": "Установить автоматический запуск",
            "manual": "Установить ручной запуск",
            "disabled": "Отключить службу",
        }
        warnings = {
            "start": "Запуск может изменить системную активность и загрузку компьютера.",
            "stop": "Остановка может прервать зависящие приложения или сетевые функции.",
            "auto": "Служба будет запускаться автоматически вместе с Windows.",
            "manual": "Служба будет запускаться только по запросу.",
            "disabled": "Служба не сможет запускаться до ручного изменения режима.",
        }
        message = (
            f"{labels[action]} службу?\nСистемное имя: {service.name}\n"
            f"Отображаемое имя: {service.display_name}\nКоманда: {service.command}\n\n"
            f"{warnings[action]} Проверьте назначение и зависимости вручную."
        )
        if not self._audit_confirmation("Подтвердите изменение службы", message):
            return
        self._start_audit_task(
            "audit_service_action",
            f"{labels[action]}: {service.name}",
            "change_service",
            service,
            action,
        )

    def _choose_service_start_type(self) -> None:
        service = self._selected_service()
        if service is None:
            return
        choices = ("Автоматически", "Вручную", "Отключена")
        label, accepted = QInputDialog.getItem(
            self, "Режим запуска службы", service.name, choices, 0, False
        )
        if not accepted:
            return
        action = {"Автоматически": "auto", "Вручную": "manual", "Отключена": "disabled"}[label]
        self._change_selected_service(action)

    def _delete_selected_service(self) -> None:
        service = self._selected_service()
        if service is None or not self._authorize_mutation():
            return
        if str(service.state).strip().casefold() not in {"stopped", "остановлена", "остановлено"}:
            self._audit_message("WARN", "Сначала остановите службу и обновите список.")
            return
        typed, accepted = QInputDialog.getText(
            self,
            "Подтверждение удаления службы",
            f"Введите системное имя службы без изменений:\n{service.name}",
            QLineEdit.EchoMode.Normal,
        )
        if not accepted or typed != service.name:
            if accepted:
                self._append_log("WARN", "Имя службы не совпало; удаление отменено.")
            return
        message = (
            f"Удалить службу {service.name}?\n{service.display_name}\nКоманда: {service.command}\n\n"
            "Операция необратима автоматически: резервная копия сохраняет параметры и ветку "
            "реестра только для ручного восстановления, но не пересоздаёт объект службы. "
            "Для восстановления может потребоваться заново установить компонент из доверенного "
            "дистрибутива и вручную восстановить конфигурацию, разрешения и зависимости. "
            "Пароль учётной записи службы не сохраняется и при повторной настройке его нужно "
            "ввести заново. Убедитесь, что доступен установщик и вы знаете способ ручного "
            "восстановления до продолжения."
        )
        if not self._confirm("Подтвердите удаление службы", message):
            self._append_log("INFO", "Удаление службы отменено пользователем.")
            return
        self._start_audit_task(
            "audit_service_action", f"Удаление службы {service.name}", "change_service", service, "delete"
        )

    @staticmethod
    def _service_executable(command: str) -> str:
        text = str(command).strip()
        if text.startswith('"') and '"' in text[1:]:
            return text[1 : text.find('"', 1)]
        match = re.search(r"(?i)^(.+?\.(?:exe|dll|sys))(?:\s|$)", text)
        return match.group(1).strip('"') if match else ""

    def _open_selected_service_location(self) -> None:
        service = self._selected_service()
        path = self._service_executable(service.command) if service is not None else ""
        if path:
            self._start_audit_task(
                "audit_open_location", "Открытие расположения службы", "open_location", path
            )

    def _show_service_context_menu(self, position: Any) -> None:
        item = self.audit_services_table.itemAt(position)
        if item is not None:
            self.audit_services_table.selectRow(item.row())
        if self._selected_service() is None:
            return
        menu = QMenu(self)
        for title, slot in (
            ("Запустить…", lambda: self._change_selected_service("start")),
            ("Остановить…", lambda: self._change_selected_service("stop")),
            ("Режим запуска…", self._choose_service_start_type),
            ("Удалить службу…", self._delete_selected_service),
            ("Открыть расположение", self._open_selected_service_location),
        ):
            action = menu.addAction(title)
            action.triggered.connect(slot)
        menu.exec(self.audit_services_table.viewport().mapToGlobal(position))

    def _browse_registry(self) -> None:
        hive, key, view, _mount_key = self._registry_context()
        self._start_audit_task(
            "audit_registry_scan",
            f"Чтение реестра {hive}\\{key or '(корень)'} [{view}]",
            "registry",
            hive,
            key,
            view,
        )

    def _registry_parent_key(self) -> None:
        key = self.registry_key.text().rstrip("\\/")
        self.registry_key.setText(key.rsplit("\\", 1)[0] if "\\" in key else "")
        self._browse_registry()

    def _enter_registry_subkey(self, item: QTableWidgetItem) -> None:
        child = item.text()
        parent = self.registry_key.text().strip().rstrip("\\/")
        self.registry_key.setText(f"{parent}\\{child}" if parent else child)
        self._browse_registry()

    def _render_registry_listing(self, listing: RegistryListing) -> None:
        self._audit_registry_listing = listing
        mount_key = next(
            (
                key
                for key in self._audit_mounts
                if listing.hive == "HKLM"
                and listing.key.casefold().startswith(key.casefold())
            ),
            "",
        )
        display_key = listing.key
        if mount_key and display_key.casefold().startswith((mount_key + "\\").casefold()):
            display_key = display_key[len(mount_key) + 1 :]
        elif mount_key and display_key.casefold() == mount_key.casefold():
            display_key = ""
        self.registry_key.setText(display_key)
        self.registry_current_label.setText(f"{listing.hive}\\{listing.key or '(корень)'} [{listing.view}]")
        self.registry_note.setText(
            f"Подразделов: {len(listing.subkeys)}; значений: {len(listing.values)}. "
            "Для добавления, изменения и удаления требуется отдельное подтверждение."
        )
        for table in (self.registry_subkeys_table, self.registry_values_table):
            blocker = QSignalBlocker(table)
            table.setRowCount(0)
            del blocker
        for subkey in listing.subkeys:
            row = self.registry_subkeys_table.rowCount()
            self.registry_subkeys_table.insertRow(row)
            self.registry_subkeys_table.setItem(row, 0, self._audit_cell(subkey, tooltip=subkey))
        for name, value in listing.values.items():
            row = self.registry_values_table.rowCount()
            self.registry_values_table.insertRow(row)
            display_name = name or "(по умолчанию)"
            name_item = self._audit_cell(display_name, tooltip=name)
            name_item.setData(Qt.ItemDataRole.UserRole, (name, value))
            self.registry_values_table.setItem(row, 0, name_item)
            self.registry_values_table.setItem(
                row, 1, self._audit_cell(_REGISTRY_TYPE_NAMES.get(value.type, f"Тип {value.type}"))
            )
            self.registry_values_table.setItem(
                row, 2, self._audit_cell(value.display(), tooltip=value.display(), mono=True)
            )
        self._refresh_audit_controls()

    def _current_registry_address(self, name: str) -> RegistryAddress:
        hive, key, view, _mount_key = self._registry_context()
        listing = self._audit_registry_listing
        if listing is not None:
            hive, key, view = listing.hive, listing.key, listing.view
        return RegistryAddress(hive=hive, key=key, name=name, view=view)

    def _registry_mount_key(self) -> str:
        data = self.registry_hive.currentData()
        if isinstance(data, tuple) and len(data) == 2 and data[0] == "HKLM":
            return str(data[1])
        return ""

    def _registry_context(self) -> tuple[str, str, int, str]:
        data = self.registry_hive.currentData()
        mount_key = self._registry_mount_key()
        hive = "HKLM" if mount_key else str(data or "HKCU")
        key = self.registry_key.text().strip().strip("\\/")
        if mount_key:
            key = f"{mount_key}\\{key}" if key else mount_key
        return hive, key, int(self.registry_view.currentData()), mount_key

    def _registry_hive_changed(self, *_args: object) -> None:
        self._audit_registry_listing = None
        self.registry_subkeys_table.setRowCount(0)
        self.registry_values_table.setRowCount(0)
        self.registry_current_label.setText("Ключ не загружен; нажмите «Открыть ключ»")
        self._refresh_audit_controls()

    def _registry_key_edited(self, *_args: object) -> None:
        self._audit_registry_listing = None
        self.registry_subkeys_table.setRowCount(0)
        self.registry_values_table.setRowCount(0)
        self.registry_current_label.setText("Путь изменён; нажмите «Открыть ключ»")
        self._refresh_audit_controls()

    def _selected_registry_value(self) -> tuple[str, RegistryValue] | None:
        selected = self.registry_values_table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        item = self.registry_values_table.item(selected[0].row(), 0)
        payload = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if (
            isinstance(payload, tuple)
            and len(payload) == 2
            and isinstance(payload[0], str)
            and isinstance(payload[1], RegistryValue)
        ):
            return payload
        return None

    def _registry_value_dialog(self, current: RegistryValue | None) -> RegistryValue | None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Типизированное значение реестра")
        form = QFormLayout(dialog)
        type_combo = QComboBox(dialog)
        for title, kind in _REGISTRY_TYPES:
            type_combo.addItem(title, kind)
        if current is not None:
            index = type_combo.findData(current.type)
            if index >= 0:
                type_combo.setCurrentIndex(index)
        data = QPlainTextEdit(dialog)
        data.setMinimumHeight(110)
        if current is not None:
            data.setPlainText(current.display())
        data.setPlaceholderText(
            "REG_BINARY: hex bytes, e.g. 01 0A FF\nREG_MULTI_SZ: one string per line"
        )
        form.addRow("Тип:", type_combo)
        form.addRow("Данные:", data)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, dialog
        )
        form.addRow(buttons)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        try:
            return self._parse_registry_value(int(type_combo.currentData()), data.toPlainText())
        except ValueError as exc:
            box = QMessageBox(self)
            box.setWindowTitle("Некорректное значение")
            box.setIcon(QMessageBox.Icon.Warning)
            box.setTextFormat(Qt.TextFormat.PlainText)
            box.setText(str(exc))
            box.setStandardButtons(QMessageBox.StandardButton.Ok)
            box.exec()
            return None

    @staticmethod
    def _parse_registry_value(kind: int, text: str) -> RegistryValue:
        if kind in (1, 2):
            return RegistryValue(kind, text)
        if kind == 3:
            try:
                return RegistryValue(kind, bytes.fromhex(text))
            except ValueError as exc:
                raise ValueError("REG_BINARY должен содержать шестнадцатеричные байты через пробел.") from exc
        if kind in (4, 11):
            try:
                value = int(text.strip(), 0)
            except ValueError as exc:
                raise ValueError("DWORD/QWORD должен быть целым числом в десятичном или 0x-виде.") from exc
            if not 0 <= value < 2 ** (32 if kind == 4 else 64):
                raise ValueError("Значение выходит за диапазон выбранного DWORD/QWORD.")
            return RegistryValue(kind, value)
        if kind == 7:
            return RegistryValue(kind, [line for line in text.splitlines() if line])
        raise ValueError("Выбран неподдерживаемый тип значения реестра.")

    def _create_registry_value(self) -> None:
        if self._audit_registry_listing is None or not self._audit_registry_listing.key:
            return
        name, accepted = QInputDialog.getText(self, "Новое значение", "Имя (пустое — значение по умолчанию):")
        if not accepted:
            return
        value = self._registry_value_dialog(None)
        if value is None:
            return
        address = self._current_registry_address(name)
        message = (
            f"Создать значение?\n{address.label}\nТип: "
            f"{_REGISTRY_TYPE_NAMES.get(value.type, value.type)}"
        )
        if not self._audit_confirmation("Подтвердите запись реестра", message):
            return
        self._start_audit_task(
            "audit_registry_edit", "Создание значения реестра", "edit_registry", address, None, value
        )

    def _edit_registry_value(self) -> None:
        selected = self._selected_registry_value()
        if selected is None:
            return
        name, old = selected
        value = self._registry_value_dialog(old)
        if value is None:
            return
        address = self._current_registry_address(name)
        message = (
            f"Изменить значение?\n{address.label}\nСтарый тип: "
            f"{_REGISTRY_TYPE_NAMES.get(old.type, old.type)}\nНовый тип: "
            f"{_REGISTRY_TYPE_NAMES.get(value.type, value.type)}"
        )
        if not self._audit_confirmation("Подтвердите запись реестра", message):
            return
        self._start_audit_task(
            "audit_registry_edit", "Изменение значения реестра", "edit_registry", address, old, value
        )

    def _delete_registry_value(self) -> None:
        selected = self._selected_registry_value()
        if selected is None:
            return
        name, old = selected
        address = self._current_registry_address(name)
        message = (
            f"Удалить значение реестра?\n{address.label}\n"
            f"Тип: {_REGISTRY_TYPE_NAMES.get(old.type, old.type)}\n\n"
            "Удаление может нарушить запуск Windows или приложения."
        )
        if not self._audit_confirmation("Подтвердите удаление значения", message):
            return
        self._start_audit_task(
            "audit_registry_edit", "Удаление значения реестра", "edit_registry", address, old, None
        )

    def _open_registry_key(self) -> None:
        listing = self._audit_registry_listing
        if listing is None or not listing.key:
            return
        address = RegistryAddress(listing.hive, listing.key, "", listing.view)
        self._start_audit_task("audit_open_registry", "Открытие ключа в Regedit", "open_registry", address)

    def _choose_registry_restore(self) -> None:
        journal = getattr(self.audit, "journal", None)
        root = str(getattr(journal, "root", ""))
        manifest, _filter = QFileDialog.getOpenFileName(
            self,
            "Выберите резервную копию значения реестра",
            root,
            "Резервные копии действий (action.json);;JSON (*.json);;Все файлы (*)",
        )
        if not manifest:
            return
        message = (
            f"Восстановить значение реестра по манифесту действия?\n{manifest}\n\n"
            "Будет восстановлено только сохранённое значение. Движок проверит тип, компьютер "
            "и пользователя и создаст новую резервную копию текущего состояния до записи. "
            "Манифест старого формата backup.json для исправлений здесь не используется."
        )
        if not self._audit_confirmation("Подтвердите восстановление реестра", message):
            return
        self._start_audit_task(
            "audit_registry_restore",
            "Восстановление значения реестра из action.json",
            "restore_registry",
            manifest,
        )

    def _choose_hive_to_mount(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self,
            "Выберите offline registry hive",
            "",
            "Файлы кустов (*.hiv *.dat *.sav);;Все файлы (*)",
        )
        if path:
            self._start_audit_task(
                "audit_hive_mount", "Подключение рабочей копии offline hive", "mount_hive", path
            )

    def _unmount_selected_hive(self) -> None:
        mount = self._audit_mounts.get(self._registry_mount_key())
        if mount is None or not self._audit_confirmation(
            "Выгрузить offline hive",
            f"Выгрузить рабочую копию?\nКлюч: {mount.key}\nИсточник: {mount.original}\n"
            f"Рабочая копия: {mount.working_copy}\nРезервная копия: {mount.backup}\n\n"
            "Действие не выгружает и не изменяет системный hive в WinRE.",
        ):
            return
        self._audit_unmounting = mount
        self._start_audit_task(
            "audit_hive_unmount", f"Выгрузка рабочей копии {mount.key}", "unmount_hive", mount
        )

    def _render_mount(self, mount: HiveMount) -> None:
        if mount.key in self._audit_mounts:
            return
        self._audit_mounts[mount.key] = mount
        self.registry_key.clear()
        self.registry_hive.addItem(f"Offline: HKLM\\{mount.key}", ("HKLM", mount.key))
        self.registry_hive.setCurrentIndex(self.registry_hive.count() - 1)
        self.registry_note.setText(
            f"Рабочая копия подключена: {mount.key}; источник {mount.original}; "
            f"резервная копия {mount.backup}. Это не системный куст WinRE."
        )
        self._refresh_audit_controls()

    def _forget_mount(self, mount: HiveMount) -> None:
        self._audit_mounts.pop(mount.key, None)
        index = next(
            (
                candidate
                for candidate in range(self.registry_hive.count())
                if self.registry_hive.itemData(candidate) == ("HKLM", mount.key)
            ),
            -1,
        )
        if index >= 0:
            if self.registry_hive.currentIndex() == index:
                self.registry_hive.setCurrentIndex(0)
            self.registry_hive.removeItem(index)
        self._audit_registry_listing = None
        self.registry_subkeys_table.setRowCount(0)
        self.registry_values_table.setRowCount(0)
        self.registry_current_label.setText("Ключ не загружен")
        self._refresh_audit_controls()

    def _scan_tasks(self) -> None:
        self._start_audit_task("audit_tasks_scan", "Аудит планировщика", "tasks")

    @staticmethod
    def _task_folder(task: TaskInfo) -> str:
        return str(task.folder or "").replace("/", "\\").strip("\\")

    @staticmethod
    def _task_read_only(task: TaskInfo) -> bool:
        path = str(task.path).replace("/", "\\").casefold()
        return path.startswith("\\microsoft\\windows\\")

    def _render_task_tree(self) -> None:
        blocker = QSignalBlocker(self.task_tree)
        self.task_tree.clear()
        root = QTreeWidgetItem(["Все задачи"])
        root.setData(0, Qt.ItemDataRole.UserRole, "")
        self.task_tree.addTopLevelItem(root)
        folders: dict[str, QTreeWidgetItem] = {"": root}
        for task in sorted(self._audit_tasks, key=lambda value: self._task_folder(value).casefold()):
            folder = self._task_folder(task)
            current = ""
            parent = root
            for part in (piece for piece in folder.split("\\") if piece):
                current = f"{current}\\{part}" if current else part
                if current not in folders:
                    child = QTreeWidgetItem([part])
                    child.setData(0, Qt.ItemDataRole.UserRole, current)
                    parent.addChild(child)
                    folders[current] = child
                parent = folders[current]
        root.setExpanded(True)
        self.task_tree.setCurrentItem(root)
        del blocker
        self._audit_task_folder = ""

    def _render_audit_tasks(self) -> None:
        if not hasattr(self, "task_table"):
            return
        current = self.task_tree.currentItem()
        if current is not None:
            self._audit_task_folder = str(current.data(0, Qt.ItemDataRole.UserRole) or "")
        tasks = self._audit_tasks
        if self._audit_task_folder:
            tasks = [task for task in tasks if self._task_folder(task) == self._audit_task_folder]
        blocker = QSignalBlocker(self.task_table)
        self.task_table.setRowCount(0)
        for task in tasks:
            row = self.task_table.rowCount()
            self.task_table.insertRow(row)
            name_item = self._audit_cell(task.name)
            name_item.setData(Qt.ItemDataRole.UserRole, task)
            folder = self._task_folder(task)
            self.task_table.setItem(row, 0, name_item)
            self.task_table.setItem(row, 1, self._audit_cell(folder))
            enabled = self._audit_cell("Включена" if task.enabled else "Отключена")
            flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
            if not self._task_read_only(task):
                flags |= Qt.ItemFlag.ItemIsUserCheckable
            else:
                enabled.setToolTip("Задания Microsoft\\Windows доступны только для чтения.")
            enabled.setFlags(flags)
            enabled.setCheckState(Qt.CheckState.Checked if task.enabled else Qt.CheckState.Unchecked)
            enabled.setData(Qt.ItemDataRole.UserRole, task)
            self.task_table.setItem(row, 2, enabled)
            details = (
                task.created,
                task.next_run,
                task.author,
                task.description,
                task.command,
            )
            for column, text in enumerate(details, start=3):
                self.task_table.setItem(
                    row,
                    column,
                    self._audit_cell(text, tooltip=text, mono=column == 7),
                )
        del blocker
        self._refresh_audit_controls()

    def _selected_task(self) -> TaskInfo | None:
        selected = self.task_table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        item = self.task_table.item(selected[0].row(), 0)
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return value if isinstance(value, TaskInfo) else None

    def _task_enabled_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 2:
            return
        task = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(task, TaskInfo) or self._task_read_only(task):
            return
        desired = item.checkState() == Qt.CheckState.Checked
        if desired == task.enabled:
            return
        action = "enable" if desired else "disable"
        self._render_audit_tasks()
        if not self._authorize_mutation():
            return
        message = (
            f"{('Включить' if desired else 'Отключить')} задачу планировщика?\n"
            f"Путь: {task.path}\nИмя: {task.name}\nКоманда: {task.command}\n\n"
            "Состояние будет обновлено в интерфейсе только после подтверждения движком."
        )
        if not self._confirm("Подтвердите изменение задачи", message):
            self._append_log("INFO", f"Изменение задачи {task.path} отменено.")
            return
        self._audit_task_change = (task, action)
        started = self._start_audit_task(
            "audit_task_change", f"{action.capitalize()} задача {task.path}", "change_task", task, action
        )
        if not started:
            self._audit_task_change = None

    def _delete_selected_task(self) -> None:
        task = self._selected_task()
        if task is None or self._task_read_only(task):
            return
        message = (
            f"Удалить выбранную задачу?\nПуть: {task.path}\nИмя: {task.name}\n"
            f"Автор: {task.author}\nКоманда: {task.command}\n\n"
            "Удаление определения задачи может быть необратимо. Проверьте её назначение вручную."
        )
        if not self._audit_confirmation("Подтвердите удаление задачи", message):
            return
        self._audit_task_change = (task, "delete")
        started = self._start_audit_task(
            "audit_task_change", f"Удаление задачи {task.path}", "change_task", task, "delete"
        )
        if not started:
            self._audit_task_change = None

    def _show_selected_task_details(self) -> None:
        task = self._selected_task()
        if task is None:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Задача: {task.path}")
        layout = QVBoxLayout(dialog)
        details = QPlainTextEdit(dialog)
        details.setReadOnly(True)
        details.setPlainText(
            f"Путь: {task.path}\nИмя: {task.name}\nПапка: {task.folder}\n"
            f"Создана: {task.created}\nСледующий запуск: {task.next_run}\n"
            f"Автор: {task.author}\nОписание: {task.description}\n"
            f"Команда: {task.command}\n\nXML:\n{task.xml}"
        )
        layout.addWidget(details)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, dialog)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.resize(760, 520)
        dialog.exec()

    def _show_task_context_menu(self, position: Any) -> None:
        item = self.task_table.itemAt(position)
        if item is not None:
            self.task_table.selectRow(item.row())
        if self._selected_task() is None:
            return
        menu = QMenu(self)
        for title, slot in (
            ("Удалить выбранную…", self._delete_selected_task),
            ("Подробности / XML", self._show_selected_task_details),
        ):
            action = menu.addAction(title)
            action.triggered.connect(slot)
        menu.exec(self.task_table.viewport().mapToGlobal(position))

    def _choose_files_root(self) -> None:
        root = QFileDialog.getExistingDirectory(
            self, "Корневая папка для анализа", self.files_root.text().strip()
        )
        if root:
            self.files_root.setText(root)

    def _scan_files(self) -> None:
        root = self.files_root.text().strip()
        if not root:
            self._audit_message("WARN", "Сначала выберите корневую папку для анализа файлов.")
            return
        minutes = self.files_minutes.value()
        self._audit_file_scan_kind = "scan"
        self._start_audit_task(
            "audit_files_scan", "Анализ изменённых файлов", "files", root, minutes
        )

    def _render_file_scan(self, result: FileScan, *, kind: str = "scan") -> None:
        self._audit_file_scan = result
        self._audit_file_scan_kind = kind
        table = self.files_table
        blocker = QSignalBlocker(table)
        table.setRowCount(0)
        for entry in result.entries:
            row = table.rowCount()
            table.insertRow(row)
            path_item = self._audit_cell(entry.path, tooltip=entry.path, mono=True)
            path_item.setData(Qt.ItemDataRole.UserRole, entry)
            values = (
                path_item,
                self._audit_cell(f"{entry.size:,}".replace(",", " ")),
                self._audit_cell(self._audit_ns_time(entry.modified_ns)),
                self._audit_cell(self._audit_ns_time(entry.created_ns)),
                self._audit_cell("Скрытый" if entry.hidden else "—"),
            )
            for column, cell in enumerate(values):
                table.setItem(row, column, cell)
        del blocker
        errors = "; ".join(str(error) for error in result.errors[:4])
        if len(result.errors) > 4:
            errors += f"; ещё ошибок: {len(result.errors) - 4}"
        prefix = "Найдено совпадений" if kind == "duplicates" else "Найдено файлов"
        pieces = [f"{prefix}: {len(result.entries)}", f"обойдёно элементов: {result.visited}"]
        if result.truncated:
            pieces.append("результат ограничен лимитом движка")
        if errors:
            pieces.append(f"ошибки: {errors}")
        self.files_status.setText("; ".join(pieces))
        self._refresh_audit_controls()

    def _selected_files(self) -> tuple[FileEntry, ...]:
        rows = self.files_table.selectionModel().selectedRows()
        entries: list[FileEntry] = []
        for selected in rows:
            item = self.files_table.item(selected.row(), 0)
            entry = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            if isinstance(entry, FileEntry):
                entries.append(entry)
        return tuple(entries)

    def _file_action(self, action: str) -> None:
        if action not in {"copy", "quarantine"}:
            self._audit_message("ERROR", "Доступны только копирование и карантин.")
            return
        entries = self._selected_files()
        if not entries:
            self._audit_message("WARN", "Выберите одну или несколько строк; скрытые строки не включаются.")
            return
        destination = ""
        if action == "copy":
            destination = QFileDialog.getExistingDirectory(self, "Папка назначения для копий", "")
            if not destination:
                return
        listing = "\n".join(entry.path for entry in entries[:12])
        if len(entries) > 12:
            listing += f"\n… ещё файлов: {len(entries) - 12}"
        description = (
            "Файлы будут скопированы в выбранную папку; исходники не удаляются."
            if action == "copy"
            else "Движок переместит только отмеченные файлы в карантин и создаст манифест. "
            "Принудительное удаление заблокированных файлов не выполняется."
        )
        if not self._audit_confirmation(
            "Подтвердите пакетную операцию",
            f"Операция: {action}\nВыбрано файлов: {len(entries)}\n{listing}\n\n{description}",
        ):
            return
        self._start_audit_task(
            "audit_file_action",
            f"{('Копирование' if action == 'copy' else 'Карантин')}: {len(entries)} файлов",
            "file_action",
            entries,
            action,
            destination,
        )

    def _restore_quarantine(self) -> None:
        if not self._authorize_mutation():
            return
        manifest, _filter = QFileDialog.getOpenFileName(
            self, "Выберите манифест карантина", "", "Манифест карантина (*.json);;Все файлы (*)"
        )
        if not manifest:
            return
        if not self._confirm(
            "Подтвердите восстановление из карантина",
            f"Будут восстановлены файлы по манифесту:\n{manifest}\n\n"
            "Выбирайте только манифест, созданный доверенным движком. Проверка целостности "
            "и конфликтов выполняется движком.",
        ):
            return
        self._start_audit_task(
            "audit_quarantine_restore", "Восстановление карантина", "restore_quarantine", manifest
        )

    def _open_selected_file_location(self) -> None:
        entries = self._selected_files()
        if entries:
            self._start_audit_task(
                "audit_open_location", "Открытие расположения файла", "open_location", entries[0].path
            )

    def _show_file_context_menu(self, position: Any) -> None:
        item = self.files_table.itemAt(position)
        if item is not None and not item.isSelected():
            item.setSelected(True)
        if not self._selected_files():
            return
        menu = QMenu(self)
        for title, slot in (
            ("Копировать выбранные…", lambda: self._file_action("copy")),
            ("В карантин…", lambda: self._file_action("quarantine")),
            ("Открыть расположение", self._open_selected_file_location),
        ):
            action = menu.addAction(title)
            action.triggered.connect(slot)
        menu.exec(self.files_table.viewport().mapToGlobal(position))

    def _run_system_action(self, action: str) -> None:
        labels = {
            "sfc": (
                "Запуск проверки системных файлов",
                "SFC проверит защищённые файлы Windows и может восстановить их из хранилища компонентов. "
                "Перед запуском обязательно создаётся новая точка восстановления Windows. Если "
                "Windows не сможет создать её (например, из-за квоты/лимита хранилища защиты "
                "системы), сканирование не начнётся. Операция займёт время и не отменяется бэкапом.",
            ),
            "diskmgmt": ("Открытие управления дисками", "Будет открыто штатное средство Windows."),
            "recovery": (
                "Перезагрузка в среду восстановления",
                "Windows будет перезагружена в WinRE. Сохраните документы; удалённое соединение прервётся.",
            ),
            "safe": (
                "Параметры запуска Safe Mode",
                "Windows откроет дополнительные параметры запуска; выберите Safe Mode на экране "
                "параметров загрузки. BCD напрямую не изменяется. Сохраните документы.",
            ),
            "uefi": (
                "Перезагрузка в UEFI / BIOS",
                "Windows будет перезагружена в настройки прошивки. Сохраните документы; удалённый "
                "доступ может быть потерян.",
            ),
            "cancel_restart": (
                "Отмена запланированной перезагрузки",
                "Будет отправлен запрос на отмену запланированного Windows перезапуска; уже "
                "выполняющаяся перезагрузка может быть неотменима.",
            ),
            "appearance": (
                "Открыть настройки темы Windows",
                "Откроются штатные параметры темы. Утилита не выполняет принудительный сброс "
                "шрифтов или записей реестра.",
            ),
        }
        item = labels.get(action)
        if item is None:
            self._audit_message("ERROR", f"Неизвестное системное действие: {action}")
            return
        title, warning = item
        if action == "diskmgmt":
            self._start_audit_task("audit_system", title, "system", action)
            return
        confirmed = (
            self._confirm(title, warning)
            if action == "appearance"
            else self._audit_confirmation(title, warning)
        )
        if not confirmed:
            self._append_log("INFO", f"Операция «{title}» отменена пользователем.")
            return
        self._start_audit_task("audit_system", title, "system", action)

    def _refresh_audit_controls(self, *_args: object) -> None:
        if not hasattr(self, "audit_process_scan_button"):
            return
        busy = bool(getattr(self, "_busy", False))
        admin = bool(getattr(self, "_is_admin", False))
        mutable = admin and not busy
        self.audit_process_scan_button.setEnabled(not busy)
        process = self._selected_audit_process()
        has_process = process is not None
        self.audit_process_kill_button.setEnabled(mutable and has_process)
        self.audit_process_tree_button.setEnabled(mutable and has_process)
        self.audit_process_suspend_button.setEnabled(mutable and has_process)
        self.audit_process_resume_button.setEnabled(mutable and has_process)
        self.audit_process_open_button.setEnabled(not busy and has_process and bool(process.path))
        self.audit_process_duplicates_button.setEnabled(not busy and has_process and bool(process.path))

        startup = self._selected_startup() if hasattr(self, "startup_table") else None
        self.startup_scan_button.setEnabled(not busy)
        self.startup_edit_button.setEnabled(mutable and startup is not None and startup.address is not None)
        self.startup_remove_button.setEnabled(mutable and startup is not None)
        self.startup_registry_button.setEnabled(not busy and startup is not None and startup.address is not None)
        self.startup_location_button.setEnabled(not busy and startup is not None and bool(startup.path))

        service = self._selected_service() if hasattr(self, "audit_services_table") else None
        self.service_scan_button.setEnabled(not busy)
        for button in (
            self.service_start_button,
            self.service_stop_button,
            self.service_start_type_button,
        ):
            button.setEnabled(mutable and service is not None)
        self.service_delete_button.setEnabled(
            mutable
            and service is not None
            and str(service.state).strip().casefold() in {"stopped", "остановлена", "остановлено"}
        )
        self.service_open_button.setEnabled(not busy and service is not None and bool(self._service_executable(service.command)))

        listing = self._audit_registry_listing
        selected_value = self._selected_registry_value() if hasattr(self, "registry_values_table") else None
        hive, _registry_path, _view, mount_key = (
            self._registry_context() if hasattr(self, "registry_hive") else ("", "", 64, "")
        )
        self.registry_browse_button.setEnabled(not busy)
        self.registry_up_button.setEnabled(not busy and bool(self.registry_key.text().strip()))
        self.registry_mount_button.setEnabled(mutable and not getattr(self, "_is_demo", False))
        self.registry_unmount_button.setEnabled(mutable and mount_key in self._audit_mounts)
        self.registry_restore_button.setEnabled(mutable)
        editable_listing = listing is not None and bool(listing.key)
        self.registry_add_value_button.setEnabled(mutable and editable_listing)
        self.registry_edit_value_button.setEnabled(mutable and editable_listing and selected_value is not None)
        self.registry_delete_value_button.setEnabled(mutable and editable_listing and selected_value is not None)
        self.registry_open_button.setEnabled(not busy and editable_listing)
        self.registry_hive.setEnabled(not busy)
        self.registry_key.setEnabled(not busy)
        self.registry_view.setEnabled(not busy)

        self.task_scan_button.setEnabled(not busy)
        selected_task = self._selected_task()
        self.task_delete_button.setEnabled(
            mutable and selected_task is not None and not self._task_read_only(selected_task)
        )
        self.task_details_button.setEnabled(not busy and self._selected_task() is not None)
        self.task_tree.setEnabled(not busy)
        self.task_table.setEnabled(not busy)

        root = self.files_root.text().strip()
        self.process_filter.setEnabled(not busy)
        for control in (
            self.hide_trusted_processes,
            self.suspicious_processes_only,
            self.signed_processes_only,
            self.group_duplicate_processes,
        ):
            control.setEnabled(not busy)
        self.files_choose_root_button.setEnabled(not busy)
        self.files_root.setEnabled(not busy)
        self.files_minutes.setEnabled(not busy)
        self.files_scan_button.setEnabled(not busy and bool(root))
        selected_files = self._selected_files()
        self.files_copy_button.setEnabled(mutable and bool(selected_files))
        self.files_quarantine_button.setEnabled(mutable and bool(selected_files))
        self.files_restore_quarantine_button.setEnabled(mutable)
        self.files_open_button.setEnabled(not busy and bool(selected_files))
        self.files_table.setEnabled(not busy)

        for action, button in self.system_action_buttons.items():
            button.setEnabled(not busy and (action in {"diskmgmt", "appearance"} or admin))

        for widget in (
            self.startup_table,
            self.audit_services_table,
            self.registry_subkeys_table,
            self.registry_values_table,
        ):
            widget.setEnabled(not busy)

    def _invalidate_audit(self, area: str) -> None:
        if area == "processes":
            self._audit_processes = []
            if hasattr(self, "_processes"):
                self._processes = []
            self.process_table.setRowCount(0)
            self._audit_message("WARN", "Снимок процессов устарел и очищен; обновите аудит вручную.")
        elif area == "startup":
            self._audit_startup_entries = []
            self.startup_table.setRowCount(0)
            self._audit_message("WARN", "Снимок автозагрузки очищен после изменения; сканируйте повторно.")
        elif area == "services":
            self._audit_services = []
            self.audit_services_table.setRowCount(0)
            self._audit_message("WARN", "Снимок служб очищен после изменения; сканируйте повторно.")
        elif area == "registry":
            self._audit_registry_listing = None
            self.registry_subkeys_table.setRowCount(0)
            self.registry_values_table.setRowCount(0)
            self.registry_current_label.setText("Данные устарели; повторно откройте ключ")
            self._audit_message("WARN", "Представление реестра очищено после изменения; откройте ключ повторно.")
        elif area == "files":
            self._audit_file_scan = None
            self.files_table.setRowCount(0)
            self.files_status.setText("Снимок очищен после операции; выполните сканирование повторно.")
            self._audit_message("WARN", "Снимок файлов очищен после операции; выполните сканирование повторно.")

    def _handle_audit_outcome(self, operation: str, result: object, error: str) -> bool:
        handled = operation.startswith("audit_") or operation == "tree_plan"
        try:
            return self._dispatch_audit_outcome(operation, result, error)
        except Exception as exc:
            if not handled:
                return False
            self._operation_failed = True
            message = f"Ошибка обработки результата аудита {operation}: {type(exc).__name__}: {exc}"
            try:
                self._append_log("ERROR", message)
            except Exception:
                pass
            label = getattr(self, "log_state_label", None)
            try:
                if label is not None:
                    label.setText("ошибка")
                    label.setStyleSheet(f"color: {_RED};")
            except Exception:
                pass
            status_bar = getattr(self, "statusBar", None)
            try:
                if callable(status_bar):
                    status_bar().showMessage(message, 12000)
            except Exception:
                pass
            return True

    def _dispatch_audit_outcome(self, operation: str, result: object, error: str) -> bool:
        if operation == "tree_plan":
            operation = "audit_tree_plan"
        if not operation.startswith("audit_"):
            return False
        if error:
            if operation == "audit_task_change":
                self._audit_task_change = None
            if operation == "audit_hive_unmount":
                self._audit_unmounting = None
            self._operation_failed = True
            self._audit_message("ERROR", f"{operation}: {error}")
            if hasattr(self, "log_state_label"):
                self.log_state_label.setText("ошибка")
                self.log_state_label.setStyleSheet(f"color: {_RED};")
            return True
        if result is False:
            self._operation_failed = True
            self._audit_message("ERROR", f"{operation}: движок не подтвердил выполнение операции.")
            if operation == "audit_task_change":
                self._audit_task_change = None
                self._render_audit_tasks()
            if operation == "audit_hive_unmount":
                self._audit_unmounting = None
            return True
        try:
            if operation == "audit_process_scan":
                if not isinstance(result, (tuple, list)) or any(
                    not isinstance(process, ProcessInfo) for process in result
                ):
                    raise TypeError("Аудит процессов вернул неподдерживаемый результат.")
                self._audit_processes = list(result)
                self._processes = list(result)
                self._render_audit_processes()
                partial = self._audit_items_have_read_errors(result) or bool(self._audit_worker_read_errors)
                if partial and hasattr(self, "process_note"):
                    self.process_note.setText(
                        "Часть метаданных процессов недоступна; результат может быть неполным. "
                        "Подробности — в журнале."
                    )
                self._report_audit_read(
                    "Загружено процессов", len(result), partial
                )
            elif operation == "audit_tree_plan":
                self._review_process_tree_plan(result)
            elif operation in {"audit_process_action", "audit_tree_kill"}:
                self._invalidate_audit("processes")
                self._audit_message("SUCCESS", "Действие над процессом подтверждено движком.")
            elif operation == "audit_startup_scan":
                if not isinstance(result, (tuple, list)) or any(
                    not isinstance(entry, StartupEntry) for entry in result
                ):
                    raise TypeError("Аудит автозагрузки вернул неподдерживаемый результат.")
                self._render_startup(list(result))
                partial = self._audit_items_have_read_errors(result) or bool(self._audit_worker_read_errors)
                if partial:
                    self.startup_note.setText(
                        f"Найдено записей: {len(result)}. Некоторые расположения недоступны; "
                        "результат может быть неполным. Подробности — в журнале."
                    )
                self._report_audit_read("Найдено записей автозагрузки", len(result), partial)
            elif operation == "audit_startup_edit":
                self._invalidate_audit("startup")
                self._audit_message("SUCCESS", "Изменение автозагрузки подтверждено движком.")
            elif operation == "audit_services_scan":
                if not isinstance(result, (tuple, list)) or any(
                    not isinstance(service, ServiceInfo) for service in result
                ):
                    raise TypeError("Аудит служб вернул неподдерживаемый результат.")
                self._audit_services = list(result)
                self._render_audit_services()
                partial = self._audit_items_have_read_errors(result) or bool(self._audit_worker_read_errors)
                if partial:
                    self.service_audit_note.setText(
                        f"Найдено служб: {len(result)}. Не все сведения служб доступны; "
                        "результат может быть неполным. Подробности — в журнале."
                    )
                self._report_audit_read("Найдено служб", len(result), partial)
            elif operation == "audit_service_action":
                self._invalidate_audit("services")
                self._audit_message("SUCCESS", "Изменение службы подтверждено движком.")
            elif operation == "audit_tasks_scan":
                if not isinstance(result, (tuple, list)) or any(
                    not isinstance(task, TaskInfo) for task in result
                ):
                    raise TypeError("Аудит задач вернул неподдерживаемый результат.")
                self._audit_tasks = list(result)
                self._render_task_tree()
                self._render_audit_tasks()
                partial = self._audit_items_have_read_errors(result) or bool(self._audit_worker_read_errors)
                self.scheduler_note.setText(
                    f"Найдено задач: {len(result)}. Переключение требует подтверждения."
                    + (" Есть неполные сведения; подробности — в журнале." if partial else "")
                )
                self._report_audit_read("Найдено задач планировщика", len(result), partial)
            elif operation == "audit_task_change":
                self._finish_task_change(result)
            elif operation == "audit_registry_scan":
                if not isinstance(result, RegistryListing):
                    raise TypeError("Обозреватель реестра вернул неподдерживаемый результат.")
                self._render_registry_listing(result)
                partial = bool(self._audit_worker_read_errors)
                if partial:
                    self.registry_note.setText(
                        f"Ключ прочитан: {result.hive}\\{result.key} [{result.view}]. "
                        "В журнале есть ошибки чтения; результат может быть неполным."
                    )
                self._report_audit_read(
                    f"Прочитан ключ {result.hive}\\{result.key} [{result.view}]",
                    len(result.subkeys) + len(result.values),
                    partial,
                )
            elif operation == "audit_registry_edit":
                self._invalidate_audit("registry")
                self._audit_message("SUCCESS", "Изменение реестра подтверждено движком.")
            elif operation == "audit_registry_restore":
                self._invalidate_audit("registry")
                self._audit_message(
                    "SUCCESS",
                    f"Значение реестра восстановлено; новое состояние сохранено в {result}.",
                )
            elif operation == "audit_hive_mount":
                if not isinstance(result, HiveMount):
                    raise TypeError("Подключение offline hive вернуло неподдерживаемый результат.")
                self._render_mount(result)
                self._audit_message("SUCCESS", f"Рабочая копия offline hive подключена: {result.key}.")
            elif operation == "audit_hive_unmount":
                mount = self._audit_unmounting
                if mount is not None:
                    self._forget_mount(mount)
                self._audit_unmounting = None
                self._audit_message("SUCCESS", "Рабочая копия offline hive выгружена.")
            elif operation in {"audit_files_scan", "audit_duplicates"}:
                if not isinstance(result, FileScan):
                    raise TypeError("Сканирование файлов вернуло неподдерживаемый результат.")
                kind = "duplicates" if operation == "audit_duplicates" else "scan"
                self._render_file_scan(result, kind=kind)
                partial = bool(result.errors or result.truncated or self._audit_worker_read_errors)
                if self._audit_worker_read_errors:
                    self.files_status.setText(
                        self.files_status.text()
                        + f"; ошибки фонового чтения: {len(self._audit_worker_read_errors)} (подробности — в журнале)"
                    )
                self._report_audit_read(
                    "Получено файлов",
                    len(result.entries),
                    partial,
                )
            elif operation in {"audit_file_action", "audit_quarantine_restore"}:
                self._invalidate_audit("files")
                self._audit_message("SUCCESS", "Операция с файлами подтверждена движком.")
            elif operation == "audit_system":
                details = f" Результат: {result}" if isinstance(result, str) and result else ""
                self._audit_message("SUCCESS", f"Системная операция передана/завершена движком.{details}")
            elif operation in {"audit_open_location", "audit_open_registry"}:
                self._audit_message("SUCCESS", "Запрос открытия передан движку.")
            else:
                raise ValueError(f"Необработанный результат аудита: {operation}")
        except Exception as exc:
            self._operation_failed = True
            self._audit_message("ERROR", f"Ошибка отображения результата аудита: {type(exc).__name__}: {exc}")
            if hasattr(self, "log_state_label"):
                self.log_state_label.setText("ошибка")
                self.log_state_label.setStyleSheet(f"color: {_RED};")
        self._refresh_audit_controls()
        return True

    def _finish_task_change(self, result: object) -> None:
        pending = self._audit_task_change
        self._audit_task_change = None
        if pending is None:
            raise RuntimeError("Не найдено ожидающее подтверждения изменение задачи.")
        original, action = pending
        if action == "delete":
            self._audit_tasks = [task for task in self._audit_tasks if task.path != original.path]
            self._render_task_tree()
        else:
            updated = result if isinstance(result, TaskInfo) else replace(
                original,
                enabled=action == "enable",
                status="Изменено; обновите сведения и XML повторным сканированием",
            )
            if updated.path != original.path or updated.enabled != (action == "enable"):
                raise RuntimeError("Ответ движка не подтверждает ожидаемое состояние задачи.")
            self._audit_tasks = [updated if task.path == original.path else task for task in self._audit_tasks]
        self._render_audit_tasks()
        self.scheduler_note.setText(
            "Состояние задачи обновлено после ответа движка. Метаданные и XML могут быть устаревшими; "
            "повторно сканируйте для проверки."
        )
        self._audit_message("SUCCESS", f"Состояние задачи {original.path} обновлено после ответа движка.")

    def _show_critical_read_only(self) -> None:
        self._explain_critical_flag()
