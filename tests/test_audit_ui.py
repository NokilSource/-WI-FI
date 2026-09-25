from __future__ import annotations

import threading
from pathlib import Path

import pytest
from PyQt6.QtCore import QItemSelectionModel, Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTableWidget,
    QTabWidget,
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
from system_repair.audit_ui import AuditUiMixin
from system_repair.demo import DemoPlatform
from system_repair.engine import RepairEngine
from system_repair.model import ProcessInfo, RegistryAddress, RegistryValue
from system_repair.ui import MainWindow


def _process(
    pid: int,
    path: str,
    *,
    critical: bool | None = False,
    signature: str = "NotSigned",
    trusted: bool = False,
    hidden: bool = False,
) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        name=path.replace("/", "\\").rsplit("\\", 1)[-1],
        path=path,
        user="LAB\\User",
        created=1_700_000_000 + pid,
        critical=critical,
        company="Lab Publisher",
        command_line=f'"{path}" --audit-test',
        signature=signature,
        parent_pid=1,
        hidden=hidden,
        trusted=trusted,
    )


class FakeAudit:
    def __init__(self) -> None:
        self.process_items: list[ProcessInfo] = []
        self.tree_plan: tuple[ProcessInfo, ...] = ()
        self.startup_items: list[StartupEntry] = []
        self.task_items: list[TaskInfo] = []
        self.service_items: list[ServiceInfo] = []
        self.file_items: tuple[FileEntry, ...] = ()
        self.registry_values: dict[str, RegistryValue] = {"Run": RegistryValue(1, "old.exe")}
        self.mount = HiveMount("SystemRepairOffline_test", "offline.hiv", "working.hiv", "backup.json")
        self.task_scan_error = False
        self.calls: list[tuple[object, ...]] = []

    def processes(self, log):
        log("INFO", "Synthetic process scan")
        return list(self.process_items)

    def process_action(self, process, action, log):
        self.calls.append(("process_action", process, action))
        log("INFO", action)

    def process_tree(self, process, log):
        self.calls.append(("process_tree", process))
        return self.tree_plan or (process,)

    def kill_tree(self, plan, log):
        self.calls.append(("kill_tree", plan))

    def startup(self, log):
        return list(self.startup_items)

    def edit_startup(self, entry, value, log):
        self.calls.append(("edit_startup", entry, value))

    def tasks(self, log):
        if self.task_scan_error:
            log("ERROR", "synthetic inaccessible task folder")
        return list(self.task_items)

    def change_task(self, task, action, log):
        self.calls.append(("change_task", task, action))
        return Path("task-backup.json")

    def services(self, log):
        return list(self.service_items)

    def change_service(self, service, action, log):
        self.calls.append(("change_service", service, action))
        return Path("service-backup.json")

    def registry(self, hive, key, view, log):
        self.calls.append(("registry", hive, key, view))
        return RegistryListing(hive, key, view, ("Child",), dict(self.registry_values))

    def edit_registry(self, address, old, new, log):
        self.calls.append(("edit_registry", address, old, new))

    def mount_hive(self, path, log):
        self.calls.append(("mount_hive", path))
        return self.mount

    def unmount_hive(self, mount, log):
        self.calls.append(("unmount_hive", mount))

    def files(self, root, minutes, log):
        self.calls.append(("files", root, minutes))
        return FileScan(self.file_items, len(self.file_items), ("inaccessible folder",), True)

    def duplicates(self, path, root, log):
        self.calls.append(("duplicates", path, root))
        return FileScan(self.file_items, len(self.file_items))

    def file_action(self, entries, action, destination, log):
        self.calls.append(("file_action", entries, action, destination))

    def restore_quarantine(self, manifest, log):
        self.calls.append(("restore_quarantine", manifest))

    def restore_registry(self, manifest, log):
        self.calls.append(("restore_registry", manifest))
        return Path("registry-backup-after-restore.json")

    def system(self, action, log):
        self.calls.append(("system", action))

    def open_location(self, path, log):
        self.calls.append(("open_location", path))

    def open_registry(self, address, log):
        self.calls.append(("open_registry", address))


class AuditHarness(AuditUiMixin, QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.audit = FakeAudit()
        self._is_admin = True
        self._busy = False
        self._operation_failed = False
        self._processes: list[ProcessInfo] = []
        self.confirm_result = True
        self.confirmations: list[tuple[str, str]] = []
        self.logs: list[tuple[str, str]] = []

        self.tabs = QTabWidget(self)
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(QWidget(), "Исправления")
        self.tabs.addTab(QWidget(), "Автозагрузка / IFEO")

        service_page = QWidget()
        service_layout = QVBoxLayout(service_page)
        service_layout.addWidget(QLabel("Legacy service summary"))
        self.services_table = QTableWidget(0, 5, service_page)
        service_layout.addWidget(self.services_table)
        self.tabs.addTab(service_page, "Службы")

        process_page = QWidget()
        process_layout = QVBoxLayout(process_page)
        controls = QHBoxLayout()
        self.process_filter = QLineEdit(process_page)
        self.terminate_process_button = QPushButton("Завершить", process_page)
        controls.addWidget(self.process_filter)
        controls.addWidget(self.terminate_process_button)
        process_layout.addLayout(controls)
        self.process_note = QLabel("Process note", process_page)
        process_layout.addWidget(self.process_note)
        self.process_table = self._audit_table(
            ("PID", "Имя", "Путь образа", "Пользователь", "Запущен", "Статус"), "processTable"
        )
        self.process_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        process_layout.addWidget(self.process_table)
        self.tabs.addTab(process_page, "Процессы")

        self.log_state_label = QLabel("готово")
        self._build_audit_ui()

    def _append_log(self, level: str, message: str) -> None:
        self.logs.append((level, message))

    def _confirm(self, title: str, text: str) -> bool:
        self.confirmations.append((title, text))
        return self.confirm_result

    def _authorize_mutation(self) -> bool:
        return self._is_admin and not self._busy

    def _refresh_action_controls(self) -> None:
        self._refresh_audit_controls()

    def _start_task(self, operation, _label, function, *args):
        if self._busy:
            return False
        self._busy = True
        self._refresh_audit_controls()
        try:
            result = function(*args, self._append_log)
            error = ""
        except Exception as exc:  # The real host forwards worker errors to the same handler.
            result = None
            error = f"{type(exc).__name__}: {exc}"
        self._busy = False
        assert self._handle_audit_outcome(operation, result, error)
        self._refresh_action_controls()
        return True


@pytest.fixture
def window(qtbot):
    widget = AuditHarness()
    qtbot.addWidget(widget)
    widget.show()
    return widget


def _select_process(window: AuditHarness, pid: int) -> None:
    for row in range(window.process_table.rowCount()):
        if window.process_table.item(row, 0).text() == str(pid):
            window.process_table.selectRow(row)
            return
    raise AssertionError(f"PID {pid} not found")


def test_process_path_column_resets_inherited_stretch_before_width_is_applied(window):
    assert window.process_table.horizontalHeader().sectionResizeMode(2) == QHeaderView.ResizeMode.Interactive
    assert window.process_table.columnWidth(2) == 360
    assert window.terminate_process_button.isHidden()


def test_process_audit_filters_signed_suspicious_and_trusted_rows(window):
    temp = _process(110, r"C:\Users\Lab\AppData\Local\Temp\worker.exe")
    temp_copy = _process(111, temp.path)
    trusted = _process(112, r"C:\Windows\System32\explorer.exe", signature="Valid", trusted=True)
    hidden = _process(113, r"C:\ProgramData\.cache\agent.exe", signature="Valid", hidden=True)
    window.audit.process_items = [temp, temp_copy, trusted, hidden]

    window.audit_process_scan_button.click()

    assert window.process_table.rowCount() == 3
    columns = window._audit_process_columns
    assert all(window.process_table.item(row, 0).text() != "112" for row in range(3))
    temp_row = next(
        row for row in range(window.process_table.rowCount()) if window.process_table.item(row, 0).text() == "110"
    )
    assert window.process_table.item(temp_row, columns["same path"]).text() == "x2"
    assert window.process_table.item(temp_row, columns["command line"]).text().endswith("--audit-test")

    window.suspicious_processes_only.setChecked(True)
    assert window.process_table.rowCount() == 3
    window.signed_processes_only.setChecked(True)
    assert window.process_table.rowCount() == 1
    assert window.process_table.item(0, 0).text() == "113"


def test_tree_kill_requires_confirmation_with_frozen_pid_path_listing(window):
    root = _process(201, r"C:\Apps\parent.exe")
    child = _process(202, r"C:\Apps\child.exe")
    window.audit.process_items = [root, child]
    window.audit.tree_plan = (child, root)
    window.audit_process_scan_button.click()
    _select_process(window, root.pid)
    window.confirm_result = False

    window.audit_process_tree_button.click()

    assert window.audit.calls[0] == ("process_tree", root)
    assert not any(call[0] == "kill_tree" for call in window.audit.calls)
    prompt = window.confirmations[-1][1]
    assert "PID 201" in prompt and "PID 202" in prompt
    assert root.path in prompt and child.path in prompt
    assert "фиксированный план" in prompt


def test_tree_kill_uses_confirmed_plan_after_planning_worker_finishes(window, qtbot):
    root = _process(211, r"C:\Apps\parent.exe")
    child = _process(212, r"C:\Apps\child.exe")
    plan = (child, root)
    window.audit.process_items = [root, child]
    window.audit.tree_plan = plan
    window.audit_process_scan_button.click()
    _select_process(window, root.pid)

    window.audit_process_tree_button.click()
    qtbot.waitUntil(lambda: any(call[0] == "kill_tree" for call in window.audit.calls), timeout=1500)

    kill_call = next(call for call in window.audit.calls if call[0] == "kill_tree")
    assert kill_call[1] == plan
    assert window.process_table.rowCount() == 0


def test_startup_edit_uses_typed_value_and_requires_confirmation(window, monkeypatch):
    address = RegistryAddress("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Updater")
    entry = StartupEntry("Updater", address.label, "old.exe", "Run", address, RegistryValue(1, "old.exe"))
    window.audit.startup_items = [entry]
    window.startup_scan_button.click()
    window.startup_table.selectRow(0)
    updated = RegistryValue(2, r"%LOCALAPPDATA%\new.exe")
    monkeypatch.setattr(window, "_registry_value_dialog", lambda _old: updated)
    window.confirm_result = True

    window.startup_edit_button.click()

    call = next(call for call in window.audit.calls if call[0] == "edit_startup")
    assert call[1:] == (entry, updated)
    assert "Updater" in window.confirmations[-1][1]
    assert window.startup_table.rowCount() == 0


def test_registry_editor_keeps_address_and_old_value_from_selected_listing(window, monkeypatch):
    old = window.audit.registry_values["Run"]
    new = RegistryValue(3, b"\x01\x02")
    window.registry_key.setText(r"Software\Microsoft\Windows\CurrentVersion\Run")
    window._browse_registry()
    window.registry_values_table.selectRow(0)
    monkeypatch.setattr(window, "_registry_value_dialog", lambda _value: new)

    window.registry_edit_value_button.click()

    call = next(call for call in window.audit.calls if call[0] == "edit_registry")
    assert call[1:] == (
        RegistryAddress("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run", 64),
        old,
        new,
    )
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Run" in window.confirmations[-1][1]
    assert window._audit_registry_listing is None


def test_task_checkbox_reverts_on_cancel_then_updates_only_after_backend_success(window):
    task = TaskInfo(
        r"\Vendor\Updater",
        "Updater",
        r"\Vendor",
        False,
        "created",
        "next",
        "Vendor",
        "Updates software",
        '"C:\\Apps\\Updater.exe"',
        "<Task />",
    )
    window.audit.task_items = [task]
    window.task_scan_button.click()
    window.confirm_result = False

    item = window.task_table.item(0, 2)
    item.setCheckState(Qt.CheckState.Checked)
    assert window.task_table.item(0, 2).checkState() == Qt.CheckState.Unchecked
    assert not any(call[0] == "change_task" for call in window.audit.calls)

    window.confirm_result = True
    window.task_table.item(0, 2).setCheckState(Qt.CheckState.Checked)
    call = next(call for call in window.audit.calls if call[0] == "change_task")
    assert call[1:] == (task, "enable")
    assert window.task_table.item(0, 2).checkState() == Qt.CheckState.Checked
    assert "XML могут быть устаревшими" in window.scheduler_note.text()


def test_microsoft_windows_tasks_are_visible_but_read_only(window):
    protected = TaskInfo(
        r"\Microsoft\Windows\Update\Task",
        "Task",
        r"\Microsoft\Windows\Update",
        True,
        "created",
        "next",
        "Microsoft",
        "System task",
        "system.exe",
        "<Task />",
    )
    window.audit.task_items = [protected]

    window.task_scan_button.click()
    window.task_table.selectRow(0)

    assert not window.task_table.item(0, 2).flags() & Qt.ItemFlag.ItemIsUserCheckable
    assert not window.task_delete_button.isEnabled()
    assert window.task_table.rowCount() == 1


def test_offline_registry_mount_browses_under_hklm_working_copy(window, monkeypatch):
    monkeypatch.setattr(
        "system_repair.audit_ui.QFileDialog.getOpenFileName",
        lambda *_args: ("offline.hiv", ""),
    )

    window._choose_hive_to_mount()

    assert window.registry_hive.currentData() == ("HKLM", window.audit.mount.key)
    window.registry_key.setText("Software")
    assert window._registry_context() == (
        "HKLM",
        window.audit.mount.key + r"\Software",
        64,
        window.audit.mount.key,
    )
    window._browse_registry()

    assert window.audit.calls[-1] == (
        "registry",
        "HKLM",
        window.audit.mount.key + r"\Software",
        64,
    )
    assert window.registry_key.text() == "Software"
    assert window._current_registry_address("Run").key == window.audit.mount.key + r"\Software"

    window._unmount_selected_hive()

    assert window.audit.calls[-1] == ("unmount_hive", window.audit.mount)
    assert window.audit.mount.key not in window._audit_mounts
    assert window.registry_hive.currentData() == "HKCU"


def test_file_scan_reports_limits_and_batch_action_receives_only_selected_rows(window):
    first = FileEntry(r"C:\Temp\one.exe", 10, 1, 2, 1, 1)
    second = FileEntry(r"C:\Temp\two.exe", 20, 3, 4, 1, 2)
    third = FileEntry(r"C:\Temp\three.exe", 30, 5, 6, 1, 3)
    window.audit.file_items = (first, second, third)
    window.files_root.setText(r"C:\Temp")

    window.files_scan_button.click()

    assert window.audit.calls[-1] == ("files", r"C:\Temp", 60)
    assert "ограничен лимитом движка" in window.files_status.text()
    assert "inaccessible folder" in window.files_status.text()
    assert window.logs[-1][0] == "WARN"
    assert window._operation_failed
    selection = window.files_table.selectionModel()
    for row in (0, 2):
        selection.select(
            window.files_table.model().index(row, 0),
            QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
        )
    window.confirm_result = True

    window.files_quarantine_button.click()

    call = next(call for call in window.audit.calls if call[0] == "file_action")
    assert call[1:] == ((first, third), "quarantine", "")
    assert "Выбрано файлов: 2" in window.confirmations[-1][1]
    assert window.files_table.rowCount() == 0


def test_system_reboot_is_confirmed_but_disk_manager_is_a_direct_read_action(window):
    window.confirm_result = False
    window._run_system_action("sfc")
    assert not any(call[0] == "system" for call in window.audit.calls)
    sfc_warning = window.confirmations[-1][1].casefold()
    assert "обязательно" in sfc_warning and "точка восстановления" in sfc_warning
    assert "квот" in sfc_warning and "сканирование не начнётся" in sfc_warning

    window._run_system_action("safe")
    assert not any(call[0] == "system" for call in window.audit.calls)
    assert "Safe Mode" in window.confirmations[-1][0]

    window._run_system_action("diskmgmt")
    assert window.audit.calls[-1] == ("system", "diskmgmt")


def test_service_delete_confirmation_explains_manual_recovery_and_missing_password(window, monkeypatch):
    service = ServiceInfo(
        "LabSvc", "Lab service", 0, "manual", "stopped", "A test service", "LabSvc.exe"
    )
    window.audit.service_items = [service]
    window.service_scan_button.click()
    window.audit_services_table.selectRow(0)
    monkeypatch.setattr(QInputDialog, "getText", lambda *_args: (service.name, True))

    window.service_delete_button.click()

    assert window.audit.calls[-1] == ("change_service", service, "delete")
    warning = window.confirmations[-1][1].casefold()
    assert "не пересоздаёт объект службы" in warning
    assert "доверенного дистрибутива" in warning
    assert "пароль учётной записи службы не сохраняется" in warning


def test_registry_value_parser_enforces_types_and_integer_ranges():
    assert AuditUiMixin._parse_registry_value(3, "01 0A ff") == RegistryValue(3, b"\x01\x0a\xff")
    assert AuditUiMixin._parse_registry_value(7, "one\ntwo") == RegistryValue(7, ["one", "two"])
    with pytest.raises(ValueError, match="диапазон"):
        AuditUiMixin._parse_registry_value(4, "0x1_0000_0000")


def test_registry_action_manifest_restore_is_separate_from_repair_backup(window, monkeypatch):
    manifest = r"C:\Backups\actions\123\action.json"
    window._browse_registry()
    monkeypatch.setattr(
        "system_repair.audit_ui.QFileDialog.getOpenFileName",
        lambda *_args: (manifest, ""),
    )

    window._choose_registry_restore()

    assert window.audit.calls[-1] == ("restore_registry", manifest)
    assert "action.json" in window.confirmations[-1][1]
    assert "backup.json" in window.confirmations[-1][1]
    assert "registry-backup-after-restore.json" in window.logs[-1][1]
    assert window._audit_registry_listing is None


def test_partial_startup_and_service_reads_report_warning_not_success(window):
    window.audit.startup_items = [StartupEntry("Run", "HKCU", "run.exe", "Run", status="Ошибка")]

    window.startup_scan_button.click()

    assert window.logs[-1][0] == "WARN"
    assert window._operation_failed
    assert "может быть неполным" in window.startup_note.text()

    window._operation_failed = False
    window.audit.service_items = [
        ServiceInfo("Partial", "Partial service", 0, "manual", "running", "", "", error="Access denied")
    ]
    window.service_scan_button.click()

    assert window.logs[-1][0] == "WARN"
    assert window._operation_failed
    assert "Не все сведения служб доступны" in window.service_audit_note.text()


def test_partial_task_scan_log_is_reflected_in_status(window):
    window.audit.task_items = [
        TaskInfo(r"\Vendor\Task", "Task", r"\Vendor", True, "", "", "", "", "", "", "Готова")
    ]
    window.audit.task_scan_error = True

    window.task_scan_button.click()

    assert window._audit_worker_read_errors == ["synthetic inaccessible task folder"]
    assert window.logs[-1][0] == "WARN"
    assert window._operation_failed
    assert "результат может быть неполным" in window.logs[-1][1].casefold()


def test_audit_outcome_catches_unexpected_render_errors(window, monkeypatch):
    def fail_render(*_args):
        raise RuntimeError("synthetic renderer fault")

    monkeypatch.setattr(window, "_refresh_audit_controls", fail_render)

    assert window._handle_audit_outcome("audit_tasks_scan", [], "")

    assert window._operation_failed
    assert any(
        level == "ERROR" and "synthetic renderer fault" in message for level, message in window.logs
    )


def test_real_main_window_rescan_replaces_stale_process_snapshot_after_mutation(
    qtbot, tmp_path, monkeypatch
):
    window = MainWindow(RepairEngine(DemoPlatform(), tmp_path / "backups"), auto_scan=False)
    qtbot.addWidget(window)
    window.show()
    monkeypatch.setattr(window, "_confirm", lambda *_args: True)

    window.audit_process_scan_button.click()
    qtbot.waitUntil(lambda: not window._busy and window._thread is None, timeout=5000)
    assert window.process_table.rowCount() == 1
    assert window.process_table.item(0, 0).text() == "4120"
    window.process_table.selectRow(0)
    window.audit_process_kill_button.click()
    qtbot.waitUntil(lambda: not window._busy and window._thread is None, timeout=5000)
    assert window.process_table.rowCount() == 0

    window.scan_button.click()
    qtbot.waitUntil(lambda: not window._busy and window._thread is None, timeout=5000)

    assert [process.pid for process in window._audit_processes] == [3088]
    assert window.process_table.rowCount() == 1
    assert window.process_table.item(0, 0).text() == "3088"


def test_real_main_window_stays_open_until_owned_resources_are_cleaned(qtbot, tmp_path, monkeypatch):
    window = MainWindow(RepairEngine(DemoPlatform(), tmp_path / "backups"), auto_scan=False)
    qtbot.addWidget(window)
    window.show()
    window.audit.demo.suspended.add(4120)
    monkeypatch.setattr(window, "_confirm", lambda *_args: True)
    entered = threading.Event()
    release = threading.Event()
    cleanup = window.audit.cleanup

    def slow_cleanup(log):
        entered.set()
        if not release.wait(timeout=5):
            raise TimeoutError("Test did not release cleanup worker")
        cleanup(log)

    monkeypatch.setattr(window.audit, "cleanup", slow_cleanup)

    window.close()
    try:
        qtbot.waitUntil(entered.is_set, timeout=5000)
        assert window.isVisible()
        assert window.audit.has_resources
    finally:
        release.set()
    qtbot.waitUntil(lambda: not window._busy and window._thread is None, timeout=5000)
    qtbot.waitUntil(lambda: not window.isVisible(), timeout=5000)

    assert not window.audit.has_resources
