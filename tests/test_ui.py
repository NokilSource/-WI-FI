from __future__ import annotations

import threading
from copy import deepcopy
from pathlib import Path

import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from system_repair.catalog import BY_ID
from system_repair.demo import DemoPlatform
from system_repair.engine import RepairEngine
from system_repair.ui import MainWindow


@pytest.fixture
def window(qtbot, tmp_path):
    backend = DemoPlatform()
    widget = MainWindow(RepairEngine(backend, tmp_path / "backups"), auto_scan=False)
    qtbot.addWidget(widget)
    widget.show()
    return widget


def wait_idle(qtbot, window):
    qtbot.waitUntil(lambda: not window._busy and window._thread is None, timeout=5000)


def test_initial_state_requires_explicit_selection(window):
    assert window._selected_repair_ids() == []
    assert not window.apply_button.isEnabled()
    assert not window.backup_button.isEnabled()
    assert not window.terminate_process_button.isEnabled()
    assert window.demo_banner.isVisible()
    assert "ДЕМО" in window.log_view.toPlainText()
    assert not window.engine.backup_root.exists()


def test_scan_reads_all_tabs_without_changing_system(window, qtbot):
    before = deepcopy(window.platform.values), window.platform.hosts
    qtbot.mouseClick(window.scan_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert window.repair_table.rowCount() == len(BY_ID)
    assert window.findings_table.rowCount() >= 4
    assert window.services_table.rowCount() == 1
    assert window.process_table.rowCount() == 2
    assert before == (window.platform.values, window.platform.hosts)
    assert not window.engine.backup_root.exists()
    assert "Проверка завершена" in window.log_view.toPlainText()


def test_cancel_confirmation_never_starts_backup_or_repairs(window, qtbot, monkeypatch):
    window.repair_items["taskmgr"].setCheckState(Qt.CheckState.Checked)
    before = deepcopy(window.platform.values)
    messages = []

    def reject(title, body):
        messages.append(body)
        return False

    monkeypatch.setattr(window, "_confirm", reject)
    qtbot.mouseClick(window.apply_button, Qt.MouseButton.LeftButton)
    assert len(messages) == 1
    assert "DisableTaskMgr" in messages[0]
    assert before == window.platform.values
    assert not window.engine.backup_root.exists()
    assert not window._busy


def test_apply_and_restore_through_buttons(window, qtbot, monkeypatch):
    before = deepcopy(window.platform.values), window.platform.hosts
    for id in ("taskmgr", "hidden", "hosts"):
        window.repair_items[id].setCheckState(Qt.CheckState.Checked)
    monkeypatch.setattr(window, "_confirm", lambda *args: True)
    qtbot.mouseClick(window.apply_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert before != (window.platform.values, window.platform.hosts)
    manifests = list(window.engine.backup_root.glob("*/backup.json"))
    assert len(manifests) == 1
    assert "Проверена запись" in window.log_view.toPlainText()

    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(manifests[0]), ""))
    qtbot.mouseClick(window.restore_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert before == (window.platform.values, window.platform.hosts)
    assert len(list(window.engine.backup_root.glob("*/backup.json"))) == 2
    assert "восстановлены" in window.log_view.toPlainText()


def test_backup_button_only_saves_and_apply_creates_another(window, qtbot, monkeypatch):
    window.repair_items["taskmgr"].setCheckState(Qt.CheckState.Checked)
    monkeypatch.setattr(window, "_confirm", lambda *args: True)
    before = deepcopy(window.platform.values)
    qtbot.mouseClick(window.backup_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert before == window.platform.values
    assert len(list(window.engine.backup_root.glob("*/backup.json"))) == 1
    qtbot.mouseClick(window.apply_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert len(list(window.engine.backup_root.glob("*/backup.json"))) == 2


def test_backup_failure_is_visible_and_unlocks_controls(window, qtbot, monkeypatch):
    window.repair_items["hidden"].setCheckState(Qt.CheckState.Checked)
    monkeypatch.setattr(window, "_confirm", lambda *args: True)

    def denied(*args):
        raise PermissionError("test backup denied")

    monkeypatch.setattr(window.platform, "snapshot_registry", denied)
    before = deepcopy(window.platform.values)
    qtbot.mouseClick(window.apply_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert before == window.platform.values
    assert "test backup denied" in window.log_view.toPlainText()
    assert window.log_state_label.text() == "ошибка"
    assert window.apply_button.isEnabled()
    assert not list(window.engine.backup_root.glob("*/backup.json"))


def test_non_admin_can_scan_but_not_mutate(qtbot, tmp_path, monkeypatch):
    backend = DemoPlatform()
    backend.is_demo = False
    monkeypatch.setattr(backend, "is_admin", lambda: False)
    window = MainWindow(RepairEngine(backend, tmp_path), auto_scan=False)
    qtbot.addWidget(window)
    window.show()
    window.repair_items["taskmgr"].setCheckState(Qt.CheckState.Checked)
    assert window.scan_button.isEnabled()
    assert not window.apply_button.isEnabled()
    assert not window.restore_button.isEnabled()
    assert not window.terminate_process_button.isEnabled()


def test_busy_worker_blocks_duplicate_actions_and_close(window, qtbot, monkeypatch):
    release = threading.Event()
    started = threading.Event()
    original_scan = window.engine.scan

    def slow_scan(log):
        started.set()
        log("INFO", "test worker active")
        if not release.wait(timeout=5):
            raise TimeoutError("Test did not release worker")
        return original_scan(log)

    monkeypatch.setattr(window.engine, "scan", slow_scan)
    qtbot.mouseClick(window.scan_button, Qt.MouseButton.LeftButton)
    try:
        qtbot.waitUntil(started.is_set)
        qtbot.waitUntil(lambda: "test worker active" in window.log_view.toPlainText())
        assert not window.scan_button.isEnabled()
        assert not window.restore_button.isEnabled()
        assert not window.close()
        assert window.isVisible()
        assert not window._start_task("duplicate", "duplicate", original_scan)
    finally:
        release.set()
        wait_idle(qtbot, window)
    assert window.scan_button.isEnabled()


def test_process_filter_and_confirmed_selected_pid_only(window, qtbot, monkeypatch):
    qtbot.mouseClick(window.scan_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    window.tabs.setCurrentIndex(3)
    window.process_filter.setText("4120")
    assert window.process_table.rowCount() == 1
    window.process_table.selectRow(0)
    assert window.terminate_process_button.isEnabled()
    prompts = []

    def confirm(title, body):
        prompts.append(body)
        return True

    monkeypatch.setattr(window, "_confirm", confirm)
    qtbot.mouseClick(window.terminate_process_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert "PID: 4120" in prompts[0] and "LabUpdater.exe" in prompts[0]
    assert [process.pid for process in window.platform.processes] == [3088]
    window.process_filter.clear()
    qtbot.mouseClick(window.scan_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert window.process_table.rowCount() == 1
    assert window.process_table.item(0, 0).text() == "3088"


def test_confirmation_is_plain_text_and_defaults_to_no(window, qtbot):
    seen = []

    def inspect_dialog():
        dialog = QApplication.activeModalWidget()
        assert isinstance(dialog, QMessageBox)
        seen.append((dialog.textFormat(), dialog.standardButton(dialog.defaultButton()), dialog.text()))
        dialog.reject()

    QTimer.singleShot(0, inspect_dialog)
    assert not window._confirm("Проверка", "<b>synthetic path & warning</b>")
    assert seen == [(Qt.TextFormat.PlainText, QMessageBox.StandardButton.No,
                     "<b>synthetic path & warning</b>")]


def test_network_confirmation_lists_disconnection_and_reboot_risk(window, qtbot, monkeypatch):
    window.repair_items["tcpip"].setCheckState(Qt.CheckState.Checked)
    prompts = []

    def reject(title, text):
        prompts.append(text)
        return False

    monkeypatch.setattr(window, "_confirm", reject)
    qtbot.mouseClick(window.apply_button, Qt.MouseButton.LeftButton)
    assert len(prompts) == 1
    assert all(term in prompts[0] for term in ("RDP", "VPN", "IP/DNS", "перезагрузка", "точка восстановления"))
    assert window.platform.network_resets == []


def test_save_log_is_plain_utf8_without_touching_system(window, qtbot, tmp_path, monkeypatch):
    destination = tmp_path / "repair.log"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args: (str(destination), ""))
    qtbot.mouseClick(window.save_logs_button, Qt.MouseButton.LeftButton)
    wait_idle(qtbot, window)
    assert "ДЕМО" in Path(destination).read_text(encoding="utf-8")
    assert not window.engine.backup_root.exists()
