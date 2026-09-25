from __future__ import annotations

import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from system_repair.audit import AuditEngine
from system_repair.audit_model import HiveMount, StartupEntry
from system_repair.demo import DemoPlatform
from system_repair.files import FileManager, entry_for
from system_repair.journal import ActionJournal
from system_repair.model import RegistryAddress, RegistryValue
from system_repair.paths import checked_path
from system_repair.registry_audit import RegistryManager


def log(*_args):
    pass


def test_protected_directory_cannot_be_bypassed_with_dotdot(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    innocent = tmp_path / "innocent"
    innocent.mkdir()
    target = protected / "file.bin"
    target.write_bytes(b"keep")
    journal = ActionJournal(tmp_path / "backups", DemoPlatform())
    manager = FileManager(journal, (protected,))
    alias = innocent / ".." / "protected" / "file.bin"

    assert checked_path(alias) == target
    with pytest.raises(PermissionError, match="защищены"):
        manager.act((entry_for(alias),), "quarantine", "", log)
    assert target.read_bytes() == b"keep"


def test_file_scan_and_quarantine_protect_repair_backups_too(tmp_path):
    journal = ActionJournal(tmp_path / "backups", DemoPlatform())
    repair_backup = journal.root.parent / "earlier-repair" / "hosts.bin"
    repair_backup.parent.mkdir(parents=True)
    repair_backup.write_bytes(b"original hosts")
    manager = FileManager(journal)

    scan = manager.scan(str(tmp_path), 0, log)
    assert not scan.entries
    with pytest.raises(PermissionError, match="защищены"):
        manager.act((entry_for(repair_backup),), "quarantine", "", log)
    assert repair_backup.read_bytes() == b"original hosts"


def test_journal_refuses_symlinked_root_before_registry_write(tmp_path):
    destination = tmp_path / "outside"
    destination.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(destination, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable: {error}")
    platform = DemoPlatform()
    manager = RegistryManager(platform, ActionJournal(link, platform))
    address = RegistryAddress("HKCU", r"Software\LocalTest", "Value")

    with pytest.raises(ValueError, match="Reparse"):
        manager.edit(address, None, RegistryValue(1, "changed"), log)
    assert platform.read_registry(address) is None
    assert not list(destination.iterdir())


def test_oversized_journal_blocks_registry_mutation(tmp_path, monkeypatch):
    import system_repair.journal as journal_module

    platform = DemoPlatform()
    manager = RegistryManager(platform, ActionJournal(tmp_path, platform))
    address = RegistryAddress("HKCU", r"Software\LocalTest", "Value")
    monkeypatch.setattr(journal_module, "MAX_MANIFEST", 64)
    with pytest.raises(ValueError, match="размер"):
        manager.edit(address, None, RegistryValue(1, "changed"), log)
    assert platform.read_registry(address) is None


def test_registry_restore_refuses_to_overwrite_changes_after_original_edit(tmp_path):
    platform = DemoPlatform()
    journal = ActionJournal(tmp_path, platform)
    manager = RegistryManager(platform, journal)
    address = RegistryAddress("HKCU", r"Software\LocalTest", "Value")
    backup = manager.edit(address, None, RegistryValue(1, "our edit"), log)
    platform.write_registry(address, RegistryValue(1, "newer edit"))

    with pytest.raises(OSError, match="изменился"):
        manager.restore(str(backup), log)
    assert platform.read_registry(address) == RegistryValue(1, "newer edit")
    assert len(list(journal.root.glob("*/action.json"))) == 1


@pytest.mark.parametrize("hive,key", [
    ("HKLM", r"Software\Microsoft\Windows Defender"),
    ("HKCU", r"Software\Policies\Microsoft\Windows Defender\Real-Time Protection"),
    ("HKLM", r"SYSTEM\CurrentControlSet\Services\WinDefend"),
    ("HKLM", r"SYSTEM\ControlSet001\Services\WdFilter"),
])
def test_registry_editor_does_not_disable_defender(tmp_path, hive, key):
    platform = DemoPlatform()
    journal = ActionJournal(tmp_path, platform)
    address = RegistryAddress(hive, key, "Start")
    with pytest.raises(PermissionError, match="защищена"):
        RegistryManager(platform, journal).edit(address, None, RegistryValue(4, 4), log)
    assert platform.read_registry(address) is None
    assert not journal.root.exists()


def test_startup_file_quarantine_uses_identity_captured_during_scan(tmp_path):
    engine, _commands = live_engine(tmp_path / "backups")
    target = tmp_path / "startup-entry.lnk"
    target.write_bytes(b"selected startup file")
    file = entry_for(target)
    entry = StartupEntry(target.name, str(tmp_path), str(target), "Startup folder",
                         path=file.path, file=file)
    target.write_bytes(b"replacement after startup scan")

    with pytest.raises(OSError, match="изменился"):
        engine.edit_startup(entry, None, log)
    assert target.read_bytes() == b"replacement after startup scan"
    assert not engine.journal.root.exists()


def test_repair_backup_refuses_symlinked_directory(tmp_path):
    from system_repair.engine import RepairEngine

    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "backup-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable: {error}")
    platform = DemoPlatform()
    engine = RepairEngine(platform, link)
    address = RegistryAddress("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr")
    before = platform.read_registry(address)
    with pytest.raises(ValueError, match="Reparse"):
        engine.apply(["taskmgr"], log)
    assert platform.read_registry(address) == before
    assert not list(outside.iterdir())


def test_cleanup_attempts_hives_even_after_resume_failure(tmp_path, monkeypatch):
    engine = AuditEngine(DemoPlatform(), tmp_path)
    engine.demo.suspended.add(123)
    mounts = [HiveMount("one", "original", "copy", "backup"),
              HiveMount("two", "original", "copy", "backup")]
    engine.reg.mounts = {mount.key: mount for mount in mounts}

    def fail_resume(_log):
        raise OSError("resume failed")

    attempted = []

    def unmount(mount, _log):
        attempted.append(mount.key)
        if mount.key == "one":
            raise OSError("unload failed")
        del engine.reg.mounts[mount.key]

    monkeypatch.setattr(engine.demo, "resume_all", fail_resume)
    monkeypatch.setattr(engine.reg, "unmount", unmount)
    with pytest.raises(OSError, match="resume failed"):
        engine.cleanup(log)
    assert attempted == ["one", "two"]
    assert set(engine.reg.mounts) == {"one"}
    assert engine.has_resources


def live_engine(tmp_path):
    platform = DemoPlatform()
    platform.is_demo = False
    platform.windows_dir = str(tmp_path / "Windows")
    platform.system_dir = str(tmp_path / "Windows" / "System32")
    commands = []
    platform._command = lambda *args, **kwargs: commands.append(args)
    return AuditEngine(platform, tmp_path), commands


@pytest.mark.parametrize("point", [None, 0, False, "123"])
def test_sfc_requires_confirmed_restore_point(tmp_path, point):
    engine, commands = live_engine(tmp_path)
    engine.platform.create_restore_point = lambda: point
    with pytest.raises(OSError, match="SFC"):
        engine.system("sfc", log)
    assert not commands
    assert not engine.journal.root.exists()


def test_reboot_is_blocked_when_resource_cleanup_fails(tmp_path):
    engine, commands = live_engine(tmp_path)

    def fail(_log):
        raise OSError("resume failed")

    engine._process_manager = SimpleNamespace(has_suspended=True, resume_all=fail)
    with pytest.raises(OSError, match="resume failed"):
        engine.system("safe", log)
    assert not commands


def test_restart_is_issued_only_after_resources_are_released(tmp_path):
    engine, commands = live_engine(tmp_path)
    events = []

    def resume(_log):
        events.append("resume")
        engine._process_manager.has_suspended = False

    engine._process_manager = SimpleNamespace(has_suspended=True, resume_all=resume)
    engine.platform._command = lambda *args, **kwargs: events.append("restart")
    engine.system("recovery", log)
    assert events == ["resume", "restart"]
    assert not engine.has_resources


@pytest.mark.parametrize("action", ["sfc", "recovery", "safe", "uefi", "cancel_restart"])
def test_system_mutation_is_blocked_when_journal_cannot_be_written(tmp_path, action):
    engine, commands = live_engine(tmp_path)

    def fail(*_args):
        raise OSError("backup disk full")

    engine.journal.record = fail
    with pytest.raises(OSError, match="backup disk full"):
        engine.system(action, log)
    assert not commands


def test_window_closes_only_after_suspended_resources_are_released(tmp_path, qtbot, monkeypatch):
    from system_repair.engine import RepairEngine
    from system_repair.ui import MainWindow

    window = MainWindow(RepairEngine(DemoPlatform(), tmp_path), auto_scan=False)
    qtbot.addWidget(window)
    window.show()
    window.audit.demo.suspended.add(4120)
    monkeypatch.setattr(window, "_confirm", lambda *_args: True)

    window.close()
    assert window.isVisible()
    qtbot.waitUntil(lambda: not window.isVisible())
    assert not window.audit.has_resources
    assert not window._busy


def test_window_remains_open_if_resource_cleanup_fails(tmp_path, qtbot, monkeypatch):
    from system_repair.engine import RepairEngine
    from system_repair.ui import MainWindow

    window = MainWindow(RepairEngine(DemoPlatform(), tmp_path), auto_scan=False)
    qtbot.addWidget(window)
    window.show()
    window.audit.demo.suspended.add(4120)
    monkeypatch.setattr(window, "_confirm", lambda *_args: True)

    def fail(_log):
        raise OSError("cannot resume")

    monkeypatch.setattr(window.audit.demo, "resume_all", fail)
    window.close()
    qtbot.waitUntil(lambda: not window._busy)
    assert window.isVisible()
    assert window._operation_failed
    assert window.audit.has_resources
    window.audit.demo.suspended.clear()
    window.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows ADS")
def test_quarantine_preserves_files_with_alternate_streams(tmp_path):
    target = tmp_path / "stream.bin"
    target.write_bytes(b"main")
    with open(str(target) + ":test", "wb") as stream:
        stream.write(b"metadata")
    manager = FileManager(ActionJournal(tmp_path / "backups", DemoPlatform()))
    with pytest.raises(PermissionError, match="ADS"):
        manager.act((entry_for(target),), "quarantine", "", log)
    assert target.read_bytes() == b"main"
    with open(str(target) + ":test", "rb") as stream:
        assert stream.read() == b"metadata"


def test_file_snapshot_with_unnormalized_alias_is_rejected(tmp_path):
    target = tmp_path / "file.bin"
    target.write_bytes(b"keep")
    entry = replace(entry_for(target), path=str(tmp_path / "extra" / ".." / target.name))
    manager = FileManager(ActionJournal(tmp_path / "backups", DemoPlatform()))
    with pytest.raises(OSError, match="изменился"):
        manager.act((entry,), "quarantine", "", log)
    assert target.exists()
