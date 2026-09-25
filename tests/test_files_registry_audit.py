from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import system_repair.files as files_module
from system_repair.demo import DemoPlatform
from system_repair.files import FileManager, entry_for
from system_repair.journal import ActionJournal
from system_repair.model import RegistryAddress, RegistryValue
from system_repair.registry_audit import RegistryManager


def _logger(*_args):
    return None


def _file_manager(tmp_path: Path, protected: tuple[Path, ...] = ()):
    platform = DemoPlatform()
    journal = ActionJournal(tmp_path / "backups", platform)
    return platform, journal, FileManager(journal, protected)


def _registry_manager(tmp_path: Path, platform: DemoPlatform | None = None):
    selected = platform or DemoPlatform()
    journal = ActionJournal(tmp_path / "backups", selected)
    return selected, journal, RegistryManager(selected, journal)


def test_file_scan_uses_modified_or_created_time_and_records_creation_fallback(tmp_path, monkeypatch):
    root = tmp_path / "scan"
    root.mkdir()
    old = root / "old.bin"
    old.write_bytes(b"old")
    now = time.time_ns()
    two_hours = 2 * 60 * 60 * 1_000_000_000
    os.utime(old, ns=(now - two_hours, now - two_hours))

    recent = root / "recent.bin"
    recent.write_bytes(b"recent")
    os.utime(recent, ns=(now, now + two_hours))

    _, _, manager = _file_manager(tmp_path)
    old_entry = entry_for(old)
    old_info = old.stat()
    # POSIX ctime is metadata-change time, not a portable creation timestamp.
    assert old_entry.created_ns == getattr(old_info, "st_birthtime_ns", old_info.st_ctime_ns)
    initial = manager.scan(str(root), 30, _logger)
    assert old_entry.path in {entry.path for entry in initial.entries}

    monkeypatch.setattr(files_module.time, "time_ns", lambda: now + two_hours)
    result = manager.scan(str(root), 30, _logger)

    assert {Path(entry.path).name for entry in result.entries} == {"recent.bin"}


def test_quarantine_refuses_protected_directories(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    target = protected / "sample.bin"
    target.write_bytes(b"keep")
    _, journal, manager = _file_manager(tmp_path, (protected,))

    with pytest.raises(PermissionError, match="защищены"):
        manager.act((entry_for(target),), "quarantine", "", _logger)

    assert target.read_bytes() == b"keep"
    assert not journal.root.exists()


def test_scan_and_quarantine_do_not_follow_symlinks(tmp_path):
    root = tmp_path / "links"
    root.mkdir()
    target = root / "target.bin"
    target.write_bytes(b"keep")
    link = root / "alias.bin"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"Symlinks are unavailable in this environment: {error}")

    _, journal, manager = _file_manager(tmp_path)
    result = manager.scan(str(root), 0, _logger)
    assert {Path(entry.path).name for entry in result.entries} == {"target.bin"}

    forged_entry = replace(entry_for(target), path=str(link.absolute()))
    with pytest.raises(ValueError, match="Reparse points"):
        manager.act((forged_entry,), "quarantine", "", _logger)
    assert target.read_bytes() == b"keep"
    assert not journal.root.exists()


def test_quarantine_refuses_files_with_multiple_hard_links(tmp_path):
    target = tmp_path / "linked.bin"
    alias = tmp_path / "alias.bin"
    target.write_bytes(b"keep")
    try:
        os.link(target, alias)
    except OSError as error:
        pytest.skip(f"Hard links are unavailable in this environment: {error}")

    _, journal, manager = _file_manager(tmp_path)
    with pytest.raises(PermissionError, match="hard links"):
        manager.act((entry_for(target),), "quarantine", "", _logger)

    assert target.read_bytes() == alias.read_bytes() == b"keep"
    assert not journal.root.exists()


def test_quarantine_rejects_file_changed_after_scan(tmp_path):
    target = tmp_path / "changed.bin"
    target.write_bytes(b"before")
    _, journal, manager = _file_manager(tmp_path)
    scanned = entry_for(target)
    target.write_bytes(b"changed after scan")

    with pytest.raises(OSError, match="Файл изменился после проверки"):
        manager.act((scanned,), "quarantine", "", _logger)

    assert target.read_bytes() == b"changed after scan"
    assert not journal.root.exists()


def test_quarantine_writes_backup_and_blob_before_removing_source(tmp_path, monkeypatch):
    target = (tmp_path / "evidence.bin").absolute()
    content = b"quarantine evidence"
    target.write_bytes(content)
    _, journal, manager = _file_manager(tmp_path)
    observed = []

    def check_before_remove():
        manifests = list(journal.root.glob("*/action.json"))
        assert len(manifests) == 1
        manifest = manifests[0]
        document = json.loads(manifest.read_text(encoding="utf-8"))
        blob = manifest.parent / "content.bin"
        assert document["kind"] == "quarantine"
        assert document["payload"]["sha256"] == hashlib.sha256(content).hexdigest()
        assert blob.read_bytes() == content
        assert target.exists()
        observed.append(manifest)

    if os.name == "nt":
        from system_repair.windows_files import _NativeWindowsApi

        original_delete = _NativeWindowsApi.mark_delete

        def check_before_delete(api, handle):
            check_before_remove()
            return original_delete(api, handle)

        monkeypatch.setattr(_NativeWindowsApi, "mark_delete", check_before_delete)
    else:
        original_unlink = Path.unlink

        def check_before_unlink(path, *args, **kwargs):
            if path == target:
                check_before_remove()
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", check_before_unlink)
    manifest = manager.act((entry_for(target),), "quarantine", "", _logger)[0]

    assert observed == [manifest]
    assert not target.exists()
    assert (manifest.parent / "content.bin").read_bytes() == content


def test_copy_is_exclusive_and_never_clobbers_existing_destination(tmp_path):
    source = tmp_path / "copy.bin"
    source.write_bytes(b"source")
    destination = tmp_path / "destination"
    destination.mkdir()
    existing = destination / source.name
    existing.write_bytes(b"do not replace")
    _, _, manager = _file_manager(tmp_path)

    with pytest.raises(FileExistsError):
        manager.act((entry_for(source),), "copy", str(destination), _logger)

    assert source.read_bytes() == b"source"
    assert existing.read_bytes() == b"do not replace"


def test_duplicate_search_distinguishes_exact_hash_from_similar_name(tmp_path):
    root = tmp_path / "duplicates"
    root.mkdir()
    original = root / "sample.exe"
    original.write_bytes(b"same content")
    exact_copy = root / "renamed.bin"
    exact_copy.write_bytes(b"same content")
    similar_name = root / "sampel.exe"
    similar_name.write_bytes(b"other content")
    unrelated = root / "notes.txt"
    unrelated.write_bytes(b"unrelated")
    _, _, manager = _file_manager(tmp_path)

    result = manager.duplicates(str(original), str(root), _logger)
    by_name = {Path(entry.path).name: entry for entry in result.entries}

    assert set(by_name) == {"renamed.bin", "sampel.exe"}
    assert by_name["renamed.bin"].digest == hashlib.sha256(b"same content").hexdigest()
    assert by_name["sampel.exe"].digest == "Имя похоже; содержимое отличается"


def test_file_scan_marks_time_limited_results_as_truncated(tmp_path, monkeypatch):
    root = tmp_path / "bounded"
    root.mkdir()
    (root / "first.bin").write_bytes(b"first")
    _, _, manager = _file_manager(tmp_path)
    ticks = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr(files_module.time, "monotonic", lambda: next(ticks))

    result = manager.scan(str(root), 0, _logger)

    assert result.truncated is True
    assert result.visited == 1
    assert result.entries == ()


@pytest.mark.parametrize("mismatch", ["checksum", "identity", "mode"])
def test_restore_checks_checksum_identity_and_demo_mode(tmp_path, monkeypatch, mismatch):
    platform, _, manager = _file_manager(tmp_path)
    target = tmp_path / "restore.bin"
    target.write_bytes(b"verified data")
    manifest = manager.act((entry_for(target),), "quarantine", "", _logger)[0]

    if mismatch == "checksum":
        (manifest.parent / "content.bin").write_bytes(b"tampered data")
        expected = "Контрольная сумма"
    elif mismatch == "identity":
        identity = platform.identity()
        monkeypatch.setattr(
            platform, "identity", lambda identity=identity: {**identity, "machine": "OTHER"}
        )
        expected = "другому компьютеру"
    else:
        monkeypatch.setattr(platform, "is_demo", False)
        expected = "другому компьютеру"

    with pytest.raises(ValueError, match=expected):
        manager.restore(str(manifest), _logger)

    assert not target.exists()
    assert manifest.exists()


def test_restore_copies_verified_blob_once_without_overwriting(tmp_path):
    target = tmp_path / "restore-once.bin"
    content = b"restore this"
    target.write_bytes(content)
    _, _, manager = _file_manager(tmp_path)
    manifest = manager.act((entry_for(target),), "quarantine", "", _logger)[0]

    restored = manager.restore(str(manifest), _logger)

    assert restored == target
    assert hashlib.sha256(restored.read_bytes()).hexdigest() == json.loads(
        manifest.read_text(encoding="utf-8")
    )["payload"]["sha256"]
    with pytest.raises(FileExistsError, match="перезапись запрещена"):
        manager.restore(str(manifest), _logger)
    assert target.read_bytes() == content


def test_restore_does_not_overwrite_an_existing_source_path(tmp_path):
    target = tmp_path / "restore-conflict.bin"
    target.write_bytes(b"original")
    _, _, manager = _file_manager(tmp_path)
    manifest = manager.act((entry_for(target),), "quarantine", "", _logger)[0]
    target.write_bytes(b"new file at original path")

    with pytest.raises(FileExistsError, match="перезапись запрещена"):
        manager.restore(str(manifest), _logger)

    assert target.read_bytes() == b"new file at original path"


def test_registry_edit_and_restore_preserve_value_types_and_snapshot_full_branch(
    tmp_path, monkeypatch
):
    platform, journal, manager = _registry_manager(tmp_path)
    key = r"Software\AuditFixture"
    address = RegistryAddress("HKCU", key, "Payload")
    old = RegistryValue(3, b"\x00\xff")
    new = RegistryValue(4, 7)
    platform.write_registry(address, old)
    platform.write_registry(RegistryAddress("HKCU", key, "Sibling"), RegistryValue(1, "keep"))
    platform.write_registry(
        RegistryAddress("HKCU", key + r"\Child", "Leaf"), RegistryValue(7, ["one", "two"])
    )
    expected_branch = platform.snapshot_registry("HKCU", key, 64)
    original_snapshot = platform.snapshot_registry
    original_record = journal.record
    original_write = platform.write_registry
    events = []
    snapshot_calls = []
    recorded_payloads = []

    def snapshot(hive, snapshot_key, view):
        branch = original_snapshot(hive, snapshot_key, view)
        snapshot_calls.append((hive, snapshot_key, view))
        events.append("snapshot")
        return branch

    def record(kind, target, payload):
        events.append("journal")
        recorded_payloads.append(payload)
        return original_record(kind, target, payload)

    def write(address_to_write, value):
        events.append("write")
        return original_write(address_to_write, value)

    monkeypatch.setattr(platform, "snapshot_registry", snapshot)
    monkeypatch.setattr(journal, "record", record)
    monkeypatch.setattr(platform, "write_registry", write)

    backup = manager.edit(address, old, new, _logger)

    assert snapshot_calls == [
        ("HKCU", key + r"\Child", 64),
        ("HKCU", key, 64),
    ]
    assert events == ["snapshot"] * len(snapshot_calls) + ["journal", "write"]
    assert recorded_payloads[0]["branch"] == expected_branch
    assert platform.read_registry(address) == new
    document = json.loads(backup.read_text(encoding="utf-8"))
    assert document["payload"]["branch"] == expected_branch
    assert document["payload"]["old"] == old.to_dict()
    assert document["payload"]["new"] == new.to_dict()
    assert document["payload"]["branch"]["values"]["Sibling"] == RegistryValue(
        1, "keep"
    ).to_dict()
    assert document["payload"]["branch"]["children"]["Child"]["values"]["Leaf"] == (
        RegistryValue(7, ["one", "two"]).to_dict()
    )

    restore_backup = manager.restore(str(backup), _logger)

    assert platform.read_registry(address) == old
    restore_document = json.loads(restore_backup.read_text(encoding="utf-8"))
    assert restore_document["payload"]["old"] == new.to_dict()
    assert restore_document["payload"]["new"] == old.to_dict()


def test_registry_edit_fails_closed_when_full_branch_journal_cannot_be_written(
    tmp_path, monkeypatch
):
    platform, journal, manager = _registry_manager(tmp_path)
    address = RegistryAddress("HKCU", r"Software\AuditFixture", "Value")
    old = RegistryValue(1, "before")
    platform.write_registry(address, old)
    snapshots = []
    original_snapshot = platform.snapshot_registry
    expected_snapshot = original_snapshot("HKCU", address.key, 64)

    def snapshot(*args):
        result = original_snapshot(*args)
        snapshots.append(result)
        return result

    def fail_record(*_args):
        raise OSError("journal unavailable")

    monkeypatch.setattr(platform, "snapshot_registry", snapshot)
    monkeypatch.setattr(journal, "record", fail_record)

    with pytest.raises(OSError, match="journal unavailable"):
        manager.edit(address, old, RegistryValue(1, "after"), _logger)

    assert snapshots == [expected_snapshot]
    assert platform.read_registry(address) == old
    assert not journal.root.exists()


def test_registry_edit_rejects_stale_old_value_without_backup_or_write(tmp_path):
    platform, journal, manager = _registry_manager(tmp_path)
    address = RegistryAddress("HKCU", r"Software\AuditFixture", "Value")
    current = RegistryValue(1, "current")
    platform.write_registry(address, current)

    with pytest.raises(OSError, match="изменился после чтения"):
        manager.edit(address, RegistryValue(1, "stale"), RegistryValue(1, "new"), _logger)

    assert platform.read_registry(address) == current
    assert not journal.root.exists()


def test_registry_edit_rejects_non_admin_without_mutation(tmp_path):
    platform, journal, manager = _registry_manager(tmp_path)
    platform.is_admin = lambda: False
    address = RegistryAddress("HKCU", r"Software\AuditFixture", "Value")
    old = RegistryValue(1, "before")
    platform.write_registry(address, old)

    with pytest.raises(PermissionError, match="администратора"):
        manager.edit(address, old, RegistryValue(1, "after"), _logger)

    assert platform.read_registry(address) == old
    assert not journal.root.exists()


@pytest.mark.parametrize("key", [r"Software\..\Audit", r"Software/Audit", "Software\\Audit\\"])
def test_registry_path_validation_rejects_traversal_and_malformed_paths(tmp_path, key):
    platform, journal, manager = _registry_manager(tmp_path)
    address = RegistryAddress("HKCU", key, "Value")

    with pytest.raises(ValueError, match="Некорректный путь"):
        manager.edit(address, None, RegistryValue(1, "value"), _logger)

    assert platform.values == DemoPlatform().values
    assert not journal.root.exists()


@pytest.mark.parametrize("key", ["SAM", "SECURITY"])
def test_registry_edit_refuses_credential_hives(tmp_path, key):
    platform, journal, manager = _registry_manager(tmp_path)
    address = RegistryAddress("HKLM", key, "Value")

    with pytest.raises(PermissionError, match="защищена"):
        manager.edit(address, None, RegistryValue(1, "value"), _logger)

    assert not journal.root.exists()


class _FakeRegistryApi:
    HKEY_LOCAL_MACHINE = object()

    def __init__(self):
        self.loaded = []
        self.flushed = []

    def LoadKey(self, hive, key, filename):
        self.loaded.append((hive, key, filename))

    def OpenKey(self, hive, key):
        return nullcontext((hive, key))

    def FlushKey(self, handle):
        self.flushed.append(handle)

def test_offline_hive_mount_uses_isolated_copy_and_mocked_windows_api(tmp_path, monkeypatch):
    platform, _, manager = _registry_manager(tmp_path)
    platform.is_demo = False
    platform.reg = _FakeRegistryApi()
    unload_calls = []
    monkeypatch.setitem(
        sys.modules,
        "win32api",
        SimpleNamespace(RegUnLoadKey=lambda hive, key: unload_calls.append((hive, key))),
    )
    monkeypatch.setattr(manager, "_hive_privileges", lambda: nullcontext())
    source = tmp_path / "isolated.hiv"
    source.write_bytes(b"fixture hive; not a real Windows hive")

    mount = manager.mount(str(source), _logger)

    assert source.read_bytes() == b"fixture hive; not a real Windows hive"
    assert Path(mount.backup).exists()
    document = json.loads(Path(mount.backup).read_text(encoding="utf-8"))
    assert document["payload"]["mount_key"] == mount.key
    assert document["payload"]["working_copy"] == "working.hiv"
    assert Path(mount.working_copy).read_bytes() == source.read_bytes()
    assert platform.reg.loaded == [
        (platform.reg.HKEY_LOCAL_MACHINE, mount.key, mount.working_copy)
    ]
    manager.unmount(mount, _logger)
    assert platform.reg.flushed == [(platform.reg.HKEY_LOCAL_MACHINE, mount.key)]
    assert unload_calls == [(platform.reg.HKEY_LOCAL_MACHINE, mount.key)]
    assert mount.key not in manager.mounts
    assert source.read_bytes() == b"fixture hive; not a real Windows hive"


@pytest.mark.parametrize("name", ["SAM", "SECURITY"])
def test_offline_hive_mount_refuses_sam_and_security_without_calling_windows_api(
    tmp_path, monkeypatch, name
):
    platform, journal, manager = _registry_manager(tmp_path)
    platform.is_demo = False
    platform.reg = _FakeRegistryApi()
    monkeypatch.setattr(manager, "_hive_privileges", lambda: nullcontext())
    source = tmp_path / name
    source.write_bytes(b"not loaded")

    with pytest.raises(PermissionError, match="SAM/SECURITY"):
        manager.mount(str(source), _logger)

    assert platform.reg.loaded == []
    assert source.read_bytes() == b"not loaded"
    assert not journal.root.exists()
