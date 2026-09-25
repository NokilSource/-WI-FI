from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import system_repair.backup as backup_module
from system_repair.catalog import BY_ID, DEFAULT_HOSTS, EXPLORER, IFEO, WINLOGON
from system_repair.demo import DemoPlatform
from system_repair.engine import RepairEngine
from system_repair.model import RegistryAddress, RegistryValue, RepairError


class SpyDemoPlatform(DemoPlatform):
    def __init__(self, *, admin: bool = True):
        super().__init__()
        self.admin = admin
        self.backup_root: Path | None = None
        self.identity_override: dict[str, str] | None = None
        self.snapshot_calls: list[tuple[str, str, int]] = []
        self.snapshot_failure: Exception | None = None
        self.network_snapshot_calls = 0
        self.network_snapshot_failure: Exception | None = None
        self.restore_point_calls = 0
        self.restore_point_result = 12345
        self.restore_point_failure: Exception | None = None
        self.write_attempts: list[tuple[RegistryAddress, RegistryValue | None]] = []
        self.successful_writes: list[tuple[RegistryAddress, RegistryValue | None]] = []
        self.backup_manifests_at_write: list[tuple[Path, ...]] = []
        self.fail_write_address: RegistryAddress | None = None
        self.ignore_write_addresses: set[RegistryAddress] = set()
        self.host_write_attempts: list[bytes | None] = []
        self.ignore_hosts_write = False
        self.reset_calls: list[str] = []
        self.terminate_calls = []

    def is_admin(self) -> bool:
        return self.admin

    def identity(self) -> dict[str, str]:
        if self.identity_override is not None:
            return copy.deepcopy(self.identity_override)
        return super().identity()

    def snapshot_registry(self, hive: str, key: str, view: int) -> dict:
        self.snapshot_calls.append((hive, key, view))
        if self.snapshot_failure is not None:
            raise self.snapshot_failure
        return super().snapshot_registry(hive, key, view)

    def write_registry(self, address: RegistryAddress, value: RegistryValue | None) -> None:
        self.write_attempts.append((address, copy.deepcopy(value)))
        if self.backup_root is not None and self.backup_root.exists():
            manifests = tuple(sorted(self.backup_root.glob("*/backup.json"), key=str))
        else:
            manifests = ()
        self.backup_manifests_at_write.append(manifests)
        if address == self.fail_write_address:
            raise OSError("injected registry write failure")
        if address in self.ignore_write_addresses:
            return
        super().write_registry(address, value)
        self.successful_writes.append((address, copy.deepcopy(value)))

    def write_hosts(self, content: bytes | None) -> None:
        self.host_write_attempts.append(copy.deepcopy(content))
        if self.ignore_hosts_write:
            return
        super().write_hosts(content)

    def network_snapshot(self) -> dict[str, str]:
        self.network_snapshot_calls += 1
        if self.network_snapshot_failure is not None:
            raise self.network_snapshot_failure
        return super().network_snapshot()

    def create_restore_point(self) -> int:
        self.restore_point_calls += 1
        if self.restore_point_failure is not None:
            raise self.restore_point_failure
        return self.restore_point_result

    def reset_network(self, kind, log, backup) -> None:
        self.reset_calls.append(kind)
        super().reset_network(kind, log, backup)

    def terminate_process(self, process) -> None:
        self.terminate_calls.append(process)
        super().terminate_process(process)


class KeyTrackingDemoPlatform(SpyDemoPlatform):
    def __init__(self, *, admin: bool = True):
        super().__init__(admin=admin)
        self.keys: set[tuple[str, str, int]] = set()
        for address in self.values:
            self._add_key_path(address.hive, address.key, address.view)

    def _add_key_path(self, hive: str, key: str, view: int) -> None:
        parts = key.split("\\")
        for end in range(1, len(parts) + 1):
            self.keys.add((hive, "\\".join(parts[:end]), view))

    def registry_subkeys(self, hive: str, key: str, view: int) -> list[str]:
        prefix = key.rstrip("\\") + "\\"
        return sorted(
            {
                path[len(prefix) :].split("\\", 1)[0]
                for found_hive, path, found_view in self.keys
                if found_hive == hive and found_view == view and path.startswith(prefix)
            }
        )

    def snapshot_registry(self, hive: str, key: str, view: int) -> dict:
        self.snapshot_calls.append((hive, key, view))
        if self.snapshot_failure is not None:
            raise self.snapshot_failure

        def snapshot(path: str) -> dict:
            values = self.registry_values(hive, path, view)
            children = {
                name: snapshot(path + "\\" + name)
                for name in self.registry_subkeys(hive, path, view)
            }
            return {
                "exists": (hive, path, view) in self.keys or bool(values or children),
                "values": {name: value.to_dict() for name, value in values.items()},
                "children": children,
            }

        return snapshot(key)

    def write_registry(self, address: RegistryAddress, value: RegistryValue | None) -> None:
        super().write_registry(address, value)
        if value is not None:
            self._add_key_path(address.hive, address.key, address.view)


def engine_for(
    directory: Path, platform: SpyDemoPlatform | None = None, *, root_name: str = "backups"
) -> tuple[SpyDemoPlatform, RepairEngine]:
    selected_platform = platform if platform is not None else SpyDemoPlatform()
    backup_root = directory / root_name
    selected_platform.backup_root = backup_root
    return selected_platform, RepairEngine(selected_platform, backup_root)


def platform_state(platform: SpyDemoPlatform) -> dict:
    state = {
        "registry": copy.deepcopy(platform.values),
        "hosts": copy.deepcopy(platform.hosts),
        "network_resets": tuple(platform.network_resets),
        "processes": tuple(platform.processes),
    }
    if hasattr(platform, "keys"):
        state["keys"] = copy.deepcopy(platform.keys)
    return state


def log_collector():
    entries = []

    def log(level: str, message: str) -> None:
        entries.append((level, message))

    return entries, log


@pytest.mark.parametrize(
    "ids",
    [[], ["not-a-repair"], ["taskmgr", "taskmgr"]],
    ids=["empty-selection", "unknown-id", "duplicate-id"],
)
def test_invalid_or_unchecked_selection_has_no_side_effects(tmp_path, ids):
    platform, engine = engine_for(tmp_path)
    before = platform_state(platform)
    entries, log = log_collector()

    with pytest.raises(ValueError):
        engine.apply(ids, log)

    assert platform_state(platform) == before
    assert platform.write_attempts == []
    assert platform.host_write_attempts == []
    assert platform.reset_calls == []
    assert platform.terminate_calls == []
    assert platform.snapshot_calls == []
    assert entries == []
    assert not engine.backup_root.exists()


def test_apply_changes_only_selected_operations(tmp_path):
    platform, engine = engine_for(tmp_path)
    before = platform_state(platform)
    selected = BY_ID["taskmgr"]

    result = engine.apply(["taskmgr"], log_collector()[1])

    expected = copy.deepcopy(before)
    for change in selected.changes:
        if change.desired is None:
            expected["registry"].pop(change.address, None)
        else:
            expected["registry"][change.address] = change.desired
    assert result.completed == ("taskmgr",)
    assert platform_state(platform) == expected
    selected_addresses = {change.address for change in selected.changes}
    assert {address for address, _ in platform.write_attempts} <= selected_addresses
    assert platform.host_write_attempts == []
    assert platform.reset_calls == []


def test_complete_backup_exists_before_first_registry_write(tmp_path):
    platform, engine = engine_for(tmp_path)

    result = engine.apply(["taskmgr"], log_collector()[1])

    assert result.backup.is_file()
    assert len(platform.backup_manifests_at_write) == 1
    assert platform.backup_manifests_at_write[0] == (result.backup,)
    document, repairs, values, _ = engine.backups.load(result.backup)
    addresses = {change.address.label for change in BY_ID["taskmgr"].changes}
    assert document["operations"] == ["taskmgr"]
    assert {repair.id for repair in repairs} == {"taskmgr"}
    assert set(values) == addresses
    assert values[
        RegistryAddress(
            "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"
        ).label
    ] == RegistryValue(4, 1)


@pytest.mark.parametrize(
    "failure",
    ["registry-snapshot", "network-snapshot", "branches-disk", "manifest-disk"],
)
def test_snapshot_or_backup_disk_failure_blocks_registry_and_network_changes(
    tmp_path, monkeypatch, failure
):
    platform, engine = engine_for(tmp_path)
    before = platform_state(platform)
    if failure == "registry-snapshot":
        platform.snapshot_failure = OSError("injected snapshot failure")
    elif failure == "network-snapshot":
        platform.network_snapshot_failure = OSError("injected network snapshot failure")
    elif failure == "branches-disk":

        def fail_backup_write(_path, _document):
            raise OSError("injected backup disk failure")

        monkeypatch.setattr(backup_module, "write_json", fail_backup_write)
    else:
        original_write_json = backup_module.write_json

        def fail_manifest_write(path, document):
            if path.name == "backup.json.tmp":
                raise OSError("injected backup manifest disk failure")
            original_write_json(path, document)

        monkeypatch.setattr(backup_module, "write_json", fail_manifest_write)

    if failure == "network-snapshot":
        expected_error = "injected network snapshot failure"
    elif failure == "manifest-disk":
        expected_error = "injected backup manifest disk failure"
    elif failure == "branches-disk":
        expected_error = "injected backup disk failure"
    else:
        expected_error = "injected snapshot failure"

    with pytest.raises(OSError, match=expected_error):
        engine.apply(["taskmgr", "winsock"], log_collector()[1])

    assert platform_state(platform) == before
    assert platform.write_attempts == []
    assert platform.host_write_attempts == []
    assert platform.reset_calls == []
    assert platform.restore_point_calls == (1 if failure == "manifest-disk" else 0)
    assert not list(engine.backup_root.glob("*/backup.json"))


def test_restore_point_failure_blocks_network_and_prior_selected_edits(tmp_path):
    platform, engine = engine_for(tmp_path)
    platform.restore_point_result = 0
    before = platform_state(platform)

    with pytest.raises(RuntimeError, match="точку восстановления"):
        engine.apply(["taskmgr", "winsock"], log_collector()[1])

    assert platform_state(platform) == before
    assert platform.write_attempts == []
    assert platform.reset_calls == []
    assert platform.restore_point_calls == 1
    assert not list(engine.backup_root.glob("*/backup.json"))


def test_manual_backup_does_not_replace_fresh_apply_backup(tmp_path):
    platform, engine = engine_for(tmp_path)
    address = RegistryAddress(
        "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"
    )
    manual = engine.create_backup(["taskmgr"], log_collector()[1])
    platform.values[address] = RegistryValue(4, 2)
    before_apply = platform_state(platform)

    result = engine.apply(["taskmgr"], log_collector()[1])

    assert result.backup != manual
    assert {manual, result.backup} == set(engine.backup_root.glob("*/backup.json"))
    assert len(platform.backup_manifests_at_write) == 1
    assert set(platform.backup_manifests_at_write[0]) == {manual, result.backup}
    assert engine.backups.load(manual)[2][address.label] == RegistryValue(4, 1)
    assert engine.backups.load(result.backup)[2][address.label] == RegistryValue(4, 2)
    expected = copy.deepcopy(before_apply)
    expected["registry"].pop(address)
    assert platform_state(platform) == expected


@pytest.mark.parametrize(
    "original",
    [
        RegistryValue(3, b"\x00\xff\x80"),
        RegistryValue(4, 2),
        RegistryValue(7, [r"C:\Windows\System32", r"C:\Tools\bin"]),
    ],
    ids=["binary-value", "dword-value", "multi-string-value"],
)
def test_registry_type_and_data_round_trip_through_backup_and_restore(tmp_path, original):
    platform, engine = engine_for(tmp_path)
    address = RegistryAddress("HKCU", EXPLORER, "Hidden")
    platform.values[address] = copy.deepcopy(original)
    before = platform_state(platform)

    applied = engine.apply(["hidden"], log_collector()[1])
    assert platform.read_registry(address) == RegistryValue(4, 1)
    assert engine.backups.load(applied.backup)[2][address.label] == original

    restored = engine.restore(applied.backup, log_collector()[1])

    assert restored.completed == ("hidden",)
    assert platform.read_registry(address) == original
    assert platform_state(platform) == before


def test_missing_registry_value_is_restored_without_losing_existing_key(tmp_path):
    platform, engine = engine_for(tmp_path, KeyTrackingDemoPlatform())
    address = RegistryAddress("HKCU", EXPLORER, "Hidden")
    platform.values.pop(address)
    original_key = (address.hive, address.key, address.view)
    assert original_key in platform.keys
    before = platform_state(platform)

    applied = engine.apply(["hidden"], log_collector()[1])
    assert engine.backups.load(applied.backup)[2][address.label] is None
    assert platform.read_registry(address) == RegistryValue(4, 1)

    engine.restore(applied.backup, log_collector()[1])

    assert platform.read_registry(address) is None
    assert platform_state(platform) == before


@pytest.mark.parametrize("add_unrelated_value", [False, True])
def test_restore_removes_only_created_value_and_keeps_new_key(tmp_path, add_unrelated_value):
    platform, engine = engine_for(tmp_path, KeyTrackingDemoPlatform())
    address = RegistryAddress("HKCU", EXPLORER, "Hidden")
    key_identity = (address.hive, address.key, address.view)
    for existing in tuple(platform.values):
        if (existing.hive, existing.key, existing.view) == key_identity:
            platform.values.pop(existing)
    platform.keys.discard(key_identity)
    before = platform_state(platform)
    assert platform.snapshot_registry(address.hive, address.key, address.view) == {
        "exists": False,
        "values": {},
        "children": {},
    }

    applied = engine.apply(["hidden"], log_collector()[1])
    assert platform.snapshot_registry(address.hive, address.key, address.view)["exists"]
    unrelated = RegistryAddress(address.hive, address.key, "OtherApplication")
    if add_unrelated_value:
        platform.values[unrelated] = RegistryValue(1, "created after repair")
    engine.restore(applied.backup, log_collector()[1])

    assert platform.snapshot_registry(address.hive, address.key, address.view) == {
        "exists": True,
        "values": {unrelated.name: platform.values[unrelated].to_dict()} if add_unrelated_value else {},
        "children": {},
    }
    assert platform.read_registry(address) is None
    # Value-only rollback cannot delete a branch another application may now use.
    before["keys"].add(key_identity)
    if add_unrelated_value:
        before["registry"][unrelated] = RegistryValue(1, "created after repair")
    assert platform_state(platform) == before


@pytest.mark.parametrize(
    ("mismatch", "value"),
    [("machine", "OTHER-MACHINE"), ("sid", "S-1-5-21-OTHER")],
    ids=["different-machine", "different-user"],
)
def test_backup_restore_rejects_a_different_machine_or_user(tmp_path, mismatch, value):
    source, source_engine = engine_for(tmp_path / "source")
    manifest = source_engine.create_backup(["taskmgr"], log_collector()[1])
    target, target_engine = engine_for(tmp_path / "target")
    target.identity_override = {**target.identity(), mismatch: value}
    before = platform_state(target)

    with pytest.raises(ValueError, match="другому компьютеру"):
        target_engine.restore(manifest, log_collector()[1])

    assert platform_state(target) == before
    assert target.write_attempts == []
    assert not target_engine.backup_root.exists()


def test_backup_restore_rejects_demo_mode_mismatch(tmp_path):
    source, source_engine = engine_for(tmp_path / "source")
    manifest = source_engine.create_backup(["taskmgr"], log_collector()[1])
    target, target_engine = engine_for(tmp_path / "target")
    target.is_demo = False
    before = platform_state(target)

    with pytest.raises(ValueError, match="другому компьютеру"):
        target_engine.restore(manifest, log_collector()[1])

    assert platform_state(target) == before
    assert target.write_attempts == []
    assert not target_engine.backup_root.exists()


@pytest.mark.parametrize("tamper", ["extra-target", "unknown-id"])
def test_restore_rejects_untrusted_backup_targets_and_operation_ids(tmp_path, tamper):
    platform, engine = engine_for(tmp_path)
    manifest = engine.create_backup(["taskmgr"], log_collector()[1])
    document = json.loads(manifest.read_text(encoding="utf-8"))
    if tamper == "extra-target":
        document["registry"][r"HKLM\Software\SystemRepairTests\Unexpected\Run [64]"] = (
            RegistryValue(1, "untrusted target").to_dict()
        )
    else:
        document["operations"] = ["unknown-operation"]
    manifest.write_text(json.dumps(document), encoding="utf-8")
    before = platform_state(platform)

    with pytest.raises(ValueError):
        engine.restore(manifest, log_collector()[1])

    assert platform_state(platform) == before
    assert platform.write_attempts == []
    assert platform.host_write_attempts == []
    assert len(list(engine.backup_root.glob("*/backup.json"))) == 1


@pytest.mark.parametrize(
    "original",
    [b"\xef\xbb\xbf127.0.0.1 sample.test\r\n\x00\xff", None],
    ids=["present", "absent"],
)
def test_hosts_backup_restore_preserves_exact_bytes_and_absence(tmp_path, original):
    platform, engine = engine_for(tmp_path)
    platform.hosts = original
    before = platform_state(platform)

    applied = engine.apply(["hosts"], log_collector()[1])

    assert platform.hosts == DEFAULT_HOSTS
    document, _, _, saved_hosts = engine.backups.load(applied.backup)
    assert saved_hosts == original
    assert document["hosts"]["existed"] is (original is not None)
    if original is not None:
        assert (applied.backup.parent / "hosts.bin").read_bytes() == original
    else:
        assert not (applied.backup.parent / "hosts.bin").exists()

    restored = engine.restore(applied.backup, log_collector()[1])

    assert restored.completed == ("hosts",)
    assert platform_state(platform) == before


def test_tampered_hosts_backup_is_rejected_before_restore_side_effects(tmp_path):
    platform, engine = engine_for(tmp_path)
    platform.hosts = b"192.0.2.9 original.test\r\n"
    manifest = engine.apply(["hosts"], log_collector()[1]).backup
    hosts_file = manifest.parent / "hosts.bin"
    hosts_file.write_bytes(hosts_file.read_bytes() + b"tampered")
    before = platform_state(platform)
    prior_host_writes = list(platform.host_write_attempts)

    with pytest.raises(ValueError, match="Контрольная сумма hosts"):
        engine.restore(manifest, log_collector()[1])

    assert platform_state(platform) == before
    assert platform.host_write_attempts == prior_host_writes
    assert platform.write_attempts == []
    assert len(list(engine.backup_root.glob("*/backup.json"))) == 1


def test_apply_reports_partial_failure_and_stops_before_later_operations(tmp_path):
    platform, engine = engine_for(tmp_path)
    hidden = RegistryAddress("HKCU", EXPLORER, "Hidden")
    super_hidden = RegistryAddress("HKCU", EXPLORER, "ShowSuperHidden")
    proxy_enable = RegistryAddress(
        "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable"
    )
    platform.fail_write_address = super_hidden
    before = platform_state(platform)
    entries, log = log_collector()

    with pytest.raises(RepairError) as caught:
        engine.apply(["hidden", "system_files", "proxy"], log)

    expected = copy.deepcopy(before)
    expected["registry"][hidden] = RegistryValue(4, 1)
    assert platform_state(platform) == expected
    assert [address for address, _ in platform.write_attempts] == [hidden, super_hidden]
    assert [address for address, _ in platform.successful_writes] == [hidden]
    assert all(address != proxy_enable for address, _ in platform.write_attempts)
    assert caught.value.backup is not None and caught.value.backup.is_file()
    assert "Уже завершено операций: 1" in str(caught.value)
    assert "Возможны частичные изменения текущей операции" in str(caught.value)
    assert any("Завершено: Показывать скрытые файлы" in message for _, message in entries)
    assert any(
        level == "ERROR" and "injected registry write failure" in message
        for level, message in entries
    )
    assert platform.host_write_attempts == []
    assert platform.reset_calls == []


def test_registry_readback_mismatch_fails_and_stops_next_operation(tmp_path):
    platform, engine = engine_for(tmp_path)
    hidden = RegistryAddress("HKCU", EXPLORER, "Hidden")
    super_hidden = RegistryAddress("HKCU", EXPLORER, "ShowSuperHidden")
    platform.ignore_write_addresses.add(hidden)
    before = platform_state(platform)

    with pytest.raises(RepairError, match="Не подтверждена запись"):
        engine.apply(["hidden", "system_files"], log_collector()[1])

    assert platform_state(platform) == before
    assert [address for address, _ in platform.write_attempts] == [hidden]
    assert platform.successful_writes == []
    assert all(address != super_hidden for address, _ in platform.write_attempts)
    assert platform.reset_calls == []


def test_concurrent_registry_change_after_backup_is_rejected_without_overwrite(
    tmp_path, monkeypatch
):
    platform, engine = engine_for(tmp_path)
    address = RegistryAddress("HKCU", EXPLORER, "Hidden")
    original_load = engine.backups.load
    load_count = 0
    externally_changed_state = []

    def change_after_backup_validation(path):
        nonlocal load_count
        loaded = original_load(path)
        load_count += 1
        if load_count == 1:
            platform.values[address] = RegistryValue(4, 9)
            externally_changed_state.append(platform_state(platform))
        return loaded

    monkeypatch.setattr(engine.backups, "load", change_after_backup_validation)

    with pytest.raises(RepairError, match="изменился после бэкапа") as caught:
        engine.apply(["hidden"], log_collector()[1])

    assert len(externally_changed_state) == 1
    assert platform_state(platform) == externally_changed_state[0]
    assert platform.write_attempts == []
    assert caught.value.backup is not None and caught.value.backup.is_file()


def test_scan_inspects_32_and_64_bit_ifeo_filters_without_modifications(tmp_path):
    platform, engine = engine_for(tmp_path)
    ifeo_values = {
        RegistryAddress("HKLM", IFEO + r"\cmd.exe", "Debugger", 32): RegistryValue(
            1, r"C:\Lab\debugger32.exe"
        ),
        RegistryAddress("HKLM", IFEO + r"\cmd.exe\Filters\shim.dll", "Debugger", 64): RegistryValue(
            1, r"C:\Lab\filter64.exe"
        ),
        RegistryAddress(
            "HKLM", IFEO + r"\regedit.exe\Filters\watch.dll", "Debugger", 32
        ): RegistryValue(1, r"C:\Lab\filter32.exe"),
    }
    platform.values.update(ifeo_values)
    before = platform_state(platform)
    entries, log = log_collector()

    result = engine.scan(log)

    observed_ifeo = {
        (finding.location, finding.name, finding.value)
        for finding in result.findings
        if finding.category == "IFEO"
    }
    expected_ifeo = {
        (f"HKLM\\{IFEO}\\cmd.exe [64]", "Debugger", r"C:\Lab\debugger.exe"),
        (f"HKLM\\{IFEO}\\cmd.exe [32]", "Debugger", r"C:\Lab\debugger32.exe"),
        (f"HKLM\\{IFEO}\\cmd.exe\\Filters\\shim.dll [64]", "Debugger", r"C:\Lab\filter64.exe"),
        (f"HKLM\\{IFEO}\\regedit.exe\\Filters\\watch.dll [32]", "Debugger", r"C:\Lab\filter32.exe"),
    }
    assert observed_ifeo == expected_ifeo
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    assert any(
        finding.category == "Run"
        and finding.name == "LabUpdater"
        and finding.location == f"HKCU\\{run_key} [64]"
        and finding.value == r"C:\Users\Lab\AppData\Local\LabUpdater.exe"
        for finding in result.findings
    )
    assert any(
        finding.category == "Winlogon"
        and finding.name == "Shell"
        and finding.location == f"HKLM\\{WINLOGON} [64]"
        and finding.value == "explorer.exe"
        and finding.status == "Типовое"
        for finding in result.findings
    )
    assert platform_state(platform) == before
    assert platform.write_attempts == []
    assert platform.host_write_attempts == []
    assert platform.reset_calls == []
    assert platform.terminate_calls == []
    assert platform.snapshot_calls == []
    assert not engine.backup_root.exists()
    assert any("изменения не выполняются" in message.casefold() for _, message in entries)


def test_no_admin_prevents_registry_writes_and_process_termination(tmp_path):
    platform, engine = engine_for(tmp_path, SpyDemoPlatform(admin=False))
    process = copy.deepcopy(platform.processes[0])
    before = platform_state(platform)

    with pytest.raises(PermissionError, match="Нужны права администратора"):
        engine.apply(["taskmgr"], log_collector()[1])
    with pytest.raises(PermissionError, match="Нужны права администратора"):
        engine.terminate(process, log_collector()[1])

    assert platform_state(platform) == before
    assert platform.write_attempts == []
    assert platform.host_write_attempts == []
    assert platform.reset_calls == []
    assert platform.terminate_calls == []
    assert not engine.backup_root.exists()
