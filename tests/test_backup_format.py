import json

import pytest

from system_repair.catalog import BY_ID
from system_repair.demo import DemoPlatform
from system_repair.engine import RepairEngine
from system_repair.model import RegistryValue


@pytest.mark.parametrize("value", [
    RegistryValue(0, None),
    RegistryValue(0, b""),
    RegistryValue(1, 'Сеть & "путь"'),
    RegistryValue(2, r"%SystemRoot%\system32"),
    RegistryValue(3, b"\x00\xff\x01"),
    RegistryValue(3, None),
    RegistryValue(4, 2**32 - 1),
    RegistryValue(5, b"\x00\x00\x00\x01"),
    RegistryValue(6, b"\x01\x00"),
    RegistryValue(7, ["first", "второй"]),
    RegistryValue(7, []),
    RegistryValue(8, b"\x00\xff"),
    RegistryValue(9, b"\x00\xff"),
    RegistryValue(10, b"\x00\xff"),
    RegistryValue(11, 2**64 - 1),
])
def test_lossless_json_value_round_trip(value):
    serialized = json.loads(json.dumps(value.to_dict()))
    assert RegistryValue.from_dict(serialized) == value


@pytest.mark.parametrize("raw", [
    None,
    {"type": True, "data": "a"},
    {"type": 12, "data": None},
    {"type": 1, "data": 2},
    {"type": 4, "data": -1},
    {"type": 4, "data": 2**32},
    {"type": 4, "data": True},
    {"type": 5, "data": 1},
    {"type": 11, "data": 2**64},
    {"type": 7, "data": ["one", 2]},
    {"type": 3, "data": "bad base64", "encoding": "base64"},
    {"type": 3, "data": "", "encoding": "exec"},
    {"type": 4, "data": 1, "surprise": "ignored?"},
])
def test_invalid_value_cannot_be_used_for_restore(raw):
    with pytest.raises(ValueError):
        RegistryValue.from_dict(raw)


def test_full_branch_backup_preserves_other_values_without_logging_contents(tmp_path):
    backend = DemoPlatform()
    address = BY_ID["taskmgr"].changes[0].address
    sibling = type(address)(address.hive, address.key, "UnrelatedApplication")
    backend.values[sibling] = RegistryValue(1, "synthetic-private-string")
    events = []
    engine = RepairEngine(backend, tmp_path)
    result = engine.apply(["taskmgr"], lambda level, message: events.append(message))
    snapshots = json.loads((result.backup.parent / "branches.json").read_text(encoding="utf-8"))
    user_branch = next(branch for branch in snapshots if branch["hive"] == "HKCU")
    assert user_branch["tree"]["values"][sibling.name] == backend.values[sibling].to_dict()
    assert "synthetic-private-string" not in "\n".join(events)
    assert backend.values[sibling].data == "synthetic-private-string"


def test_native_windows_registry_data_model_can_be_imported_without_loading_windows():
    from system_repair.windows import WindowsPlatform

    assert WindowsPlatform.is_demo is False


def test_manual_network_backup_does_not_consume_restore_point_quota(tmp_path, monkeypatch):
    backend = DemoPlatform()
    calls = []

    def restore_point():
        calls.append("point")
        return 123

    monkeypatch.setattr(backend, "create_restore_point", restore_point)
    engine = RepairEngine(backend, tmp_path)
    manual = engine.create_backup(["winsock"], lambda *args: None)
    assert calls == []
    assert json.loads(manual.read_text(encoding="utf-8"))["restore_point"] is None
    applied = engine.apply(["winsock"], lambda *args: None)
    assert applied.backup != manual
    assert calls == ["point"]
    assert json.loads(applied.backup.read_text(encoding="utf-8"))["restore_point"] == 123
    assert backend.network_resets == ["winsock"]
