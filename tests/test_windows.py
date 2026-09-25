from __future__ import annotations

import ntpath
import os
import re
import struct
import uuid

import pytest

from system_repair.model import RegistryAddress, RegistryValue
from system_repair.windows import WindowsPlatform

native_windows = pytest.mark.skipif(os.name != "nt", reason="requires native Windows APIs")


def windows_platform() -> WindowsPlatform:
    if struct.calcsize("P") != 8:
        pytest.skip("System Repair supports 64-bit Windows only")
    return WindowsPlatform()


@native_windows
def test_native_identity_sid_and_admin_lookup_are_read_only():
    platform = windows_platform()

    identity = platform.identity()
    admin = platform.is_admin()

    assert set(identity) == {"machine", "sid", "windows"}
    assert all(isinstance(value, str) and value.strip() for value in identity.values())
    assert re.fullmatch(r"S-\d+(?:-\d+)+", identity["sid"])
    assert ntpath.isabs(identity["windows"])
    assert isinstance(admin, bool)


@native_windows
def test_winreg_snapshot_and_restore_preserve_bytes_dword_and_multisz():
    platform = windows_platform()
    if not platform.is_admin():
        pytest.skip("WindowsPlatform registry writes require an elevated test process")

    winreg = platform.reg
    key = rf"Software\SystemRepairTests\{uuid.uuid4().hex}"
    addresses = {
        "Binary": RegistryAddress("HKCU", key, "Binary"),
        "Counter": RegistryAddress("HKCU", key, "Counter"),
        "SearchPath": RegistryAddress("HKCU", key, "SearchPath"),
    }
    original = {
        "Binary": RegistryValue(winreg.REG_BINARY, b"\x00\xff\x80\x10"),
        "Counter": RegistryValue(winreg.REG_DWORD, 0xA1B2C3D4),
        "SearchPath": RegistryValue(winreg.REG_MULTI_SZ, [r"C:\Windows\System32", r"C:\Tools\bin"]),
    }
    changed = {
        "Binary": RegistryValue(winreg.REG_BINARY, b"\x01\x02"),
        "Counter": RegistryValue(winreg.REG_DWORD, 7),
        "SearchPath": RegistryValue(winreg.REG_MULTI_SZ, [r"C:\Changed"]),
    }

    try:
        for name, value in original.items():
            platform.write_registry(addresses[name], value)
        snapshot = platform.snapshot_registry("HKCU", key, 64)
        assert snapshot == {
            "exists": True,
            "values": {name: value.to_dict() for name, value in original.items()},
            "children": {},
        }

        for name, value in changed.items():
            platform.write_registry(addresses[name], value)
        assert platform.registry_values("HKCU", key, 64) == changed

        restored = {
            name: RegistryValue.from_dict(value) for name, value in snapshot["values"].items()
        }
        for name, value in restored.items():
            platform.write_registry(addresses[name], value)

        assert platform.registry_values("HKCU", key, 64) == original
        assert platform.snapshot_registry("HKCU", key, 64) == snapshot
    finally:
        try:
            winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, key, access=winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            pass


@pytest.mark.parametrize(
    ("kind", "expected_arguments"),
    [
        ("winsock", ["winsock", "reset"]),
        ("tcpip", ["int", "ip", "reset"]),
    ],
)
def test_network_reset_uses_fixed_netsh_arguments_without_running_commands(
    monkeypatch, tmp_path, kind, expected_arguments
):
    platform = object.__new__(WindowsPlatform)
    monkeypatch.setattr(platform, "_require_admin", lambda: None)
    invocations = []
    entries = []

    def command(program, arguments, log=None):
        invocations.append((program, list(arguments)))
        return "mocked netsh output"

    monkeypatch.setattr(platform, "_command", command)
    backup = tmp_path / "backup"
    expected = list(expected_arguments)
    if kind == "tcpip":
        expected.append(str(backup / "tcpip-reset.log"))

    platform.reset_network(kind, lambda level, message: entries.append((level, message)), backup)

    assert invocations == [("netsh.exe", expected)]
    assert any(level == "WARN" and "кодом 0" in message and "не гарантирует" in message
               for level, message in entries)


def test_restore_point_verifies_new_unique_sequence_without_policy_bypass(monkeypatch):
    platform = object.__new__(WindowsPlatform)
    monkeypatch.setattr(platform, "_require_admin", lambda: None)
    invocations = []

    def command(program, arguments, **kwargs):
        invocations.append((program, arguments, kwargs))
        return "123\r\n"

    monkeypatch.setattr(platform, "_command", command)
    assert platform.create_restore_point() == 123
    program, arguments, options = invocations[0]
    assert program == "powershell.exe"
    assert arguments[:4] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
    script = arguments[4]
    assert "Checkpoint-Computer" in script and "Get-ComputerRestorePoint" in script
    assert "-WarningAction Stop" in script and "$before -notcontains" in script
    assert len(set(re.findall(r"System Repair [a-f0-9]{32}", script))) == 1
    assert "ExecutionPolicy" not in script and "Bypass" not in script
    assert options == {"timeout": 300}


@pytest.mark.parametrize("output", ["", "0", "-1", "not a number", "123\n123"])
def test_restore_point_rejects_unconfirmed_result(monkeypatch, output):
    platform = object.__new__(WindowsPlatform)
    monkeypatch.setattr(platform, "_require_admin", lambda: None)
    monkeypatch.setattr(platform, "_command", lambda *args, **kwargs: output)
    with pytest.raises(OSError):
        platform.create_restore_point()
