from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

import system_repair.audit as audit_module
import system_repair.powershell as powershell_module
from system_repair.audit import AuditEngine
from system_repair.demo import DemoPlatform


def _logger(entries):
    return lambda level, message: entries.append((level, message))


def _unexpected_command(*args, **kwargs):
    pytest.fail(f"Unexpected system command: {args!r} {kwargs!r}")


@pytest.mark.parametrize(
    "action",
    ["sfc", "diskmgmt", "recovery", "safe", "uefi", "cancel_restart", "appearance"],
)
def test_demo_system_actions_never_execute_commands(tmp_path, monkeypatch, action):
    platform = DemoPlatform()
    engine = AuditEngine(platform, tmp_path / "backups")
    entries = []
    monkeypatch.setattr(audit_module.subprocess, "Popen", _unexpected_command)
    monkeypatch.setattr(audit_module.subprocess, "run", _unexpected_command)
    monkeypatch.setattr(platform, "_command", _unexpected_command, raising=False)
    monkeypatch.setattr(audit_module.os, "startfile", _unexpected_command, raising=False)

    engine.system(action, _logger(entries))

    assert len(entries) == 1
    assert "ДЕМО" in entries[0][1]
    assert not engine.journal.root.exists()


@pytest.mark.parametrize("action", ["sfc", "recovery", "safe", "uefi", "cancel_restart"])
def test_demo_privileged_system_actions_reject_non_admin(tmp_path, action):
    platform = DemoPlatform()
    platform.is_admin = lambda: False
    engine = AuditEngine(platform, tmp_path / "backups")

    with pytest.raises(PermissionError, match="администратора"):
        engine.system(action, _logger([]))

    assert not engine.journal.root.exists()


@pytest.mark.parametrize("action", ["diskmgmt", "appearance"])
def test_unprivileged_demo_system_actions_are_available_without_admin(tmp_path, action):
    platform = DemoPlatform()
    platform.is_admin = lambda: False
    engine = AuditEngine(platform, tmp_path / "backups")
    entries = []

    engine.system(action, _logger(entries))

    assert len(entries) == 1
    assert "ДЕМО" in entries[0][1]
    assert not engine.journal.root.exists()


def test_system_rejects_unknown_action_before_any_command_or_admin_check(tmp_path, monkeypatch):
    platform = DemoPlatform()
    platform.is_admin = lambda: False
    engine = AuditEngine(platform, tmp_path / "backups")
    monkeypatch.setattr(audit_module.subprocess, "Popen", _unexpected_command)
    monkeypatch.setattr(platform, "_command", _unexpected_command, raising=False)

    with pytest.raises(ValueError, match="Неизвестное системное действие"):
        engine.system("restart-arbitrary-command", _logger([]))

    assert not engine.journal.root.exists()


def test_audit_engine_rejects_demo_file_mutation_without_admin(tmp_path):
    platform = DemoPlatform()
    platform.is_admin = lambda: False
    engine = AuditEngine(platform, tmp_path / "backups")
    entries = engine.files("synthetic demo path", 0, _logger([])).entries

    with pytest.raises(PermissionError, match="администратора"):
        engine.file_action((entries[0],), "quarantine", "", _logger([]))

    assert tuple(engine.demo.file_items) == entries
    assert not engine.journal.root.exists()


def test_run_json_uses_fixed_executable_and_keeps_payload_on_stdin(tmp_path, monkeypatch):
    system_dir = tmp_path / "Windows" / "System32"
    platform = SimpleNamespace(system_dir=str(system_dir))
    script = "$inputData | ConvertTo-Json -Compress"
    injected_path = "C:\\Temp\\sample.exe'; Start-Process calc; #"
    payload = {"paths": [injected_path], "label": "проверка"}
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout='{"ok": true}', stderr="")

    monkeypatch.setattr(powershell_module.subprocess, "run", fake_run)

    result = powershell_module.run_json(platform, script, payload, timeout=17)

    command = captured["command"]
    kwargs = captured["kwargs"]
    executable = system_dir / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    assert result == {"ok": True}
    assert command[:5] == [
        str(executable),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    ]
    assert command[5].endswith(script)
    assert injected_path not in command[5]
    assert json.loads(kwargs["input"]) == payload
    assert "проверка" in kwargs["input"]
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 17
    assert kwargs["capture_output"] is True
    assert kwargs["encoding"] == "utf-8"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell UTF-8 transport")
def test_native_powershell_roundtrips_unicode_without_stdin_bom():
    from system_repair.windows import WindowsPlatform

    payload = {"label": "проверка", "path": "C:\\Lab\\test.exe'; no code here; #"}
    result = powershell_module.run_json(
        WindowsPlatform(), "$inputData | ConvertTo-Json -Compress", payload
    )
    assert result == payload
