from __future__ import annotations

import ntpath
import os
import struct
import subprocess
import sys
import types
from dataclasses import replace

import psutil
import pytest

import system_repair.processes as processes
from system_repair.audit_model import SignatureInfo
from system_repair.model import ProcessInfo
from system_repair.processes import ProcessManager, SignatureInspector
from system_repair.windows import WindowsPlatform


class FakeHandle:
    def __init__(self, process):
        self.process = process
        self.closed = False


class FakeKernel:
    def __init__(self, processes):
        self.processes = processes
        self.opened = []
        self.closed = []
        self.terminated = []
        self.events = []

    def OpenProcess(self, access, _inherit, pid):
        process = self.processes.get(pid)
        if process is None:
            return 0
        handle = FakeHandle(process)
        self.opened.append((access, handle))
        self.events.append(("open", pid))
        return handle

    def IsProcessCritical(self, handle, result):
        process = handle.process
        if process.get("critical_error"):
            return False
        result._obj.value = bool(process.get("critical", False))
        return True

    def GetProcessTimes(self, handle, created, exited, kernel, user):
        process = handle.process
        if process.get("times_error"):
            return False
        ticks = int((process["created"] + 11_644_473_600) * 10_000_000)
        created._obj.dwHighDateTime = ticks >> 32
        created._obj.dwLowDateTime = ticks & 0xFFFFFFFF
        for field in (exited, kernel, user):
            field._obj.dwHighDateTime = 0
            field._obj.dwLowDateTime = 0
        return True

    def QueryFullProcessImageNameW(self, handle, _flags, buffer, size):
        process = handle.process
        if process.get("path_error"):
            return False
        buffer.value = process["path"]
        size._obj.value = len(process["path"])
        return True

    def TerminateProcess(self, handle, _exit_code):
        self.terminated.append(handle.process["pid"])
        self.events.append(("terminate", handle.process["pid"]))
        handle.process["exited"] = True
        return True

    def WaitForSingleObject(self, handle, _timeout):
        return 0 if handle.process.get("exited") else 0x102

    def CloseHandle(self, handle):
        handle.closed = True
        self.closed.append(handle)
        return True


class FakeNtDll:
    def __init__(self):
        self.suspended = []
        self.partially_suspended = []
        self.resumed = []
        self.suspend_status = 0
        self.resume_status = 0

    def NtSuspendProcess(self, handle):
        pid = handle.process["pid"]
        self.suspended.append(pid)
        if self.suspend_status < 0:
            self.partially_suspended.append(pid)
        return self.suspend_status

    def NtResumeProcess(self, handle):
        pid = handle.process["pid"]
        self.resumed.append(pid)
        if pid in self.partially_suspended:
            self.partially_suspended.remove(pid)
        return self.resume_status


class FakeBackend:
    is_demo = False
    system_dir = r"C:\Windows\System32"
    windows_dir = r"C:\Windows"

    def __init__(self, processes):
        self.kernel = FakeKernel(processes)

    def _require_admin(self):
        return None


def _native(pid, path, *, created=1_700_000_000.0, critical=False):
    return {"pid": pid, "path": path, "created": created, "critical": critical}


def _process(pid, path, *, created=1_700_000_000.0, critical=False, name=None, parent_pid=1):
    return ProcessInfo(
        pid=pid,
        name=name or ntpath.basename(path),
        path=path,
        user="user",
        created=created,
        critical=critical,
        parent_pid=parent_pid,
    )


def _logs():
    return []


def _logger(entries):
    return lambda level, message: entries.append((level, message))


def test_signature_inspector_batches_and_caches_without_interpolating_paths(tmp_path, monkeypatch):
    first = tmp_path / "first.exe"
    second = tmp_path / "second.exe"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    calls = []

    def run_json(backend, script, payload, timeout):
        calls.append((backend, script, payload, timeout))
        return [
            {
                "path": path,
                "status": "Valid",
                "company": "Microsoft Corporation",
                "signer": "CN=Microsoft Windows, O=Microsoft Corporation, C=US",
            }
            for path in payload["paths"]
        ]

    monkeypatch.setitem(sys.modules, "system_repair.powershell", types.SimpleNamespace(run_json=run_json))
    backend = FakeBackend({})
    inspector = SignatureInspector(backend)

    results = inspector.inspect_many([str(first), str(second), str(first)])
    assert results[str(first)].status == "Valid"
    assert results[str(second)].company == "Microsoft Corporation"
    assert len(calls) == 1
    assert calls[0][2]["paths"] == [str(first), str(second)]
    assert "first.exe" not in calls[0][1]
    inspector.inspect_many([str(first), str(second)])
    assert len(calls) == 1


def test_hidden_path_detects_windows_hidden_parent_attribute(monkeypatch):
    path = r"C:\Users\test\Private\worker.exe"

    def fake_stat(candidate):
        normalized = ntpath.normcase(ntpath.normpath(candidate))
        if normalized == r"c:\users\test\private":
            return types.SimpleNamespace(st_file_attributes=0x2)
        return types.SimpleNamespace(st_file_attributes=0)

    monkeypatch.setattr(processes.os, "stat", fake_stat)
    assert processes._is_hidden_path(path)


def test_signature_inspector_invalidates_cache_after_file_changes(tmp_path, monkeypatch):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"one")
    calls = []

    def run_json(_backend, _script, payload, timeout):
        assert timeout == 120
        calls.append(tuple(payload["paths"]))
        return [{"path": path, "status": "NotSigned"} for path in payload["paths"]]

    monkeypatch.setitem(sys.modules, "system_repair.powershell", types.SimpleNamespace(run_json=run_json))
    inspector = SignatureInspector(FakeBackend({}))
    inspector.inspect(str(target))
    target.write_bytes(b"changed content")
    inspector.inspect(str(target))
    assert len(calls) == 2


def test_signature_failures_are_unknown_and_not_company_based(tmp_path, monkeypatch):
    target = tmp_path / "unsigned.exe"
    target.write_bytes(b"unsigned")
    monkeypatch.setitem(
        sys.modules,
        "system_repair.powershell",
        types.SimpleNamespace(
            run_json=lambda *_args, **_kwargs: [
                {"path": str(target), "status": "NotSigned", "company": "Microsoft Corporation", "signer": ""}
            ]
        ),
    )
    inspector = SignatureInspector(FakeBackend({}))
    signature = inspector.inspect(str(target))
    assert signature.status == "NotSigned"


def test_signature_backend_failure_is_unknown(tmp_path, monkeypatch):
    target = tmp_path / "unavailable.exe"
    target.write_bytes(b"file")

    def failed_query(*_args, **_kwargs):
        raise OSError("PowerShell unavailable")

    monkeypatch.setitem(
        sys.modules,
        "system_repair.powershell",
        types.SimpleNamespace(run_json=failed_query),
    )
    assert SignatureInspector(FakeBackend({})).inspect(str(target)).status == "UnknownError"


def test_process_inventory_includes_command_parent_hidden_critical_signature_and_strict_trust(tmp_path, monkeypatch):
    hidden = r"C:\Users\test\.cache\agent.exe"
    temp_path = r"C:\Users\test\AppData\Local\Temp\worker.exe"
    specs = [
        {"pid": 900001, "name": "agent.exe", "path": hidden, "user": "u", "created": 1700000000.0,
         "command": [hidden, "--flag", "two words"], "parent": 400001, "critical": False},
        {"pid": 900002, "name": "worker.exe", "path": temp_path, "user": "u", "created": 1700000001.0,
         "command": [temp_path], "parent": 900001, "critical": True},
        {"pid": 900003, "name": "winlogon.exe", "path": r"C:\Windows\System32\winlogon.exe", "user": "u",
             "created": 1700000002.0, "command": ["winlogon.exe"], "parent": 1, "critical": False},
        {"pid": 900004, "name": "devicehelper.exe", "path": r"C:\Windows\System32\devicehelper.exe", "user": "u",
             "created": 1700000003.0, "command": ["devicehelper.exe"], "parent": 1, "critical": False},
    ]

    class FakePsutilProcess:
        def __init__(self, spec):
            self.pid = spec["pid"]
            self.spec = spec

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def oneshot(self):
            return self

        def name(self):
            return self.spec["name"]

        def exe(self):
            return self.spec["path"]

        def username(self):
            return self.spec["user"]

        def create_time(self):
            return self.spec["created"]

        def cmdline(self):
            return self.spec["command"]

        def ppid(self):
            return self.spec["parent"]

    native = {
        item["pid"]: _native(item["pid"], item["path"], created=item["created"], critical=item["critical"])
        for item in specs
    }
    monkeypatch.setattr(psutil, "process_iter", lambda: [FakePsutilProcess(item) for item in specs])
    manager = ProcessManager(FakeBackend(native))
    monkeypatch.setattr(
        manager.signatures,
        "inspect_many",
        lambda paths: {
            hidden: SignatureInfo("Valid", "Microsoft Corporation", "CN=Unknown, O=Microsoft Corporation"),
            temp_path: SignatureInfo("Valid", "Microsoft Corporation", "CN=Unknown, O=Microsoft Corporation"),
            specs[2]["path"]: SignatureInfo("Valid", "Microsoft Corporation", "CN=Third Party, O=Other Corp"),
            specs[3]["path"]: SignatureInfo("Valid", "Unrelated Company", "CN=Microsoft Windows, O=Microsoft Corporation"),
        },
    )

    rows = {item.pid: item for item in manager.list_processes(_logger(_logs()))}
    assert rows[900001].command_line.endswith('--flag "two words"')
    assert rows[900001].parent_pid == 400001
    assert rows[900001].hidden is True
    assert rows[900001].trusted is False
    assert rows[900002].critical is True
    assert rows[900002].status == "Критический"
    assert rows[900002].trusted is False
    assert rows[900003].trusted is False
    assert rows[900004].trusted is True


def test_process_inventory_marks_critical_unknown_when_held_handle_identity_differs(monkeypatch):
    pid = 900005
    scanned_path = r"C:\Users\test\worker.exe"
    scanned_created = 1_700_000_000.0
    live_path = r"C:\Users\test\reused-pid.exe"

    class FakePsutilProcess:
        def __init__(self):
            self.pid = pid

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def oneshot(self):
            return self

        def name(self):
            return "worker.exe"

        def exe(self):
            return scanned_path

        def username(self):
            return "test-user"

        def create_time(self):
            return scanned_created

        def cmdline(self):
            return [scanned_path]

        def ppid(self):
            return 1

    monkeypatch.setattr(psutil, "process_iter", lambda: [FakePsutilProcess()])
    backend = FakeBackend(
        {pid: _native(pid, live_path, created=scanned_created, critical=True)}
    )
    manager = ProcessManager(backend)
    monkeypatch.setattr(
        manager.signatures,
        "inspect_many",
        lambda _paths: {scanned_path: SignatureInfo("Valid")},
    )

    [row] = manager.list_processes(_logger(_logs()))

    assert row.path == scanned_path
    assert row.critical is None
    assert row.status == "Критичность не проверена"
    assert len(backend.kernel.closed) == 1
    assert backend.kernel.closed[0].closed


def test_action_rejects_unknown_criticality_and_protected_or_ancestor_pids_before_opening():
    backend = FakeBackend({})
    manager = ProcessManager(backend)
    log = _logger(_logs())
    ordinary = _process(900010, r"C:\Tools\worker.exe")

    with pytest.raises(PermissionError, match="Критичность"):
        manager.action(replace(ordinary, critical=None), "kill", log)
    with pytest.raises(PermissionError, match="идентификация"):
        manager.action(replace(ordinary, path=""), "kill", log)
    with pytest.raises(PermissionError, match="Защищённый"):
        manager.action(_process(900011, r"C:\Windows\System32\csrss.exe"), "kill", log)
    for pid in (os.getpid(), os.getppid(), 4):
        with pytest.raises(PermissionError):
            manager.action(replace(ordinary, pid=pid), "kill", log)
    assert backend.kernel.opened == []


@pytest.mark.parametrize("field,value", [("created", 1_699_999_990.0), ("path", r"C:\Other\worker.exe")])
def test_kill_rejects_pid_reuse_identity_and_closes_handle(field, value):
    actual = _native(900020, r"C:\Tools\worker.exe")
    backend = FakeBackend({900020: actual})
    manager = ProcessManager(backend)
    process = _process(900020, actual["path"])
    with pytest.raises(RuntimeError, match="PID"):
        manager.action(replace(process, **{field: value}), "kill", _logger(_logs()))
    assert backend.kernel.terminated == []
    assert len(backend.kernel.closed) == 1
    assert backend.kernel.closed[0].closed


def test_kill_uses_the_verified_handle_and_closes_it():
    actual = _native(900021, r"C:\Tools\worker.exe")
    backend = FakeBackend({900021: actual})
    manager = ProcessManager(backend)
    manager.action(_process(900021, actual["path"]), "kill", _logger(_logs()))
    access, handle = backend.kernel.opened[0]
    assert access & 0x0001
    assert backend.kernel.terminated == [900021]
    assert backend.kernel.closed == [handle]
    assert handle.closed


def test_live_criticality_query_failure_blocks_kill_and_closes_handle():
    actual = _native(900026, r"C:\Tools\worker.exe")
    actual["critical_error"] = True
    backend = FakeBackend({900026: actual})
    manager = ProcessManager(backend)
    with pytest.raises(OSError, match="критичность"):
        manager.action(_process(900026, actual["path"]), "kill", _logger(_logs()))
    assert backend.kernel.terminated == []
    assert backend.kernel.closed[0].closed


@pytest.mark.parametrize("code,errno,detail", [(5, 13, "Access is denied."), (87, 22, "The parameter is incorrect.")])
def test_native_error_preserves_operation_and_windows_error_code(monkeypatch, code, errno, detail):
    native_error = OSError(errno, detail)
    native_error.winerror = code

    def win_error(actual_code):
        assert actual_code == code
        return native_error

    monkeypatch.setattr(processes.ctypes, "WinError", win_error, raising=False)
    monkeypatch.setattr(processes.ctypes, "get_last_error", lambda: code, raising=False)
    message = "Не удалось проверить критичность процесса"
    error = ProcessManager._raise_last_error(message)

    assert error is native_error
    assert error.errno == errno
    assert error.winerror == code
    assert message in str(error)
    assert detail in str(error)
    assert error.args == (errno, f"{message}: {detail}")


def test_suspend_is_not_repeated_and_resume_only_uses_manager_owned_handle():
    actual = _native(900022, r"C:\Tools\worker.exe")
    backend = FakeBackend({900022: actual})
    manager = ProcessManager(backend)
    manager._ntdll = FakeNtDll()
    process = _process(900022, actual["path"])
    log = _logger(_logs())

    manager.action(process, "suspend", log)
    first_handle = backend.kernel.opened[0][1]
    manager.action(process, "suspend", log)
    assert manager._ntdll.suspended == [900022]
    assert manager.has_suspended
    assert not first_handle.closed

    manager.action(process, "resume", log)
    assert manager._ntdll.resumed == [900022]
    assert not manager.has_suspended
    assert first_handle.closed
    with pytest.raises(PermissionError, match="не приостанавливала"):
        manager.action(process, "resume", log)


def test_suspended_process_must_be_resumed_before_kill():
    actual = _native(900028, r"C:\Tools\worker.exe")
    backend = FakeBackend({900028: actual})
    manager = ProcessManager(backend)
    manager._ntdll = FakeNtDll()
    process = _process(900028, actual["path"])
    log = _logger(_logs())
    manager.action(process, "suspend", log)

    with pytest.raises(PermissionError, match="Сначала возобновите"):
        manager.action(process, "kill", log)
    assert backend.kernel.terminated == []
    manager.action(process, "resume", log)


def test_suspend_failure_retains_uncertain_state_and_allows_explicit_recovery():
    system_native = _native(900023, r"C:\Windows\System32\notepad.exe")
    system_backend = FakeBackend({900023: system_native})
    system_manager = ProcessManager(system_backend)
    with pytest.raises(PermissionError, match="системных каталогов"):
        system_manager.action(_process(900023, system_native["path"]), "suspend", _logger(_logs()))
    assert system_backend.kernel.opened == []

    native = _native(900024, r"C:\Tools\worker.exe")
    backend = FakeBackend({900024: native})
    manager = ProcessManager(backend)
    manager._ntdll = FakeNtDll()
    manager._ntdll.suspend_status = -0x3FFFFFFF
    process = _process(900024, native["path"])
    entries = _logs()
    with pytest.raises(OSError, match="NTSTATUS"):
        manager.action(process, "suspend", _logger(entries))
    handle = backend.kernel.opened[0][1]
    record = manager._suspended[process.pid]
    assert manager._ntdll.partially_suspended == [process.pid]
    assert manager.has_suspended
    assert record.uncertain
    assert not handle.closed
    assert any("неопределенным состоянием" in message for _, message in entries)
    with pytest.raises(RuntimeError, match="сначала попробуйте возобновить"):
        manager.action(process, "suspend", _logger(entries))

    manager.action(process, "resume", _logger(entries))

    assert manager._ntdll.resumed == [process.pid]
    assert manager._ntdll.partially_suspended == []
    assert not manager.has_suspended
    assert handle.closed
    assert any("после неопределенного результата" in message for _, message in entries)


def test_suspend_rejects_system_paths_without_opening_handle():
    system_native = _native(900023, r"C:\Windows\System32\notepad.exe")
    system_backend = FakeBackend({900023: system_native})
    system_manager = ProcessManager(system_backend)
    with pytest.raises(PermissionError, match="системных каталогов"):
        system_manager.action(_process(900023, system_native["path"]), "suspend", _logger(_logs()))
    assert system_backend.kernel.opened == []


def test_resume_all_uses_only_retained_handles():
    native = _native(900025, r"C:\Tools\worker.exe")
    backend = FakeBackend({900025: native})
    manager = ProcessManager(backend)
    manager._ntdll = FakeNtDll()
    process = _process(900025, native["path"])
    manager.action(process, "suspend", _logger(_logs()))
    manager.resume_all(_logger(_logs()))
    assert manager._ntdll.resumed == [900025]
    assert not manager.has_suspended
    assert backend.kernel.closed[0].closed


def test_resume_all_releases_a_handle_if_the_suspended_process_exited():
    native = _native(900027, r"C:\Tools\worker.exe")
    backend = FakeBackend({900027: native})
    manager = ProcessManager(backend)
    manager._ntdll = FakeNtDll()
    process = _process(900027, native["path"])
    manager.action(process, "suspend", _logger(_logs()))
    handle = backend.kernel.opened[0][1]
    native["exited"] = True

    manager.resume_all(_logger(_logs()))

    assert manager._ntdll.resumed == []
    assert not manager.has_suspended
    assert handle.closed


def test_plan_tree_returns_immutable_child_first_records(monkeypatch):
    root = _process(900030, r"C:\Tools\root.exe", parent_pid=1)
    child = _process(900031, r"C:\Tools\child.exe", parent_pid=root.pid)
    grandchild = _process(900032, r"C:\Tools\grandchild.exe", parent_pid=child.pid)
    manager = ProcessManager(FakeBackend({}))
    monkeypatch.setattr(manager, "list_processes", lambda _log: [root, child, grandchild])

    plan = manager.plan_tree(root, _logger(_logs()))
    assert isinstance(plan, tuple)
    assert [process.pid for process in plan] == [grandchild.pid, child.pid, root.pid]


def test_kill_tree_preflights_every_handle_before_child_first_termination():
    root = _process(900040, r"C:\Tools\root.exe", parent_pid=1)
    child = _process(900041, r"C:\Tools\child.exe", parent_pid=root.pid)
    native = {
        root.pid: _native(root.pid, root.path),
        child.pid: _native(child.pid, child.path),
    }
    backend = FakeBackend(native)
    manager = ProcessManager(backend)
    manager.kill_tree((child, root), _logger(_logs()))
    assert [kind for kind, _ in backend.kernel.events] == [
        "open", "open", "terminate", "terminate"
    ]
    assert backend.kernel.terminated == [child.pid, root.pid]
    assert all(handle.closed for _, handle in backend.kernel.opened)


def test_kill_tree_stale_target_aborts_before_any_termination():
    root = _process(900050, r"C:\Tools\root.exe", parent_pid=1)
    child = _process(900051, r"C:\Tools\child.exe", parent_pid=root.pid)
    backend = FakeBackend(
        {
            root.pid: _native(root.pid, root.path),
            child.pid: _native(child.pid, child.path, created=1_700_000_010.0),
        }
    )
    manager = ProcessManager(backend)
    with pytest.raises(RuntimeError, match="PID"):
        manager.kill_tree((child, root), _logger(_logs()))
    assert backend.kernel.terminated == []
    assert all(handle.closed for _, handle in backend.kernel.opened)


def test_kill_tree_revalidates_each_target_after_preflight():
    root = _process(900052, r"C:\Tools\root.exe", parent_pid=1)
    child = _process(900053, r"C:\Tools\child.exe", parent_pid=root.pid)
    root_native = _native(root.pid, root.path)
    backend = FakeBackend({root.pid: root_native, child.pid: _native(child.pid, child.path)})
    manager = ProcessManager(backend)
    terminate = backend.kernel.TerminateProcess

    def terminate_and_update(handle, exit_code):
        result = terminate(handle, exit_code)
        if handle.process["pid"] == child.pid:
            root_native["critical"] = True
        return result

    backend.kernel.TerminateProcess = terminate_and_update
    with pytest.raises(PermissionError, match="критический"):
        manager.kill_tree((child, root), _logger(_logs()))
    assert backend.kernel.terminated == [child.pid]
    assert all(handle.closed for _, handle in backend.kernel.opened)


def test_kill_tree_rejects_parent_first_or_mutable_plans():
    root = _process(900060, r"C:\Tools\root.exe", parent_pid=1)
    child = _process(900061, r"C:\Tools\child.exe", parent_pid=root.pid)
    backend = FakeBackend({})
    manager = ProcessManager(backend)
    with pytest.raises(ValueError, match="потомков"):
        manager.kill_tree((root, child), _logger(_logs()))
    with pytest.raises(ValueError, match="непустой неизменяемый"):
        manager.kill_tree([child, root], _logger(_logs()))
    assert backend.kernel.opened == []


@pytest.mark.skipif(os.name != "nt" or struct.calcsize("P") != 8, reason="requires native 64-bit Windows")
def test_native_manager_terminates_only_its_owned_child():
    backend = WindowsPlatform()
    if not backend.is_admin():
        pytest.skip("Native process actions require an elevated test runner")
    manager = ProcessManager(backend)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        process = psutil.Process(child.pid)
        snapshot = ProcessInfo(
            pid=child.pid,
            name=process.name(),
            path=process.exe(),
            user=process.username(),
            created=process.create_time(),
            critical=False,
            parent_pid=process.ppid(),
        )
        manager.action(snapshot, "kill", _logger(_logs()))
        assert child.wait(timeout=5) == 1
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
