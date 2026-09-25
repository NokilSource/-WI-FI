from __future__ import annotations

import os
import subprocess
import sys
import types
import weakref
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from system_repair.audit_model import ServiceInfo, SignatureInfo, TaskInfo
from system_repair.model import RegistryValue
from system_repair.task_service import WindowsTaskService


class FakeBackend:
    is_demo = False
    windows_dir = r"C:\Windows"
    system_dir = r"C:\Windows\System32"

    def __init__(self, events: list | None = None, admin: bool = True):
        self.events = events if events is not None else []
        self.admin = admin
        self.registry_snapshot = {
            "exists": True,
            "values": {
                "Start": RegistryValue(4, 3).to_dict(),
                "ImagePath": RegistryValue(2, r"\??\C:\Apps\worker.exe").to_dict(),
                "Security": RegistryValue(3, b"\x00\xff").to_dict(),
            },
            "children": {
                "Parameters": {
                    "exists": True,
                    "values": {"ServiceDll": RegistryValue(1, "worker.dll").to_dict()},
                    "children": {},
                }
            },
        }
        self.registry_snapshots: list[dict] | None = None
        self.registry_snapshot_error: Exception | None = None
        self.registry_snapshot_calls = 0

    def snapshot_registry(self, hive, key, view):
        self.events.append(("registry_snapshot", hive, key, view))
        self.registry_snapshot_calls += 1
        if self.registry_snapshot_error is not None:
            raise self.registry_snapshot_error
        if self.registry_snapshots is not None:
            return deepcopy(self.registry_snapshots[self.registry_snapshot_calls - 1])
        return deepcopy(self.registry_snapshot)

    def _require_admin(self):
        if not self.admin:
            raise PermissionError("administrator required")
        self.events.append(("admin",))


class FakeJournal:
    def __init__(self, events: list | None = None, fail: bool = False):
        self.events = events if events is not None else []
        self.fail = fail
        self.records: list[tuple[str, str, dict]] = []

    def record(self, *, kind: str, target: str, payload: dict) -> Path:
        self.events.append(("record", kind, target, payload))
        if self.fail:
            raise OSError("backup storage unavailable")
        self.records.append((kind, target, payload))
        return Path(f"/backup/{kind}.json")


def _logs():
    entries = []
    return entries, lambda level, message: entries.append((level, message))


class FakeCollection:
    def __init__(self, values):
        self.values = list(values)
        self.Count = len(self.values)

    def Item(self, index):
        return self.values[index - 1]


class FakeAction:
    Type = 0
    Path = r"C:\Apps\worker.exe"
    Arguments = "--safe"
    WorkingDirectory = r"C:\Apps"


class FakeTask:
    def __init__(self, state, path=r"\Vendor\Worker"):
        self.state = state
        self.Path = path
        self.Name = path.rsplit(chr(92), 1)[-1]
        self.State = 3
        self.NextRunTime = "2030-04-05 06:07:08"
        self._xml = "<Task><Settings><Enabled>true</Enabled></Settings></Task>"

    @property
    def Xml(self):
        return self._xml

    @property
    def Enabled(self):
        return self.state.enabled

    @Enabled.setter
    def Enabled(self, enabled):
        self.state.events.append(("task_enable", enabled))
        self.state.enabled = enabled

    @property
    def Definition(self):
        return types.SimpleNamespace(
            RegistrationInfo=types.SimpleNamespace(
                Date="2026-01-02T03:04:05",
                Author="Vendor",
                Description="Background worker",
            ),
            Actions=FakeCollection([FakeAction()]),
        )

    def GetSecurityDescriptor(self, flags):
        self.state.events.append(("task_sddl", flags))
        return "O:SYG:SYD:P(A;;FA;;;SY)"

    def Enable(self, enabled):
        self.state.events.append(("task_enable", enabled))
        self.state.enabled = enabled

    def Delete(self, flags):
        self.state.events.append(("task_delete", flags))
        self.state.deleted = True


class FakeTaskState:
    def __init__(self, events, enabled=False):
        self.events = events
        self.enabled = enabled
        self.deleted = False


class FakeFolder:
    def __init__(self, path, tasks=(), children=(), events=None, fail_tasks=False):
        self.Path = path
        self._tasks = list(tasks)
        self._children = list(children)
        self.events = events if events is not None else []
        self.fail_tasks = fail_tasks

    def GetTasks(self, flags):
        self.events.append(("get_tasks", self.Path, flags))
        if self.fail_tasks:
            raise OSError("folder access denied")
        return FakeCollection(self._tasks)

    def GetFolders(self, flags):
        self.events.append(("get_folders", self.Path, flags))
        return FakeCollection(self._children)


class FakeScheduler:
    def __init__(self, root, tasks):
        self.root = root
        self.tasks = tasks
        self.task_folders = {}
        self.connected = False

    def Connect(self):
        self.connected = True

    def GetFolder(self, path):
        if path == "\\":
            return self.root
        return self.task_folders.setdefault(path.casefold(), FakeRegisteredFolder(self, path))

    def task(self, path):
        task = self.tasks[path.casefold()]
        if task.state.deleted:
            raise KeyError(path)
        return task


class FakeRegisteredFolder:
    def __init__(self, scheduler, path):
        self.scheduler = scheduler
        self.path = path

    def GetTask(self, name):
        return self.scheduler.task(self.path.rstrip(chr(92)) + chr(92) + name)

    def DeleteTask(self, name, flags):
        task = self.GetTask(name)
        task.Delete(flags)


def _install_com(monkeypatch, scheduler, events):
    pythoncom = types.ModuleType("pythoncom")
    pythoncom.COINIT_APARTMENTTHREADED = 2
    pythoncom.RPC_E_CHANGED_MODE = -2147417850
    pythoncom.CoInitializeEx = lambda _flags: events.append(("co_init",))
    pythoncom.CoUninitialize = lambda: events.append(("co_uninit",))
    client = types.ModuleType("win32com.client")

    def dispatch(_name):
        return scheduler() if callable(scheduler) else scheduler

    client.Dispatch = dispatch
    win32com = types.ModuleType("win32com")
    win32com.__path__ = []
    win32com.client = client
    monkeypatch.setitem(sys.modules, "pythoncom", pythoncom)
    monkeypatch.setitem(sys.modules, "win32com", win32com)
    monkeypatch.setitem(sys.modules, "win32com.client", client)


def _task_info(path=r"\Vendor\Worker", enabled=False):
    state = FakeTaskState([], enabled=enabled)
    return FakeTask(state, path), state, TaskInfo(
        path=path,
        name=path.rsplit(chr(92), 1)[-1],
        folder=path.rsplit(chr(92), 1)[0] or chr(92),
        enabled=enabled,
        created="2026-01-02T03:04:05",
        next_run="2030-04-05 06:07:08",
        author="Vendor",
        description="Background worker",
        command='"C:\\Apps\\worker.exe" --safe',
        xml="<Task><Settings><Enabled>true</Enabled></Settings></Task>",
    )


def test_tasks_walks_folders_includes_hidden_and_balances_com_apartment(monkeypatch):
    events = []
    root_state = FakeTaskState(events)
    root_task = FakeTask(root_state, r"\RootTask")
    nested_state = FakeTaskState(events, enabled=True)
    nested_task = FakeTask(nested_state, r"\Vendor\Worker")
    nested = FakeFolder(r"\Vendor", [nested_task], events=events)
    root = FakeFolder("\\", [root_task], [nested], events=events)
    scheduler = FakeScheduler(root, {})
    _install_com(monkeypatch, scheduler, events)
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events))
    entries, log = _logs()

    tasks = service.tasks(log)

    assert [item.path for item in tasks] == [r"\RootTask", r"\Vendor\Worker"]
    assert tasks[1].command == r"C:\Apps\worker.exe --safe [рабочая папка: C:\Apps]"
    assert tasks[1].created == "2026-01-02T03:04:05"
    assert all(entry[2] == 1 for entry in events if entry[0] == "get_tasks")
    assert events.count(("co_init",)) == events.count(("co_uninit",)) == 1
    assert scheduler.connected
    assert any(level == "INFO" and "прочитано задач — 2" in message for level, message in entries)


@pytest.mark.parametrize("fail_operation", [False, True])
def test_scheduler_releases_com_references_before_uninitializing(monkeypatch, fail_operation):
    events = []
    references = {}

    def make_scheduler():
        task = FakeTask(FakeTaskState(events), r"\Vendor\Worker")
        root = FakeFolder("\\", [task], events=events)
        scheduler = FakeScheduler(root, {})
        references.update(
            scheduler=weakref.ref(scheduler),
            folder=weakref.ref(root),
            task=weakref.ref(task),
        )
        return scheduler

    _install_com(monkeypatch, make_scheduler, events)
    pythoncom = sys.modules["pythoncom"]
    uninitialize = pythoncom.CoUninitialize

    def check_released_before_uninitialize():
        assert all(reference() is None for reference in references.values())
        uninitialize()

    pythoncom.CoUninitialize = check_released_before_uninitialize
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events))
    expected_error = OSError("scheduler operation failed")

    def inspect_scheduler(scheduler):
        folder = scheduler.GetFolder("\\")
        if fail_operation:
            raise expected_error
        return folder.Path

    if fail_operation:
        with pytest.raises(OSError, match="scheduler operation failed") as caught:
            service._scheduler(inspect_scheduler)
        assert caught.value is expected_error
        assert caught.value.args == ("scheduler operation failed",)
    else:
        tasks = service.tasks(lambda *_: None)
        assert [task.path for task in tasks] == [r"\Vendor\Worker"]

    assert events.count(("co_init",)) == events.count(("co_uninit",)) == 1


def test_scheduler_connect_failure_releases_com_object_before_uninitializing(monkeypatch):
    events = []
    references = {}
    expected_error = OSError("scheduler connect failed")

    class RaisingScheduler:
        def Connect(self):
            raise expected_error

    def make_scheduler():
        scheduler = RaisingScheduler()
        references["scheduler"] = weakref.ref(scheduler)
        return scheduler

    _install_com(monkeypatch, make_scheduler, events)
    pythoncom = sys.modules["pythoncom"]
    uninitialize = pythoncom.CoUninitialize

    def check_released_before_uninitialize():
        assert references["scheduler"]() is None
        uninitialize()

    pythoncom.CoUninitialize = check_released_before_uninitialize
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events))

    with pytest.raises(OSError, match="scheduler connect failed") as caught:
        service._scheduler(lambda _scheduler: pytest.fail("operation ran after failed Connect"))

    assert caught.value is expected_error
    assert events.count(("co_init",)) == events.count(("co_uninit",)) == 1


def test_scheduler_does_not_uninitialize_an_existing_different_apartment(monkeypatch):
    events = []
    scheduler = FakeScheduler(FakeFolder("\\", events=events), {})
    _install_com(monkeypatch, scheduler, events)
    pythoncom = sys.modules["pythoncom"]

    class ChangedModeError(Exception):
        hresult = pythoncom.RPC_E_CHANGED_MODE

    def initialize_in_changed_mode(_flags):
        events.append(("co_init",))
        raise ChangedModeError("COM already uses another apartment model")

    pythoncom.CoInitializeEx = initialize_in_changed_mode
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events))

    assert service._scheduler(lambda current: current.GetFolder("\\").Path) == "\\"
    assert events.count(("co_init",)) == 1
    assert ("co_uninit",) not in events


def test_tasks_logs_folder_errors_and_continues(monkeypatch):
    events = []
    inaccessible = FakeFolder(r"\Denied", events=events, fail_tasks=True)
    good_state = FakeTaskState(events)
    good_task = FakeTask(good_state, r"\Good\Worker")
    good = FakeFolder(r"\Good", [good_task], events=events)
    root = FakeFolder("\\", children=[inaccessible, good], events=events)
    _install_com(monkeypatch, FakeScheduler(root, {}), events)
    entries, log = _logs()

    tasks = WindowsTaskService(FakeBackend(), FakeJournal()).tasks(log)

    assert [item.path for item in tasks] == [r"\Good\Worker"]
    assert any(level == "ERROR" and r"\Denied" in message for level, message in entries)


def test_change_task_journals_xml_and_sddl_before_enable_and_reads_back(monkeypatch):
    events = []
    registered, state, info = _task_info()
    state.events = events
    root = FakeFolder("\\", events=events)
    scheduler = FakeScheduler(root, {info.path.casefold(): registered})
    _install_com(monkeypatch, scheduler, events)
    journal = FakeJournal(events)
    service = WindowsTaskService(FakeBackend(events), journal)
    entries, log = _logs()

    backup = service.change_task(info, "enable", log)

    assert backup == Path("/backup/task.json")
    assert events.index(next(event for event in events if event[0] == "record")) < events.index(("task_enable", True))
    kind, target, payload = journal.records[0]
    assert (kind, target) == ("task", info.path)
    assert payload["xml"] == info.xml
    assert payload["sddl"] == "O:SYG:SYD:P(A;;FA;;;SY)"
    assert payload["enabled"] is False
    assert state.enabled is True
    assert any(level == "OK" and "действие enable проверено" in message for level, message in entries)


def test_change_task_rejects_stale_or_protected_tasks_before_journaling(monkeypatch):
    events = []
    registered, _, info = _task_info()
    registered._xml = "<Task>changed</Task>"
    scheduler = FakeScheduler(FakeFolder("\\"), {info.path.casefold(): registered})
    _install_com(monkeypatch, scheduler, events)
    journal = FakeJournal(events)
    service = WindowsTaskService(FakeBackend(events), journal)

    with pytest.raises(RuntimeError, match="XML задачи изменился"):
        service.change_task(info, "disable", lambda *_: None)
    protected = replace(info, path=r"\Microsoft\Windows\UpdateOrchestrator\Reboot")
    with pytest.raises(PermissionError, match="только для чтения"):
        service.change_task(protected, "disable", lambda *_: None)

    assert journal.records == []
    assert not any(event[0] in {"task_enable", "task_delete"} for event in events)


def test_delete_task_uses_parent_folder_and_records_before_delete(monkeypatch):
    events = []
    registered, state, info = _task_info()
    state.events = events
    scheduler = FakeScheduler(FakeFolder("\\", events=events), {info.path.casefold(): registered})
    _install_com(monkeypatch, scheduler, events)
    journal = FakeJournal(events)
    entries, log = _logs()

    backup = WindowsTaskService(FakeBackend(events), journal).change_task(info, "delete", log)

    assert backup == Path("/backup/task.json")
    assert events.index(next(event for event in events if event[0] == "record")) < events.index(
        next(event for event in events if event[0] == "task_delete")
    )
    assert state.deleted
    assert any(level == "WARN" and "учетные данные не входят" in message for level, message in entries)


def test_task_backup_failure_prevents_mutation(monkeypatch):
    events = []
    registered, state, info = _task_info()
    scheduler = FakeScheduler(FakeFolder("\\"), {info.path.casefold(): registered})
    _install_com(monkeypatch, scheduler, events)
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events, fail=True))

    with pytest.raises(OSError, match="backup storage unavailable"):
        service.change_task(info, "disable", lambda *_: None)

    assert state.enabled is False
    assert not any(event[0] in {"task_enable", "task_delete"} for event in events)


def test_task_and_service_mutations_require_admin_before_opening_platform_apis(monkeypatch):
    events = []
    registered, _, info = _task_info()
    scheduler = FakeScheduler(FakeFolder("\\", events=events), {info.path.casefold(): registered})
    _install_com(monkeypatch, scheduler, events)
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    journal = FakeJournal(events)
    service = WindowsTaskService(FakeBackend(events, admin=False), journal)

    with pytest.raises(PermissionError, match="administrator required"):
        service.change_task(info, "enable", lambda *_: None)
    with pytest.raises(PermissionError, match="administrator required"):
        service.change_service(_scanned_service(fake), "auto", lambda *_: None)

    assert journal.records == []
    assert not any(event[0] in {"task_enable", "change_config", "open_scm", "co_init"} for event in events)


SERVICE_CONSTANTS = {
    "SC_MANAGER_CONNECT": 0x1,
    "SC_MANAGER_ENUMERATE_SERVICE": 0x4,
    "SERVICE_WIN32": 0x30,
    "SERVICE_DRIVER": 0x0B,
    "SERVICE_STATE_ALL": 0x3,
    "SC_ENUM_PROCESS_INFO": 0,
    "SERVICE_QUERY_CONFIG": 0x1,
    "SERVICE_CHANGE_CONFIG": 0x2,
    "SERVICE_QUERY_STATUS": 0x4,
    "SERVICE_ENUMERATE_DEPENDENTS": 0x8,
    "SERVICE_START": 0x10,
    "SERVICE_STOP": 0x20,
    "SERVICE_STOPPED": 1,
    "SERVICE_RUNNING": 4,
    "SERVICE_STOP_PENDING": 3,
    "SERVICE_ACTIVE": 1,
    "SERVICE_CONTROL_STOP": 1,
    "SERVICE_CONFIG_DESCRIPTION": 1,
    "SERVICE_NO_CHANGE": 0xFFFFFFFF,
    "DELETE": 0x00010000,
    "READ_CONTROL": 0x00020000,
}


class FakeSCM:
    def __init__(self, events, *, name="VendorSvc", display_name="Vendor Worker", image=r"C:\Apps\worker.exe"):
        self.events = events
        self.name = name
        self.config = [0x10, 3, 1, image, "", 0, ["RpcSs"], "LocalSystem", display_name]
        self.description = "Vendor worker service"
        self.state = 1
        self.pid = 0
        self.deleted = False
        self.dependents = []
        self.security = "O:SYG:SYD:(A;;CCLCSWLOCRRC;;;SY)"

    def api(self):
        api = types.ModuleType("win32service")
        for key, value in SERVICE_CONSTANTS.items():
            setattr(api, key, value)
        api.OpenSCManager = lambda machine, database, access: self._open_scm(machine, database, access)
        api.EnumServicesStatusEx = lambda *args: self._enumerate(*args)
        api.OpenService = lambda manager, name, access: self._open_service(manager, name, access)
        api.QueryServiceConfig = lambda handle: tuple(self.config)
        api.QueryServiceConfig2 = lambda handle, level: self.description
        api.QueryServiceStatusEx = lambda handle: (
            self.config[0], self.state, 0, 0, 0, 0, 0, self.pid, 0
        )
        api.QueryServiceObjectSecurity = lambda handle, flags: self.security
        api.StartService = lambda handle, args: self._start()
        api.ControlService = lambda handle, control: self._stop(control)
        api.ChangeServiceConfig = lambda handle, *args: self._change_config(args)
        api.DeleteService = lambda handle: self._delete()
        api.EnumDependentServices = lambda handle, status: self.dependents
        api.CloseServiceHandle = lambda handle: handle.Close()
        return api

    def _open_scm(self, machine, database, access):
        self.events.append(("open_scm", machine, database, access))
        return FakeHandle(self.events, "SCM")

    def _enumerate(self, manager, service_type, service_state, group, info_level):
        self.events.append(("enumerate", service_type, service_state, group, info_level))
        if self.deleted:
            return []
        status = (self.config[0], self.state, 0, 0, 0, 0, 0, self.pid, 0)
        return [{"ServiceName": self.name, "DisplayName": self.config[8], "ServiceStatusProcess": status}]

    def _open_service(self, manager, name, access):
        self.events.append(("open_service", name, access))
        if self.deleted:
            raise FakeWinError(1060)
        if name.casefold() != self.name.casefold():
            raise FakeWinError(1060)
        return FakeHandle(self.events, name)

    def _start(self):
        self.events.append(("start",))
        self.state = 4
        self.pid = 4321

    def _stop(self, control):
        self.events.append(("stop", control))
        self.state = 1
        self.pid = 0

    def _change_config(self, args):
        self.events.append(("change_config", args))
        self.config[1] = args[1]

    def _delete(self):
        self.events.append(("delete",))
        self.deleted = True


class FakeHandle:
    def __init__(self, events, name):
        self.events = events
        self.name = name

    def Close(self):
        self.events.append(("close", self.name))


class FakeWinError(OSError):
    def __init__(self, code):
        super().__init__(code, "mock SCM error")
        self.winerror = code


def _install_scm(monkeypatch, fake):
    api = fake.api()
    security = types.ModuleType("win32security")
    security.SDDL_REVISION_1 = 1
    security.ConvertSecurityDescriptorToStringSecurityDescriptor = (
        lambda descriptor, revision, flags: descriptor
    )
    monkeypatch.setitem(sys.modules, "win32service", api)
    monkeypatch.setitem(sys.modules, "win32security", security)
    return api


def _install_signatures(monkeypatch, statuses=None):
    module = types.ModuleType("system_repair.processes")

    class SignatureInspector:
        def __init__(self, backend):
            self.backend = backend

        def inspect_many(self, paths):
            module.paths = list(paths)
            return {path: SignatureInfo(status=(statuses or {}).get(path, "Valid")) for path in paths}

    module.SignatureInspector = SignatureInspector
    monkeypatch.setitem(sys.modules, "system_repair.processes", module)
    return module


def _scanned_service(fake, *, signature="Valid", suspicious=False, error=""):
    return ServiceInfo(
        name=fake.name,
        display_name=fake.config[8],
        pid=fake.pid,
        start_type={2: "Авто", 3: "Вручную", 4: "Отключена"}.get(fake.config[1], "Вручную"),
        state="Остановлена" if fake.state == 1 else "Работает",
        description=fake.description,
        command=fake.config[3],
        account=fake.config[7],
        signature=signature,
        suspicious=suspicious,
        error=error,
    )


def test_services_query_local_scm_batch_signatures_and_keep_unknown_nonmalicious(monkeypatch):
    events = []
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    module = _install_signatures(monkeypatch)
    entries, log = _logs()

    services = WindowsTaskService(FakeBackend(), FakeJournal()).services(log)

    assert len(services) == 1
    assert services[0].name == "VendorSvc"
    assert services[0].display_name == "Vendor Worker"
    assert services[0].start_type == "Вручную"
    assert services[0].state == "Остановлена"
    assert services[0].command == fake.config[3]
    assert services[0].signature == "Valid"
    assert services[0].suspicious is False
    assert module.paths == [r"C:\Apps\worker.exe"]
    assert any(event[0] == "enumerate" and event[3] is None for event in events)
    assert any(level == "INFO" and "эвристика" in message for level, message in entries)


def test_unknown_signature_alone_is_not_suspicious_and_unsigned_is_heuristic(monkeypatch):
    events = []
    fake = FakeSCM(events)
    fake.description = ""
    _install_scm(monkeypatch, fake)
    _install_signatures(monkeypatch, {r"C:\Apps\worker.exe": "UnknownError"})

    services = WindowsTaskService(FakeBackend(), FakeJournal()).services(lambda *_: None)

    assert services[0].signature == "UnknownError"
    assert services[0].suspicious is True

    fake.description = "Vendor worker"
    _install_signatures(monkeypatch, {r"C:\Apps\worker.exe": "UnknownError"})
    assert WindowsTaskService(FakeBackend(), FakeJournal()).services(lambda *_: None)[0].suspicious is False

    _install_signatures(monkeypatch, {r"C:\Apps\worker.exe": "NotSigned"})
    assert WindowsTaskService(FakeBackend(), FakeJournal()).services(lambda *_: None)[0].suspicious is True


def test_services_in_user_profile_are_flagged_without_calling_them_malware(monkeypatch):
    events = []
    fake = FakeSCM(events, image=r"C:\Users\Alice\worker.exe")
    _install_scm(monkeypatch, fake)
    _install_signatures(monkeypatch, {r"C:\Users\Alice\worker.exe": "Valid"})

    service = WindowsTaskService(FakeBackend(), FakeJournal()).services(lambda *_: None)[0]

    assert service.signature == "Valid"
    assert service.suspicious is True
    assert "зараж" not in service.error.casefold()


def test_unquoted_user_profile_path_is_flagged_without_guessing_executable(monkeypatch):
    events = []
    fake = FakeSCM(events, image=r"%USERPROFILE%\worker.exe")
    _install_scm(monkeypatch, fake)

    service = WindowsTaskService(FakeBackend(), FakeJournal()).services(lambda *_: None)[0]

    assert service.suspicious is True
    assert "однозначно разобрать" in service.error


def test_change_service_backs_up_full_snapshot_before_config_mutation_and_verifies_readback(monkeypatch):
    events = []
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    journal = FakeJournal(events)
    service = WindowsTaskService(FakeBackend(events), journal)
    entries, log = _logs()

    backup = service.change_service(_scanned_service(fake), "auto", log)

    assert backup == Path("/backup/service.json")
    assert events.index(next(event for event in events if event[0] == "record")) < events.index(
        next(event for event in events if event[0] == "change_config")
    )
    kind, target, payload = journal.records[0]
    assert (kind, target) == ("service", "VendorSvc")
    assert payload["config"]["binary_path"] == r"C:\Apps\worker.exe"
    assert payload["config"]["dependencies"] == ["RpcSs"]
    assert payload["description"] == fake.description
    assert payload["status"]["current_state"] == 1
    assert payload["sddl"] == fake.security
    assert payload["credentials_included"] is False
    assert fake.config[1] == 2
    assert any(level == "OK" and "действие auto проверено" in message for level, message in entries)


def test_change_service_rejects_stale_configuration_before_journaling(monkeypatch):
    events = []
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    service = _scanned_service(fake)
    fake.config[3] = r"C:\Apps\changed.exe"
    journal = FakeJournal(events)

    with pytest.raises(RuntimeError, match="изменилась после сканирования"):
        WindowsTaskService(FakeBackend(events), journal).change_service(service, "manual", lambda *_: None)

    assert journal.records == []
    assert not any(event[0] in {"change_config", "start", "stop", "delete"} for event in events)


@pytest.mark.parametrize(
    ("name", "display", "service_type", "image"),
    [
        ("WinDefend", "Microsoft Defender Antivirus Service", 0x10, r"C:\Apps\worker.exe"),
        ("VendorSecurity", "Vendor Security Service", 0x10, r"C:\Apps\worker.exe"),
        ("DriverSvc", "Vendor Driver", 0x1, r"C:\Apps\driver.sys"),
        ("VendorSvc", "Vendor Worker", 0x10, r"C:\Windows\System32\worker.exe"),
    ],
)
def test_protected_services_are_never_mutated(monkeypatch, name, display, service_type, image):
    events = []
    fake = FakeSCM(events, name=name, display_name=display, image=image)
    fake.config[0] = service_type
    _install_scm(monkeypatch, fake)
    journal = FakeJournal(events)

    with pytest.raises(PermissionError, match="запрещено"):
        WindowsTaskService(FakeBackend(events), journal).change_service(
            _scanned_service(fake), "disabled", lambda *_: None
        )

    assert journal.records == []
    assert not any(event[0] in {"change_config", "start", "stop", "delete"} for event in events)


def test_service_backup_failure_and_running_delete_do_not_mutate(monkeypatch):
    events = []
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events, fail=True))

    with pytest.raises(OSError, match="backup storage unavailable"):
        service.change_service(_scanned_service(fake), "disabled", lambda *_: None)
    assert not any(event[0] == "change_config" for event in events)

    fake.state = 4
    fake.pid = 4321
    journal = FakeJournal(events)
    with pytest.raises(PermissionError, match="только остановленную"):
        WindowsTaskService(FakeBackend(events), journal).change_service(
            _scanned_service(fake), "delete", lambda *_: None
        )
    assert journal.records[0][2]["status"]["current_state"] == 4
    assert not any(event[0] == "delete" for event in events)


@pytest.mark.parametrize(
    ("action", "initial_state", "expected_state", "expected_event"),
    [("start", 1, 4, "start"), ("stop", 4, 1, "stop")],
)
def test_service_start_stop_only_target_and_verify_bounded_readback(
    monkeypatch, action, initial_state, expected_state, expected_event
):
    events = []
    fake = FakeSCM(events)
    fake.state = initial_state
    fake.pid = 4321 if initial_state == 4 else 0
    _install_scm(monkeypatch, fake)
    journal = FakeJournal(events)

    WindowsTaskService(FakeBackend(events), journal).change_service(
        _scanned_service(fake), action, lambda *_: None
    )

    assert fake.state == expected_state
    assert events.index(next(event for event in events if event[0] == "record")) < events.index(
        next(event for event in events if event[0] == expected_event)
    )
    assert not any(event[0] == "stop_dependent" for event in events)


def test_service_start_times_out_without_claiming_success(monkeypatch):
    from system_repair import task_service as task_service_module

    events = []
    fake = FakeSCM(events)
    api = _install_scm(monkeypatch, fake)
    api.StartService = lambda handle, args: events.append(("start",))
    monkeypatch.setattr(task_service_module, "_SERVICE_WAIT_SECONDS", 0)
    journal = FakeJournal(events)

    with pytest.raises(TimeoutError, match="Тайм-аут ожидания"):
        WindowsTaskService(FakeBackend(events), journal).change_service(
            _scanned_service(fake), "start", lambda *_: None
        )

    assert journal.records
    assert events.index(next(event for event in events if event[0] == "record")) < events.index(
        next(event for event in events if event[0] == "start")
    )


def test_delete_refuses_active_dependents_without_stopping_them(monkeypatch):
    events = []
    fake = FakeSCM(events)
    fake.dependents = [{"ServiceName": "DependentSvc", "Status": {"CurrentState": 4}}]
    _install_scm(monkeypatch, fake)
    journal = FakeJournal(events)

    with pytest.raises(PermissionError, match="работающие зависимые"):
        WindowsTaskService(FakeBackend(events), journal).change_service(
            _scanned_service(fake), "delete", lambda *_: None
        )

    assert journal.records
    assert not fake.deleted
    assert not any(event[0] in {"stop", "stop_dependent", "delete"} for event in events)


def test_delete_warns_about_missing_password_and_verifies_scm_readback(monkeypatch):
    events = []
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    journal = FakeJournal(events)
    entries, log = _logs()
    backend = FakeBackend(events)

    WindowsTaskService(backend, journal).change_service(_scanned_service(fake), "delete", log)

    assert fake.deleted is True
    payload = journal.records[0][2]
    assert payload["credentials_included"] is False
    assert payload["automatic_restore"] is False
    assert "Автоматическое восстановление не поддерживается" in payload["restore_note"]
    assert payload["registry_branch"] == {
        "hive": "HKLM",
        "key": r"SYSTEM\CurrentControlSet\Services\VendorSvc",
        "view": 64,
        "snapshot": backend.registry_snapshot,
    }
    assert RegistryValue.from_dict(payload["registry_branch"]["snapshot"]["values"]["Security"]) == (
        RegistryValue(3, b"\x00\xff")
    )
    assert RegistryValue.from_dict(
        payload["registry_branch"]["snapshot"]["children"]["Parameters"]["values"]["ServiceDll"]
    ) == RegistryValue(1, "worker.dll")
    snapshot_events = [event for event in events if event[0] == "registry_snapshot"]
    assert snapshot_events == [
        ("registry_snapshot", "HKLM", r"SYSTEM\CurrentControlSet\Services\VendorSvc", 64),
        ("registry_snapshot", "HKLM", r"SYSTEM\CurrentControlSet\Services\VendorSvc", 64),
    ]
    snapshot_indexes = [index for index, event in enumerate(events) if event[0] == "registry_snapshot"]
    record_index = next(index for index, event in enumerate(events) if event[0] == "record")
    delete_index = next(index for index, event in enumerate(events) if event[0] == "delete")
    assert snapshot_indexes[0] < record_index < snapshot_indexes[1] < delete_index
    assert any(level == "WARN" and "пароль учетной записи" in message for level, message in entries)


def test_service_delete_fails_closed_when_registry_branch_backup_fails(monkeypatch):
    events = []
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    backend = FakeBackend(events)
    backend.registry_snapshot_error = OSError("registry read denied")
    journal = FakeJournal(events)
    entries, log = _logs()

    with pytest.raises(OSError, match="registry read denied"):
        WindowsTaskService(backend, journal).change_service(_scanned_service(fake), "delete", log)

    assert journal.records == []
    assert not fake.deleted
    assert not any(event[0] == "record" for event in events)
    assert any(level == "ERROR" and "удаление отменено" in message for level, message in entries)


def test_service_delete_rejects_registry_branch_changed_after_backup(monkeypatch):
    events = []
    fake = FakeSCM(events)
    _install_scm(monkeypatch, fake)
    backend = FakeBackend(events)
    original = deepcopy(backend.registry_snapshot)
    changed = deepcopy(original)
    changed["values"]["Start"] = RegistryValue(4, 4).to_dict()
    backend.registry_snapshots = [original, changed]
    journal = FakeJournal(events)

    with pytest.raises(RuntimeError, match="Ветка реестра службы изменилась"):
        WindowsTaskService(backend, journal).change_service(
            _scanned_service(fake), "delete", lambda *_: None
        )

    assert len(journal.records) == 1
    assert not fake.deleted
    assert backend.registry_snapshot_calls == 2
    assert not any(event[0] == "delete" for event in events)


def test_service_delete_polls_marked_for_delete_until_service_is_absent(monkeypatch):
    from system_repair import task_service as task_service_module

    events = []
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events))
    codes = iter((1072, 1060))
    calls = []

    def open_service(_manager, _name, _access):
        code = next(codes)
        calls.append(code)
        raise FakeWinError(code)

    api = types.SimpleNamespace(SERVICE_QUERY_STATUS=0x4, OpenService=open_service)
    monkeypatch.setattr(task_service_module.time, "sleep", lambda _seconds: None)

    service._verify_service_deleted(api, object(), "VendorSvc")

    assert calls == [1072, 1060]


def test_service_delete_reports_pending_timeout_for_marked_service(monkeypatch):
    from system_repair import task_service as task_service_module

    events = []
    service = WindowsTaskService(FakeBackend(events), FakeJournal(events))
    calls = []

    def open_service(_manager, _name, _access):
        calls.append("open")
        raise FakeWinError(1072)

    api = types.SimpleNamespace(SERVICE_QUERY_STATUS=0x4, OpenService=open_service)
    monkeypatch.setattr(task_service_module, "_SERVICE_WAIT_SECONDS", 0)

    with pytest.raises(TimeoutError, match="ERROR_SERVICE_MARKED_FOR_DELETE.*ожидающим"):
        service._verify_service_deleted(api, object(), "VendorSvc")

    assert calls == ["open"]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ('"C:\\Program Files\\Vendor\\svc.exe" -k run', r"C:\Program Files\Vendor\svc.exe"),
        (r"C:\Program Files\Vendor\svc.exe -k run", ""),
        (r"%SystemRoot%\System32\svchost.exe -k netsvcs", r"%SystemRoot%\System32\svchost.exe"),
        ('"C:\\Program Files\\broken.exe -k run', ""),
        (r"relative\service.exe -k run", ""),
        (r"C:\Program Files\no-extension --run", ""),
    ],
)
def test_service_image_parser_fails_closed(command, expected):
    from system_repair.task_service import _service_image_path

    assert _service_image_path(command) == expected


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Task Scheduler and SCM")
def test_native_task_and_service_scans_are_read_only():
    script = """
import faulthandler
import sys
faulthandler.enable(file=sys.stderr, all_threads=True)
try:
    import pythoncom
    import win32com.client
    import win32security
    import win32service
except ImportError:
    print("pywin32-unavailable")
    raise SystemExit(0)

from system_repair.audit_model import ServiceInfo, TaskInfo
from system_repair.task_service import WindowsTaskService
from system_repair.windows import WindowsPlatform

entries = []
log = lambda level, message: entries.append((level, message))
service = WindowsTaskService(WindowsPlatform(), None)
tasks = service.tasks(log)
services = service.services(log)
if any(level == "ERROR" for level, _ in entries) and not tasks and not services:
    print("native-scanners-unavailable")
else:
    assert all(isinstance(task, TaskInfo) and task.path.startswith("\\\\") for task in tasks)
    assert all(isinstance(item, ServiceInfo) and item.name for item in services)
    print("native-scans-ok")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, (
        f"native inventory child exited {completed.returncode}; "
        f"stdout={completed.stdout!r}; stderr={completed.stderr!r}"
    )
    assert completed.stderr == "", f"native inventory child wrote to stderr: {completed.stderr}"
    outcome = completed.stdout.strip()
    if outcome == "pywin32-unavailable":
        pytest.skip("pywin32 is not installed")
    if outcome == "native-scanners-unavailable":
        pytest.skip("Task Scheduler and SCM are unavailable to this Windows account")
    assert outcome == "native-scans-ok", f"unexpected native inventory child output: {outcome!r}"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Task Scheduler")
def test_native_task_scans_release_worker_com_apartments_cleanly():
    script = """
import faulthandler
import sys
faulthandler.enable(file=sys.stderr, all_threads=True)
try:
    import pythoncom
    import win32com.client
except ImportError:
    print("pywin32-unavailable")
    raise SystemExit(0)

import concurrent.futures
from system_repair.audit_model import TaskInfo
from system_repair.task_service import WindowsTaskService
from system_repair.windows import WindowsPlatform

# Importing pythoncom initializes only this main thread; workers must balance their own COM apartments.
service = WindowsTaskService(WindowsPlatform(), None)
def scan_repeatedly(_worker):
    counts = []
    for _ in range(3):
        tasks = service.tasks(lambda *_: None)
        assert tasks, "native Task Scheduler scan returned no tasks"
        assert all(isinstance(task, TaskInfo) and task.path.startswith("\\\\") for task in tasks)
        counts.append(len(tasks))
    return counts

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
    results = list(workers.map(scan_repeatedly, range(2)))
assert len(results) == 2 and all(len(counts) == 3 and all(counts) for counts in results)
print("native-worker-scans-ok")
"""
    completed = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        text=True,
        timeout=180,
    )

    assert completed.returncode == 0, (
        f"native worker inventory child exited {completed.returncode}; "
        f"stdout={completed.stdout!r}; stderr={completed.stderr!r}"
    )
    diagnostics = completed.stderr.casefold()
    assert "windows fatal exception" not in diagnostics, completed.stderr
    assert "access violation" not in diagnostics, completed.stderr
    outcome = completed.stdout.strip()
    if outcome == "pywin32-unavailable":
        pytest.skip("pywin32 is not installed")
    assert outcome == "native-worker-scans-ok", (
        f"unexpected native worker inventory output: {completed.stdout!r}; "
        f"stderr={completed.stderr!r}"
    )
