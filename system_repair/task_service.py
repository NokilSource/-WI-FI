from __future__ import annotations

import ntpath
import os
import re
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from system_repair.audit_model import ServiceInfo, TaskInfo
from system_repair.model import Log

if TYPE_CHECKING:
    from system_repair.journal import ActionJournal
    from system_repair.windows import WindowsPlatform


_TASK_SECURITY_INFORMATION = 0x1 | 0x2 | 0x4
_SERVICE_SECURITY_INFORMATION = 0x1 | 0x2 | 0x4
_SERVICE_WAIT_SECONDS = 30.0
_SERVICE_POLL_SECONDS = 0.25
_MAX_COM_ITEMS = 100_000

_TASK_STATES = {
    0: "Неизвестно",
    1: "Отключена",
    2: "В очереди",
    3: "Готова",
    4: "Работает",
}
_SERVICE_STATES = {
    1: "Остановлена",
    2: "Запускается",
    3: "Останавливается",
    4: "Работает",
    5: "Продолжает работу",
    6: "Приостанавливается",
    7: "Приостановлена",
}
_SERVICE_START_TYPES = {
    0: "Загрузка",
    1: "Система",
    2: "Авто",
    3: "Вручную",
    4: "Отключена",
}
_UNKNOWN_SIGNATURES = frozenset({
    "",
    "unknown",
    "неизвестно",
    "не проверена",
    "не проверено",
    "not checked",
    "unavailable",
    "unknownerror",
    "ошибка",
    "error",
})
_PROTECTED_SERVICE_NAMES = frozenset({
    "appidsvc",
    "bfe",
    "cryptsvc",
    "dcomlaunch",
    "eventlog",
    "lsm",
    "mpssvc",
    "rpceptmapper",
    "rpcss",
    "samss",
    "schedule",
    "securityhealthservice",
    "sense",
    "sgrmbroker",
    "sgrmagent",
    "trustedinstaller",
    "wdboot",
    "wdfilter",
    "wdnisdrv",
    "wdnissvc",
    "windefend",
    "winmgmt",
    "wscsvc",
})
_PROTECTED_SERVICE_TOKENS = (
    "antivirus",
    "anti-virus",
    "anti malware",
    "antimalware",
    "defender",
    "endpoint protection",
    "endpoint security",
    "firewall",
    "security",
    "security health",
)


class WindowsTaskService:
    """Read-only Windows task/service inventory with journaled, guarded changes."""

    def __init__(self, backend: WindowsPlatform, journal: ActionJournal):
        self.backend = backend
        self.journal = journal

    def _require_admin(self) -> None:
        if getattr(self.backend, "is_demo", False):
            raise PermissionError("Демонстрационный режим не может изменять задачи или службы.")
        require_admin = getattr(self.backend, "_require_admin", None)
        if callable(require_admin):
            require_admin()
            return
        is_admin = getattr(self.backend, "is_admin", None)
        if not callable(is_admin) or not is_admin():
            raise PermissionError("Операция требует подтверждённых прав администратора.")

    @contextmanager
    def _scheduler(self) -> Iterator[Any]:
        try:
            import pythoncom
            import win32com.client
        except ImportError as error:
            raise RuntimeError("Для Планировщика заданий требуется установленный pywin32.") from error

        initialized = False
        try:
            pythoncom.CoInitialize()
            initialized = True
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            yield scheduler
        finally:
            if initialized:
                pythoncom.CoUninitialize()

    @staticmethod
    def _com_items(collection: Any) -> list[Any]:
        try:
            count = int(collection.Count)
        except AttributeError:
            return list(collection)
        if count < 0 or count > _MAX_COM_ITEMS:
            raise ValueError(f"Недопустимое число элементов COM-коллекции: {count}.")
        return [collection.Item(index) for index in range(1, count + 1)]

    @staticmethod
    def _display_value(value: Any) -> str:
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _display_time(value: Any) -> str:
        if value is None:
            return ""
        if getattr(value, "year", None) == 1:
            return ""
        return value.isoformat(sep=" ", timespec="seconds") if hasattr(value, "isoformat") else str(value)

    @staticmethod
    def _quote_task_path(path: str) -> str:
        if any(character.isspace() for character in path) or '"' in path:
            return '"' + path.replace('"', '\\"') + '"'
        return path

    @classmethod
    def _task_command(cls, registered_task: Any) -> str:
        definition = registered_task.Definition
        actions = cls._com_items(definition.Actions)
        commands = []
        for action in actions:
            action_type = int(action.Type)
            if action_type == 0:
                path = cls._display_value(action.Path).strip()
                arguments = cls._display_value(action.Arguments).strip()
                command = cls._quote_task_path(path) if path else ""
                working_directory = cls._display_value(action.WorkingDirectory).strip()
                if arguments:
                    command = f"{command} {arguments}".strip()
                if working_directory:
                    command = f"{command} [рабочая папка: {working_directory}]".strip()
                commands.append(command or "Действие запуска без указанного пути")
            elif action_type == 5:
                class_id = cls._display_value(getattr(action, "ClassId", "")).strip()
                commands.append(f"COM-обработчик {class_id}".strip())
            else:
                commands.append(f"Действие Планировщика типа {action_type}")
        return "; ".join(commands)

    @staticmethod
    def _task_xml(registered_task: Any) -> str:
        xml = getattr(registered_task, "Xml", None)
        if xml is None:
            xml = getattr(registered_task, "GetXml", None)
        if callable(xml):
            xml = xml()
        if not isinstance(xml, str) or not xml:
            raise RuntimeError("Планировщик не вернул XML задачи; безопасное изменение невозможно.")
        return xml

    @classmethod
    def _task_info(cls, registered_task: Any, folder_path: str) -> TaskInfo:
        path = cls._display_value(registered_task.Path).strip()
        name = cls._display_value(registered_task.Name).strip()
        if not path or not name:
            raise RuntimeError("У зарегистрированной задачи отсутствует имя или полный путь.")
        definition = registered_task.Definition
        registration = definition.RegistrationInfo
        state = int(registered_task.State)
        return TaskInfo(
            path=path,
            name=name,
            folder=folder_path,
            enabled=bool(registered_task.Enabled),
            created=cls._display_time(getattr(registration, "Date", None)),
            next_run=cls._display_time(getattr(registered_task, "NextRunTime", None)),
            author=cls._display_value(getattr(registration, "Author", "")),
            description=cls._display_value(getattr(registration, "Description", "")),
            command=cls._task_command(registered_task),
            xml=cls._task_xml(registered_task),
            status=_TASK_STATES.get(state, "Неизвестно"),
        )

    def tasks(self, log: Log) -> list[TaskInfo]:
        tasks: list[TaskInfo] = []
        folders_seen: set[str] = set()
        try:
            with self._scheduler() as scheduler:
                try:
                    root = scheduler.GetFolder("\\")
                except Exception as error:
                    log("ERROR", f"Не удалось открыть корень Планировщика заданий: {error}")
                    return tasks
                pending = [root]
                while pending:
                    folder = pending.pop()
                    folder_path = self._display_value(getattr(folder, "Path", "\\")).strip() or "\\"
                    folder_key = folder_path.replace("/", "\\").casefold()
                    if folder_key in folders_seen:
                        continue
                    folders_seen.add(folder_key)
                    try:
                        registered_tasks = self._com_items(folder.GetTasks(1))
                    except Exception as error:
                        registered_tasks = []
                        log("ERROR", f"Не удалось перечислить задачи в {folder_path}: {error}")
                    for registered_task in registered_tasks:
                        try:
                            tasks.append(self._task_info(registered_task, folder_path))
                        except Exception as error:
                            task_path = self._display_value(getattr(registered_task, "Path", "неизвестная задача"))
                            log("WARN", f"Не удалось прочитать задачу {task_path}: {error}")
                    try:
                        child_folders = self._com_items(folder.GetFolders(0))
                    except Exception as error:
                        log("ERROR", f"Не удалось перечислить подпапки {folder_path}: {error}")
                        continue
                    pending.extend(reversed(child_folders))
        except Exception as error:
            log("ERROR", f"Сканирование Планировщика заданий прервано: {error}")

        tasks.sort(key=lambda item: (item.folder.casefold(), item.name.casefold(), item.path.casefold()))
        log("INFO", f"Планировщик заданий: прочитано задач — {len(tasks)}, папок — {len(folders_seen)}.")
        return tasks

    @staticmethod
    def _canonical_task_path(path: str) -> str:
        value = path.replace("/", "\\")
        parts = [part for part in value.split("\\") if part]
        if not value.startswith("\\") or not parts or any(part in {".", ".."} for part in parts):
            raise ValueError("Для изменения требуется полный путь задачи из Планировщика.")
        if "\x00" in value:
            raise ValueError("Путь задачи содержит недопустимый символ.")
        return "\\" + "\\".join(parts)

    @staticmethod
    def _get_registered_task(scheduler: Any, path: str) -> Any:
        folder_path, _, name = path.rpartition("\\")
        return scheduler.GetFolder(folder_path or "\\").GetTask(name)

    @staticmethod
    def _is_task_not_found(error: Exception) -> bool:
        if isinstance(error, (FileNotFoundError, KeyError)):
            return True
        code = _error_code(error)
        return code in {2, 3, 0x80070002, 0x80070003, 0x8004130F}

    @classmethod
    def _get_task_sddl(cls, registered_task: Any) -> str:
        getter = getattr(registered_task, "GetSecurityDescriptor", None)
        if not callable(getter):
            raise RuntimeError("Планировщик не предоставил дескриптор безопасности задачи.")
        sddl = getter(_TASK_SECURITY_INFORMATION)
        if not isinstance(sddl, str) or not sddl:
            raise RuntimeError("Не удалось сохранить SDDL дескриптора задачи.")
        return sddl

    def change_task(self, task: TaskInfo, action: str, log: Log) -> Path:
        action = action.casefold().strip()
        if action not in {"enable", "disable", "delete"}:
            raise ValueError("Действие для задачи должно быть enable, disable или delete.")
        path = self._canonical_task_path(task.path)
        if _is_windows_task_path(path):
            raise PermissionError(
                "Задачи в \\Microsoft\\Windows\\ доступны только для чтения и защищены от изменения."
            )
        self._require_admin()

        with self._scheduler() as scheduler:
            try:
                current = self._get_registered_task(scheduler, path)
            except Exception as error:
                raise RuntimeError("Задача исчезла или стала недоступна; повторите сканирование.") from error
            current_xml = self._task_xml(current)
            if current_xml != task.xml:
                raise RuntimeError("XML задачи изменился после сканирования; обновите список и повторите.")
            if bool(current.Enabled) is not task.enabled:
                raise RuntimeError("Состояние задачи изменилось после сканирования; обновите список.")
            current_sddl = self._get_task_sddl(current)
            payload = {
                "version": 1,
                "object": "scheduled_task",
                "path": path,
                "xml": current_xml,
                "sddl": current_sddl,
                "enabled": bool(current.Enabled),
                "credentials_included": False,
                "restore_note": "XML не содержит сохраненные пароли учетных записей; их нужно ввести повторно.",
            }
            backup = self._record("task", path, payload, log)

            try:
                latest = self._get_registered_task(scheduler, path)
                if self._task_xml(latest) != current_xml:
                    raise RuntimeError("Задача изменилась во время создания бэкапа; изменение отменено.")
                if bool(latest.Enabled) is not payload["enabled"]:
                    raise RuntimeError("Состояние задачи изменилось во время создания бэкапа; изменение отменено.")
                if self._get_task_sddl(latest) != current_sddl:
                    raise RuntimeError("Права задачи изменились во время создания бэкапа; изменение отменено.")
                if action == "delete":
                    log("WARN", "Удаление задачи нельзя полностью отменить: сохраненные учетные данные не входят в XML.")
                    folder_path, _, name = path.rpartition("\\")
                    scheduler.GetFolder(folder_path or "\\").DeleteTask(name, 0)
                    try:
                        self._get_registered_task(scheduler, path)
                    except Exception as error:
                        if not self._is_task_not_found(error):
                            raise
                    else:
                        raise RuntimeError("Планировщик по-прежнему возвращает удаленную задачу.")
                else:
                    enabled = action == "enable"
                    if bool(latest.Enabled) != enabled:
                        latest.Enabled = enabled
                    readback = self._get_registered_task(scheduler, path)
                    if bool(readback.Enabled) is not enabled:
                        raise RuntimeError("Планировщик не подтвердил новое состояние задачи.")
                log("OK", f"Задача {path}: действие {action} проверено. Бэкап: {backup}")
            except Exception as error:
                log("ERROR", f"Действие {action} для задачи {path} не подтверждено; бэкап: {backup}. {error}")
                raise
        return backup

    def _record(self, kind: str, target: str, payload: dict[str, Any], log: Log) -> Path:
        try:
            destination = self.journal.record(kind=kind, target=target, payload=payload)
            if not isinstance(destination, (str, os.PathLike)):
                raise TypeError("Журнал не вернул путь к сохраненному бэкапу.")
            path = Path(destination)
        except Exception as error:
            log("ERROR", f"Обязательный бэкап {kind} не сохранен; изменение не выполнялось: {error}")
            raise
        log("OK", f"Снимок {kind} сохранен: {path}")
        return path

    def _service_registry_branch(self, name: str) -> dict[str, Any]:
        if "/" in name or "\\" in name:
            raise ValueError("Имя службы нельзя использовать как путь ветки реестра.")
        key = rf"SYSTEM\CurrentControlSet\Services\{name}"
        snapshot = self.backend.snapshot_registry("HKLM", key, 64)
        if (
            not isinstance(snapshot, Mapping)
            or snapshot.get("exists") is not True
            or not isinstance(snapshot.get("values"), Mapping)
            or not isinstance(snapshot.get("children"), Mapping)
        ):
            raise RuntimeError("Не получен полный снимок ветки реестра службы.")
        return {"hive": "HKLM", "key": key, "view": 64, "snapshot": dict(snapshot)}

    @staticmethod
    def _service_api() -> Any:
        try:
            import win32service

            return win32service
        except ImportError as error:
            raise RuntimeError("Для диспетчера служб требуется установленный pywin32.") from error

    @staticmethod
    def _service_security_api() -> Any:
        try:
            import win32security

            return win32security
        except ImportError as error:
            raise RuntimeError("Для резервного копирования служб требуется pywin32/win32security.") from error

    @staticmethod
    def _close_handle(api: Any, handle: Any) -> None:
        close = getattr(handle, "Close", None)
        if callable(close):
            close()
            return
        api.CloseServiceHandle(handle)

    @contextmanager
    def _managed_handle(self, api: Any, handle: Any) -> Iterator[Any]:
        try:
            yield handle
        finally:
            self._close_handle(api, handle)

    @staticmethod
    def _query_config(api: Any, handle: Any) -> dict[str, Any]:
        raw = api.QueryServiceConfig(handle)
        if not isinstance(raw, (tuple, list)) or len(raw) < 9:
            raise RuntimeError("SCM вернул неполную конфигурацию службы.")
        dependencies = raw[6] or []
        if isinstance(dependencies, str):
            dependencies = [dependencies] if dependencies else []
        return {
            "service_type": int(raw[0]),
            "start_type": int(raw[1]),
            "error_control": int(raw[2]),
            "binary_path": str(raw[3] or ""),
            "load_order_group": str(raw[4] or ""),
            "tag_id": int(raw[5] or 0),
            "dependencies": [str(item) for item in dependencies],
            "account": str(raw[7] or ""),
            "display_name": str(raw[8] or ""),
        }

    @staticmethod
    def _query_status(api: Any, handle: Any) -> dict[str, int]:
        raw = api.QueryServiceStatusEx(handle)
        names = (
            "service_type",
            "current_state",
            "controls_accepted",
            "win32_exit_code",
            "service_specific_exit_code",
            "check_point",
            "wait_hint",
            "process_id",
            "service_flags",
        )
        aliases = {
            "service_type": ("service_type", "ServiceType", "dwServiceType"),
            "current_state": ("current_state", "CurrentState", "dwCurrentState"),
            "controls_accepted": ("controls_accepted", "ControlsAccepted", "dwControlsAccepted"),
            "win32_exit_code": ("win32_exit_code", "Win32ExitCode", "dwWin32ExitCode"),
            "service_specific_exit_code": (
                "service_specific_exit_code",
                "ServiceSpecificExitCode",
                "dwServiceSpecificExitCode",
            ),
            "check_point": ("check_point", "CheckPoint", "dwCheckPoint"),
            "wait_hint": ("wait_hint", "WaitHint", "dwWaitHint"),
            "process_id": ("process_id", "ProcessId", "dwProcessId"),
            "service_flags": ("service_flags", "ServiceFlags", "dwServiceFlags"),
        }
        if isinstance(raw, Mapping):
            nested = raw.get("ServiceStatusProcess") or raw.get("status")
            if nested is not None:
                raw = nested
        if isinstance(raw, Mapping):
            values = {}
            for name in names:
                values[name] = next((raw[key] for key in aliases[name] if key in raw), 0)
        elif isinstance(raw, (tuple, list)) and len(raw) >= 7:
            values = {name: raw[index] if index < len(raw) else 0 for index, name in enumerate(names)}
        else:
            values = {
                name: next((getattr(raw, key) for key in aliases[name] if hasattr(raw, key)), 0)
                for name in names
            }
            if not values["current_state"]:
                raise RuntimeError("SCM вернул неизвестный формат статуса службы.")
        try:
            return {name: int(value or 0) for name, value in values.items()}
        except (TypeError, ValueError) as error:
            raise RuntimeError("SCM вернул поврежденный статус службы.") from error

    @staticmethod
    def _query_description(api: Any, handle: Any) -> str:
        value = api.QueryServiceConfig2(handle, api.SERVICE_CONFIG_DESCRIPTION)
        if isinstance(value, Mapping):
            value = value.get("Description", value.get("lpDescription", ""))
        return str(value or "")

    @staticmethod
    def _query_sddl(api: Any, security_api: Any, handle: Any) -> str:
        descriptor = api.QueryServiceObjectSecurity(handle, _SERVICE_SECURITY_INFORMATION)
        revision = getattr(security_api, "SDDL_REVISION_1", 1)
        sddl = security_api.ConvertSecurityDescriptorToStringSecurityDescriptor(
            descriptor, revision, _SERVICE_SECURITY_INFORMATION
        )
        if not isinstance(sddl, str) or not sddl:
            raise RuntimeError("Не удалось экспортировать SDDL службы.")
        return sddl

    @classmethod
    def _service_details(
        cls,
        api: Any,
        handle: Any,
        *,
        security_api: Any | None = None,
        strict: bool = False,
    ) -> dict[str, Any]:
        errors: list[str] = []
        try:
            config = cls._query_config(api, handle)
        except Exception as error:
            if strict:
                raise
            config = None
            errors.append(f"конфигурация: {error}")
        try:
            description = cls._query_description(api, handle)
            description_readable = True
        except Exception as error:
            if strict:
                raise
            description = ""
            description_readable = False
            errors.append(f"описание: {error}")
        try:
            status = cls._query_status(api, handle)
        except Exception as error:
            if strict:
                raise
            status = None
            errors.append(f"состояние: {error}")
        sddl = None
        if security_api is not None:
            try:
                sddl = cls._query_sddl(api, security_api, handle)
            except Exception as error:
                if strict:
                    raise
                errors.append(f"дескриптор безопасности: {error}")
        if strict and (config is None or not description_readable or status is None or sddl is None):
            raise RuntimeError("Не удалось получить полный снимок службы для безопасного изменения.")
        return {
            "config": config,
            "description": description,
            "description_readable": description_readable,
            "status": status,
            "sddl": sddl,
            "errors": errors,
        }

    @staticmethod
    def _enumerated_service_name(entry: Any, key: str, index: int, default: str = "") -> str:
        if isinstance(entry, Mapping):
            return str(entry.get(key, default) or default)
        if isinstance(entry, (tuple, list)) and len(entry) > index:
            return str(entry[index] or default)
        return default

    @staticmethod
    def _normalize_enum_result(result: Any) -> list[Any]:
        if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], (tuple, list)):
            result = result[0]
        return list(result)

    def services(self, log: Log) -> list[ServiceInfo]:
        try:
            api = self._service_api()
        except Exception as error:
            log("ERROR", f"Не удалось загрузить Windows Service Control Manager API: {error}")
            return []

        services: list[ServiceInfo] = []
        snapshots: list[tuple[str, str, dict[str, Any]]] = []
        manager = None
        try:
            manager = api.OpenSCManager(
                None,
                None,
                api.SC_MANAGER_CONNECT | api.SC_MANAGER_ENUMERATE_SERVICE,
            )
            service_types = api.SERVICE_WIN32 | api.SERVICE_DRIVER
            records = self._normalize_enum_result(api.EnumServicesStatusEx(
                manager,
                service_types,
                api.SERVICE_STATE_ALL,
                None,
                api.SC_ENUM_PROCESS_INFO,
            ))
        except Exception as error:
            if manager is not None:
                self._close_handle(api, manager)
            log("ERROR", f"Не удалось перечислить службы локального компьютера: {error}")
            return services

        try:
            for entry in records:
                name = self._enumerated_service_name(entry, "ServiceName", 0).strip()
                display_name = self._enumerated_service_name(entry, "DisplayName", 1).strip()
                if not name:
                    log("WARN", "SCM вернул запись службы без имени; запись пропущена.")
                    continue
                handle = None
                try:
                    handle = api.OpenService(
                        manager,
                        name,
                        api.SERVICE_QUERY_CONFIG | api.SERVICE_QUERY_STATUS,
                    )
                    with self._managed_handle(api, handle) as service_handle:
                        snapshot = self._service_details(api, service_handle)
                except Exception as error:
                    snapshot = {
                        "config": None,
                        "description": "",
                        "description_readable": False,
                        "status": None,
                        "sddl": None,
                        "errors": [str(error)],
                    }
                for detail_error in snapshot["errors"]:
                    log("WARN", f"Не удалось полностью проверить службу {name}: {detail_error}")
                snapshots.append((name, display_name, snapshot))
        finally:
            self._close_handle(api, manager)

        signature_paths: list[str] = []
        for _, _, snapshot in snapshots:
            config = snapshot["config"]
            if config:
                image = _expand_service_path(
                    _service_image_path(config["binary_path"]), self.backend
                )
                if image:
                    signature_paths.append(image)
                else:
                    snapshot["errors"].append("не удалось однозначно разобрать путь исполняемого файла")
        signature_paths = list(dict.fromkeys(signature_paths))
        signatures = self._inspect_signatures(signature_paths, log)

        for name, display_name, snapshot in snapshots:
            config = snapshot["config"]
            status = snapshot["status"]
            image = (
                _expand_service_path(_service_image_path(config["binary_path"]), self.backend)
                if config
                else ""
            )
            signature = _signature_for_path(signatures, image)
            error_text = "; ".join(snapshot["errors"])
            if config is None:
                start_type = "Неизвестно"
                command = ""
                account = ""
                actual_display_name = display_name
                service_state = "Неизвестно"
                pid = 0
                user_path = False
                missing_description = False
            else:
                start_type = _SERVICE_START_TYPES.get(config["start_type"], f"Неизвестно ({config['start_type']})")
                command = config["binary_path"]
                account = config["account"]
                actual_display_name = config["display_name"] or display_name
                service_state = _SERVICE_STATES.get(status["current_state"], "Неизвестно") if status else "Неизвестно"
                pid = status["process_id"] if status else 0
                user_path = _is_user_directory(config["binary_path"]) or _is_user_directory(image)
                missing_description = snapshot["description_readable"] and not snapshot["description"].strip()
            suspicious = (
                missing_description
                or user_path
                or _signature_is_suspicious(signature)
            )
            services.append(ServiceInfo(
                name=name,
                display_name=actual_display_name,
                pid=pid,
                start_type=start_type,
                state=service_state,
                description=snapshot["description"],
                command=command,
                account=account,
                signature=signature,
                suspicious=suspicious,
                error=error_text,
            ))

        services.sort(key=lambda item: (item.display_name.casefold(), item.name.casefold()))
        log("INFO", f"SCM: прочитано служб — {len(services)}; подозрительность — эвристика, не вердикт о заражении.")
        return services

    def _inspect_signatures(self, paths: list[str], log: Log) -> dict[str, Any]:
        if not paths:
            return {}
        try:
            from system_repair.processes import SignatureInspector

            inspector = SignatureInspector(self.backend)
            result = inspector.inspect_many(paths)
        except Exception as error:
            log("WARN", f"Проверка подписи служб недоступна; неизвестная подпись не является признаком заражения: {error}")
            return {}
        if isinstance(result, Mapping):
            values = result.items()
        elif isinstance(result, Sequence) and not isinstance(result, (str, bytes, bytearray)):
            values = zip(paths, result, strict=False)
        else:
            log("WARN", "Проверка подписи вернула неизвестный формат; статус остается неизвестным.")
            return {}
        return {_path_key(str(path)): value for path, value in values}

    def change_service(self, service: ServiceInfo, action: str, log: Log) -> Path:
        action = action.casefold().strip()
        start_types = {"auto": 2, "manual": 3, "disabled": 4}
        if action not in {"start", "stop", "delete", *start_types}:
            raise ValueError("Действие для службы: start, stop, auto, manual, disabled или delete.")
        if not service.name or "\x00" in service.name:
            raise ValueError("У службы отсутствует допустимое системное имя.")
        self._require_admin()

        api = self._service_api()
        security_api = self._service_security_api()
        access = api.SERVICE_QUERY_CONFIG | api.SERVICE_QUERY_STATUS | _read_control(api)
        access |= {
            "start": api.SERVICE_START,
            "stop": api.SERVICE_STOP,
            "delete": getattr(api, "DELETE", 0x00010000),
            "auto": api.SERVICE_CHANGE_CONFIG,
            "manual": api.SERVICE_CHANGE_CONFIG,
            "disabled": api.SERVICE_CHANGE_CONFIG,
        }[action]
        if action == "delete":
            access |= api.SERVICE_ENUMERATE_DEPENDENTS

        manager = api.OpenSCManager(None, None, api.SC_MANAGER_CONNECT)
        try:
            handle = api.OpenService(manager, service.name, access)
        except Exception:
            self._close_handle(api, manager)
            raise

        backup: Path | None = None
        try:
            with self._managed_handle(api, handle) as service_handle:
                snapshot = self._service_details(api, service_handle, security_api=security_api, strict=True)
                self._assert_service_snapshot(service, snapshot)
                config = snapshot["config"]
                image = _service_image_path(config["binary_path"])
                protection_reason = _protected_service_reason(
                    api,
                    self.backend,
                    service.name,
                    config["display_name"],
                    config["service_type"],
                    image,
                )
                if protection_reason:
                    raise PermissionError(f"Изменение службы запрещено: {protection_reason}.")

                registry_branch = None
                if action == "delete":
                    try:
                        registry_branch = self._service_registry_branch(service.name)
                    except Exception as error:
                        log(
                            "ERROR",
                            "Обязательный снимок ветки реестра службы не получен; "
                            f"удаление отменено: {error}",
                        )
                        raise

                payload = {
                    "version": 1,
                    "object": "service",
                    "name": service.name,
                    "config": config,
                    "description": snapshot["description"],
                    "status": snapshot["status"],
                    "sddl": snapshot["sddl"],
                    "credentials_included": False,
                    "restore_note": "SCM не предоставляет сохраненный пароль учетной записи службы.",
                }
                if registry_branch is not None:
                    payload["registry_branch"] = registry_branch
                    payload["automatic_restore"] = False
                    payload["restore_note"] = (
                        "Автоматическое восстановление не поддерживается; ветка реестра сохранена "
                        "только как резервная копия. Пароль учетной записи службы не сохраняется."
                    )
                backup = self._record("service", service.name, payload, log)

                latest = self._service_details(api, service_handle, security_api=security_api, strict=True)
                if _service_config_key(latest) != _service_config_key(snapshot) or latest["sddl"] != snapshot["sddl"]:
                    raise RuntimeError("Конфигурация или права службы изменились во время бэкапа; действие отменено.")
                if registry_branch is not None:
                    try:
                        latest_registry_branch = self._service_registry_branch(service.name)
                    except Exception as error:
                        log(
                            "ERROR",
                            "Не удалось повторно проверить ветку реестра службы после бэкапа; "
                            f"удаление отменено: {error}",
                        )
                        raise
                    if latest_registry_branch != registry_branch:
                        raise RuntimeError(
                            "Ветка реестра службы изменилась после сохранения бэкапа; удаление отменено."
                        )
                config = latest["config"]
                current_state = latest["status"]["current_state"]

                if action == "delete":
                    stopped = getattr(api, "SERVICE_STOPPED", 1)
                    if current_state != stopped:
                        raise PermissionError("Удалять можно только остановленную службу; принудительное удаление запрещено.")
                    dependents = api.EnumDependentServices(service_handle, api.SERVICE_ACTIVE)
                    if dependents:
                        raise PermissionError("У службы есть работающие зависимые службы; они не останавливались.")
                    if self._query_status(api, service_handle)["current_state"] != stopped:
                        raise PermissionError("Служба запущена; принудительное удаление запрещено.")
                    log(
                        "WARN",
                        "Удаление службы нельзя автоматически отменить: ветка реестра сохранена только "
                        "как бэкап; пароль учетной записи службы не сохраняется.",
                    )
                    api.DeleteService(service_handle)
                elif action == "start":
                    running = getattr(api, "SERVICE_RUNNING", 4)
                    stopped = getattr(api, "SERVICE_STOPPED", 1)
                    if current_state == running:
                        log("INFO", f"Служба {service.name} уже работает.")
                    elif current_state != stopped:
                        raise RuntimeError("Служба переходит между состояниями; обновите список и повторите.")
                    else:
                        api.StartService(service_handle, None)
                    if current_state != running:
                        self._wait_service_state(api, service_handle, running)
                elif action == "stop":
                    stopped = getattr(api, "SERVICE_STOPPED", 1)
                    stop_pending = getattr(api, "SERVICE_STOP_PENDING", 3)
                    if current_state == stopped:
                        log("INFO", f"Служба {service.name} уже остановлена.")
                    elif current_state == stop_pending:
                        self._wait_service_state(api, service_handle, stopped)
                    else:
                        api.ControlService(service_handle, api.SERVICE_CONTROL_STOP)
                        self._wait_service_state(api, service_handle, stopped)
                else:
                    new_start_type = start_types[action]
                    if config["start_type"] != new_start_type:
                        no_change = getattr(api, "SERVICE_NO_CHANGE", 0xFFFFFFFF)
                        api.ChangeServiceConfig(
                            service_handle,
                            no_change,
                            new_start_type,
                            no_change,
                            None,
                            None,
                            False,
                            None,
                            None,
                            None,
                            None,
                        )
                    readback = self._query_config(api, service_handle)
                    if readback["start_type"] != new_start_type:
                        raise RuntimeError("SCM не подтвердил новый тип запуска службы.")
                    for field in ("service_type", "binary_path", "display_name", "account"):
                        if readback[field] != config[field]:
                            raise RuntimeError(f"После изменения неожиданно изменилось поле {field}.")

            if action == "delete":
                self._verify_service_deleted(api, manager, service.name)
            log("OK", f"Служба {service.name}: действие {action} проверено. Бэкап: {backup}")
        except Exception as error:
            if backup is not None:
                log("ERROR", f"Действие {action} для службы {service.name} не подтверждено; бэкап: {backup}. {error}")
            raise
        finally:
            self._close_handle(api, manager)
        return backup

    @staticmethod
    def _assert_service_snapshot(service: ServiceInfo, snapshot: dict[str, Any]) -> None:
        if service.error:
            raise RuntimeError("Снимок службы содержит ошибки чтения; повторите полное сканирование.")
        config = snapshot["config"]
        expected = {
            "name": service.name,
            "display_name": service.display_name,
            "binary_path": service.command,
            "account": service.account,
            "start_type": service.start_type,
        }
        actual = {
            "name": service.name,
            "display_name": config["display_name"],
            "binary_path": config["binary_path"],
            "account": config["account"],
            "start_type": _SERVICE_START_TYPES.get(
                config["start_type"], f"Неизвестно ({config['start_type']})"
            ),
        }
        if expected != actual:
            raise RuntimeError("Конфигурация службы изменилась после сканирования; обновите список.")
        if service.description != snapshot["description"]:
            raise RuntimeError("Описание службы изменилось после сканирования; обновите список.")

    def _wait_service_state(self, api: Any, handle: Any, target_state: int) -> dict[str, int]:
        deadline = time.monotonic() + _SERVICE_WAIT_SECONDS
        while True:
            status = self._query_status(api, handle)
            if status["current_state"] == target_state:
                return status
            if time.monotonic() >= deadline:
                expected = _SERVICE_STATES.get(target_state, str(target_state))
                actual = _SERVICE_STATES.get(status["current_state"], str(status["current_state"]))
                raise TimeoutError(f"Тайм-аут ожидания состояния «{expected}»; служба сообщает «{actual}».")
            time.sleep(min(_SERVICE_POLL_SECONDS, max(0.0, deadline - time.monotonic())))

    def _verify_service_deleted(self, api: Any, manager: Any, name: str) -> None:
        deadline = time.monotonic() + _SERVICE_WAIT_SECONDS
        marked_for_delete = False
        while True:
            try:
                handle = api.OpenService(manager, name, api.SERVICE_QUERY_STATUS)
            except Exception as error:
                error_code = _error_code(error)
                if error_code == 1060:
                    return
                if error_code != 1072:
                    raise
                marked_for_delete = True
            else:
                self._close_handle(api, handle)
            if time.monotonic() >= deadline:
                if marked_for_delete:
                    raise TimeoutError(
                        "SCM продолжает возвращать ERROR_SERVICE_MARKED_FOR_DELETE; "
                        "удаление службы остается ожидающим и не подтверждено."
                    )
                raise TimeoutError("SCM не подтвердил удаление службы в отведенное время.")
            time.sleep(min(_SERVICE_POLL_SECONDS, max(0.0, deadline - time.monotonic())))


def _error_code(error: Exception) -> int | None:
    values = (
        getattr(error, "winerror", None),
        getattr(error, "errno", None),
        getattr(error, "hresult", None),
        *getattr(error, "args", ()),
    )
    for value in values:
        if not isinstance(value, int):
            continue
        unsigned = value & 0xFFFFFFFF
        if unsigned & 0xFFFF0000 == 0x80070000:
            return unsigned & 0xFFFF
        return unsigned
    return None


def _is_windows_task_path(path: str) -> bool:
    normalized = "\\" + "\\".join(part for part in path.replace("/", "\\").split("\\") if part)
    root = "\\microsoft\\windows"
    return normalized.casefold() == root or normalized.casefold().startswith(root + "\\")


def _service_image_path(command: str) -> str:
    value = command.strip()
    if not value or "\x00" in value:
        return ""
    if value.startswith('"'):
        closing = _closing_quote(value)
        if closing <= 1 or (value[closing + 1:] and not value[closing + 1].isspace()):
            return ""
        image = value[1:closing]
    else:
        match = re.search(r"(?i)\.(?:exe|sys|dll)(?=$|\s)", value)
        if match is None:
            return ""
        image = value[:match.end()]
        if any(character.isspace() for character in image):
            return ""
        variable = re.match(r"^%([^%]+)%", image)
        if variable and variable.group(1).casefold() not in {"systemroot", "windir"}:
            return ""
    image = image.strip()
    if not image or not (ntpath.isabs(image) or re.match(r"^%[^%]+%[\\/]", image)):
        return ""
    return image


def _closing_quote(value: str) -> int:
    backslashes = 0
    for index in range(1, len(value)):
        character = value[index]
        if character == "\\":
            backslashes += 1
            continue
        if character == '"' and backslashes % 2 == 0:
            return index
        backslashes = 0
    return -1


def _path_key(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path.replace("/", "\\")))


def _signature_value(info: Any) -> str:
    if isinstance(info, Mapping):
        value = info.get("status", "Не проверена")
    else:
        value = getattr(info, "status", "Не проверена")
    return str(value or "Не проверена")


def _signature_for_path(signatures: Mapping[str, Any], path: str) -> str:
    if not path:
        return "Не проверена"
    return _signature_value(signatures.get(_path_key(path), "Не проверена"))


def _signature_is_suspicious(status: str) -> bool:
    normalized = status.strip().casefold()
    return normalized not in _UNKNOWN_SIGNATURES and normalized != "valid"


def _is_user_directory(path: str) -> bool:
    value = path.replace("/", "\\").casefold()
    if any(token in value for token in ("%appdata%", "%localappdata%", "%temp%", "%userprofile%")):
        return True
    normalized = ntpath.normpath(value)
    parts = [part for part in normalized.split("\\") if part]
    for part in parts:
        if part in {"users", "documents and settings"}:
            return True
        if part in {"appdata", "temp", "tmp", "downloads", "desktop"}:
            return True
    return False


def _expand_service_path(path: str, backend: Any) -> str:
    value = os.path.expandvars(path)
    windows_dir = str(getattr(backend, "windows_dir", "") or "")
    if windows_dir:
        value = re.sub(r"(?i)%systemroot%|%windir%", lambda _: windows_dir, value)
        if value.casefold().startswith("\\systemroot\\"):
            value = ntpath.join(windows_dir, value[len("\\SystemRoot\\"):])
    if value.casefold().startswith("\\??\\"):
        value = value[4:]
    if value.casefold().startswith("\\\\?\\unc\\"):
        value = "\\\\" + value[8:]
    elif value.casefold().startswith("\\\\?\\"):
        value = value[4:]
    return value


def _within_directory(path: str, directory: str) -> bool:
    if not path or not directory:
        return False
    candidate = _path_key(path).rstrip("\\")
    root = _path_key(directory).rstrip("\\")
    return bool(root and (candidate == root or candidate.startswith(root + "\\")))


def _protected_service_reason(
    api: Any,
    backend: Any,
    name: str,
    display_name: str,
    service_type: int,
    image: str,
) -> str:
    driver_mask = getattr(api, "SERVICE_DRIVER", 0x0B)
    if service_type & driver_mask:
        return "драйверы защищены от этих действий"
    name_key = name.casefold()
    display_key = display_name.casefold()
    if name_key in _PROTECTED_SERVICE_NAMES:
        return "это основная или защитная служба Windows"
    if any(token in f"{name_key} {display_key}" for token in _PROTECTED_SERVICE_TOKENS):
        return "защитные и антивирусные службы защищены"
    if not image:
        return "путь исполняемого файла не удалось однозначно разобрать"
    expanded = _expand_service_path(image, backend)
    if expanded.casefold().startswith(("\\systemroot\\", "%systemroot%\\")):
        return "образ размещен в системном каталоге Windows"
    roots = (
        getattr(backend, "windows_dir", ""),
        getattr(backend, "system_dir", ""),
    )
    if any(_within_directory(expanded, str(root or "")) for root in roots):
        return "образы из системных каталогов Windows защищены"
    return ""


def _read_control(api: Any) -> int:
    return getattr(api, "READ_CONTROL", 0x00020000)


def _service_config_key(snapshot: dict[str, Any]) -> tuple[Any, ...]:
    config = snapshot["config"]
    return (
        config["service_type"],
        config["start_type"],
        config["error_control"],
        config["binary_path"],
        config["load_order_group"],
        config["tag_id"],
        tuple(config["dependencies"]),
        config["account"],
        config["display_name"],
        snapshot["description"],
    )
