from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

from system_repair.audit_model import FileEntry, FileScan, ServiceInfo, TaskInfo
from system_repair.model import Log, ProcessInfo


class DemoAudit:
    def __init__(self, platform, journal):
        self.platform, self.journal = platform, journal
        self.suspended: set[int] = set()
        self.task_items = [
            TaskInfo(r"\Lab\Updater", "Updater", "\\Lab\\", True, "2026-09-25", "2026-09-26 09:00",
                     "Lab", "Демонстрация пользовательского задания", r"C:\Lab\Updater.exe --check", "<Task>demo</Task>"),
            TaskInfo(r"\Microsoft\Windows\Demo", "Demo", "\\Microsoft\\Windows\\", True, "2026-09-01", "",
                     "Microsoft", "Синтетический пример защищённого раздела", "demo.exe", "<Task>protected-demo</Task>"),
        ]
        self.service_items = [ServiceInfo("LabService", "Lab test service", 0, "manual", "stopped", "",
                                          r'"C:\Users\Lab\AppData\Local\LabService.exe"', "LocalSystem", "NotSigned", True)]
        now = time.time_ns()
        self.file_items = [
            FileEntry(r"C:\Users\Lab\AppData\Local\Temp\sample.exe", 4096, now, now, 0, 1, True),
            FileEntry(r"C:\Users\Lab\AppData\Local\Temp\sample-copy.exe", 4096, now, now, 0, 2),
        ]
        self.quarantined: dict[str, tuple[FileEntry, ...]] = {}

    @property
    def has_suspended(self) -> bool:
        return bool(self.suspended)

    def list_processes(self, log: Log) -> list[ProcessInfo]:
        result = []
        for process in self.platform.processes:
            result.append(replace(process, critical=False, company="Lab Software" if process.pid == 4120 else "Microsoft Corporation",
                                  command_line=f'"{process.path}" --demo', signature="NotSigned" if process.pid == 4120 else "Valid",
                                  signer="" if process.pid == 4120 else "CN=Microsoft Windows", trusted=process.pid == 3088,
                                  parent_pid=3088 if process.pid == 4120 else 0,
                                  status="Приостановлен" if process.pid in self.suspended else process.status))
        log("INFO", "ДЕМО: процессы и подписи синтетические; реальные файлы не проверялись.")
        return result

    def action(self, process: ProcessInfo, action: str, log: Log) -> None:
        current = next((item for item in self.platform.processes if item.pid == process.pid and item.created == process.created
                        and item.path == process.path), None)
        if current is None:
            raise ValueError("Процесс изменился или завершился.")
        if process.critical or action not in ("kill", "suspend", "resume"):
            raise PermissionError("Недопустимая операция с процессом.")
        if action == "kill":
            self.platform.terminate_process(current)
            self.suspended.discard(process.pid)
        elif action == "suspend":
            if process.pid in self.suspended:
                raise ValueError("Этот процесс уже приостановлен утилитой.")
            self.suspended.add(process.pid)
        else:
            if process.pid not in self.suspended:
                raise ValueError("Возобновлять можно только процессы, приостановленные этим экземпляром.")
            self.suspended.remove(process.pid)
        log("WARN", f"ДЕМО: {action} PID {process.pid}; реальная система не изменена.")

    def plan_tree(self, root: ProcessInfo, log: Log) -> tuple[ProcessInfo, ...]:
        processes = self.list_processes(log)
        selected = [item for item in processes if item.parent_pid == root.pid]
        return tuple(selected + [root])

    def kill_tree(self, plan: tuple[ProcessInfo, ...], log: Log) -> None:
        for process in plan:
            self.action(process, "kill", log)

    def resume_all(self, log: Log) -> None:
        self.suspended.clear()
        log("INFO", "ДЕМО: приостановленные процессы возобновлены.")

    def tasks(self, log: Log) -> list[TaskInfo]:
        log("INFO", "ДЕМО: прочитаны синтетические задания.")
        return list(self.task_items)

    def change_task(self, task: TaskInfo, action: str, log: Log) -> Path:
        if task not in self.task_items or task.path.casefold().startswith("\\microsoft\\windows\\"):
            raise PermissionError("Задание изменилось или находится в защищённом разделе.")
        if action not in ("enable", "disable", "delete"):
            raise ValueError("Неизвестное действие.")
        backup = self.journal.record("task", task.path, {"xml": task.xml, "enabled": task.enabled})
        self.task_items.remove(task)
        if action != "delete":
            self.task_items.append(replace(task, enabled=action == "enable", xml=f"<Task>{action}</Task>"))
        log("WARN", f"ДЕМО: {action} {task.path}. Бэкап: {backup}")
        return backup

    def services(self, log: Log) -> list[ServiceInfo]:
        log("INFO", "ДЕМО: прочитана синтетическая служба.")
        return list(self.service_items)

    def change_service(self, service: ServiceInfo, action: str, log: Log) -> Path:
        if service not in self.service_items:
            raise ValueError("Конфигурация службы изменилась.")
        if action not in ("start", "stop", "auto", "manual", "disabled", "delete"):
            raise ValueError("Неизвестное действие.")
        if action == "delete" and service.state != "stopped":
            raise ValueError("Сначала остановите службу.")
        backup = self.journal.record("service", service.name, {"image": service.command, "start": service.start_type})
        self.service_items.remove(service)
        if action != "delete":
            self.service_items.append(replace(service, state={"start": "running", "stop": "stopped"}.get(action, service.state),
                                               start_type=action if action in ("auto", "manual", "disabled") else service.start_type))
        log("WARN", f"ДЕМО: {action} {service.name}. Бэкап: {backup}")
        return backup

    def files(self, root: str, minutes: int, log: Log) -> FileScan:
        log("INFO", "ДЕМО: отображаются образцы, реальный каталог не читается.")
        return FileScan(tuple(self.file_items), len(self.file_items))

    def file_action(self, entries, action, destination, log):
        if action not in ("copy", "quarantine") or not entries:
            raise ValueError("Выберите файлы и допустимую операцию.")
        if any(entry not in self.file_items for entry in entries):
            raise ValueError("Демонстрационный список изменился.")
        backup = self.journal.record("demo-files", action, {"paths": [entry.path for entry in entries]})
        if action == "quarantine":
            self.quarantined[str(backup)] = entries
            self.file_items = [entry for entry in self.file_items if entry not in entries]
        log("WARN", f"ДЕМО: {action}; ни один настоящий файл не изменён. Журнал: {backup}")
        return (backup,)

    def restore_quarantine(self, manifest: str, log: Log):
        if manifest not in self.quarantined:
            raise ValueError("Этот демо-карантин не создан текущим экземпляром.")
        self.file_items.extend(self.quarantined.pop(manifest))
        log("INFO", "ДЕМО: файлы возвращены в синтетический список.")
