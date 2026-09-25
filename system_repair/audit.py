from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from system_repair.audit_demo import DemoAudit
from system_repair.audit_model import FileEntry, HiveMount, StartupEntry
from system_repair.files import FileManager, checked_path
from system_repair.journal import ActionJournal
from system_repair.model import Log, ProcessInfo, RegistryAddress, RegistryValue
from system_repair.registry_audit import RegistryManager, validate_address


class AuditEngine:
    def __init__(self, platform, backup_root: Path):
        self.platform = platform
        self.journal = ActionJournal(backup_root, platform)
        self.reg = RegistryManager(platform, self.journal)
        self.demo = DemoAudit(platform, self.journal) if platform.is_demo else None
        self._process_manager = None
        self._task_service = None
        self._file_manager = None

    @property
    def file_manager(self):
        if self._file_manager is None:
            protected = [Path(__file__).resolve().parent]
            if getattr(sys, "frozen", False):
                protected.extend((Path(sys.executable).resolve(), Path(sys._MEIPASS).resolve()))
            if not self.platform.is_demo:
                protected.append(Path(self.platform.windows_dir))
                protected.extend(Path(os.environ[name]) for name in ("ProgramFiles", "ProgramFiles(x86)") if os.environ.get(name))
            self._file_manager = FileManager(self.journal, tuple(protected))
        return self._file_manager

    def _admin(self):
        if not self.platform.is_admin():
            raise PermissionError("Нужен запуск от имени администратора под тем же пользователем.")

    @property
    def process_manager(self):
        if self.demo:
            return self.demo
        if self._process_manager is None:
            from system_repair.processes import ProcessManager

            self._process_manager = ProcessManager(self.platform)
        return self._process_manager

    @property
    def task_service(self):
        if self.demo:
            return self.demo
        if self._task_service is None:
            from system_repair.task_service import WindowsTaskService

            self._task_service = WindowsTaskService(self.platform, self.journal)
        return self._task_service

    @property
    def has_resources(self) -> bool:
        manager = self.demo or self._process_manager
        return bool(self.reg.mounts or (manager and manager.has_suspended))

    def cleanup(self, log: Log) -> None:
        errors = []
        manager = self.demo or self._process_manager
        if manager and manager.has_suspended:
            try:
                manager.resume_all(log)
            except Exception as error:
                errors.append(str(error))
        for mount in list(self.reg.mounts.values()):
            try:
                self.reg.unmount(mount, log)
            except Exception as error:
                errors.append(f"{mount.key}: {error}")
        if errors or self.has_resources:
            raise OSError("Не все ресурсы освобождены; повторите попытку. " + "; ".join(errors))

    def processes(self, log: Log) -> list[ProcessInfo]:
        return self.process_manager.list_processes(log)

    def process_action(self, process: ProcessInfo, action: str, log: Log):
        self._admin()
        return self.process_manager.action(process, action, log)

    def process_tree(self, root: ProcessInfo, log: Log):
        return self.process_manager.plan_tree(root, log)

    def kill_tree(self, plan: tuple[ProcessInfo, ...], log: Log):
        self._admin()
        return self.process_manager.kill_tree(plan, log)

    def startup(self, log: Log):
        return self.reg.startup(log)

    def edit_startup(self, entry: StartupEntry, value: RegistryValue | None, log: Log):
        self._admin()
        if entry.address is not None:
            return self.reg.edit(entry.address, entry.value, value, log)
        if entry.path and value is None:
            if self.demo:
                raise ValueError("Изменения настоящих папок автозагрузки запрещены в демо.")
            if entry.file is None or entry.file.path != entry.path:
                raise ValueError("Нет исходного снимка файла автозагрузки; обновите список.")
            return self.file_manager.act((entry.file,), "quarantine", "", log)
        raise ValueError("Выберите доступное значение реестра или файл Startup для карантина.")

    def tasks(self, log: Log):
        return self.task_service.tasks(log)

    def change_task(self, task, action: str, log: Log):
        self._admin()
        return self.task_service.change_task(task, action, log)

    def services(self, log: Log):
        return self.task_service.services(log)

    def change_service(self, service, action: str, log: Log):
        self._admin()
        return self.task_service.change_service(service, action, log)

    def registry(self, hive: str, key: str, view: int, log: Log):
        return self.reg.listing(hive, key, view, log)

    def edit_registry(self, address: RegistryAddress, old: RegistryValue | None, new: RegistryValue | None, log: Log):
        return self.reg.edit(address, old, new, log)

    def restore_registry(self, manifest: str, log: Log):
        return self.reg.restore(manifest, log)

    def mount_hive(self, path: str, log: Log) -> HiveMount:
        return self.reg.mount(path, log)

    def unmount_hive(self, mount: HiveMount, log: Log):
        self._admin()
        return self.reg.unmount(mount, log)

    def files(self, root: str, minutes: int, log: Log):
        if self.demo:
            return self.demo.files(root, minutes, log)
        return self.file_manager.scan(root, minutes, log)

    def duplicates(self, path: str, root: str, log: Log):
        if self.demo:
            return self.demo.files(root, 0, log)
        return self.file_manager.duplicates(path, root, log)

    def file_action(self, entries: tuple[FileEntry, ...], action: str, destination: str, log: Log):
        self._admin()
        if self.demo:
            return self.demo.file_action(entries, action, destination, log)
        return self.file_manager.act(entries, action, destination, log)

    def restore_quarantine(self, manifest: str, log: Log):
        self._admin()
        if self.demo:
            return self.demo.restore_quarantine(manifest, log)
        return self.file_manager.restore(manifest, log)

    def open_location(self, path: str, log: Log):
        if self.demo:
            log("INFO", f"ДЕМО: открытие папки {path} не выполняется.")
            return
        file = checked_path(path)
        if not file.exists():
            raise FileNotFoundError(path)
        subprocess.Popen([str(Path(self.platform.windows_dir) / "explorer.exe"), "/select,", str(file)], shell=False)

    def open_registry(self, address: RegistryAddress, log: Log):
        validate_address(address)
        if self.demo:
            log("INFO", f"ДЕМО: Regedit → {address.label}")
            return
        last_key = RegistryAddress("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit", "LastKey")
        hive = {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE"}[address.hive]
        self.reg.edit(last_key, self.platform.read_registry(last_key), RegistryValue(1, f"{hive}\\{address.key}"), log)
        subprocess.Popen([str(Path(self.platform.windows_dir) / "regedit.exe")], shell=False)
        log("INFO", "Путь задан через LastKey; уже открытый Regedit может потребовать перезапуска.")

    def system(self, action: str, log: Log):
        if action not in ("sfc", "diskmgmt", "recovery", "safe", "uefi", "cancel_restart", "appearance"):
            raise ValueError("Неизвестное системное действие.")
        if action not in ("diskmgmt", "appearance"):
            self._admin()
        if self.demo:
            log("WARN", f"ДЕМО: {action}; реальные команды и перезагрузка не выполняются.")
            return
        if action == "diskmgmt":
            subprocess.Popen([str(Path(self.platform.system_dir) / "mmc.exe"), str(Path(self.platform.system_dir) / "diskmgmt.msc")], shell=False)
        elif action == "appearance":
            os.startfile("ms-settings:themes")
            log("INFO", "Открыты штатные параметры темы. Принудительный сброс шрифтов реестром не выполняется.")
        elif action == "sfc":
            point = self.platform.create_restore_point()
            if type(point) is not int or point <= 0:
                raise OSError("Не подтверждена новая точка восстановления; SFC не запущен.")
            backup = self.journal.record("sfc", "sfc /scannow", {"restore_point": point})
            log("INFO", f"SFC: точка восстановления {point}; журнал действия: {backup}")
            self.platform._command("sfc.exe", ["/scannow"], log, timeout=1800)
            log("WARN", "Проверка SFC завершилась; прочитайте результат и CBS.log. Код 0 не доказывает отсутствие повреждений.")
        else:
            arguments = {"recovery": ["/r", "/o", "/t", "0"], "safe": ["/r", "/o", "/t", "0"],
                         "uefi": ["/r", "/fw", "/t", "0"], "cancel_restart": ["/a"]}[action]
            if action == "safe":
                log("WARN", "После перезапуска: Поиск неисправностей → Дополнительные параметры → Параметры загрузки → F4/F5. BCD не изменяется.")
            self.journal.record("system", action, {"command": "shutdown.exe", "arguments": arguments})
            if action in ("recovery", "safe", "uefi") and self.has_resources:
                self.cleanup(log)
            self.platform._command("shutdown.exe", arguments, log)
