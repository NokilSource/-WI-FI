from __future__ import annotations

from pathlib import Path

from system_repair.backup import BackupStore
from system_repair.catalog import DEFAULT_HOSTS, REPAIRS, selected_repairs
from system_repair.inspection import inspect_startup
from system_repair.model import (
    Finding,
    Log,
    Platform,
    ProcessInfo,
    RegistryAddress,
    RegistryValue,
    RepairError,
    RepairResult,
    RepairState,
    ScanResult,
)


class RepairEngine:
    def __init__(self, platform: Platform, backup_root: Path):
        self.platform = platform
        self.backup_root = backup_root
        self.backups = BackupStore(platform, backup_root)

    def _require_admin(self) -> None:
        if not self.platform.is_admin():
            raise PermissionError("Нужны права администратора. Запустите приложение от имени администратора под тем же пользователем.")

    def scan(self, log: Log) -> ScanResult:
        log("INFO", "Проверка параметров. Изменения не выполняются.")
        states = {}
        for repair in REPAIRS:
            try:
                if repair.kind == "registry":
                    changed = [change for change in repair.changes
                               if self.platform.read_registry(change.address) != change.desired]
                    states[repair.id] = RepairState("Отличается" if changed else "Норма", repair.detail)
                elif repair.kind == "hosts":
                    content = self.platform.read_hosts() or b""
                    lines = [line.strip() for line in content.decode("utf-8-sig", errors="replace").splitlines()]
                    count = sum(bool(line) and not line.startswith("#") for line in lines)
                    states[repair.id] = RepairState("Проверить" if count else "Норма", f"Активных строк: {count}. {self.platform.hosts_path()}")
                else:
                    states[repair.id] = RepairState("По запросу", repair.detail)
            except OSError as error:
                states[repair.id] = RepairState("Ошибка", str(error))
                log("ERROR", f"{repair.title}: {error}")
        findings = inspect_startup(self.platform)
        try:
            processes = self.platform.list_processes()
        except OSError as error:
            processes = []
            findings.append(Finding("Процессы", "Ошибка чтения", "", str(error), "Ошибка"))
            log("ERROR", f"Не удалось прочитать процессы: {error}")
        try:
            services = self.platform.list_services()
        except OSError as error:
            services = [Finding("Службы", "Ошибка чтения", "", str(error), "Ошибка")]
        errors = sum(state.status == "Ошибка" for state in states.values())
        errors += sum(finding.status == "Ошибка" for finding in findings + services)
        log("WARN" if errors else "OK", f"Проверка завершена. Ошибок чтения: {errors}. "
            "Отличие от типовой конфигурации не доказывает заражение.")
        return ScanResult(states, findings, processes, services)

    def create_backup(self, ids: list[str], log: Log, *, require_restore_point: bool = False) -> Path:
        repairs = selected_repairs(ids)
        if any(repair.kind in ("winsock", "tcpip") for repair in repairs):
            self._require_admin()
        path = self.backups.create(repairs, log, require_restore_point=require_restore_point)
        self.backups.load(path)
        return path

    def _write_checked(self, address: RegistryAddress, old: RegistryValue | None,
                       new: RegistryValue | None, log: Log) -> None:
        if self.platform.read_registry(address) != old:
            raise RuntimeError(f"Параметр изменился после бэкапа; повторите проверку: {address.label}")
        if old == new:
            log("INFO", f"Без изменений: {address.label}")
            return
        self.platform.write_registry(address, new)
        if self.platform.read_registry(address) != new:
            raise RuntimeError(f"Не подтверждена запись: {address.label}")
        log("OK", f"Проверена запись: {address.label}")

    def _write_hosts_checked(self, old: bytes | None, new: bytes | None, log: Log) -> None:
        if self.platform.read_hosts() != old:
            raise RuntimeError("Файл hosts изменился после бэкапа. Повторите проверку.")
        self.platform.write_hosts(new)
        if self.platform.read_hosts() != new:
            raise RuntimeError("Не подтверждена запись hosts.")
        log("OK", f"Проверена запись: {self.platform.hosts_path()}")

    def apply(self, ids: list[str], log: Log) -> RepairResult:
        repairs = selected_repairs(ids)
        self._require_admin()
        backup = self.create_backup(ids, log, require_restore_point=True)
        _, _, previous, hosts = self.backups.load(backup)
        completed = []
        try:
            for repair in repairs:
                log("INFO", f"Начало: {repair.title}")
                for change in repair.changes:
                    self._write_checked(change.address, previous[change.address.label], change.desired, log)
                if repair.kind == "hosts":
                    self._write_hosts_checked(hosts, DEFAULT_HOSTS, log)
                elif repair.kind in ("winsock", "tcpip"):
                    self.platform.reset_network(repair.kind, log, backup.parent)
                completed.append(repair.id)
                log("OK", f"Завершено: {repair.title}")
        except Exception as error:
            message = f"Остановлено: {error}. Уже завершено операций: {len(completed)}. "
            message += f"Возможны частичные изменения текущей операции. Бэкап: {backup}"
            log("ERROR", message)
            raise RepairError(message, backup) from error
        reboot = any(repair.reboot for repair in repairs)
        if reboot:
            log("WARN", "Требуется перезагрузка Windows. Проверьте вывод netsh и доступность сети после перезапуска.")
        else:
            log("INFO", "Приложения/Проводник могут потребовать перезапуска или повторного входа в Windows.")
        return RepairResult(backup, tuple(completed), reboot)

    def restore(self, manifest: Path, log: Log) -> RepairResult:
        self._require_admin()
        document, repairs, values, hosts = self.backups.load(manifest)
        local = tuple(repair for repair in repairs if repair.kind not in ("winsock", "tcpip"))
        if any(repair.kind in ("winsock", "tcpip") for repair in repairs):
            recovery = (f"Точка Windows № {document['restore_point']} (rstrui.exe)."
                        if document.get("restore_point") else "Это ручной снимок; точка Windows не создавалась.")
            log("WARN", f"Сетевой стек не откатывается импортом реестра. {recovery} "
                "network.json содержит конфигурацию для ручного восстановления.")
        if not local:
            raise ValueError("Этот бэкап содержит только сетевой стек. Для него нужен ручной откат по network.json "
                             "или точка восстановления Windows, если она была создана.")
        safety = self.create_backup([repair.id for repair in local], log)
        _, _, current, current_hosts = self.backups.load(safety)
        try:
            for repair in local:
                for change in repair.changes:
                    self._write_checked(change.address, current[change.address.label], values[change.address.label], log)
                if repair.kind == "hosts":
                    self._write_hosts_checked(current_hosts, hosts, log)
        except Exception as error:
            message = f"Откат прерван; возможны частичные изменения: {error}. Бэкап перед откатом: {safety}"
            log("ERROR", message)
            raise RepairError(message, safety) from error
        log("OK", "Выбранные значения реестра и hosts восстановлены; может потребоваться повторный вход в Windows.")
        return RepairResult(safety, tuple(repair.id for repair in local), False)

    def terminate(self, process: ProcessInfo, log: Log) -> None:
        self._require_admin()
        self.platform.terminate_process(process)
        log("WARN", f"Завершён PID {process.pid}: {process.name}. Несохранённые данные процесса не восстанавливаются.")
