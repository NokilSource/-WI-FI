from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from system_repair.audit_model import HiveMount, RegistryListing, StartupEntry
from system_repair.files import checked_path, copy_verified, entry_for
from system_repair.inspection import inspect_startup
from system_repair.journal import ActionJournal
from system_repair.model import Log, RegistryAddress, RegistryValue


def validate_address(address: RegistryAddress) -> None:
    if address.hive not in ("HKCU", "HKLM") or address.view not in (32, 64):
        raise ValueError("Допустимы только HKCU/HKLM и представления 32/64.")
    if not address.key or "\x00" in address.key + address.name or "/" in address.key:
        raise ValueError("Некорректный путь реестра.")
    if any(part in ("", ".", "..") for part in address.key.split("\\")):
        raise ValueError("Некорректный путь реестра.")
    if len(address.key) > 16384 or len(address.name) > 16383:
        raise ValueError("Слишком длинное имя реестра.")


class RegistryManager:
    def __init__(self, platform, journal: ActionJournal):
        self.platform = platform
        self.journal = journal
        self.mounts: dict[str, HiveMount] = {}

    def listing(self, hive: str, key: str, view: int, log: Log) -> RegistryListing:
        validate_address(RegistryAddress(hive, key or "Software", "", view))
        result = RegistryListing(hive, key, view,
                                 tuple(self.platform.registry_subkeys(hive, key, view)),
                                 self.platform.registry_values(hive, key, view))
        log("INFO", f"Прочитан реестр: {hive}\\{key} [{view}], значений: {len(result.values)}")
        return result

    def edit(self, address: RegistryAddress, old: RegistryValue | None,
             new: RegistryValue | None, log: Log) -> Path:
        if not self.platform.is_admin():
            raise PermissionError("Для изменений реестра нужны права администратора.")
        validate_address(address)
        lowered = address.key.casefold()
        parts = lowered.split("\\")
        defender_keys = (r"software\policies\microsoft\windows defender",
                         r"software\microsoft\windows defender")
        defender_service = (len(parts) >= 4 and parts[0] == "system"
                            and (parts[1] == "currentcontrolset" or parts[1].startswith("controlset"))
                            and parts[2] == "services"
                            and parts[3] in {"windefend", "wdnissvc", "wdnisdrv", "wdfilter", "wdboot", "sense", "securityhealthservice"})
        if (any(lowered == key or lowered.startswith(key + "\\") for key in defender_keys)
                or address.hive == "HKLM" and (parts[0] in ("sam", "security", "hardware", "bcd00000000") or defender_service)):
            raise PermissionError("Эта ветка защищена; утилита не изменяет учётные данные или защиту Windows.")
        if new is not None:
            RegistryValue.from_dict(new.to_dict())
        if self.platform.read_registry(address) != old:
            raise OSError("Параметр изменился после чтения; обновите список.")
        snapshot = self.platform.snapshot_registry(address.hive, address.key, address.view)
        backup = self.journal.record("registry-value", address.label,
                                     {"address": asdict(address), "old": old.to_dict() if old else None,
                                      "new": new.to_dict() if new else None, "branch": snapshot})
        if self.platform.read_registry(address) != old:
            raise OSError("Параметр изменился во время бэкапа; запись отменена.")
        self.platform.write_registry(address, new)
        if self.platform.read_registry(address) != new:
            raise OSError(f"Не подтверждена запись. Возможны частичные изменения. Бэкап: {backup}")
        log("OK", f"Реестр: {address.label}; резервная копия: {backup}")
        return backup

    def restore(self, path: str, log: Log) -> Path:
        document = self.journal.load(Path(path), "registry-value")
        payload = document["payload"]
        address = RegistryAddress(**payload["address"])
        value = RegistryValue.from_dict(payload["old"]) if payload["old"] is not None else None
        expected = RegistryValue.from_dict(payload["new"]) if payload["new"] is not None else None
        return self.edit(address, expected, value, log)

    def startup(self, log: Log) -> list[StartupEntry]:
        entries = []
        for finding in inspect_startup(self.platform):
            address = None
            value = None
            if finding.status != "Ошибка" and finding.location.startswith(("HKCU\\", "HKLM\\")):
                location, view = finding.location.rsplit(" [", 1)
                hive, key = location.split("\\", 1)
                address = RegistryAddress(hive, key, finding.name, int(view.rstrip("]")))
                value = self.platform.read_registry(address)
            entries.append(StartupEntry(finding.name, finding.location, finding.value,
                                        finding.category, address, value, status=finding.status))
        for hive in ("HKCU", "HKLM"):
            for view in (32, 64):
                key = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                for name in ("BootShell",):
                    address = RegistryAddress(hive, key, name, view)
                    try:
                        value = self.platform.read_registry(address)
                        if value is not None:
                            entries.append(StartupEntry(name, address.label, value.display(), "BootShell", address, value))
                    except OSError as error:
                        log("ERROR", f"{address.label}: {error}")
        if not self.platform.is_demo:
            import win32com.shell.shell as shell
            import win32com.shell.shellcon as shellcon

            for csidl in (shellcon.CSIDL_STARTUP, shellcon.CSIDL_COMMON_STARTUP):
                folder = Path(shell.SHGetFolderPath(0, csidl, None, 0))
                try:
                    for path in checked_path(folder).iterdir():
                        if path.is_file():
                            checked_path(path)
                            file = entry_for(path)
                            entries.append(StartupEntry(path.name, str(folder), str(path), "Startup folder",
                                                        path=file.path, file=file))
                except (OSError, ValueError) as error:
                    log("ERROR", f"Startup {folder}: {error}")
        log("INFO", f"Автозагрузка: {len(entries)} записей. BootShell/Winlogon не исправляются автоматически.")
        return entries

    @contextmanager
    def _hive_privileges(self):
        import win32api
        import win32con
        import win32security

        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
        previous = None
        try:
            desired = [(win32security.LookupPrivilegeValue(None, name), win32con.SE_PRIVILEGE_ENABLED)
                       for name in ("SeBackupPrivilege", "SeRestorePrivilege")]
            previous = win32security.AdjustTokenPrivileges(token, False, desired)
            if win32api.GetLastError():
                raise PermissionError("Нет привилегий загрузки/выгрузки автономного куста.")
            yield
        finally:
            try:
                if previous is not None:
                    win32security.AdjustTokenPrivileges(token, False, previous)
            finally:
                token.Close()

    def mount(self, filename: str, log: Log) -> HiveMount:
        if not self.platform.is_admin():
            raise PermissionError("Загрузка куста требует администратора.")
        if self.platform.is_demo:
            raise ValueError("Автономные кусты недоступны в демо; демонстрация никогда не загружает реальный реестр.")
        source = checked_path(filename)
        if source.name.casefold() in ("sam", "security"):
            raise PermissionError("Кусты учётных данных SAM/SECURITY не поддерживаются.")
        key = "SystemRepairOffline_" + uuid.uuid4().hex
        backup = self.journal.record("offline-hive", str(source),
                                     {"mode": "working-copy", "mount_key": key,
                                      "working_copy": "working.hiv", "original_copy": "original.hiv",
                                      "owner_pid": os.getpid()})
        original = backup.parent / "original.hiv"
        working = backup.parent / "working.hiv"
        copy_verified(source, original)
        copy_verified(original, working)
        mount = HiveMount(key, str(source), str(working), str(backup))
        with self._hive_privileges():
            self.platform.reg.LoadKey(self.platform.reg.HKEY_LOCAL_MACHINE, key, str(working))
            self.mounts[key] = mount
        log("WARN", f"Загружена РАБОЧАЯ КОПИЯ HKLM\\{key}. Исходный куст не изменяется. После редактирования выгрузите: {working}")
        return mount

    def unmount(self, mount: HiveMount, log: Log) -> None:
        import win32api

        if self.mounts.get(mount.key) != mount:
            raise ValueError("Разрешена выгрузка только куста, загруженного этим экземпляром приложения.")
        with self._hive_privileges():
            with self.platform.reg.OpenKey(self.platform.reg.HKEY_LOCAL_MACHINE, mount.key) as handle:
                self.platform.reg.FlushKey(handle)
            win32api.RegUnLoadKey(self.platform.reg.HKEY_LOCAL_MACHINE, mount.key)
            del self.mounts[mount.key]
        log("OK", f"Куст выгружен. Отредактированная копия: {mount.working_copy}. Оригинал не перезаписан.")
