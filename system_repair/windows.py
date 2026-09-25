from __future__ import annotations

import ctypes
import getpass
import ntpath
import os
import platform as host_platform
import queue
import struct
import subprocess
import threading
import time
import uuid
from ctypes import wintypes
from pathlib import Path

import psutil

from system_repair.backup import MAX_HOSTS_SIZE
from system_repair.model import Finding, Log, ProcessInfo, RegistryAddress, RegistryValue

PROTECTED_NAMES = frozenset({
    "system", "registry", "idle", "secure system", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
})


class WindowsPlatform:
    is_demo = False

    def __init__(self):
        if os.name != "nt" or struct.calcsize("P") != 8:
            raise OSError("Поддерживается только 64-разрядная Windows и 64-разрядный Python.")
        import winreg

        self.reg = winreg
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.shell = ctypes.WinDLL("shell32", use_last_error=True)
        self._bind_api()
        self.system_dir = self._directory(self.kernel.GetSystemDirectoryW)
        self.windows_dir = self._directory(self.kernel.GetSystemWindowsDirectoryW)
        self.platform_label = f"Windows {host_platform.release()} x64 · {getpass.getuser()}"
        self._identity = None

    def _bind_api(self) -> None:
        definitions = [
            (self.kernel.GetSystemDirectoryW, [wintypes.LPWSTR, wintypes.UINT], wintypes.UINT),
            (self.kernel.GetSystemWindowsDirectoryW, [wintypes.LPWSTR, wintypes.UINT], wintypes.UINT),
            (self.kernel.GetCurrentProcess, [], wintypes.HANDLE),
            (self.kernel.CloseHandle, [wintypes.HANDLE], wintypes.BOOL),
            (self.kernel.LocalFree, [wintypes.HLOCAL], wintypes.HLOCAL),
            (self.kernel.GetOEMCP, [], wintypes.UINT),
            (self.kernel.OpenProcess, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            (self.kernel.IsProcessCritical, [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            (self.kernel.GetProcessTimes, [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
            (self.kernel.QueryFullProcessImageNameW, [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.kernel.TerminateProcess, [wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            (self.kernel.WaitForSingleObject, [wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            (self.advapi.OpenProcessToken, [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL),
            (self.advapi.GetTokenInformation, [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.advapi.ConvertSidToStringSidW, [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL),
            (self.shell.IsUserAnAdmin, [], wintypes.BOOL),
        ]
        for function, arguments, result in definitions:
            function.argtypes = arguments
            function.restype = result

    @staticmethod
    def _directory(function) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        size = function(buffer, len(buffer))
        if not size or size >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def is_admin(self) -> bool:
        return bool(self.shell.IsUserAnAdmin())

    def _require_admin(self) -> None:
        if not self.is_admin():
            raise PermissionError("Операция требует прав администратора.")

    def identity(self) -> dict[str, str]:
        if self._identity is not None:
            return dict(self._identity)
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not size.value:
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 1, buffer, size.value, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = ctypes.cast(buffer, ctypes.POINTER(wintypes.LPVOID)).contents.value
            text = wintypes.LPWSTR()
            if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                user_sid = text.value
            finally:
                self.kernel.LocalFree(ctypes.cast(text, wintypes.HLOCAL))
        finally:
            self.kernel.CloseHandle(token)
        guid = self.read_registry(RegistryAddress("HKLM", r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"))
        if guid is None or not isinstance(guid.data, str):
            raise OSError("Не удалось определить идентификатор компьютера для бэкапа.")
        self._identity = {"machine": guid.data, "sid": user_sid, "windows": self.windows_dir}
        return dict(self._identity)

    def _root(self, hive: str):
        return {"HKCU": self.reg.HKEY_CURRENT_USER, "HKLM": self.reg.HKEY_LOCAL_MACHINE}[hive]

    def _view(self, view: int) -> int:
        return {32: self.reg.KEY_WOW64_32KEY, 64: self.reg.KEY_WOW64_64KEY}[view]

    def read_registry(self, address: RegistryAddress) -> RegistryValue | None:
        try:
            with self.reg.OpenKey(self._root(address.hive), address.key, 0, self.reg.KEY_READ | self._view(address.view)) as key:
                data, kind = self.reg.QueryValueEx(key, address.name)
                return RegistryValue(kind, data)
        except FileNotFoundError:
            return None

    def write_registry(self, address: RegistryAddress, value: RegistryValue | None) -> None:
        self._require_admin()
        access = self.reg.KEY_SET_VALUE | self._view(address.view)
        if value is None:
            try:
                with self.reg.OpenKey(self._root(address.hive), address.key, 0, access) as key:
                    self.reg.DeleteValue(key, address.name)
            except FileNotFoundError:
                pass
        else:
            with self.reg.CreateKeyEx(self._root(address.hive), address.key, 0, access) as key:
                self.reg.SetValueEx(key, address.name, 0, value.type, value.data)

    def registry_values(self, hive: str, key: str, view: int) -> dict[str, RegistryValue]:
        try:
            with self.reg.OpenKey(self._root(hive), key, 0, self.reg.KEY_READ | self._view(view)) as handle:
                return {name: RegistryValue(kind, data)
                        for name, data, kind in (self.reg.EnumValue(handle, index)
                                                for index in range(self.reg.QueryInfoKey(handle)[1]))}
        except FileNotFoundError:
            return {}

    def registry_subkeys(self, hive: str, key: str, view: int) -> list[str]:
        try:
            with self.reg.OpenKey(self._root(hive), key, 0, self.reg.KEY_READ | self._view(view)) as handle:
                return [self.reg.EnumKey(handle, index) for index in range(self.reg.QueryInfoKey(handle)[0])]
        except FileNotFoundError:
            return []

    def snapshot_registry(self, hive: str, key: str, view: int) -> dict:
        count = 0

        def snapshot(path: str, depth: int) -> dict:
            nonlocal count
            count += 1
            if depth > 64 or count > 10000:
                raise OSError("Ветка реестра превышает безопасный размер бэкапа.")
            try:
                with self.reg.OpenKey(self._root(hive), path, 0, self.reg.KEY_READ | self._view(view)) as handle:
                    subkey_count, value_count, _ = self.reg.QueryInfoKey(handle)
                    values = {}
                    for index in range(value_count):
                        name, data, kind = self.reg.EnumValue(handle, index)
                        values[name] = RegistryValue(kind, data).to_dict()
                    children = [self.reg.EnumKey(handle, index) for index in range(subkey_count)]
            except FileNotFoundError:
                return {"exists": False, "values": {}, "children": {}}
            return {"exists": True, "values": values,
                    "children": {name: snapshot(path + "\\" + name, depth + 1) for name in children}}

        return snapshot(key, 0)

    def hosts_path(self) -> str:
        return str(Path(self.system_dir) / "drivers" / "etc" / "hosts")

    def _hosts_file(self) -> Path:
        path = Path(self.hosts_path())
        for part in (Path(self.system_dir), path.parent.parent, path.parent, path):
            try:
                status = part.lstat()
            except FileNotFoundError:
                if part != path:
                    raise
                continue
            if status.st_file_attributes & 0x400:
                raise OSError("hosts или родительский каталог является reparse point; требуется ручная проверка.")
        return path

    def read_hosts(self) -> bytes | None:
        try:
            with self._hosts_file().open("rb") as stream:
                content = stream.read(MAX_HOSTS_SIZE + 1)
            if len(content) > MAX_HOSTS_SIZE:
                raise OSError("hosts превышает безопасный предел 2 MiB.")
            return content
        except FileNotFoundError:
            return None

    def write_hosts(self, content: bytes | None) -> None:
        self._require_admin()
        path = self._hosts_file()
        if content is None:
            path.unlink(missing_ok=True)
            return
        if len(content) > MAX_HOSTS_SIZE:
            raise ValueError("hosts превышает безопасный предел 2 MiB.")
        # In-place writes retain the existing file's ACL and attributes.
        with path.open("r+b" if path.exists() else "xb") as stream:
            stream.write(content)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())

    def _command(self, program: str, arguments: list[str], log: Log | None = None, timeout: int = 120) -> str:
        programs = {name: Path(self.system_dir) / name for name in ("netsh.exe", "ipconfig.exe", "sfc.exe", "shutdown.exe")}
        programs["powershell.exe"] = Path(self.system_dir) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if program not in programs:
            raise ValueError("Недопустимая системная команда.")
        command = [str(programs[program]), *arguments]
        if log:
            log("INFO", subprocess.list2cmdline(command))
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            shell=False, creationflags=subprocess.CREATE_NO_WINDOW,
            text=True, encoding="utf-16le" if program == "sfc.exe" else f"cp{self.kernel.GetOEMCP()}", errors="replace",
        )
        lines: queue.Queue[str | None] = queue.Queue()

        def reader() -> None:
            try:
                for line in process.stdout:
                    lines.put(line)
            finally:
                lines.put(None)

        worker = threading.Thread(target=reader, daemon=True)
        worker.start()
        deadline = time.monotonic() + timeout
        output = []
        size = 0
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"Системная команда не завершилась за {timeout} секунд; состояние может быть частично изменено.")
                try:
                    line = lines.get(timeout=min(remaining, 0.2))
                except queue.Empty:
                    continue
                if line is None:
                    break
                size += len(line)
                if size > 10 * 1024 * 1024:
                    raise OSError("Слишком большой вывод системной команды.")
                output.append(line)
                if log and line.strip():
                    log("INFO", line.rstrip())
            code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
            text = "".join(output)
            if code:
                raise OSError(f"{program} завершился с кодом {code}: {text[-2000:]}")
            return text
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            worker.join(timeout=2)
            process.stdout.close()

    def network_snapshot(self) -> dict[str, str]:
        return {
            "ipv4": self._command("netsh.exe", ["interface", "ipv4", "dump"]),
            "ipv6": self._command("netsh.exe", ["interface", "ipv6", "dump"]),
            "winsock": self._command("netsh.exe", ["winsock", "dump"]),
            "ipconfig": self._command("ipconfig.exe", ["/all"]),
        }

    def create_restore_point(self) -> int:
        self._require_admin()
        description = "System Repair " + uuid.uuid4().hex
        # System Restore can report success while reusing a point from the last 24 hours.
        script = (
            "$ErrorActionPreference = 'Stop'; "
            "$before = @(Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object { [long]$_.SequenceNumber }); "
            f"Checkpoint-Computer -Description '{description}' -RestorePointType MODIFY_SETTINGS "
            "-ErrorAction Stop -WarningAction Stop; "
            "$point = Get-ComputerRestorePoint -ErrorAction Stop | Where-Object { "
            f"$_.Description -eq '{description}' -and $before -notcontains [long]$_.SequenceNumber "
            "} | Sort-Object SequenceNumber -Descending | Select-Object -First 1; "
            "if ($null -eq $point) { throw 'A NEW restore point was not confirmed. Network reset cancelled.' }; "
            "[Console]::WriteLine([long]$point.SequenceNumber)"
        )
        text = self._command("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], timeout=300)
        try:
            sequence = int(text.strip())
        except ValueError as error:
            raise OSError("Windows не подтвердила новую точку восстановления. Сброс отменён.") from error
        if sequence <= 0:
            raise OSError("Недопустимый номер точки восстановления. Сброс отменён.")
        return sequence

    def reset_network(self, kind: str, log: Log, backup: Path) -> None:
        self._require_admin()
        commands = {
            "winsock": ["winsock", "reset"],
            "tcpip": ["int", "ip", "reset", str(backup / "tcpip-reset.log")],
        }
        if kind not in commands:
            raise ValueError("Неизвестная сетевая операция.")
        self._command("netsh.exe", commands[kind], log)
        log("WARN", "netsh завершился с кодом 0. Проверьте его вывод: код не гарантирует сброс каждого компонента.")

    def list_processes(self) -> list[ProcessInfo]:
        processes = []
        for process in psutil.process_iter():
            try:
                with process.oneshot():
                    name, path, user, created = process.name(), process.exe(), process.username(), process.create_time()
                status = "Проверить путь" if any(part in path.casefold() for part in ("\\appdata\\", "\\temp\\", "\\downloads\\")) else "Информация"
                if name.casefold() in PROTECTED_NAMES or process.pid in (0, 4, os.getpid()):
                    status = "Защищён"
                processes.append(ProcessInfo(process.pid, name, path, user, created, status))
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                processes.append(ProcessInfo(process.pid, f"PID {process.pid}", "", "Нет доступа", 0, "Нет доступа"))
        return sorted(processes, key=lambda process: process.pid)

    def terminate_process(self, process: ProcessInfo) -> None:
        self._require_admin()
        own_tree = {os.getpid(), os.getppid(), 0, 4}
        own_tree.update(parent.pid for parent in psutil.Process().parents())
        if process.pid in own_tree or not process.path or process.created <= 0 or process.name.casefold() in PROTECTED_NAMES:
            raise PermissionError("Системный, собственный или недоступный процесс завершать запрещено.")
        handle = self.kernel.OpenProcess(0x1000 | 0x0001 | 0x00100000, False, process.pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            critical = wintypes.BOOL()
            if not self.kernel.IsProcessCritical(handle, ctypes.byref(critical)):
                raise ctypes.WinError(ctypes.get_last_error())
            if critical.value:
                raise PermissionError("Windows пометила процесс как критический. Завершение запрещено.")
            created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
            if not self.kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
                raise ctypes.WinError(ctypes.get_last_error())
            start = ((created.dwHighDateTime << 32) | created.dwLowDateTime) / 10000000 - 11644473600
            path = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(path))
            if not self.kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            if abs(start - process.created) > 0.001 or ntpath.normcase(path.value) != ntpath.normcase(process.path):
                raise RuntimeError("PID уже принадлежит другому процессу. Обновите список и повторите выбор.")
            if ntpath.basename(path.value).casefold() in PROTECTED_NAMES:
                raise PermissionError("Системный процесс завершать запрещено.")
            if not self.kernel.TerminateProcess(handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            if self.kernel.WaitForSingleObject(handle, 5000) != 0:
                raise TimeoutError("Запрос завершения отправлен, но выход процесса ещё не подтверждён.")
        finally:
            self.kernel.CloseHandle(handle)

    def list_services(self) -> list[Finding]:
        findings = []
        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
                status = "Проверить путь" if any(part in info["binpath"].casefold() for part in ("\\appdata\\", "\\temp\\")) else "Информация"
                findings.append(Finding("Службы", info["name"], info["binpath"],
                                        f"{info['status']} / {info['start_type']} / {info['username']}", status))
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                findings.append(Finding("Службы", service.name(), "", "Нет доступа", "Ошибка"))
        return sorted(findings, key=lambda finding: finding.name.casefold())
