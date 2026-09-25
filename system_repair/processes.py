from __future__ import annotations

import ctypes
import ntpath
import os
import re
import stat
import subprocess
import threading
from collections import defaultdict
from collections.abc import Iterable
from ctypes import wintypes
from typing import Any

import psutil

from system_repair.audit_model import SignatureInfo
from system_repair.model import Log, ProcessInfo
from system_repair.windows import PROTECTED_NAMES, WindowsPlatform

PROCESS_TERMINATE = 0x0001
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

_SIGNATURE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$results = @(
    foreach ($item in @($inputData.paths)) {
        $path = [string]$item
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
            $company = ''
            try {
                $company = [string][System.Diagnostics.FileVersionInfo]::GetVersionInfo($path).CompanyName
            } catch {}
            $signer = ''
            if ($null -ne $signature.SignerCertificate) {
                $signer = [string]$signature.SignerCertificate.Subject
            }
            [pscustomobject]@{
                path = $path
                status = [string]$signature.Status
                company = $company
                signer = $signer
            }
        } catch {
            [pscustomobject]@{ path = $path; status = 'UnknownError'; company = ''; signer = '' }
        }
    }
)
ConvertTo-Json -InputObject $results -Compress -Depth 4
"""


def _path_key(path: str) -> str:
    normalized = ntpath.normpath(path.strip().replace("/", "\\"))
    if normalized.startswith("\\\\?\\UNC\\"):
        normalized = "\\\\" + normalized[8:]
    elif normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return ntpath.normcase(normalized)


def _unknown_signature() -> SignatureInfo:
    return SignatureInfo(status="UnknownError")


class SignatureInspector:
    """Batches Authenticode and version-resource queries through PowerShell."""

    def __init__(self, backend: WindowsPlatform):
        self.backend = backend
        self._cache: dict[tuple[str, int, int, int, int], SignatureInfo] = {}
        self._latest_key: dict[str, tuple[str, int, int, int, int]] = {}
        self._lock = threading.RLock()

    def inspect(self, path: str) -> SignatureInfo:
        return self.inspect_many([path]).get(path, _unknown_signature())

    def inspect_many(self, paths: Iterable[str]) -> dict[str, SignatureInfo]:
        requested = [path for path in paths if isinstance(path, str) and path]
        results: dict[str, SignatureInfo] = {}
        pending: dict[tuple[str, int, int, int, int], list[str]] = {}

        with self._lock:
            for path in requested:
                try:
                    metadata = os.stat(path)
                except (OSError, ValueError):
                    results[path] = _unknown_signature()
                    continue
                normalized = _path_key(path)
                key = (
                    normalized,
                    int(getattr(metadata, "st_dev", 0)),
                    int(getattr(metadata, "st_ino", 0)),
                    int(metadata.st_size),
                    int(getattr(metadata, "st_mtime_ns", metadata.st_mtime * 1_000_000_000)),
                )
                previous = self._latest_key.get(normalized)
                if previous is not None and previous != key:
                    self._cache.pop(previous, None)
                self._latest_key[normalized] = key
                if key in self._cache:
                    results[path] = self._cache[key]
                else:
                    pending.setdefault(key, []).append(path)

            if pending:
                queried = self._query_signatures([aliases[0] for aliases in pending.values()])
                for key, aliases in pending.items():
                    path = aliases[0]
                    result = queried.get(_path_key(path), _unknown_signature())
                    self._cache[key] = result
                    results.update((alias, result) for alias in aliases)

        return results

    def _query_signatures(self, paths: list[str]) -> dict[str, SignatureInfo]:
        try:
            from system_repair.powershell import run_json

            response = run_json(self.backend, _SIGNATURE_SCRIPT, {"paths": paths}, timeout=120)
        except Exception:
            return {_path_key(path): _unknown_signature() for path in paths}

        if isinstance(response, dict):
            if "path" in response:
                records = [response]
            else:
                records = response.get("results", [])
                if not isinstance(records, (list, tuple)):
                    records = []
        elif isinstance(response, list):
            records = response
        else:
            records = []

        expected = {_path_key(path) for path in paths}
        results: dict[str, SignatureInfo] = {}
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                continue
            key = _path_key(record["path"])
            if key not in expected:
                continue
            status = record.get("status")
            if not isinstance(status, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", status):
                status = "UnknownError"
            company = record.get("company")
            signer = record.get("signer")
            results[key] = SignatureInfo(
                status=status,
                company=company[:1024] if isinstance(company, str) else "",
                signer=signer[:2048] if isinstance(signer, str) else "",
            )
        for key in expected:
            results.setdefault(key, _unknown_signature())
        return results


def _is_microsoft_signer(signer: str) -> bool:
    return bool(re.search(r"(?:^|,\s*)O\s*=\s*Microsoft Corporation\s*(?:,|$)", signer, re.IGNORECASE))


def _system_directories(backend: WindowsPlatform) -> tuple[str, ...]:
    windows_dir = getattr(backend, "windows_dir", "")
    candidates = [getattr(backend, "system_dir", "")]
    if windows_dir:
        candidates.extend(
            ntpath.join(windows_dir, directory)
            for directory in ("System32", "SysWOW64", "WinSxS")
        )
    return tuple(_path_key(path) for path in candidates if path)


def _is_under(path: str, directory: str) -> bool:
    normalized_path = _path_key(path)
    normalized_directory = _path_key(directory)
    return normalized_path == normalized_directory or normalized_path.startswith(
        normalized_directory.rstrip("\\") + "\\"
    )


def _is_trusted_process(path: str, signature: SignatureInfo, backend: WindowsPlatform) -> bool:
    if signature.status.casefold() != "valid" or not _is_microsoft_signer(signature.signer):
        return False
    return any(_is_under(path, directory) for directory in _system_directories(backend))


def _is_suspicious_path(path: str) -> bool:
    normalized = "\\" + _path_key(path).strip("\\") + "\\"
    return any(token in normalized for token in ("\\temp\\", "\\appdata\\", "\\downloads\\"))


def _is_hidden_path(path: str) -> bool:
    if not path:
        return False
    components = ntpath.normpath(path).replace("/", "\\").split("\\")
    if any(component.startswith(".") and component not in (".", "..") for component in components):
        return True
    hidden_attribute = getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0x2)
    candidate = ntpath.normpath(path)
    while candidate:
        try:
            attributes = getattr(os.stat(candidate), "st_file_attributes", 0)
            if attributes & hidden_attribute:
                return True
        except (OSError, ValueError):
            pass
        parent = ntpath.dirname(candidate)
        if not parent or parent == candidate:
            break
        candidate = parent
    return False


class _SuspendedProcess:
    __slots__ = ("process", "handle", "resumed", "uncertain")

    def __init__(self, process: ProcessInfo, handle: Any):
        self.process = process
        self.handle = handle
        self.resumed = False
        self.uncertain = False


class ProcessManager:
    """Audits processes and performs guarded actions on verified process handles."""

    def __init__(self, backend: WindowsPlatform):
        self.backend = backend
        self.signatures = SignatureInspector(backend)
        self._suspended: dict[int, _SuspendedProcess] = {}
        self._lock = threading.RLock()
        self._ntdll: Any | None = None

    @property
    def has_suspended(self) -> bool:
        with self._lock:
            return bool(self._suspended)

    @staticmethod
    def _log(log: Log, level: str, message: str) -> None:
        try:
            log(level, message)
        except Exception:
            pass

    def list_processes(self, log: Log) -> list[ProcessInfo]:
        snapshots: list[tuple[int, str, str, str, float, str, int]] = []
        try:
            iterator = psutil.process_iter()
            for process in iterator:
                try:
                    pid = int(process.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, TypeError, ValueError):
                    continue
                if pid <= 0:
                    continue
                try:
                    with process.oneshot():
                        name = self._read_process_value(process, "name", f"PID {pid}")
                        path = self._read_process_value(process, "exe", "")
                        user = self._read_process_value(process, "username", "")
                        created = self._read_process_value(process, "create_time", 0.0)
                        command = self._read_process_value(process, "cmdline", ())
                        parent_pid = self._read_process_value(process, "ppid", 0)
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
                except (psutil.AccessDenied, OSError, AttributeError):
                    name, path, user, created, command, parent_pid = f"PID {pid}", "", "", 0.0, (), 0

                try:
                    created = float(created)
                except (TypeError, ValueError):
                    created = 0.0
                try:
                    parent_pid = int(parent_pid or 0)
                except (TypeError, ValueError):
                    parent_pid = 0
                if not isinstance(name, str) or not name:
                    name = f"PID {pid}"
                if not isinstance(path, str):
                    path = ""
                if not isinstance(user, str):
                    user = ""
                if isinstance(command, (list, tuple)):
                    command_line = subprocess.list2cmdline([str(argument) for argument in command])
                else:
                    command_line = ""
                snapshots.append((pid, name, path, user, created, command_line, parent_pid))
        except (psutil.Error, OSError) as error:
            self._log(log, "ERROR", f"Не удалось перечислить процессы: {error}")
            return []

        signatures = self.signatures.inspect_many(path for _, _, path, *_ in snapshots if path)
        results = []
        for pid, name, path, user, created, command_line, parent_pid in snapshots:
            critical = self._critical_for_pid(pid, path, created)
            hidden = _is_hidden_path(path)
            signature = signatures.get(path, _unknown_signature())
            suspicious = _is_suspicious_path(path) or hidden
            trusted = _is_trusted_process(path, signature, self.backend)
            if not path or created <= 0:
                status = "Неизвестна идентификация"
            elif critical is True:
                status = "Критический"
            elif critical is None:
                status = "Критичность не проверена"
            elif suspicious:
                status = "Проверить путь"
            else:
                status = "Информация"
            results.append(
                ProcessInfo(
                    pid=pid,
                    name=name,
                    path=path,
                    user=user,
                    created=created,
                    status=status,
                    critical=critical,
                    company=signature.company,
                    command_line=command_line,
                    signature=signature.status,
                    signer=signature.signer,
                    parent_pid=parent_pid,
                    hidden=hidden,
                    trusted=trusted,
                )
            )
        results.sort(key=lambda process: process.pid)
        self._log(log, "INFO", f"Обнаружено процессов: {len(results)}.")
        return results

    @staticmethod
    def _read_process_value(process: psutil.Process, method: str, default: Any) -> Any:
        try:
            return getattr(process, method)()
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError, AttributeError):
            return default

    def _critical_for_pid(self, pid: int, expected_path: str, expected_created: float) -> bool | None:
        kernel = getattr(self.backend, "kernel", None)
        if kernel is None or not all(
            hasattr(kernel, function)
            for function in (
                "OpenProcess",
                "IsProcessCritical",
                "GetProcessTimes",
                "QueryFullProcessImageNameW",
                "WaitForSingleObject",
                "CloseHandle",
            )
        ):
            return None
        try:
            expected_created = float(expected_created)
        except (TypeError, ValueError, OverflowError):
            return None
        if not expected_path or not 0 < expected_created < float("inf"):
            return None
        handle = None
        try:
            handle = kernel.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid
            )
            if not handle:
                return None

            if kernel.WaitForSingleObject(handle, 0) != WAIT_TIMEOUT:
                return None

            created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
            if not kernel.GetProcessTimes(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ):
                return None
            ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
            live_created = ticks / 10_000_000 - 11_644_473_600

            path_buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(path_buffer))
            if not kernel.QueryFullProcessImageNameW(
                handle, 0, path_buffer, ctypes.byref(size)
            ):
                return None
            if (
                abs(live_created - expected_created) > 0.001
                or _path_key(path_buffer.value) != _path_key(expected_path)
            ):
                return None

            result = wintypes.BOOL()
            if not kernel.IsProcessCritical(handle, ctypes.byref(result)):
                return None
            return bool(result.value)
        except (OSError, AttributeError, TypeError, ValueError):
            return None
        finally:
            if handle:
                try:
                    kernel.CloseHandle(handle)
                except (OSError, AttributeError, TypeError):
                    pass

    def action(self, process: ProcessInfo, action: str, log: Log) -> None:
        operation = action.strip().casefold() if isinstance(action, str) else ""
        if operation == "kill":
            self._kill(process, log)
        elif operation == "suspend":
            self._suspend(process, log)
        elif operation == "resume":
            self._resume(process, log)
        else:
            raise ValueError("Поддерживаются только действия kill, suspend и resume.")

    def _ensure_admin(self) -> None:
        if getattr(self.backend, "is_demo", False):
            raise PermissionError("Действия над реальными процессами недоступны в демонстрационном режиме.")
        require_admin = getattr(self.backend, "_require_admin", None)
        if callable(require_admin):
            require_admin()
            return
        is_admin = getattr(self.backend, "is_admin", None)
        if not callable(is_admin) or not is_admin():
            raise PermissionError("Операция требует подтверждённых прав администратора.")

    @staticmethod
    def _identity_fields_valid(process: ProcessInfo) -> None:
        if not isinstance(process, ProcessInfo):
            raise TypeError("Ожидается снимок ProcessInfo.")
        if (
            type(process.pid) is not int
            or process.pid <= 0
            or not isinstance(process.path, str)
            or not process.path
            or not ntpath.isabs(process.path)
            or not isinstance(process.name, str)
            or not process.name.strip()
            or not isinstance(process.created, (int, float))
            or not 0 < float(process.created) < float("inf")
        ):
            raise PermissionError("Неизвестная идентификация процесса: обновите список перед действием.")
        if process.critical is not False:
            raise PermissionError("Критичность процесса неизвестна или включена; действие запрещено.")

    @staticmethod
    def _protected(process: ProcessInfo, live_path: str | None = None) -> bool:
        names = {process.name.casefold(), ntpath.basename(process.path).casefold()}
        if live_path:
            names.add(ntpath.basename(live_path).casefold())
        return bool(names & PROTECTED_NAMES)

    def _current_ancestor_pids(self) -> set[int]:
        pids = {os.getpid(), os.getppid(), 0, 4}
        try:
            pids.update(int(parent.pid) for parent in psutil.Process(os.getpid()).parents())
        except (psutil.Error, OSError, AttributeError, TypeError, ValueError) as error:
            raise PermissionError("Не удалось проверить цепочку родительских процессов.") from error
        return pids

    def _validate_snapshot(self, process: ProcessInfo, *, suspend: bool = False) -> None:
        self._identity_fields_valid(process)
        if process.pid in self._current_ancestor_pids():
            raise PermissionError("Собственный процесс или его родитель завершать/приостанавливать запрещено.")
        if self._protected(process):
            raise PermissionError("Защищённый системный процесс изменять запрещено.")
        if suspend and any(_is_under(process.path, directory) for directory in _system_directories(self.backend)):
            raise PermissionError("Приостановка процессов из системных каталогов запрещена.")

    def _kernel(self):
        kernel = getattr(self.backend, "kernel", None)
        if kernel is None:
            raise OSError("Windows API процессов недоступен.")
        return kernel

    @staticmethod
    def _close_handle(kernel: Any, handle: Any) -> None:
        if handle:
            result = kernel.CloseHandle(handle)
            if result is False or (type(result) is int and result == 0):
                raise ProcessManager._raise_last_error("Не удалось закрыть дескриптор процесса")

    @staticmethod
    def _raise_last_error(message: str) -> OSError:
        win_error = getattr(ctypes, "WinError", None)
        if callable(win_error):
            error = win_error(ctypes.get_last_error())
            error.args = (f"{message}: {error}",)
            return error
        return OSError(message)

    def _open_checked_handle(self, process: ProcessInfo, access: int, *, suspend: bool = False):
        self._validate_snapshot(process, suspend=suspend)
        kernel = self._kernel()
        handle = kernel.OpenProcess(access, False, process.pid)
        if not handle:
            raise self._raise_last_error("Не удалось открыть процесс")
        try:
            self._verify_handle_identity(handle, process, suspend=suspend)
        except Exception:
            try:
                self._close_handle(kernel, handle)
            except Exception:
                pass
            raise
        return handle

    def _critical_from_handle(self, handle: Any) -> bool:
        result = wintypes.BOOL()
        if not self._kernel().IsProcessCritical(handle, ctypes.byref(result)):
            raise self._raise_last_error("Не удалось проверить критичность процесса")
        return bool(result.value)

    def _verify_handle_identity(self, handle: Any, process: ProcessInfo, *, suspend: bool = False) -> None:
        self._validate_snapshot(process, suspend=suspend)
        kernel = self._kernel()
        wait_result = kernel.WaitForSingleObject(handle, 0)
        if wait_result == WAIT_OBJECT_0:
            raise RuntimeError("Процесс уже завершился; обновите список процессов.")
        if wait_result != WAIT_TIMEOUT:
            raise self._raise_last_error("Не удалось проверить состояние процесса")
        critical = self._critical_from_handle(handle)
        if critical:
            raise PermissionError("Windows пометила процесс как критический; действие запрещено.")

        created, _exited, _kernel_time, _user_time = (wintypes.FILETIME() for _ in range(4))
        if not kernel.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(_exited),
            ctypes.byref(_kernel_time),
            ctypes.byref(_user_time),
        ):
            raise self._raise_last_error("Не удалось проверить время создания процесса")
        ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
        live_created = ticks / 10_000_000 - 11_644_473_600

        path = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(path))
        if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
            raise self._raise_last_error("Не удалось проверить путь процесса")
        live_path = path.value
        if (
            abs(live_created - float(process.created)) > 0.001
            or _path_key(live_path) != _path_key(process.path)
        ):
            raise RuntimeError("PID уже принадлежит другому процессу. Обновите список и повторите выбор.")
        if self._protected(process, live_path):
            raise PermissionError("Системный процесс изменять запрещено.")
        if suspend and any(_is_under(live_path, directory) for directory in _system_directories(self.backend)):
            raise PermissionError("Приостановка процессов из системных каталогов запрещена.")

    def _kill(self, process: ProcessInfo, log: Log) -> None:
        self._validate_snapshot(process)
        self._ensure_admin()
        with self._lock:
            if process.pid in self._suspended:
                raise PermissionError("Сначала возобновите процесс, приостановленный этой утилитой.")
            handle = self._open_checked_handle(
                process,
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
            )
            kernel = self._kernel()
            try:
                self._verify_handle_identity(handle, process)
                if not kernel.TerminateProcess(handle, 1):
                    raise self._raise_last_error("Не удалось завершить процесс")
                if kernel.WaitForSingleObject(handle, 5000) != WAIT_OBJECT_0:
                    raise TimeoutError("Запрос завершения отправлен, но выход процесса ещё не подтверждён.")
                self._log(log, "INFO", f"Процесс {process.name} (PID {process.pid}) завершён.")
            finally:
                self._close_handle(kernel, handle)

    def _get_ntdll(self):
        if self._ntdll is None:
            loader = getattr(ctypes, "WinDLL", None)
            if not callable(loader):
                raise OSError("NtSuspendProcess/NtResumeProcess доступны только в Windows.")
            self._ntdll = loader("ntdll")
            for name in ("NtSuspendProcess", "NtResumeProcess"):
                function = getattr(self._ntdll, name)
                try:
                    function.argtypes = [wintypes.HANDLE]
                    function.restype = ctypes.c_int32
                except (AttributeError, TypeError):
                    pass
        return self._ntdll

    @staticmethod
    def _check_ntstatus(status: Any, function: str) -> None:
        code = int(status)
        if code < 0:
            raise OSError(f"{function} завершился с NTSTATUS 0x{code & 0xFFFFFFFF:08X}.")

    @staticmethod
    def _same_identity(first: ProcessInfo, second: ProcessInfo) -> bool:
        return (
            first.pid == second.pid
            and _path_key(first.path) == _path_key(second.path)
            and abs(float(first.created) - float(second.created)) <= 0.001
        )

    def _suspend(self, process: ProcessInfo, log: Log) -> None:
        self._ensure_admin()
        self._validate_snapshot(process, suspend=True)
        with self._lock:
            existing = self._suspended.get(process.pid)
            if existing is not None:
                if not self._same_identity(existing.process, process):
                    raise RuntimeError("PID уже принадлежит другому приостановленному процессу.")
                if existing.uncertain:
                    raise RuntimeError(
                        "Результат NtSuspendProcess неизвестен; сначала попробуйте возобновить процесс."
                    )
                self._verify_handle_identity(existing.handle, existing.process, suspend=True)
                self._log(log, "WARN", f"PID {process.pid} уже приостановлен этой утилитой; повторный вызов пропущен.")
                return

            handle = self._open_checked_handle(
                process,
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME | SYNCHRONIZE,
                suspend=True,
            )
            record = _SuspendedProcess(process, handle)
            try:
                self._verify_handle_identity(handle, process, suspend=True)
                self._suspended[process.pid] = record
                ntdll = self._get_ntdll()
                record.uncertain = True
                status = ntdll.NtSuspendProcess(handle)
                self._check_ntstatus(status, "NtSuspendProcess")
                record.uncertain = False
                self._log(log, "INFO", f"Процесс {process.name} (PID {process.pid}) приостановлен.")
            except Exception as error:
                if record.uncertain:
                    self._log(
                        log,
                        "ERROR",
                        f"NtSuspendProcess завершился с неопределенным состоянием PID {process.pid}; "
                        f"удерживаемый дескриптор сохранен. Попробуйте возобновить процесс: {error}",
                    )
                else:
                    if self._suspended.get(process.pid) is record:
                        del self._suspended[process.pid]
                    try:
                        self._close_handle(self._kernel(), handle)
                    except Exception:
                        pass
                raise

    def _resume_record(self, pid: int, record: _SuspendedProcess, log: Log) -> None:
        with self._lock:
            if self._suspended.get(pid) is not record:
                return
            level = "INFO"
            if not record.resumed:
                kernel = self._kernel()
                was_uncertain = record.uncertain
                wait_result = kernel.WaitForSingleObject(record.handle, 0)
                if wait_result == WAIT_OBJECT_0:
                    record.resumed = True
                    record.uncertain = False
                    level = "WARN"
                    message = f"PID {pid} уже завершился; удерживаемый дескриптор закрыт."
                else:
                    if wait_result != WAIT_TIMEOUT:
                        raise self._raise_last_error("Не удалось проверить состояние приостановленного процесса")
                    self._verify_handle_identity(record.handle, record.process, suspend=True)
                    status = self._get_ntdll().NtResumeProcess(record.handle)
                    self._check_ntstatus(status, "NtResumeProcess")
                    record.resumed = True
                    record.uncertain = False
                    if was_uncertain:
                        level = "WARN"
                        message = (
                            f"Для PID {pid} отправлено возобновление после неопределенного "
                            "результата NtSuspendProcess."
                        )
                    else:
                        message = f"Процесс {record.process.name} (PID {pid}) возобновлён."
            else:
                kernel = self._kernel()
                message = f"Дескриптор процесса {record.process.name} (PID {pid}) освобождён."
            self._close_handle(kernel, record.handle)
            del self._suspended[pid]
            self._log(log, level, message)

    def _resume(self, process: ProcessInfo, log: Log) -> None:
        self._ensure_admin()
        self._identity_fields_valid(process)
        if process.pid in self._current_ancestor_pids() or self._protected(process):
            raise PermissionError("Собственный или защищённый процесс возобновлять через этот интерфейс запрещено.")
        with self._lock:
            record = self._suspended.get(process.pid)
            if record is None:
                raise PermissionError("Эта утилита не приостанавливала данный процесс.")
            if not self._same_identity(record.process, process):
                raise RuntimeError("PID уже принадлежит другому приостановленному процессу.")
            self._resume_record(process.pid, record, log)

    def resume_all(self, log: Log) -> None:
        errors = []
        with self._lock:
            records = list(self._suspended.items())
            for pid, record in records:
                try:
                    self._resume_record(pid, record, log)
                except Exception as error:
                    errors.append((pid, error))
                    self._log(log, "ERROR", f"Не удалось возобновить PID {pid}: {error}")
        if errors:
            pids = ", ".join(str(pid) for pid, _ in errors)
            raise RuntimeError(f"Не удалось возобновить все удерживаемые процессы (PID: {pids}).") from errors[0][1]

    def plan_tree(self, root: ProcessInfo, log: Log) -> tuple[ProcessInfo, ...]:
        if not isinstance(root, ProcessInfo):
            raise TypeError("Ожидается корневой снимок ProcessInfo.")
        inventory = self.list_processes(log)
        by_pid = {process.pid: process for process in inventory}
        if len(by_pid) != len(inventory):
            raise RuntimeError("Снимок содержит повторяющиеся PID; обновите список процессов.")
        listed_root = by_pid.get(root.pid)
        if listed_root is None or not self._same_identity(listed_root, root):
            raise RuntimeError("Корневой процесс изменился или завершился; обновите список процессов.")

        children: dict[int, list[ProcessInfo]] = defaultdict(list)
        for process in inventory:
            if process.parent_pid > 0:
                children[process.parent_pid].append(process)
        for group in children.values():
            group.sort(key=lambda process: process.pid)

        ordered: list[ProcessInfo] = []
        active: set[int] = set()
        visited: set[int] = set()

        def visit(process: ProcessInfo) -> None:
            if process.pid in active:
                raise RuntimeError("В дереве процессов обнаружен цикл; планирование отменено.")
            if process.pid in visited:
                return
            active.add(process.pid)
            self._validate_snapshot(process)
            for child in children.get(process.pid, ()):
                visit(child)
            active.remove(process.pid)
            visited.add(process.pid)
            ordered.append(process)

        visit(listed_root)
        plan = tuple(ordered)
        self._log(
            log,
            "WARN",
            f"Сформирован неизменяемый план завершения дерева из {len(plan)} процессов; требуется подтверждение.",
        )
        return plan

    @staticmethod
    def _validate_child_first(plan: tuple[ProcessInfo, ...]) -> None:
        positions = {process.pid: index for index, process in enumerate(plan)}
        for process in plan:
            parent_position = positions.get(process.parent_pid)
            if parent_position is not None and positions[process.pid] >= parent_position:
                raise ValueError("План дерева должен содержать потомков раньше их родителей.")

    def kill_tree(self, plan: tuple[ProcessInfo, ...], log: Log) -> None:
        if not isinstance(plan, tuple) or not plan:
            raise ValueError("Для завершения требуется непустой неизменяемый план дерева.")
        pids = [process.pid for process in plan if isinstance(process, ProcessInfo)]
        if len(pids) != len(plan) or len(set(pids)) != len(plan):
            raise ValueError("План содержит неверный тип записи или повторяющийся PID.")
        self._validate_child_first(plan)
        self._ensure_admin()

        with self._lock:
            suspended = {process.pid for process in plan} & self._suspended.keys()
            if suspended:
                pids_text = ", ".join(str(pid) for pid in sorted(suspended))
                raise PermissionError(f"Сначала возобновите процессы, приостановленные этой утилитой: {pids_text}.")
            kernel = self._kernel()
            handles: dict[int, Any] = {}
            access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE
            try:
                for process in plan:
                    handles[process.pid] = self._open_checked_handle(process, access)

                # Validate the entire frozen selection again before any process is terminated.
                for process in plan:
                    self._verify_handle_identity(handles[process.pid], process)

                for process in plan:
                    handle = handles[process.pid]
                    self._verify_handle_identity(handle, process)
                    if not kernel.TerminateProcess(handle, 1):
                        raise self._raise_last_error(f"Не удалось завершить PID {process.pid}")
                    if kernel.WaitForSingleObject(handle, 5000) != WAIT_OBJECT_0:
                        raise TimeoutError(f"Выход PID {process.pid} ещё не подтверждён.")
                    self._log(log, "INFO", f"Процесс {process.name} (PID {process.pid}) завершён по плану дерева.")
            finally:
                for handle in handles.values():
                    try:
                        self._close_handle(kernel, handle)
                    except Exception:
                        pass

    def __del__(self):
        try:
            if self._suspended:
                self.resume_all(lambda *_args: None)
        except Exception:
            pass
