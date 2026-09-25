from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import struct
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path

from system_repair.audit_model import FileEntry
from system_repair.journal import ActionJournal
from system_repair.paths import checked_path

MAX_FILE = 512 * 1024 * 1024
_EPOCH_FILETIME = 116_444_736_000_000_000

_GENERIC_READ = 0x80000000
_DELETE = 0x00010000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_DISPOSITION_INFO_CLASS = 4
_FILE_STREAM_INFO = 7
_FILE_ID_INFO_CLASS = 18
_FILE_BEGIN = 0
_ERROR_MORE_DATA = 234
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class _FILE_ID_128(ctypes.Structure):
    _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = [("VolumeSerialNumber", ctypes.c_uint64), ("FileId", _FILE_ID_128)]


class _FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", ctypes.c_ubyte)]


@dataclass(frozen=True)
class _HandleInfo:
    device: int
    inode: int
    size: int
    modified_ns: int
    attributes: int
    links: int


class _NativeWindowsApi:
    def __init__(self):
        if os.name != "nt":
            raise OSError("Завершение карантина по дескриптору доступно только в Windows.")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
        ]
        self.kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self.kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
        self.kernel.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self.kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        self.kernel.ReadFile.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        self.kernel.ReadFile.restype = wintypes.BOOL
        self.kernel.SetFilePointerEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        ]
        self.kernel.SetFilePointerEx.restype = wintypes.BOOL
        self.kernel.SetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self.kernel.SetFileInformationByHandle.restype = wintypes.BOOL

    @staticmethod
    def _winerror(operation: str) -> OSError:
        error = ctypes.WinError(ctypes.get_last_error())
        return OSError(error.errno, f"{operation}: {error.strerror}")

    def open_file(self, path: Path):
        filename = str(path)
        if len(filename) >= 248 and not filename.startswith("\\\\?\\"):
            filename = "\\\\?\\" + filename
        handle = self.kernel.CreateFileW(
            filename,
            _GENERIC_READ | _DELETE,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
        if handle in (None, 0, _INVALID_HANDLE_VALUE):
            raise self._winerror("CreateFileW")
        return handle

    def file_info(self, handle) -> _HandleInfo:
        info = _BY_HANDLE_FILE_INFORMATION()
        if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise self._winerror("GetFileInformationByHandle")
        id_info = _FILE_ID_INFO()
        if not self.kernel.GetFileInformationByHandleEx(
            handle, _FILE_ID_INFO_CLASS, ctypes.byref(id_info), ctypes.sizeof(id_info)
        ):
            raise self._winerror("GetFileInformationByHandleEx(FileIdInfo)")
        filetime = (info.ftLastWriteTime.dwHighDateTime << 32) | info.ftLastWriteTime.dwLowDateTime
        return _HandleInfo(
            device=int(id_info.VolumeSerialNumber),
            inode=int.from_bytes(bytes(id_info.FileId.Identifier), "little"),
            size=(int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow),
            modified_ns=(filetime - _EPOCH_FILETIME) * 100,
            attributes=int(info.dwFileAttributes),
            links=int(info.nNumberOfLinks),
        )

    def final_path(self, handle) -> str:
        size = 512
        while size <= 32768:
            buffer = ctypes.create_unicode_buffer(size)
            length = self.kernel.GetFinalPathNameByHandleW(handle, buffer, size, 0)
            if not length:
                raise self._winerror("GetFinalPathNameByHandleW")
            if length < size:
                return buffer.value
            size = length + 1
        raise OSError("Путь открытого файла превышает безопасный предел.")

    def stream_names(self, handle) -> tuple[str, ...]:
        size = 64 * 1024
        while size <= 16 * 1024 * 1024:
            buffer = ctypes.create_string_buffer(size)
            if self.kernel.GetFileInformationByHandleEx(
                handle, _FILE_STREAM_INFO, buffer, size
            ):
                raw = buffer.raw
                names = []
                offset = 0
                while True:
                    if offset + 24 > size:
                        raise OSError("Повреждён ответ перечисления потоков файла.")
                    next_offset, name_length = struct.unpack_from("<II", raw, offset)
                    name_end = offset + 24 + name_length
                    if not name_length or name_length % 2 or name_end > size:
                        raise OSError("Повреждённое имя потока файла.")
                    names.append(raw[offset + 24 : name_end].decode("utf-16-le", errors="strict"))
                    if next_offset == 0:
                        return tuple(names)
                    if next_offset < 24 + name_length or offset + next_offset > size:
                        raise OSError("Повреждённая цепочка потоков файла.")
                    offset += next_offset
            error = ctypes.get_last_error()
            if error != _ERROR_MORE_DATA:
                raise self._winerror("GetFileInformationByHandleEx(FileStreamInfo)")
            size *= 2
        raise OSError("Список потоков файла превышает безопасный предел.")

    def read(self, handle, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        count = wintypes.DWORD()
        if not self.kernel.ReadFile(handle, buffer, size, ctypes.byref(count), None):
            raise self._winerror("ReadFile")
        return buffer.raw[: count.value]

    def rewind(self, handle) -> None:
        if not self.kernel.SetFilePointerEx(handle, 0, None, _FILE_BEGIN):
            raise self._winerror("SetFilePointerEx")

    def mark_delete(self, handle) -> None:
        info = _FILE_DISPOSITION_INFO(True)
        if not self.kernel.SetFileInformationByHandle(
            handle,
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise self._winerror("SetFileInformationByHandle(FileDispositionInfo)")

    def close(self, handle) -> None:
        if not self.kernel.CloseHandle(handle):
            raise self._winerror("CloseHandle")


def _get_native_api() -> _NativeWindowsApi:
    return _NativeWindowsApi()


def _normalized_path(path: str | Path) -> str:
    value = str(path)
    if os.name == "nt":
        value = value.replace("/", "\\")
        if value.startswith("\\\\?\\UNC\\") or value.startswith("\\\\.\\"):
            raise ValueError("UNC/device paths are not eligible for quarantine.")
        if value.startswith("\\\\?\\"):
            value = value[4:]
        drive, _tail = ntpath.splitdrive(value)
        if len(drive) != 2 or drive[1] != ":":
            raise ValueError("Не удалось подтвердить обычный локальный путь файла.")
        return ntpath.normcase(ntpath.normpath(value))
    if not os.path.isabs(value):
        raise ValueError("Для карантина требуется абсолютный путь.")
    return os.path.normcase(os.path.normpath(value))


def _is_within(path: str, root: str) -> bool:
    path_module = ntpath if os.name == "nt" else os.path
    try:
        return path_module.commonpath((path, root)) == root
    except ValueError:
        return False


def _validate_location(final_path: str, expected_path: str, protected: tuple[str, ...]) -> None:
    actual = _normalized_path(final_path)
    if actual != expected_path:
        raise OSError("Путь открытого файла изменился; обновите список перед карантином.")
    if any(_is_within(actual, root) for root in protected):
        raise PermissionError("Системный каталог или каталог резервных копий защищён от карантина.")


def _validate_info(info: _HandleInfo, entry: FileEntry) -> None:
    if info.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise PermissionError("Reparse point нельзя помещать в карантин.")
    if info.attributes & _FILE_ATTRIBUTE_DIRECTORY:
        raise ValueError("В карантин разрешено помещать только обычные файлы.")
    if info.attributes & _FILE_ATTRIBUTE_ENCRYPTED:
        raise PermissionError("Файлы EFS не перемещаются: резервная копия не сохраняет шифрование.")
    if info.device <= 0 or info.inode <= 0 or info.links <= 0:
        raise OSError("Файловая система не предоставила надёжную идентичность файла.")
    if (info.device, info.inode, info.size, info.modified_ns) != (
        entry.device,
        entry.inode,
        entry.size,
        entry.modified_ns,
    ):
        raise OSError("Файл изменился после проверки; обновите список.")
    if info.links != 1:
        raise PermissionError("Файлы с несколькими hard links не перемещаются в карантин.")
    if info.size > MAX_FILE:
        raise ValueError("Файл превышает лимит карантина 512 MiB.")


def _hash_handle(api: _NativeWindowsApi, handle, expected_size: int) -> str:
    api.rewind(handle)
    digest = hashlib.sha256()
    count = 0
    while chunk := api.read(handle, 1024 * 1024):
        count += len(chunk)
        if count > MAX_FILE:
            raise ValueError("Файл увеличился во время чтения.")
        digest.update(chunk)
    if count != expected_size:
        raise OSError("Размер файла изменился во время чтения.")
    return digest.hexdigest()


def _copy_handle(api: _NativeWindowsApi, handle, destination: Path, expected_size: int) -> str:
    api.rewind(handle)
    digest = hashlib.sha256()
    count = 0
    with destination.open("xb") as stream:
        while chunk := api.read(handle, 1024 * 1024):
            count += len(chunk)
            if count > MAX_FILE:
                raise ValueError("Файл увеличился во время копирования.")
            stream.write(chunk)
            digest.update(chunk)
        if count != expected_size:
            raise OSError("Размер файла изменился во время копирования.")
        stream.flush()
        os.fsync(stream.fileno())
    return digest.hexdigest()


def _hash_blob(path: Path) -> str:
    path = checked_path(path)
    before = path.stat()
    if before.st_size > MAX_FILE:
        raise ValueError("Копия в карантине превышает безопасный предел.")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > MAX_FILE:
                raise ValueError("Копия в карантине увеличилась во время проверки.")
            digest.update(chunk)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or count != before.st_size:
        raise OSError("Копия в карантине изменилась во время проверки.")
    return digest.hexdigest()


def quarantine_locked(
    entry: FileEntry,
    journal: ActionJournal,
    protected: tuple[Path, ...],
) -> Path:
    """Back up and delete a selected file through one locked Windows handle."""
    if (
        not isinstance(entry, FileEntry)
        or not isinstance(entry.path, str)
        or not entry.path
        or type(entry.device) is not int
        or entry.device <= 0
        or type(entry.inode) is not int
        or entry.inode <= 0
        or type(entry.size) is not int
        or entry.size < 0
        or type(entry.modified_ns) is not int
    ):
        raise ValueError("Для карантина требуется полный снимок идентичности файла.")

    source = checked_path(entry.path)
    expected_path = _normalized_path(source)
    if _normalized_path(entry.path) != expected_path:
        raise ValueError("Путь снимка не является каноническим; обновите список файлов.")
    protected_paths = tuple(_normalized_path(checked_path(path)) for path in protected)
    api = _get_native_api()
    handle = api.open_file(source)
    try:
        info = api.file_info(handle)
        _validate_info(info, entry)
        _validate_location(api.final_path(handle), expected_path, protected_paths)
        streams = api.stream_names(handle)
        if streams != ("::$DATA",):
            raise PermissionError("Файл содержит ADS или поток нельзя проверить; карантин отменён.")

        checksum = _hash_handle(api, handle, entry.size)
        payload = {"file": asdict(entry), "sha256": checksum}
        manifest = Path(journal.record("quarantine", str(source), payload))
        blob = checked_path(manifest.parent / "content.bin")
        copied_checksum = _copy_handle(api, handle, blob, entry.size)
        if copied_checksum != checksum or _hash_blob(blob) != checksum:
            raise OSError("Копия карантина не совпадает с содержимым исходного файла.")

        document = journal.load(manifest, "quarantine")
        if document.get("target") != str(source) or document.get("payload") != payload:
            raise OSError("Манифест карантина не подтверждает выбранный файл и его контрольную сумму.")

        final_info = api.file_info(handle)
        _validate_info(final_info, entry)
        _validate_location(api.final_path(handle), expected_path, protected_paths)
        if api.stream_names(handle) != ("::$DATA",):
            raise PermissionError("Список потоков изменился; карантин отменён.")
        api.mark_delete(handle)
    finally:
        api.close(handle)
    return manifest
