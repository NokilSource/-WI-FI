from __future__ import annotations

import ctypes
import os
import struct
from dataclasses import replace
from pathlib import Path

import pytest

import system_repair.windows_files as windows_files
from system_repair.demo import DemoPlatform
from system_repair.files import entry_for
from system_repair.journal import ActionJournal


class FakeHandle:
    def __init__(self, path: Path):
        self.path = path
        self.stream = path.open("rb")
        self.deleted = False


class FakeWindowsApi:
    def __init__(self, *, locked=False, streams=("::$DATA",), attributes=0, change_after_first=False):
        self.locked = locked
        self.streams = streams
        self.attributes = attributes
        self.change_after_first = change_after_first
        self.handles = []
        self.events = []
        self.info_calls = 0

    def open_file(self, path: Path):
        self.events.append(("open", path))
        if self.locked:
            raise PermissionError("sharing violation")
        handle = FakeHandle(path)
        self.handles.append(handle)
        return handle

    def file_info(self, handle):
        info = os.fstat(handle.stream.fileno())
        result = windows_files._HandleInfo(
            device=info.st_dev,
            inode=info.st_ino,
            size=info.st_size,
            modified_ns=info.st_mtime_ns,
            attributes=self.attributes,
            links=info.st_nlink,
        )
        self.info_calls += 1
        if self.change_after_first and self.info_calls > 1:
            return replace(result, modified_ns=result.modified_ns + 1)
        return result

    def final_path(self, handle):
        return str(handle.path.resolve())

    def stream_names(self, handle):
        self.events.append(("streams", handle))
        return self.streams

    def read(self, handle, size):
        return handle.stream.read(size)

    def rewind(self, handle):
        handle.stream.seek(0)

    def mark_delete(self, handle):
        self.events.append(("delete", handle))
        handle.deleted = True

    def close(self, handle):
        self.events.append(("close", handle))
        handle.stream.close()
        if handle.deleted:
            handle.path.unlink()


def _journal(path: Path) -> ActionJournal:
    return ActionJournal(path / "backups", DemoPlatform())


def _use_fake(monkeypatch, api):
    monkeypatch.setattr(windows_files, "_get_native_api", lambda: api)


def test_quarantine_copies_verifies_then_deletes_by_the_same_handle(tmp_path, monkeypatch):
    target = tmp_path / "selected.bin"
    content = b"locked quarantine contents" * 100
    target.write_bytes(content)
    entry = entry_for(target)
    journal = _journal(tmp_path)
    api = FakeWindowsApi()
    _use_fake(monkeypatch, api)

    manifest = windows_files.quarantine_locked(entry, journal, ())

    assert not target.exists()
    assert (manifest.parent / "content.bin").read_bytes() == content
    document = journal.load(manifest, "quarantine")
    assert document["target"] == str(target)
    assert document["payload"]["file"] == entry.__dict__
    assert len(api.handles) == 1
    handle = api.handles[0]
    assert [name for name, *_ in api.events].count("open") == 1
    assert [name for name, *_ in api.events].count("delete") == 1
    assert api.events[-2:] == [("delete", handle), ("close", handle)]
    assert handle.deleted and handle.stream.closed


@pytest.mark.parametrize(
    "changes",
    [
        {"inode": 0},
        {"inode": 1},
        {"device": 0},
        {"size": 1000},
        {"modified_ns": 1},
    ],
)
def test_stale_or_missing_snapshot_identity_preserves_source(tmp_path, monkeypatch, changes):
    target = tmp_path / "stale.bin"
    target.write_bytes(b"keep this file")
    entry = entry_for(target)
    journal = _journal(tmp_path)
    api = FakeWindowsApi()
    _use_fake(monkeypatch, api)

    with pytest.raises((OSError, ValueError), match="снимок|идентичност|изменился"):
        windows_files.quarantine_locked(replace(entry, **changes), journal, ())

    assert target.read_bytes() == b"keep this file"
    assert not journal.root.exists()
    assert not any(name == "delete" for name, *_ in api.events)
    assert all(handle.stream.closed for handle in api.handles)


def test_sharing_lock_failure_preserves_original_without_creating_journal(tmp_path, monkeypatch):
    target = tmp_path / "locked.bin"
    target.write_bytes(b"another handle owns the file")
    entry = entry_for(target)
    journal = _journal(tmp_path)
    api = FakeWindowsApi(locked=True)
    _use_fake(monkeypatch, api)

    with pytest.raises(PermissionError, match="sharing violation"):
        windows_files.quarantine_locked(entry, journal, ())

    assert target.read_bytes() == b"another handle owns the file"
    assert not journal.root.exists()
    assert [name for name, *_ in api.events] == ["open"]


@pytest.mark.parametrize("streams,attributes", [(("::$DATA", ":metadata:$DATA"), 0), (("::$DATA",), 0x4000)])
def test_unsupported_stream_or_efs_is_rejected_while_handle_is_locked(
    tmp_path, monkeypatch, streams, attributes
):
    target = tmp_path / "extended.bin"
    target.write_bytes(b"original")
    entry = entry_for(target)
    journal = _journal(tmp_path)
    api = FakeWindowsApi(streams=streams, attributes=attributes)
    _use_fake(monkeypatch, api)

    with pytest.raises(PermissionError):
        windows_files.quarantine_locked(entry, journal, ())

    assert target.read_bytes() == b"original"
    assert not journal.root.exists()
    assert not any(name == "delete" for name, *_ in api.events)


def test_handle_final_path_is_checked_against_protected_directories(tmp_path, monkeypatch):
    protected = tmp_path / "protected"
    protected.mkdir()
    target = protected / "important.bin"
    target.write_bytes(b"do not move")
    entry = entry_for(target)
    journal = _journal(tmp_path)
    api = FakeWindowsApi()
    _use_fake(monkeypatch, api)

    with pytest.raises(PermissionError, match="защищён"):
        windows_files.quarantine_locked(entry, journal, (protected,))

    assert target.read_bytes() == b"do not move"
    assert not journal.root.exists()
    assert not any(name == "delete" for name, *_ in api.events)


def test_handle_identity_is_checked_again_after_blob_and_journal_are_durable(tmp_path, monkeypatch):
    target = tmp_path / "changed-during-copy.bin"
    target.write_bytes(b"source remains if handle state changes")
    entry = entry_for(target)
    journal = _journal(tmp_path)
    api = FakeWindowsApi(change_after_first=True)
    _use_fake(monkeypatch, api)

    with pytest.raises(OSError, match="изменился"):
        windows_files.quarantine_locked(entry, journal, ())

    assert target.read_bytes() == b"source remains if handle state changes"
    assert journal.root.exists()
    assert not any(name == "delete" for name, *_ in api.events)
    assert all(handle.stream.closed for handle in api.handles)


def test_native_open_uses_read_delete_access_and_read_sharing_only():
    class Recorder:
        def CreateFileW(self, *arguments):
            self.arguments = arguments
            return 42

    api = windows_files._NativeWindowsApi.__new__(windows_files._NativeWindowsApi)
    api.kernel = Recorder()

    assert api.open_file(Path(r"C:\Temp\selected.bin")) == 42
    arguments = api.kernel.arguments
    assert arguments[1] == windows_files._GENERIC_READ | windows_files._DELETE
    assert arguments[2] == windows_files._FILE_SHARE_READ
    assert arguments[4] == windows_files._OPEN_EXISTING
    assert arguments[5] & windows_files._FILE_FLAG_OPEN_REPARSE_POINT


def test_native_stream_info_parser_reads_stream_names_from_the_handle():
    class Recorder:
        def GetFileInformationByHandleEx(self, _handle, info_class, buffer, size):
            assert info_class == windows_files._FILE_STREAM_INFO
            assert size >= 24
            raw_name = "::$DATA".encode("utf-16-le")
            record = struct.pack("<IIqq", 0, len(raw_name), 1, 1) + raw_name
            ctypes.memmove(buffer, record, len(record))
            return 1

    api = windows_files._NativeWindowsApi.__new__(windows_files._NativeWindowsApi)
    api.kernel = Recorder()

    assert api.stream_names(42) == ("::$DATA",)


def test_native_delete_uses_single_byte_boolean_on_the_held_handle():
    class Recorder:
        def SetFileInformationByHandle(self, handle, info_class, buffer, size):
            assert handle == 42
            assert info_class == windows_files._FILE_DISPOSITION_INFO_CLASS
            assert size == 1
            assert ctypes.string_at(buffer, size) == b"\x01"
            return 1

    api = windows_files._NativeWindowsApi.__new__(windows_files._NativeWindowsApi)
    api.kernel = Recorder()
    api.mark_delete(42)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file handles")
def test_native_quarantine_of_owned_temporary_file(tmp_path):
    target = tmp_path / "native-quarantine.bin"
    content = b"native file-handle quarantine" * 128
    target.write_bytes(content)
    journal = _journal(tmp_path)

    manifest = windows_files.quarantine_locked(entry_for(target), journal, ())

    assert not target.exists()
    assert (manifest.parent / "content.bin").read_bytes() == content
    assert journal.load(manifest, "quarantine")["payload"]["sha256"]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows sharing semantics")
def test_native_sharing_violation_does_not_delete_owned_temporary_file(tmp_path):
    target = tmp_path / "native-locked.bin"
    target.write_bytes(b"leave this file")
    journal = _journal(tmp_path)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    blocker = kernel.CreateFileW(str(target), 0x80000000, 0x00000001, None, 3, 0x80, None)
    assert blocker not in (None, 0, ctypes.c_void_p(-1).value)
    try:
        with pytest.raises(OSError):
            windows_files.quarantine_locked(entry_for(target), journal, ())
        assert target.read_bytes() == b"leave this file"
        assert not journal.root.exists()
    finally:
        assert kernel.CloseHandle(blocker)
