from __future__ import annotations

from dataclasses import dataclass

from system_repair.model import RegistryAddress, RegistryValue


@dataclass(frozen=True)
class SignatureInfo:
    status: str = "Не проверена"
    company: str = ""
    signer: str = ""


@dataclass(frozen=True)
class TaskInfo:
    path: str
    name: str
    folder: str
    enabled: bool
    created: str
    next_run: str
    author: str
    description: str
    command: str
    xml: str
    status: str = "Информация"


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    display_name: str
    pid: int
    start_type: str
    state: str
    description: str
    command: str
    account: str = ""
    signature: str = "Не проверена"
    suspicious: bool = False
    error: str = ""


@dataclass(frozen=True)
class StartupEntry:
    name: str
    location: str
    command: str
    category: str
    address: RegistryAddress | None = None
    value: RegistryValue | None = None
    path: str = ""
    status: str = "Проверить"
    file: FileEntry | None = None


@dataclass(frozen=True)
class RegistryListing:
    hive: str
    key: str
    view: int
    subkeys: tuple[str, ...]
    values: dict[str, RegistryValue]


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    modified_ns: int
    created_ns: int
    device: int
    inode: int
    hidden: bool = False
    digest: str = ""


@dataclass(frozen=True)
class FileScan:
    entries: tuple[FileEntry, ...]
    visited: int
    errors: tuple[str, ...] = ()
    truncated: bool = False


@dataclass(frozen=True)
class HiveMount:
    key: str
    original: str
    working_copy: str
    backup: str
