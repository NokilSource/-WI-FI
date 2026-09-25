from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

Log = Callable[[str, str], None]


@dataclass(frozen=True)
class RegistryAddress:
    hive: Literal["HKCU", "HKLM"]
    key: str
    name: str
    view: Literal[32, 64] = 64

    @property
    def label(self) -> str:
        return f"{self.hive}\\{self.key}\\{self.name} [{self.view}]"


@dataclass(frozen=True)
class RegistryValue:
    type: int
    data: Any

    def to_dict(self) -> dict:
        if isinstance(self.data, bytes):
            return {"type": self.type, "data": base64.b64encode(self.data).decode("ascii"),
                    "encoding": "base64"}
        return {"type": self.type, "data": self.data}

    @classmethod
    def from_dict(cls, value: dict) -> RegistryValue:
        if not isinstance(value, dict) or set(value) not in (
            {"type", "data"}, {"type", "data", "encoding"}
        ):
            raise ValueError("Некорректное значение реестра в бэкапе")
        kind, data = value["type"], value["data"]
        if type(kind) is not int or not 0 <= kind <= 11:
            raise ValueError("Неподдерживаемый тип реестра")
        if "encoding" in value:
            if value["encoding"] != "base64" or not isinstance(data, str):
                raise ValueError("Некорректная кодировка реестра")
            data = base64.b64decode(data, validate=True)
        if kind in (1, 2):
            valid = isinstance(data, str)
        elif kind in (4, 11):
            valid = type(data) is int and 0 <= data < 2 ** (64 if kind == 11 else 32)
        elif kind == 7:
            valid = isinstance(data, list) and all(isinstance(item, str) for item in data)
        else:
            valid = isinstance(data, bytes) or data is None
        if not valid:
            raise ValueError("Данные не соответствуют типу реестра")
        return cls(kind, data)

    def display(self) -> str:
        if isinstance(self.data, bytes):
            return self.data.hex(" ")
        if isinstance(self.data, list):
            return "; ".join(self.data)
        return str(self.data)


@dataclass(frozen=True)
class RegistryChange:
    address: RegistryAddress
    desired: RegistryValue | None


@dataclass(frozen=True)
class Repair:
    id: str
    category: str
    title: str
    detail: str
    kind: Literal["registry", "hosts", "winsock", "tcpip"] = "registry"
    changes: tuple[RegistryChange, ...] = ()
    reboot: bool = False


@dataclass(frozen=True)
class Finding:
    category: str
    name: str
    location: str
    value: str
    status: str = "Проверить"


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    path: str
    user: str
    created: float
    status: str = "Информация"
    critical: bool | None = None
    company: str = ""
    command_line: str = ""
    signature: str = "Не проверена"
    signer: str = ""
    parent_pid: int = 0
    hidden: bool = False
    trusted: bool = False


@dataclass(frozen=True)
class RepairState:
    status: str
    detail: str


@dataclass
class ScanResult:
    states: dict[str, RepairState]
    findings: list[Finding]
    processes: list[ProcessInfo]
    services: list[Finding]


@dataclass(frozen=True)
class RepairResult:
    backup: Path
    completed: tuple[str, ...]
    reboot: bool


class RepairError(RuntimeError):
    def __init__(self, message: str, backup: Path | None = None):
        super().__init__(message)
        self.backup = backup


class Platform(Protocol):
    is_demo: bool
    platform_label: str

    def is_admin(self) -> bool: ...
    def identity(self) -> dict[str, str]: ...
    def read_registry(self, address: RegistryAddress) -> RegistryValue | None: ...
    def write_registry(self, address: RegistryAddress, value: RegistryValue | None) -> None: ...
    def registry_values(self, hive: str, key: str, view: int) -> dict[str, RegistryValue]: ...
    def registry_subkeys(self, hive: str, key: str, view: int) -> list[str]: ...
    def snapshot_registry(self, hive: str, key: str, view: int) -> dict: ...
    def hosts_path(self) -> str: ...
    def read_hosts(self) -> bytes | None: ...
    def write_hosts(self, content: bytes | None) -> None: ...
    def create_restore_point(self) -> int: ...
    def network_snapshot(self) -> dict[str, str]: ...
    def reset_network(self, kind: str, log: Log, backup: Path) -> None: ...
    def list_processes(self) -> list[ProcessInfo]: ...
    def terminate_process(self, process: ProcessInfo) -> None: ...
    def list_services(self) -> list[Finding]: ...
