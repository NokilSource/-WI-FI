from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from system_repair.catalog import EXPLORER, IFEO, INTERNET, POLICIES, WINLOGON
from system_repair.model import Finding, Log, ProcessInfo, RegistryAddress, RegistryValue


class DemoPlatform:
    """In-memory fixtures only; never delegates to Windows APIs or real processes."""

    is_demo = True
    platform_label = "ДЕМО · Windows 11 x64 · LAB-WIN11"

    def __init__(self):
        self.values = {
            RegistryAddress("HKCU", POLICIES + r"\System", "DisableTaskMgr"): RegistryValue(4, 1),
            RegistryAddress("HKCU", POLICIES + r"\System", "DisableRegistryTools"): RegistryValue(4, 1),
            RegistryAddress("HKCU", EXPLORER, "Hidden"): RegistryValue(4, 2),
            RegistryAddress("HKCU", EXPLORER, "ShowSuperHidden"): RegistryValue(4, 0),
            RegistryAddress("HKCU", INTERNET, "ProxyEnable"): RegistryValue(4, 1),
            RegistryAddress("HKCU", INTERNET, "ProxyServer"): RegistryValue(1, "127.0.0.1:8080"),
            RegistryAddress("HKLM", WINLOGON, "Shell"): RegistryValue(1, "explorer.exe"),
            RegistryAddress("HKLM", WINLOGON, "Userinit"): RegistryValue(1, r"C:\Windows\system32\userinit.exe,"),
            RegistryAddress("HKLM", IFEO + r"\cmd.exe", "Debugger"): RegistryValue(1, r"C:\Lab\debugger.exe"),
            RegistryAddress("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "LabUpdater"):
                RegistryValue(1, r"C:\Users\Lab\AppData\Local\LabUpdater.exe"),
        }
        self.hosts = b"127.0.0.1 localhost\r\n0.0.0.0 demo.invalid\r\n"
        self.processes = [
            ProcessInfo(4120, "LabUpdater.exe", r"C:\Users\Lab\AppData\Local\LabUpdater.exe", "LAB\\Admin", 1700000000.0, "Проверить путь"),
            ProcessInfo(3088, "explorer.exe", r"C:\Windows\explorer.exe", "LAB\\Admin", 1699999800.0),
        ]
        self.network_resets: list[str] = []

    def is_admin(self) -> bool:
        return True

    def identity(self) -> dict[str, str]:
        return {"machine": "DEMO-MACHINE", "sid": "DEMO-USER", "windows": r"C:\Windows"}

    def read_registry(self, address: RegistryAddress) -> RegistryValue | None:
        return deepcopy(self.values.get(address))

    def write_registry(self, address: RegistryAddress, value: RegistryValue | None) -> None:
        if value is None:
            self.values.pop(address, None)
        else:
            self.values[address] = deepcopy(value)

    def registry_values(self, hive: str, key: str, view: int) -> dict[str, RegistryValue]:
        return {a.name: deepcopy(value) for a, value in self.values.items()
                if (a.hive, a.key, a.view) == (hive, key, view)}

    def registry_subkeys(self, hive: str, key: str, view: int) -> list[str]:
        prefix = key + "\\"
        return sorted({a.key[len(prefix):].split("\\")[0] for a in self.values
                       if a.hive == hive and a.view == view and a.key.startswith(prefix)})

    def snapshot_registry(self, hive: str, key: str, view: int) -> dict:
        values = self.registry_values(hive, key, view)
        children = self.registry_subkeys(hive, key, view)
        return {"exists": bool(values or children),
                "values": {name: value.to_dict() for name, value in values.items()},
                "children": {child: self.snapshot_registry(hive, key + "\\" + child, view)
                             for child in children}}

    def hosts_path(self) -> str:
        return r"C:\Windows\System32\drivers\etc\hosts"

    def read_hosts(self) -> bytes | None:
        return self.hosts

    def write_hosts(self, content: bytes | None) -> None:
        self.hosts = content

    def create_restore_point(self) -> int:
        return 12345

    def network_snapshot(self) -> dict[str, str]:
        return {"demo.txt": "Synthetic configuration; no system commands executed."}

    def reset_network(self, kind: str, log: Log, backup: Path) -> None:
        self.network_resets.append(kind)
        log("WARN", f"ДЕМО: имитация сброса {kind}; система не изменена.")

    def list_processes(self) -> list[ProcessInfo]:
        return list(self.processes)

    def terminate_process(self, process: ProcessInfo) -> None:
        if process not in self.processes:
            raise RuntimeError("Процесс уже завершился или PID был использован повторно.")
        self.processes.remove(process)

    def list_services(self) -> list[Finding]:
        return [Finding("Службы", "LabService", r"C:\Lab\service.exe", "stopped / manual", "Информация")]
