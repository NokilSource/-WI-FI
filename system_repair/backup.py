from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from system_repair.catalog import NETWORK_BRANCHES, selected_repairs
from system_repair.model import Log, Platform, RegistryValue, Repair
from system_repair.paths import checked_path

MAX_HOSTS_SIZE = 2 * 1024 * 1024


def write_json(path: Path, data: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


class BackupStore:
    def __init__(self, platform: Platform, root: Path):
        self.platform = platform
        self.root = root

    def create(self, repairs: tuple[Repair, ...], log: Log, *, require_restore_point: bool = False) -> Path:
        now = datetime.now(UTC)
        root = checked_path(self.root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder = checked_path(root) / f"{now:%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}"
        folder.mkdir(mode=0o700)
        log("INFO", f"Сохраняется резервная копия: {folder}")
        network = any(repair.kind in ("winsock", "tcpip") for repair in repairs)
        branches = {(c.address.hive, c.address.key, c.address.view)
                    for repair in repairs for c in repair.changes}
        if network:
            branches.update(("HKLM", key, 64) for key in NETWORK_BRANCHES)
        snapshots = {}
        for hive, key, view in sorted(branches):
            snapshots[(hive, key, view)] = self.platform.snapshot_registry(hive, key, view)
        write_json(folder / "branches.json", [
            {"hive": hive, "key": key, "view": view, "tree": tree}
            for (hive, key, view), tree in snapshots.items()
        ])
        values = {}
        for repair in repairs:
            for change in repair.changes:
                address = change.address
                tree = snapshots[(address.hive, address.key, address.view)]
                matching = {name.casefold(): value for name, value in tree.get("values", {}).items()}
                values[address.label] = matching.get(address.name.casefold())

        hosts = None
        if any(repair.kind == "hosts" for repair in repairs):
            content = self.platform.read_hosts()
            if content is not None:
                if len(content) > MAX_HOSTS_SIZE:
                    raise ValueError("Файл hosts превышает безопасный предел 2 MiB.")
                with (folder / "hosts.bin").open("xb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            hosts = {"existed": content is not None,
                     "sha256": hashlib.sha256(content).hexdigest() if content is not None else None}

        restore_point = None
        if network:
            write_json(folder / "network.json", self.platform.network_snapshot())
        if network and require_restore_point:
            log("INFO", "Создаётся точка восстановления Windows перед сбросом сети.")
            restore_point = self.platform.create_restore_point()
            if not restore_point:
                raise RuntimeError("Windows не подтвердила точку восстановления. Сброс сети отменён.")
            log("INFO", f"Точка восстановления создана: {restore_point}")

        manifest = {
            "version": 1, "created_utc": now.isoformat(),
            "identity": self.platform.identity(), "demo": self.platform.is_demo,
            "operations": [repair.id for repair in repairs], "registry": values,
            "hosts": hosts, "restore_point": restore_point,
        }
        # Only a completely written manifest makes a backup usable.
        write_json(folder / "backup.json.tmp", manifest)
        (folder / "backup.json.tmp").replace(folder / "backup.json")
        log("OK", f"Бэкап сохранён и готов к проверке: {folder / 'backup.json'}")
        return folder / "backup.json"

    def load(self, path: Path) -> tuple[dict, tuple[Repair, ...], dict[str, RegistryValue | None], bytes | None]:
        path = checked_path(path)
        if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("Манифест бэкапа недопустим или слишком велик.")
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] != 1:
            raise ValueError("Неизвестный формат бэкапа.")
        if document.get("identity") != self.platform.identity() or document.get("demo") is not self.platform.is_demo:
            raise ValueError("Бэкап относится к другому компьютеру, пользователю или режиму.")
        ids = document.get("operations")
        if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            raise ValueError("Повреждён список операций бэкапа.")
        repairs = selected_repairs(ids)
        expected = {c.address.label for repair in repairs for c in repair.changes}
        raw_values = document.get("registry")
        if not isinstance(raw_values, dict) or set(raw_values) != expected:
            raise ValueError("Набор параметров бэкапа не соответствует выбранным исправлениям.")
        values = {name: RegistryValue.from_dict(value) if value is not None else None
                  for name, value in raw_values.items()}
        content = None
        if any(repair.kind == "hosts" for repair in repairs):
            hosts = document.get("hosts")
            if not isinstance(hosts, dict) or type(hosts.get("existed")) is not bool:
                raise ValueError("Повреждены метаданные hosts.")
            if hosts["existed"]:
                file = checked_path(path.parent / "hosts.bin")
                if file.is_symlink() or file.stat().st_size > MAX_HOSTS_SIZE:
                    raise ValueError("Недопустимый файл hosts в бэкапе.")
                content = file.read_bytes()
                if hashlib.sha256(content).hexdigest() != hosts.get("sha256"):
                    raise ValueError("Контрольная сумма hosts не совпадает. Откат отменён.")
        return document, repairs, values, content
