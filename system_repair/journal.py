from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from system_repair.backup import write_json
from system_repair.paths import checked_path

MAX_MANIFEST = 16 * 1024 * 1024


class ActionJournal:
    """Durable local snapshots for explicitly selected administrative actions."""

    def __init__(self, root: Path, platform):
        self.root = Path(os.path.abspath(root)) / "actions"
        self.platform = platform

    def record(self, kind: str, target: str, payload: dict) -> Path:
        document = {"format": "system-repair-action", "version": 1,
                    "identity": self.platform.identity(), "demo": self.platform.is_demo,
                    "kind": kind, "target": target, "payload": payload,
                    "created": datetime.now(UTC).isoformat()}
        encoded = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_MANIFEST:
            raise ValueError("Резервная копия действия превышает безопасный размер 16 MiB.")
        document = json.loads(encoded)
        root = checked_path(self.root)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder = checked_path(root) / f"{datetime.now(UTC):%Y%m%dT%H%M%S}-{uuid.uuid4().hex}"
        folder.mkdir(mode=0o700)
        path = folder / "action.json"
        write_json(folder / "action.tmp", document)
        (folder / "action.tmp").replace(path)
        if self.load(path, kind) != document:
            raise OSError("Не подтверждена запись резервной копии действия.")
        return path

    def load(self, path: Path, kind: str) -> dict:
        path = checked_path(path)
        if not path.is_file() or path.stat().st_size > MAX_MANIFEST:
            raise ValueError("Недопустимый манифест действия.")
        data = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or data.get("format") != "system-repair-action" or type(data.get("version")) is not int
                or data["version"] != 1 or data.get("kind") != kind):
            raise ValueError("Неверный тип резервной копии действия.")
        if data.get("identity") != self.platform.identity() or data.get("demo") is not self.platform.is_demo:
            raise ValueError("Резервная копия принадлежит другому компьютеру, пользователю или режиму.")
        if not isinstance(data.get("target"), str) or not isinstance(data.get("payload"), dict):
            raise ValueError("Повреждено содержимое резервной копии действия.")
        return data
