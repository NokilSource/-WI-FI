from __future__ import annotations

import os
import stat
from pathlib import Path


def checked_path(value: str | Path) -> Path:
    path = Path(os.path.abspath(value))
    if os.name == "nt" and (str(path).startswith("\\\\") or ":" in str(path)[2:]):
        raise ValueError("Разрешены только обычные локальные пути без ADS/UNC/device namespaces.")
    for item in [*reversed(path.parents), path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"Reparse points/символические ссылки не обрабатываются: {item}")
    # Also expand Windows short (8.3) names before checking protected directories.
    return Path(os.path.realpath(path))
