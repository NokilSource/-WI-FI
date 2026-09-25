from __future__ import annotations

import json
import subprocess
from pathlib import Path


def run_json(platform, script: str, payload: object, timeout: int = 120) -> object:
    """Only developer-owned script text; all external data travels over JSON stdin."""
    preamble = (
        "$ErrorActionPreference='Stop'; "
        "[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false); "
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
        "$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json; "
    )
    executable = Path(platform.system_dir) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    result = subprocess.run(
        [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", preamble + script],
        input=json.dumps(payload, ensure_ascii=False), capture_output=True,
        encoding="utf-8", errors="replace", timeout=timeout, shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise OSError(f"Windows PowerShell: {result.stderr[-2000:]}")
    if len(result.stdout) > 32 * 1024 * 1024:
        raise ValueError("Вывод диагностики превысил безопасный размер.")
    try:
        return json.loads(result.stdout.lstrip("\ufeff"))
    except ValueError as error:
        raise OSError("Windows вернула некорректные данные диагностики.") from error
