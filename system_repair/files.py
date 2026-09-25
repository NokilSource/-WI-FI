from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import asdict, replace
from difflib import SequenceMatcher
from pathlib import Path

from system_repair.audit_model import FileEntry, FileScan
from system_repair.journal import ActionJournal
from system_repair.model import Log
from system_repair.paths import checked_path

MAX_FILE = 512 * 1024 * 1024


def entry_for(path: Path) -> FileEntry:
    path = checked_path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Не обычный файл: {path}")
    return FileEntry(str(path), info.st_size, info.st_mtime_ns,
                     getattr(info, "st_birthtime_ns", info.st_ctime_ns), info.st_dev, info.st_ino,
                     bool(getattr(info, "st_file_attributes", 0) & 2))


def same_file(left: FileEntry, right: FileEntry) -> bool:
    return (left.path, left.size, left.modified_ns, left.device, left.inode) == (
        right.path, right.size, right.modified_ns, right.device, right.inode)


def digest(path: Path) -> str:
    path = checked_path(path)
    before = entry_for(path)
    if before.size > MAX_FILE:
        raise ValueError("Файл превышает лимит 512 MiB; используйте специализированное копирование.")
    hashed = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > MAX_FILE:
                raise ValueError("Файл увеличился во время вычисления SHA-256.")
            hashed.update(chunk)
    if not same_file(before, entry_for(path)):
        raise OSError("Файл изменился во время вычисления SHA-256.")
    return hashed.hexdigest()


def copy_verified(source: Path, destination: Path) -> str:
    source, destination = checked_path(source), checked_path(destination)
    before = entry_for(source)
    if before.size > MAX_FILE:
        raise ValueError("Файл превышает лимит копирования 512 MiB.")
    hashed = hashlib.sha256()
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            count = 0
            while chunk := src.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_FILE:
                    raise ValueError("Файл увеличился во время копирования.")
                dst.write(chunk)
                hashed.update(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        if not same_file(before, entry_for(source)) or digest(destination) != hashed.hexdigest():
            raise OSError("Файл изменился во время копирования или копия повреждена.")
    except Exception:
        # A failed copy stays on disk as evidence, never replaces an existing destination.
        raise
    return hashed.hexdigest()


class FileManager:
    def __init__(self, journal: ActionJournal, protected: tuple[Path, ...] = ()):
        self.journal = journal
        self.protected = tuple(checked_path(path) for path in (*protected, journal.root.parent))

    def scan(self, root: str, minutes: int, log: Log) -> FileScan:
        if not 0 <= minutes <= 525600:
            raise ValueError("Интервал: 0 (все файлы) или до 525600 минут.")
        folder = checked_path(root)
        if not folder.is_dir():
            raise ValueError("Выберите существующий локальный каталог.")
        threshold = time.time_ns() - minutes * 60 * 1_000_000_000
        pending, found, errors = [folder], [], []
        visited, started, truncated = 0, time.monotonic(), False
        while pending:
            if visited >= 20000 or len(found) >= 5000 or time.monotonic() - started > 30:
                truncated = True
                break
            current = pending.pop()
            try:
                with os.scandir(current) as listing:
                    for item in listing:
                        visited += 1
                        if visited > 20000 or len(found) >= 5000 or time.monotonic() - started > 30:
                            truncated = True
                            break
                        info = item.stat(follow_symlinks=False)
                        if item.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                            continue
                        path = Path(item.path)
                        if path == self.journal.root.parent or path.is_relative_to(self.journal.root.parent):
                            continue
                        if item.is_dir(follow_symlinks=False):
                            pending.append(path)
                        elif item.is_file(follow_symlinks=False):
                            entry = entry_for(path)
                            if not minutes or max(entry.modified_ns, entry.created_ns) >= threshold:
                                found.append(entry)
            except (OSError, ValueError) as error:
                errors.append(f"{current}: {error}")
        found.sort(key=lambda entry: max(entry.modified_ns, entry.created_ns), reverse=True)
        log("WARN" if truncated or errors else "OK",
            f"Файлы: {len(found)}, просмотрено: {visited}, ошибок: {len(errors)}. "
            + ("Достигнут лимит; результат неполный." if truncated else "Поиск завершён."))
        for error in errors[:50]:
            log("WARN", error)
        return FileScan(tuple(found), visited, tuple(errors), truncated)

    def duplicates(self, path: str, root: str, log: Log) -> FileScan:
        target = checked_path(path)
        original = entry_for(target)
        target_hash = digest(target)
        scan = self.scan(root, 0, log)
        results, errors = [], list(scan.errors)
        started = time.monotonic()
        truncated = scan.truncated
        for entry in scan.entries:
            if time.monotonic() - started > 30:
                truncated = True
                break
            other = Path(entry.path)
            if other == target:
                continue
            similar = SequenceMatcher(None, target.stem.casefold(), other.stem.casefold()).ratio() >= 0.8
            try:
                equal = entry.size == original.size and digest(other) == target_hash
                if equal or similar:
                    results.append(replace(entry, digest=target_hash if equal else "Имя похоже; содержимое отличается"))
            except (OSError, ValueError) as error:
                errors.append(f"{other}: {error}")
        if not same_file(original, entry_for(target)) or digest(target) != target_hash:
            raise OSError("Исходный файл изменился во время поиска дубликатов.")
        log("INFO", "Точное совпадение — SHA-256; похожее имя не доказывает одинаковое содержимое.")
        return FileScan(tuple(results), scan.visited, tuple(errors), truncated)

    def _check_mutable(self, entry: FileEntry) -> Path:
        path = checked_path(entry.path)
        if not same_file(entry, entry_for(path)):
            raise OSError(f"Файл изменился после проверки: {path}")
        if any(path == root or path.is_relative_to(root) for root in self.protected):
            raise PermissionError(f"Системный каталог/бэкапы защищены от карантина: {path}")
        if path.stat().st_nlink != 1:
            raise PermissionError("Файлы с несколькими hard links не перемещаются в карантин.")
        return path

    def act(self, entries: tuple[FileEntry, ...], action: str, destination: str, log: Log) -> tuple[Path, ...]:
        if action not in ("copy", "quarantine") or not entries or len(entries) > 200:
            raise ValueError("Выберите 1–200 файлов и операцию копирования/карантина.")
        if len({entry.path for entry in entries}) != len(entries):
            raise ValueError("Один файл выбран несколько раз.")
        for entry in entries:
            if action == "quarantine":
                self._check_mutable(entry)
            elif not same_file(entry, entry_for(Path(entry.path))):
                raise OSError(f"Файл изменился: {entry.path}")
        folder = checked_path(destination) if action == "copy" else None
        if folder is not None and not folder.is_dir():
            raise ValueError("Выберите существующий каталог назначения.")
        completed = []
        for entry in entries:
            source = checked_path(entry.path)
            try:
                if action == "copy":
                    target = checked_path(folder / source.name)
                    copy_verified(source, target)
                    completed.append(target)
                elif os.name == "nt":
                    from system_repair.windows_files import quarantine_locked

                    completed.append(quarantine_locked(entry, self.journal, self.protected))
                else:
                    source = self._check_mutable(entry)
                    checksum = digest(source)
                    manifest = self.journal.record("quarantine", str(source),
                                                   {"file": asdict(entry), "sha256": checksum})
                    blob = manifest.parent / "content.bin"
                    if copy_verified(source, blob) != checksum:
                        raise OSError("Изменилось содержимое исходного файла; удаление отменено.")
                    self._check_mutable(entry)
                    if digest(source) != checksum:
                        raise OSError("Файл изменился перед карантином.")
                    source.unlink()
                    completed.append(manifest)
                log("OK", f"{action}: {source} → {completed[-1]}")
            except Exception as error:
                log("ERROR", f"Остановлено после {len(completed)} файлов: {error}. "
                    "Уже завершённые операции не отменены. Заблокированные файлы не удаляются принудительно.")
                raise
        return tuple(completed)

    def restore(self, manifest: str, log: Log) -> Path:
        path = checked_path(manifest)
        document = self.journal.load(path, "quarantine")
        target = checked_path(document["target"])
        if any(target == root or target.is_relative_to(root) for root in self.protected):
            raise PermissionError("Восстановление в защищённый системный каталог запрещено.")
        if target.exists() or not target.parent.is_dir():
            raise FileExistsError("Исходный путь занят или родительская папка отсутствует; перезапись запрещена.")
        blob = checked_path(path.parent / "content.bin")
        if digest(blob) != document["payload"]["sha256"]:
            raise ValueError("Контрольная сумма карантина не совпадает.")
        self.journal.record("quarantine-restore", str(target), {"source": str(path)})
        copy_verified(blob, target)
        log("OK", f"Восстановлена копия: {target}. Исходный карантин сохранён; файл не запускался.")
        return target
