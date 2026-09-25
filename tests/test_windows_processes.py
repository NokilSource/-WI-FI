import os
import subprocess
import sys
from dataclasses import replace

import psutil
import pytest

from system_repair.model import ProcessInfo
from system_repair.windows import WindowsPlatform

pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows process handles")


@pytest.fixture
def native():
    backend = WindowsPlatform()
    if not backend.is_admin():
        pytest.skip("Native termination checks require an elevated test runner")
    return backend


@pytest.fixture
def owned_child():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        process = psutil.Process(child.pid)
        info = ProcessInfo(child.pid, process.name(), process.exe(), process.username(), process.create_time())
        yield child, info
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def test_native_termination_rejects_stale_creation_time_and_wrong_path(native, owned_child):
    child, info = owned_child
    with pytest.raises(RuntimeError, match="PID"):
        native.terminate_process(replace(info, created=info.created - 5))
    assert child.poll() is None
    with pytest.raises(RuntimeError, match="PID"):
        native.terminate_process(replace(info, path=info.path + ".different"))
    assert child.poll() is None


def test_critical_flag_on_owned_child_blocks_termination(native, owned_child, monkeypatch):
    child, info = owned_child

    def critical(_handle, output):
        output._obj.value = True
        return True

    monkeypatch.setattr(native.kernel, "IsProcessCritical", critical)
    with pytest.raises(PermissionError, match="критический"):
        native.terminate_process(info)
    assert child.poll() is None


def test_failed_criticality_query_is_fail_closed(native, owned_child, monkeypatch):
    child, info = owned_child
    monkeypatch.setattr(native.kernel, "IsProcessCritical", lambda *args: False)
    with pytest.raises(OSError):
        native.terminate_process(info)
    assert child.poll() is None


def test_native_termination_refuses_self_and_parent_before_opening_handle(native, monkeypatch):
    def unexpected_open(*args):
        raise AssertionError("Protected process handle must not be opened for termination")

    monkeypatch.setattr(native.kernel, "OpenProcess", unexpected_open)
    for pid in (os.getpid(), os.getppid(), 4):
        with pytest.raises(PermissionError):
            native.terminate_process(ProcessInfo(pid, "test.exe", sys.executable, "test", 1))


def test_native_termination_closes_only_the_owned_test_child(native, owned_child):
    child, info = owned_child
    native.terminate_process(info)
    assert child.wait(timeout=5) == 1
