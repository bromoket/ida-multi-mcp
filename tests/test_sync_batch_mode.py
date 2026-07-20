"""Regression tests for batch-mode handling in ida_mcp/sync.py.

Batch mode (idc.batch(1)) suppresses IDA's modal dialogs so an MCP tool call
can never block the UI waiting for user input. Because it is a global,
process-wide flag, leaking it is catastrophic from the user's point of view:
IDA silently stops showing *every* dialog -- including ones the plugin never
touches, like the 'g' jump-to-address box, the script chooser, and the
save-on-close prompt -- until IDA is restarted.

Two historical defects are pinned here:

  1. Batch save/restore was done per-call from the RPC worker thread. Two
     overlapping requests interleaved as: A saves 0, B saves 1 (A's value),
     A restores 0, B restores 1 -> stuck ON forever.
  2. call_stack.get() blocked on an empty queue when a reentrant @idasync
     popped the entry first, parking the IDA main thread and stranding the
     batch restore (upstream ida-pro-mcp #406).

The real sync module is imported here with IDA modules stubbed, so the actual
production code paths execute.
"""

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PKG = "ida_multi_mcp.ida_mcp"
_SYNC_PATH = (
    Path(__file__).resolve().parents[1]
    / "src" / "ida_multi_mcp" / "ida_mcp" / "sync.py"
)


class _FakeIdc:
    """Models idc.batch(): sets the global flag, returns the previous value."""

    def __init__(self):
        self.value = 0
        self.history = []

    def batch(self, new_value):
        old = self.value
        self.value = int(new_value)
        self.history.append((old, self.value))
        return old


@pytest.fixture
def sync(monkeypatch):
    """Load the real sync.py against IDA stubs.

    sync.py is loaded straight from its file rather than imported normally:
    ida_multi_mcp.ida_mcp.__init__ eagerly pulls in every api_* submodule,
    which needs a real IDA. Stubbing the parent packages keeps that __init__
    from running while still letting sync.py's relative imports resolve.
    """
    fake_idc = _FakeIdc()

    idaapi = MagicMock()
    idaapi.get_kernel_version.return_value = "9.4"
    idaapi.MFF_WRITE = 0x2
    # execute_sync runs the callable inline, like IDA does on the main thread.
    idaapi.execute_sync = lambda fn, flags: fn()

    def _pkg(name):
        m = types.ModuleType(name)
        m.__path__ = []  # mark as a package so submodule imports resolve
        return m

    rpc_stub = types.ModuleType(f"{_PKG}.rpc")
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})

    jsonrpc_stub = types.ModuleType(f"{_PKG}.zeromcp.jsonrpc")
    jsonrpc_stub.RequestCancelledError = type("RequestCancelledError", (Exception,), {})
    jsonrpc_stub.get_current_cancel_event = lambda: None

    for name, mod in {
        "idaapi": idaapi,
        "idc": fake_idc,
        "ida_kernwin": MagicMock(),
        "ida_multi_mcp": _pkg("ida_multi_mcp"),
        _PKG: _pkg(_PKG),
        f"{_PKG}.zeromcp": _pkg(f"{_PKG}.zeromcp"),
        f"{_PKG}.rpc": rpc_stub,
        f"{_PKG}.zeromcp.jsonrpc": jsonrpc_stub,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)

    # No implicit timeout: keeps the profile hook out of these tests.
    monkeypatch.setenv("IDA_MCP_TOOL_TIMEOUT_SEC", "0")

    spec = importlib.util.spec_from_file_location(f"{_PKG}.sync", _SYNC_PATH)
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, f"{_PKG}.sync", mod)
    spec.loader.exec_module(mod)

    mod._fake_idc = fake_idc  # expose for assertions
    yield mod


def test_batch_enabled_during_call_and_restored_after(sync):
    """A tool body runs with dialogs suppressed; the flag is cleared on exit."""
    seen = []

    @sync.idasync
    def tool():
        seen.append(sync._fake_idc.value)
        return "ok"

    assert tool() == "ok"
    assert seen == [1], "batch mode must be ON while the tool body runs"
    assert sync._fake_idc.value == 0, "batch mode must be restored afterwards"


def test_batch_restored_when_tool_raises(sync):
    """An exception in the tool body must not strand batch mode."""

    @sync.idasync
    def boom():
        raise ValueError("kaboom")

    with pytest.raises(ValueError):
        boom()
    assert sync._fake_idc.value == 0


def test_nested_enter_leave_does_not_clobber(sync):
    """Reference counting: only the outermost leave restores the saved value."""
    idc = sync._fake_idc

    sync._enter_batch()
    assert idc.value == 1
    sync._enter_batch()
    assert idc.value == 1
    sync._leave_batch()
    assert idc.value == 1, "inner leave must NOT restore yet"
    sync._leave_batch()
    assert idc.value == 0, "outermost leave restores"


def test_interleaved_calls_do_not_leak_batch_mode(sync):
    """The original bug: A saves 0, B saves 1, A restores 0, B restores 1.

    With per-call save/restore the flag ends stuck at 1. With reference
    counting against a single saved outer value it ends at 0.
    """
    idc = sync._fake_idc

    sync._enter_batch()   # request A arrives
    sync._enter_batch()   # request B overlaps A
    sync._leave_batch()   # A completes first
    sync._leave_batch()   # B completes

    assert idc.value == 0, "overlapping requests must not pin batch mode ON"


def test_reset_batch_mode_recovers_a_stuck_session(sync):
    """ui_unstick's engine: force the flag off even with a corrupted depth."""
    idc = sync._fake_idc

    # Simulate a leak: depth left non-zero and the flag stuck on.
    sync._enter_batch()
    sync._enter_batch()
    assert idc.value == 1

    result = sync.reset_batch_mode()

    assert idc.value == 0
    assert result["ok"] is True
    assert result["previous_depth"] == 2
    # And the counter is clean, so normal calls work again afterwards.
    sync._enter_batch()
    sync._leave_batch()
    assert idc.value == 0


def test_concurrent_workers_do_not_leak_batch_mode(sync):
    """End-to-end proof through the public API, with real threads.

    This is the field scenario: two MCP requests arrive on different worker
    threads and overlap. execute_sync is modelled faithfully -- a lock, since
    IDA serializes work on its main thread.

    Under the old code batch(1) ran on the *worker* thread before
    execute_sync, so B could sample the flag while A still held it:
        A: batch(1)->0 | B: batch(1)->1 | A: batch(0) | B: batch(1)  <- stuck
    Doing the toggle inside execute_sync puts it behind the same lock, so the
    interleave cannot happen.
    """
    import threading
    import time as _time

    idc = sync._fake_idc
    main_thread_lock = threading.Lock()
    real_execute_sync = sync.idaapi.execute_sync

    def serialized_execute_sync(fn, flags):
        with main_thread_lock:  # IDA runs one thing at a time on the main thread
            return fn()

    sync.idaapi.execute_sync = serialized_execute_sync

    a_is_inside_body = threading.Event()

    @sync.idasync
    def slow_tool():
        a_is_inside_body.set()
        # Wait until B has also toggled batch mode. Whether B *can* is the
        # whole question: with the toggle on the worker thread it slips
        # through, with it inside execute_sync it is stuck behind the lock.
        deadline = _time.monotonic() + 1.0
        while len(idc.history) < 2 and _time.monotonic() < deadline:
            _time.sleep(0.01)
        return "A"

    @sync.idasync
    def quick_tool():
        return "B"

    try:
        a = threading.Thread(target=slow_tool)
        b = threading.Thread(target=quick_tool)
        a.start()
        assert a_is_inside_body.wait(timeout=5), "worker A never started"
        b.start()  # B now overlaps A
        a.join(timeout=10)
        b.join(timeout=10)
        assert not a.is_alive() and not b.is_alive(), "workers deadlocked"
    finally:
        sync.idaapi.execute_sync = real_execute_sync

    assert idc.value == 0, (
        "batch mode leaked across overlapping requests -- IDA would show no "
        f"dialogs from here on (flag={idc.value}, history={idc.history})"
    )


def test_reentrant_call_raises_instead_of_blocking(sync):
    """Upstream #406: a nested @idasync must error, never hang the main thread.

    Before the fix the inner call did a blocking call_stack.get() on a queue a
    reentrant caller had already drained, parking the IDA main thread forever.
    If this test hangs rather than fails, the regression is back.
    """

    @sync.idasync
    def inner():
        return "inner"

    @sync.idasync
    def outer():
        return inner()

    with pytest.raises(sync.IDASyncError, match="Call stack is not empty"):
        outer()

    # Critically, the failed reentrant call must still leave the UI usable.
    assert sync._fake_idc.value == 0, "a reentrancy error must not strand batch mode"
