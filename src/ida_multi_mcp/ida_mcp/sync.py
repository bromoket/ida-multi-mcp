import logging
import queue
import functools
import os
import sys
import threading
import time
from enum import IntEnum
import idaapi
import ida_kernwin
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""
    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 15.0


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC



call_stack = queue.LifoQueue()

# ---------------------------------------------------------------------------
# Batch-mode handling
# ---------------------------------------------------------------------------
# Batch mode (idc.batch(1)) suppresses IDA's modal dialogs so a tool call can
# never block the UI waiting for user input. It is a *global, process-wide*
# flag, so it must be handled carefully:
#
#   1. It is toggled on the IDA main thread only (inside execute_sync). IDA's
#      API is not thread-safe, and the previous code called idc.batch() from
#      the RPC worker thread.
#   2. Nesting is reference-counted against a single saved "outer" value. The
#      previous save/restore was per-call, so two overlapping requests would
#      interleave as: A saves 0, B saves 1 (A's value), A restores 0,
#      B restores 1 -- leaving batch mode stuck ON for the rest of the
#      session. That silently disables *every* IDA dialog, including ones the
#      plugin never touches: the "g" jump-to-address box, the script chooser,
#      and the save-on-close prompt.
#
# _batch_depth/_batch_saved are only ever touched on the main thread, which
# execute_sync serializes, so no extra locking is needed.
_batch_depth = 0
_batch_saved = 0


def _enter_batch() -> None:
    """Enable batch mode, remembering the caller's value on the outermost entry."""
    global _batch_depth, _batch_saved
    if _batch_depth == 0:
        _batch_saved = idc.batch(1)
    _batch_depth += 1


def _leave_batch() -> None:
    """Restore the original batch value once the outermost call unwinds."""
    global _batch_depth
    if _batch_depth > 0:
        _batch_depth -= 1
    if _batch_depth == 0:
        idc.batch(_batch_saved)


def reset_batch_mode() -> dict:
    """Force batch mode off and clear the nesting counter.

    Recovery hatch: if batch mode ever leaks (a hard crash on the main thread
    between _enter_batch and _leave_batch), IDA stops showing dialogs until
    restart. This restores it without losing the session.
    """
    global _batch_depth, _batch_saved
    previous_depth = _batch_depth
    _batch_depth = 0
    _batch_saved = 0
    # idc.batch() returns the value it replaced -- report it, since that is the
    # number that actually says whether IDA was muted. A previous_batch of 1
    # with previous_depth 0 means a genuine leak (dialogs were dead and our
    # counter had already unwound); depth > 0 means a call was still in flight.
    previous_batch = idc.batch(0)
    # Native cancellation is sticky too, and a stranded flag makes every SDK
    # call bail instantly -- clear it as part of getting unstuck.
    ida_kernwin.clr_cancelled()
    return {
        "ok": True,
        "previous_depth": previous_depth,
        "previous_batch": int(previous_batch),
        "was_stuck": bool(previous_batch) and previous_depth == 0,
        "batch": 0,
    }


def _sync_wrapper(ff):
    """Call a function ff with a specific IDA safety_mode."""

    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            # Non-blocking: a reentrant @idasync invoked synchronously inside
            # another ff() may have already popped this entry. A blocking get()
            # here would park the IDA main thread on an empty queue forever,
            # which also strands the batch-mode restore below (upstream #406).
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<unknown>"
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        # Toggle batch mode here: this runs on the IDA main thread.
        _enter_batch()
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            _leave_batch()
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass

    idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res

def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None):
    """Run ff on the IDA main thread under batch mode, with timeout/cancel support.

    Batch mode is entered/left inside _sync_wrapper (on the main thread), not
    here -- see the batch-mode notes above.
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:
        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            # Native cancellation. The setprofile hook below only runs between
            # *Python* bytecodes, so it cannot preempt a pure-C SDK call --
            # ida_bytes.find_bytes on a large IDB holds the main thread well
            # past the deadline, and every queued tool call times out behind
            # it. Many SDK calls poll user_cancelled() and bail with BADADDR /
            # MERR_CANCELED within a poll cycle (ida_search.find_*,
            # find_bytes/bin_search, decompile*, build_strlist, auto_wait), so
            # firing set_cancelled() at the deadline frees the main thread.
            # set_cancelled() is documented THREAD_SAFE, hence the Timer.
            # Ported from mrexodia/ida-pro-mcp 55533c47 (issue #235).
            ida_kernwin.clr_cancelled()  # drop any stale flag
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            if deadline is not None:
                def _fire_native_cancel():
                    cancel_fired_at[0] = time.monotonic()
                    ida_kernwin.set_cancelled()

                native_timer = threading.Timer(timeout, _fire_native_cancel)
                native_timer.daemon = True
                native_timer.start()

            def profilefunc(frame, event, arg):
                # Check request-level cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                # If the native cancel just fired, give the tool a short grace
                # window to format a partial response instead of racing the
                # IDASyncError. Beyond that we still raise, to bound latency.
                fired_at = cancel_fired_at[0]
                if fired_at is not None and time.monotonic() < fired_at + 5.0:
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)
                if native_timer is not None:
                    native_timer.cancel()
                # The cancelled flag is sticky: without an unconditional
                # clear, every later user_cancelled() returns True forever and
                # each subsequent tool aborts instantly.
                ida_kernwin.clr_cancelled()

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff)
    return _sync_wrapper(ff)


def idasync(f):
    """Run the function on the IDA main thread in write mode.
    
    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


# Backwards compatibility aliases
idaread = idasync
idawrite = idasync


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """
    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func
    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)
    
    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets
    
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
