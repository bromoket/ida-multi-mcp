"""Cross-platform file locking for ida-multi-mcp.

Uses fcntl.flock on Unix and msvcrt.locking on Windows for cross-process
exclusion, plus a per-path in-process lock so threads of the same process
serialize cheaply instead of spinning on the OS lock.
"""

import os
import sys
import threading
import time


class FileLockTimeout(Exception):
    """Raised when file lock acquisition times out."""
    pass


# Per-path in-process locks. The OS file lock serializes across processes;
# this serializes threads within one process without busy-waiting on the
# file lock (and avoids a same-process thread spinning until timeout).
_PATH_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}


def _get_path_lock(lock_path: str) -> threading.Lock:
    key = os.path.abspath(lock_path)
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


class FileLock:
    """Cross-platform file lock using context manager.

    Usage:
        with FileLock("path/to/file.lock"):
            # exclusive access to the resource
    """

    def __init__(self, lock_path: str, timeout: float = 5.0):
        """
        Args:
            lock_path: Path to the lock file
            timeout: Maximum seconds to wait for lock (default 5.0)
        """
        self.lock_path = lock_path
        self.timeout = timeout
        self._fd: int | None = None
        self._thread_lock = _get_path_lock(lock_path)
        self._thread_locked = False

    def acquire(self) -> None:
        """Acquire the lock (in-process first, then cross-process)."""
        # Serialize same-process threads up front so they don't spin on the
        # OS file lock. A nested acquire on the same path fails fast here
        # rather than self-deadlocking on the file lock.
        if not self._thread_lock.acquire(timeout=self.timeout):
            raise FileLockTimeout(
                f"Could not acquire in-process lock on {self.lock_path} "
                f"within {self.timeout}s"
            )
        self._thread_locked = True

        try:
            os.makedirs(os.path.dirname(self.lock_path) or ".", exist_ok=True)
            self._fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR)

            if sys.platform == "win32":
                self._acquire_windows()
            else:
                self._acquire_unix()
        except BaseException:
            # Release the in-process lock if the OS lock could not be taken.
            self._thread_lock.release()
            self._thread_locked = False
            raise

    def release(self) -> None:
        """Release the lock (cross-process first, then in-process)."""
        try:
            if self._fd is not None:
                if sys.platform == "win32":
                    self._release_windows()
                else:
                    self._release_unix()
                os.close(self._fd)
                self._fd = None
        finally:
            if self._thread_locked:
                self._thread_lock.release()
                self._thread_locked = False

    def _acquire_unix(self) -> None:
        import fcntl
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise FileLockTimeout(
                        f"Could not acquire lock on {self.lock_path} "
                        f"within {self.timeout}s"
                    )
                time.sleep(0.05)

    def _release_unix(self) -> None:
        import fcntl
        fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _acquire_windows(self) -> None:
        import msvcrt
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                return
            except (OSError, IOError):
                if time.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise FileLockTimeout(
                        f"Could not acquire lock on {self.lock_path} "
                        f"within {self.timeout}s"
                    )
                time.sleep(0.05)

    def _release_windows(self) -> None:
        import msvcrt
        try:
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except (OSError, IOError):
            pass  # Already unlocked

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()
