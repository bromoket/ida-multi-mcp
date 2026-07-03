"""IDA SDK version compatibility shims.

Provides unified wrappers for APIs that moved between IDA 8.3 and 9.3.
Import from this module instead of from version-specific ``ida_*`` modules.

Known migrations:
- Entry point functions (get_entry_qty, get_entry_ordinal, get_entry,
  get_entry_name): ida_nalt (8.x) → ida_entry (9.0+, exclusive in 9.3+).
- inf_is_64bit: idaapi (8.x) → ida_ida (9.0+).
"""

from __future__ import annotations

import idaapi

# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

_kernel_version = idaapi.get_kernel_version()  # e.g. "9.3"
_major, _minor = (int(x) for x in _kernel_version.split(".")[:2])


# ---------------------------------------------------------------------------
# Entry point API (ida_nalt in 8.x, ida_entry in 9.x)
# ---------------------------------------------------------------------------

try:
    import ida_entry as _entry_mod
    if not hasattr(_entry_mod, "get_entry_qty"):
        raise ImportError
except ImportError:
    import ida_nalt as _entry_mod  # type: ignore[no-redef]


def get_entry_qty() -> int:
    return _entry_mod.get_entry_qty()


def get_entry_ordinal(index: int) -> int:
    return _entry_mod.get_entry_ordinal(index)


def get_entry(ordinal: int) -> int:
    return _entry_mod.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str:
    return _entry_mod.get_entry_name(ordinal)


# ---------------------------------------------------------------------------
# inf_is_64bit (idaapi in 8.x, ida_ida in 9.x)
# ---------------------------------------------------------------------------

try:
    import ida_ida
    if hasattr(ida_ida, "inf_is_64bit"):
        def inf_is_64bit() -> bool:
            return ida_ida.inf_is_64bit()
    else:
        raise AttributeError
except (ImportError, AttributeError):
    def inf_is_64bit() -> bool:  # type: ignore[misc]
        return idaapi.inf_is_64bit()


# ---------------------------------------------------------------------------
# Binary search (ida_bytes.bin_search signature/return drifted in IDA 9.0)
# ---------------------------------------------------------------------------
#
# IDA 9.0 changed ida_bytes.bin_search in two ways that silently broke every
# caller written against the 8.x API:
#   1. The compiled_binpat_vec_t overload now returns a tuple
#      ``(match_ea, index)`` instead of a scalar ``ea_t``. Old code that did
#      ``ea = bin_search(...)`` then ``hex(ea)`` raises TypeError on the tuple.
#   2. The raw bytes+mask overload
#      ``bin_search(start, end, image, mask, len, flags)`` -- though still
#      listed in the docstring -- raises "Wrong number or type of arguments"
#      from the SWIG layer on 9.3. Confirmed empirically on IDA 9.3 SP2.
#
# The user-friendly ``ida_bytes.find_bytes`` (added in 9.0) returns a scalar
# ``ea_t`` (BADADDR on miss) and internally handles both bytes+mask searches
# and wildcard pattern strings (accepting both ``?`` and ``??``), so we route
# through it on 9.0+ and fall back to legacy ``bin_search`` on 8.x. The tuple
# guard in the fallback keeps it correct even if a 9.x build ever reaches it.
#
# See the regression note in api_analysis.find_bytes for the full trace.

import ida_bytes

_IDA_GE_90 = (_major, _minor) >= (9, 0)

DEFAULT_SEARCH_FLAGS = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW


def _unwrap_bin_search(res: object) -> int:
    """bin_search returns (ea, index) on 9.x, scalar ea on 8.x. Normalize."""
    if isinstance(res, tuple):
        return res[0]
    return res  # type: ignore[return-value]


def find_bytes_masked(
    ea: int,
    max_ea: int,
    data: bytes,
    mask: bytes | None,
    flags: int = DEFAULT_SEARCH_FLAGS,
) -> int:
    """Search for raw bytes with an optional per-byte 0xFF/0x00 mask.
    Returns the match address, or idaapi.BADADDR if not found.
    Works across IDA 8.x and 9.x."""
    if _IDA_GE_90:
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)
    return _unwrap_bin_search(
        ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)
    )


def find_pattern(
    ea: int,
    max_ea: int,
    pattern: str,
    flags: int = DEFAULT_SEARCH_FLAGS,
) -> int:
    """Search for a wildcard byte pattern string, e.g. '48 8B ?? ??'.
    Returns the match address, or idaapi.BADADDR if not found.
    Works across IDA 8.x and 9.x."""
    if _IDA_GE_90:
        # find_bytes parses the pattern string itself and accepts both the
        # '?' and '??' wildcard spellings.
        return ida_bytes.find_bytes(pattern, ea, range_end=max_ea, flags=flags)
    binpat = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(binpat, ea, pattern, 16)
    if len(binpat) == 0:  # parse failure: return value is unreliable, length is not
        return idaapi.BADADDR
    return _unwrap_bin_search(ida_bytes.bin_search(ea, max_ea, binpat, flags))
