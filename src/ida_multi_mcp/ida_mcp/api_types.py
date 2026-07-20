import re
from typing import Annotated, TypedDict

import ida_typeinf
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_frame
import ida_ida
import idaapi

from .rpc import tool
from .sync import idasync, ida_major, tool_timeout
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    parse_decls_ctypes,
    my_modifier_t,
    StructureMember,
    StructureDefinition,
    StructRead,
    StructFieldUpsert,
    StructMemberUpsert,
    TypeEdit,
    read_bytes_bss_safe,
    read_int_bss_safe,
)


# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idasync
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[dict]:
    """Declare types"""
    decls = normalize_list_input(decls)
    results = []

    for decl in decls:
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(decl, flags)

            pretty_messages = "\n".join(messages)
            if errors > 0:
                results.append(
                    {"decl": decl, "error": f"Failed to parse:\n{pretty_messages}"}
                )
            else:
                results.append({"decl": decl, "ok": True})
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idasync
def read_struct(queries: list[StructRead] | StructRead) -> list[dict]:
    """Reads struct type definition and parses actual memory values at the
    given address as instances of that struct type.

    If struct name is not provided, attempts to auto-detect from address.
    Auto-detection only works if IDA already has type information applied
    at that address

    Returns struct layout with actual memory values for each field.
    """

    queries = normalize_dict_list(queries)

    results = []
    for query in queries:
        addr_str = query.get("addr", "")
        struct_name = query.get("struct", "")

        try:
            # Parse address - this is required
            if not addr_str:
                results.append(
                    {
                        "addr": None,
                        "struct": struct_name,
                        "members": None,
                        "error": "Address is required for reading struct fields",
                    }
                )
                continue

            try:
                addr = parse_address(addr_str)
            except Exception:
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Failed to resolve address: {addr_str}",
                    }
                )
                continue

            # Auto-detect struct type from address if not provided
            if not struct_name:
                tif_auto = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif_auto, addr) and tif_auto.is_udt():
                    struct_name = tif_auto.get_type_name()

            if not struct_name:
                results.append(
                    {
                        "addr": addr_str,
                        "struct": None,
                        "members": None,
                        "error": "No struct specified and could not auto-detect from address",
                    }
                )
                continue

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": "Failed to get struct details",
                    }
                )
                continue

            members = []
            for member in udt_data:
                offset = member.begin() // 8
                member_type = member.type._print()
                member_name = member.name
                member_size = member.type.get_size()

                # Read memory value at member address
                member_addr = addr + offset
                try:
                    if member.type.is_ptr():
                        from . import compat
                        is_64bit = compat.inf_is_64bit()
                        ptr_size = 8 if is_64bit else 4
                        value = read_int_bss_safe(member_addr, ptr_size)
                        value_str = f"0x{value:0{ptr_size * 2}X}"
                    elif member_size in (1, 2, 4, 8):
                        value = read_int_bss_safe(member_addr, member_size)
                        value_str = f"0x{value:0{member_size * 2}X} ({value})"
                    else:
                        bytes_data = [
                            f"{byte:02X}"
                            for byte in read_bytes_bss_safe(member_addr, min(member_size, 16))
                        ]
                        value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                except Exception:
                    value_str = "<failed to read>"

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "size": member_size,
                    "value": value_str,
                }

                members.append(member_info)

            results.append(
                {"addr": addr_str, "struct": struct_name, "members": members}
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr_str,
                    "struct": struct_name,
                    "members": None,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def search_structs(
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
) -> list[dict]:
    """Search structs"""
    results = []
    limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()

                    results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": (
                                udt_data.is_union
                                if tif.get_udt_details(udt_data)
                                else False
                            ),
                            "ordinal": ordinal,
                        }
                    )

    return results


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idasync
def set_type(edits: list[TypeEdit] | TypeEdit) -> list[dict]:
    """Apply types (function/global/local/stack)"""

    def parse_addr_type(s: str) -> dict:
        # Support "addr:typename" format (auto-detects kind)
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "ty": parts[1].strip()}
        # Just typename without address (invalid)
        return {"ty": s.strip()}

    edits = normalize_dict_list(edits, parse_addr_type)
    results = []

    for edit in edits:
        try:
            # Auto-detect kind if not provided
            kind = edit.get("kind")
            if not kind:
                if "signature" in edit:
                    kind = "function"
                elif "variable" in edit:
                    kind = "local"
                elif "addr" in edit:
                    # Check if address points to a function
                    try:
                        addr = parse_address(edit["addr"])
                        func = idaapi.get_func(addr)
                        if func and "name" in edit and "ty" in edit:
                            kind = "stack"
                        else:
                            kind = "global"
                    except Exception:
                        kind = "global"
                else:
                    kind = "global"

            if kind == "function":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "Function not found"})
                    continue

                tif = ida_typeinf.tinfo_t(edit["signature"], None, ida_typeinf.PT_SIL)
                if not tif.is_func():
                    results.append({"edit": edit, "error": "Not a function type"})
                    continue

                success = ida_typeinf.apply_tinfo(
                    func.start_ea, tif, ida_typeinf.PT_SIL
                )
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "global":
                ea = idaapi.get_name_ea(idaapi.BADADDR, edit.get("name", ""))
                if ea == idaapi.BADADDR:
                    ea = parse_address(edit["addr"])

                tif = get_type_by_name(edit["ty"])
                success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "local":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "Function not found"})
                    continue

                new_tif = ida_typeinf.tinfo_t(edit["ty"], None, ida_typeinf.PT_SIL)
                modifier = my_modifier_t(edit["variable"], new_tif)
                success = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "stack":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"edit": edit, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(edit["name"])
                if not udm:
                    results.append({"edit": edit, "error": f"{edit['name']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8

                tif = get_type_by_name(edit["ty"])
                success = ida_frame.set_frame_member_type(func, offset, tif)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to set type",
                    }
                )

            else:
                results.append({"edit": edit, "error": f"Unknown kind: {kind}"})

        except Exception as e:
            results.append({"edit": edit, "error": str(e)})

    return results


@tool
@idasync
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[dict]:
    """Infer types"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "hexrays",
                        "confidence": "high",
                    }
                )
                continue

            # Try getting existing type info
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "existing",
                        "confidence": "high",
                    }
                )
                continue

            # Try to guess from size
            size = ida_bytes.get_item_size(ea)
            if size > 0:
                type_guess = {
                    1: "uint8_t",
                    2: "uint16_t",
                    4: "uint32_t",
                    8: "uint64_t",
                }.get(size, f"uint8_t[{size}]")

                results.append(
                    {
                        "addr": addr,
                        "inferred_type": type_guess,
                        "method": "size_based",
                        "confidence": "low",
                    }
                )
                continue

            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                }
            )

        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Enum Upsert — idempotent enum creation/update
# ============================================================================


def _parse_enum_value(raw) -> int:
    """Parse an enum member value from int, str ('0x...', decimal), or None."""
    if raw is None:
        raise ValueError("Enum member value is required")
    if isinstance(raw, int):
        return raw
    s = str(raw).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


@tool
@idasync
def enum_upsert(
    queries: Annotated[list[dict] | dict,
        "Enum upsert: name, members [{name, value}], bitfield (optional bool)"],
) -> list[dict]:
    """Create or extend local enums in an idempotent way. Creates the enum if
    it doesn't exist, then upserts each member: skips if name+value already match,
    reports conflict if name or value collides with a different entry. Never
    destructively replaces existing members."""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        enum_name = str(query.get("name", "") or "").strip()
        members = normalize_dict_list(query.get("members"))
        bitfield = bool(query.get("bitfield", False))

        if not enum_name:
            results.append({"name": enum_name, "error": "Enum name is required"})
            continue
        if not members or members == [{}]:
            results.append({"name": enum_name, "error": "At least one member is required"})
            continue

        try:
            enum_id = idc.get_enum(enum_name)
            created = enum_id == idc.BADADDR
            if created:
                enum_id = idc.add_enum(idc.BADADDR, enum_name, 0)
                if enum_id == idc.BADADDR:
                    results.append({"name": enum_name, "error": f"Failed to create enum: {enum_name}"})
                    continue

            if bool(idc.is_bf(enum_id)) != bitfield and not created:
                results.append({"name": enum_name, "enum_id": hex(enum_id),
                                "error": f"Enum bitfield mismatch for {enum_name}"})
                continue
            idc.set_enum_bf(enum_id, bitfield)

            member_results = []
            created_count = skipped_count = conflict_count = 0

            for member in members:
                member_name = str(member.get("name", "") or "").strip()
                if not member_name:
                    member_results.append({"name": "", "error": "Member name is required"})
                    conflict_count += 1
                    continue
                try:
                    value = _parse_enum_value(member.get("value"))
                except Exception as exc:
                    member_results.append({"name": member_name, "error": str(exc)})
                    conflict_count += 1
                    continue

                existing_mid = idc.get_enum_member_by_name(member_name)
                if existing_mid != idc.BADADDR:
                    existing_enum = idc.get_enum_member_enum(existing_mid)
                    existing_value = idc.get_enum_member_value(existing_mid)
                    if existing_enum == enum_id and existing_value == value:
                        member_results.append({"name": member_name, "value": value, "skipped": True})
                        skipped_count += 1
                        continue
                    member_results.append({
                        "name": member_name, "value": value,
                        "error": f"Name conflict: {member_name} exists with value {existing_value}",
                    })
                    conflict_count += 1
                    continue

                existing_const = idc.get_enum_member(enum_id, value, 0, -1)
                if existing_const != -1:
                    existing_name = idc.get_enum_member_name(existing_const) or ""
                    if existing_name == member_name:
                        member_results.append({"name": member_name, "value": value, "skipped": True})
                        skipped_count += 1
                        continue
                    member_results.append({
                        "name": member_name, "value": value,
                        "error": f"Value conflict: {value} belongs to {existing_name}",
                    })
                    conflict_count += 1
                    continue

                rc = idc.add_enum_member(enum_id, member_name, value, -1)
                if rc != 0:
                    member_results.append({"name": member_name, "value": value,
                                           "error": f"add_enum_member failed: rc={rc}"})
                    conflict_count += 1
                    continue
                member_results.append({"name": member_name, "value": value, "created": True})
                created_count += 1

            result_dict: dict = {
                "name": enum_name, "enum_id": hex(enum_id), "created": created,
                "bitfield": bitfield, "members": member_results,
                "summary": {"created": created_count, "skipped": skipped_count, "conflicts": conflict_count},
            }
            if conflict_count > 0:
                result_dict["error"] = f"{conflict_count} member conflict(s)"
            results.append(result_dict)
        except Exception as exc:
            results.append({"name": enum_name, "error": str(exc)})

    return results


# ============================================================================
# Struct member upsert (gap-fill / retype / rename by offset)
# ============================================================================
#
# Ported from mrexodia/ida-pro-mcp PR #473 (ProN00b), adapted to this fork.
# Uses only the modern ida_typeinf API (tinfo_t/udt_type_data_t); the legacy
# ida_struct module was removed in IDA 9.0.
#
# The point is offset-addressed editing: struct members live at fixed offsets,
# so replacing one never shifts the others. That makes it safe to fill in a
# reverse-engineered layout incrementally -- the usual "field_20 is actually a
# CItemData*" workflow -- without rewriting the whole struct declaration.


class StructFieldUpsertResult(TypedDict, total=False):
    offset: str
    name: str
    old: str
    ty: str
    created: bool
    replaced: bool
    skipped: bool
    error: str


class StructMemberUpsertSummaryResult(TypedDict):
    created: int
    replaced: int
    skipped: int
    conflicts: int


class StructMemberUpsertResult(TypedDict, total=False):
    struct: str
    dry_run: bool
    members: list[StructFieldUpsertResult]
    summary: StructMemberUpsertSummaryResult
    error: str


_SIZE_TO_BTF = {
    1: ida_typeinf.BTF_UINT8,
    2: ida_typeinf.BTF_UINT16,
    4: ida_typeinf.BTF_UINT32,
    8: ida_typeinf.BTF_UINT64,
}


def _parse_offset(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        raise ValueError("Offset is required")
    return int(text, 0)


def _parse_type_tinfo(text: str) -> ida_typeinf.tinfo_t:
    """Resolve a type name or C declaration to a tinfo_t.

    get_type_by_name covers primitives and named struct/enum/typedef/union;
    parse_decl is the fallback for real declarations (pointers, arrays).
    """
    text = str(text).strip().rstrip(";").strip()
    if not text:
        raise ValueError("Empty type")
    try:
        return get_type_by_name(text)
    except Exception:
        pass
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tif, None, f"{text} __mcp_tmp;", ida_typeinf.PT_SIL) is not None:
        return tif
    raise ValueError(f"Could not parse type: {text!r}")


def _build_member_tinfo(field: dict) -> ida_typeinf.tinfo_t:
    """Build the new member type from `size` (int) or `type` (name/decl)."""
    type_text = str(field.get("type") or "").strip()
    raw_size = field.get("size")
    has_size = raw_size not in (None, "", 0)

    if type_text and has_size:
        raise ValueError("Provide either `size` or `type`, not both")
    if type_text:
        return _parse_type_tinfo(type_text)
    if not has_size:
        raise ValueError("Provide `size` or `type` for the new member")

    size = int(raw_size)
    if size not in _SIZE_TO_BTF:
        raise ValueError(f"`size` must be one of 1/2/4/8 (got {size})")
    return ida_typeinf.tinfo_t(_SIZE_TO_BTF[size])


# IDA names synthetic gap members `gap<hex-offset>` (gap4, gap1C, ...). Match
# that shape exactly, NOT a bare "gap" prefix: upstream used
# cur_name.startswith("gap"), which silently reclassified real fields like
# `gap_count` or `gapSize` as fillable gaps and dropped their old_type guard --
# i.e. an unguarded clobber of named work. Confirmed live on IDA 9.4.
_GAP_NAME_RE = re.compile(r"^gap[0-9A-Fa-f]+$")


def _is_gap_like(udm) -> bool:
    """True if this member is a real gap or an IDA-generated gapNN placeholder."""
    return bool(udm.is_gap() or _GAP_NAME_RE.match(udm.name or ""))


def _old_type_matches(old_type: str, udm) -> bool:
    """Does `old_type` identify the member currently at this offset?

    Compares the raw spellings first, then falls back to parsing `old_type` and
    comparing resolved types. That fallback is what makes the tool replayable:
    IDA normalizes spellings on storage (`int` -> `signed __int32`), so after a
    successful upsert a literal re-run of the *same* command would otherwise
    fail its own guard -- breaking retry/resume, which is exactly how an agent
    drives this.
    """
    cur_type_str = udm.type._print()
    if old_type in (udm.name, cur_type_str, str(udm.type)):
        return True
    try:
        parsed = _parse_type_tinfo(old_type)
    except Exception:
        return False
    if parsed._print() == cur_type_str:
        return True
    try:
        return bool(parsed.equals_to(udm.type))
    except Exception:
        return False


def _find_member_overlap(tif: ida_typeinf.tinfo_t, bit_off: int, bit_end: int):
    """First real (non-gap) member overlapping [bit_off, bit_end), else None."""
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return None
    for member in udt:
        if member.is_gap():
            continue
        if member.offset < bit_end and member.offset + member.size > bit_off:
            return member
    return None


def _upsert_struct_member(
    tif: ida_typeinf.tinfo_t, field: dict, dry_run: bool
) -> StructFieldUpsertResult:
    """Replace/insert a single struct member covering `offset` (or a bare hole)."""
    result: StructFieldUpsertResult = {}

    off_bytes = _parse_offset(field.get("offset"))
    result["offset"] = hex(off_bytes)

    name = str(field.get("name", "") or "").strip()
    if not name:
        return {**result, "error": "Member `name` is required"}
    result["name"] = name

    new_tif = _build_member_tinfo(field)
    new_size = new_tif.get_size()
    if new_size in (0, ida_typeinf.BADSIZE):
        return {**result, "error": "Could not determine size of the new member type"}
    result["ty"] = new_tif._print()

    bit_off = off_bytes * 8
    bit_end = bit_off + new_size * 8
    old_type = str(field.get("old_type", "") or "").strip()

    idx, udm = tif.get_udm_by_offset(bit_off)

    # Case 1: bare hole. Real fixed-struct gaps usually have no covering member
    # at all (explicit gapNN members only appear after UI struct-editor edits),
    # so get_udm_by_offset returns nothing. Insert into the hole.
    if idx < 0 or udm is None:
        result["old"] = f"hole at {hex(off_bytes)}"
        overlap = _find_member_overlap(tif, bit_off, bit_end)
        if overlap is not None:
            return {
                **result,
                "error": (
                    f"New member [{hex(off_bytes)}, {hex(off_bytes + new_size)}) overlaps "
                    f"existing member {overlap.name!r} at {hex(overlap.offset // 8)}"
                ),
            }
        if old_type and not old_type.lower().startswith("gap"):
            return {
                **result,
                "error": (
                    f"`old_type` {old_type!r} provided but offset {hex(off_bytes)} is an "
                    "empty hole (no covering member)"
                ),
            }
        if dry_run:
            return {**result, "created": True}
        code = tif.add_udm(name, new_tif, bit_off)
        if code != ida_typeinf.TERR_OK:
            return {**result, "error": f"add_udm failed (code {code})"}
        return {**result, "created": True}

    # Case 2/3: a member covers offset.
    m_begin = udm.offset
    m_end = m_begin + udm.size
    real_is_gap = udm.is_gap()
    cur_name = udm.name
    cur_type_str = udm.type._print()
    # gapNN placeholders (from the UI struct editor) are fillable like gaps.
    gap_like = _is_gap_like(udm)
    result["old"] = (
        f"gap {cur_name or '(anon)'} ({udm.size // 8} bytes) at {hex(m_begin // 8)}"
        if gap_like
        else f"{cur_type_str} {cur_name} at {hex(m_begin // 8)}"
    )

    # The new member must fit entirely inside the covering member, so we never
    # spill into (and clobber) an adjacent field.
    if bit_off < m_begin or bit_end > m_end:
        return {
            **result,
            "error": (
                f"New member [{hex(off_bytes)}, {hex(off_bytes + new_size)}) does not fit "
                f"within covering member [{hex(m_begin // 8)}, {hex(m_end // 8)})"
            ),
        }

    if not gap_like:
        if not old_type:
            return {
                **result,
                "error": (
                    f"`old_type` is required to replace named member {cur_name!r} "
                    f"(type {cur_type_str!r})"
                ),
            }
        if not _old_type_matches(old_type, udm):
            return {
                **result,
                "error": (
                    f"`old_type` {old_type!r} does not match member {cur_name!r} of "
                    f"type {cur_type_str!r} at {hex(off_bytes)}"
                ),
            }
    elif (
        old_type
        and not _old_type_matches(old_type, udm)
        and not old_type.lower().startswith("gap")
    ):
        return {
            **result,
            "error": f"`old_type` {old_type!r} provided but offset {hex(off_bytes)} is a gap",
        }

    # Idempotent: identical named member already present.
    if (
        not gap_like
        and cur_name == name
        and bit_off == m_begin
        and udm.size == new_size * 8
        and cur_type_str == result["ty"]
    ):
        return {**result, "skipped": True}

    outcome_key = "created" if gap_like else "replaced"
    if dry_run:
        return {**result, outcome_key: True}

    # In-place retype+rename when a named member exactly matches the span.
    if not gap_like and bit_off == m_begin and udm.size == new_size * 8:
        code = tif.set_udm_type(idx, new_tif)
        if code != ida_typeinf.TERR_OK:
            return {**result, "error": f"set_udm_type failed (code {code})"}
        code = tif.rename_udm(idx, name)
        if code != ida_typeinf.TERR_OK:
            return {**result, "error": f"rename_udm failed (code {code})"}
        return {**result, outcome_key: True}

    # Otherwise carve the covering member down to a hole and add. Deleting a
    # member never shifts the others (offset-addressed), so this is safe. A
    # real gapNN member must be deleted first; a synthetic gap is empty.
    if not real_is_gap:
        code = tif.del_udm(idx)
        if code != ida_typeinf.TERR_OK:
            return {**result, "error": f"del_udm failed (code {code})"}
    code = tif.add_udm(name, new_tif, bit_off)
    if code != ida_typeinf.TERR_OK:
        return {**result, "error": f"add_udm failed (code {code})"}
    return {**result, outcome_key: True}


@tool
@idasync
@tool_timeout(120.0)
def struct_member_upsert(
    queries: Annotated[
        list[StructMemberUpsert] | StructMemberUpsert,
        "Replace gap/placeholder or named struct members by offset without shifting layout",
    ],
) -> list[StructMemberUpsertResult]:
    """Upsert struct members by offset (gap-fill, retype, rename) idempotently.

    Fills a reverse-engineered struct in incrementally without rewriting the
    whole declaration. Existing members never shift. Replacing a *named* member
    requires old_type as a guard so concurrent work is not silently clobbered;
    gaps need no guard. Use dry_run to validate a batch first.
    """
    queries = normalize_dict_list(queries)
    results: list[StructMemberUpsertResult] = []

    for query in queries:
        struct_name = str(query.get("struct", "") or query.get("name", "") or "").strip()
        members = normalize_dict_list(query.get("members"))
        dry_run = bool(query.get("dry_run", False))

        if not struct_name:
            results.append({"struct": struct_name, "error": "Struct name is required"})
            continue
        if not members or members == [{}]:
            results.append(
                {"struct": struct_name, "error": "At least one member is required"}
            )
            continue

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name) or not tif.is_udt():
                results.append(
                    {"struct": struct_name, "error": f"Struct not found: {struct_name}"}
                )
                continue

            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt) and udt.is_union:
                results.append(
                    {
                        "struct": struct_name,
                        "error": "Unions are not supported (member offsets overlap)",
                    }
                )
                continue

            member_results: list[StructFieldUpsertResult] = []
            created = replaced = skipped = conflicts = 0
            for field in members:
                try:
                    res = _upsert_struct_member(tif, field, dry_run)
                except Exception as exc:
                    res = {
                        "offset": str(field.get("offset", "")),
                        "name": str(field.get("name", "")),
                        "error": str(exc),
                    }
                if res.get("error"):
                    conflicts += 1
                elif res.get("skipped"):
                    skipped += 1
                elif res.get("created"):
                    created += 1
                elif res.get("replaced"):
                    replaced += 1
                member_results.append(res)

            result_dict: StructMemberUpsertResult = {
                "struct": struct_name,
                "dry_run": dry_run,
                "members": member_results,
                "summary": {
                    "created": created,
                    "replaced": replaced,
                    "skipped": skipped,
                    "conflicts": conflicts,
                },
            }
            if conflicts > 0:
                result_dict["error"] = f"{conflicts} member conflict(s)"
            results.append(result_dict)
        except Exception as exc:
            results.append({"struct": struct_name, "error": str(exc)})

    return results
