"""Tests for struct_member_upsert (api_types).

Ported from mrexodia/ida-pro-mcp PR #473 (ProN00b).

These run *inside* IDA against the real type system, which is the only place
the tinfo_t/udt semantics under test actually exist. Each test builds its own
deterministic scratch struct via declare_type and removes it in a finally, so
they are binary-agnostic and leak nothing into the IDB.

The behaviours pinned here are the ones that make offset-addressed editing
safe: filling a hole must not shift neighbours, replacing a named member must
require an old_type guard, an identical upsert must be a no-op, an oversized
member must be refused rather than silently clobbering the next field, and
dry_run must not mutate.
"""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_error,
)
from ..api_types import (
    declare_type,
    struct_member_upsert,
)


# ---------------------------------------------------------------------------
# struct_member_upsert
#
# Binary-agnostic: every test builds its own deterministic scratch struct with
# declare_type and removes it in a finally, so nothing leaks into the IDB.
# ---------------------------------------------------------------------------


def _delete_type(name: str) -> None:
    """Best-effort removal of a local type so tests stay self-cleaning."""
    import ida_typeinf

    try:
        ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE)
    except Exception:
        pass


def _reset_struct(name: str, body: str) -> None:
    """(Re)declare a scratch struct from a fresh slate; skip if it won't parse."""
    _delete_type(name)
    result = declare_type(f"struct {name} {{ {body} }};")
    if result and result[0].get("error"):
        skip_test(f"failed to declare {name}: {result[0]['error']}")


def _members_by_name(struct_name: str) -> dict:
    info = type_inspect({"name": struct_name, "include_members": True})[0]
    assert info.get("exists") is True
    return info, {m["name"]: m for m in (info.get("members") or [])}


@test()
def test_struct_member_upsert_fills_bare_hole():
    """A bare hole (no covering member) is a valid insert target, without shifting neighbors."""
    name = "__TestUpsertHole__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b; unsigned __int64 c;")

        # Shrink b (u64 @ 0x8) -> u32, leaving a 4-byte bare hole at 0xC.
        shrink = struct_member_upsert(
            {
                "struct": name,
                "members": [
                    {"offset": "0x8", "name": "b_lo", "old_type": "unsigned __int64", "size": 4}
                ],
            }
        )
        assert_is_list(shrink, min_length=1)
        assert "error" not in shrink[0]
        assert shrink[0]["summary"]["replaced"] == 1

        # Fill the bare hole at 0xC (get_udm_by_offset returns nothing here).
        fill = struct_member_upsert(
            {"struct": name, "members": [{"offset": "0xC", "name": "b_hi", "size": 4}]}
        )
        assert_is_list(fill, min_length=1)
        assert "error" not in fill[0]
        assert fill[0]["summary"]["created"] == 1
        assert fill[0]["members"][0].get("created") is True

        info, members = _members_by_name(name)
        assert members["b_lo"]["offset"] == "0x8" and members["b_lo"]["size"] == 4
        assert members["b_hi"]["offset"] == "0xc" and members["b_hi"]["size"] == 4
        # Neighbor unshifted, overall size preserved.
        assert members["c"]["offset"] == "0x10"
        assert info["size"] == 24
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_fills_gap_member_without_old_type():
    """A `gapNN` placeholder member is fillable with old_type omitted."""
    name = "__TestUpsertGap__"
    try:
        _reset_struct(name, "unsigned __int64 a; _BYTE gap8[8]; unsigned __int64 c;")
        res = struct_member_upsert(
            {"struct": name, "members": [{"offset": "0x8", "name": "g_lo", "size": 4}]}
        )
        assert_is_list(res, min_length=1)
        assert "error" not in res[0]
        assert res[0]["summary"]["created"] == 1
        assert res[0]["members"][0].get("created") is True

        _info, members = _members_by_name(name)
        assert members["g_lo"]["offset"] == "0x8" and members["g_lo"]["size"] == 4
        assert members["c"]["offset"] == "0x10"
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_retypes_named_member_in_place():
    """Same-size retype+rename of a named member keeps its offset (uses the C-decl `type` path)."""
    name = "__TestUpsertRetype__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b; unsigned __int64 c;")
        res = struct_member_upsert(
            {
                "struct": name,
                "members": [
                    {"offset": "0x8", "name": "b_ptr", "old_type": "unsigned __int64", "type": "void *"}
                ],
            }
        )
        assert_is_list(res, min_length=1)
        assert "error" not in res[0]
        assert res[0]["summary"]["replaced"] == 1

        _info, members = _members_by_name(name)
        assert "b_ptr" in members and members["b_ptr"]["offset"] == "0x8"
        assert members["c"]["offset"] == "0x10"
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_is_idempotent():
    """Re-applying an identical member is reported as skipped."""
    name = "__TestUpsertIdem__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b;")
        edit = {"offset": "0x8", "name": "b_ai", "old_type": "unsigned __int64", "size": 8}

        first = struct_member_upsert({"struct": name, "members": [dict(edit)]})
        assert_is_list(first, min_length=1)
        assert first[0]["summary"]["replaced"] == 1

        second = struct_member_upsert({"struct": name, "members": [dict(edit)]})
        assert_is_list(second, min_length=1)
        assert "error" not in second[0]
        assert second[0]["summary"]["skipped"] == 1
        assert second[0]["members"][0].get("skipped") is True
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_guards_named_members():
    """Missing or mismatched old_type on a named member is a conflict, not a clobber."""
    name = "__TestUpsertGuard__"
    try:
        _reset_struct(name, "unsigned __int64 a; unsigned __int64 b; unsigned __int64 c;")
        res = struct_member_upsert(
            {
                "struct": name,
                "members": [
                    {"offset": "0x10", "name": "c_wrong", "old_type": "uint32_t", "size": 8},
                    {"offset": "0x10", "name": "c_missing", "size": 8},
                ],
            }
        )
        assert_is_list(res, min_length=1)
        assert res[0]["summary"]["conflicts"] == 2
        assert "error" in res[0]
        errors = " ".join((m.get("error") or "") for m in res[0]["members"]).lower()
        assert "old_type" in errors

        # The named member must be untouched by the rejected edits.
        _info, members = _members_by_name(name)
        assert "c" in members and members["c"]["offset"] == "0x10"
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_rejects_overflow():
    """A member that would spill past its covering member is rejected."""
    name = "__TestUpsertOverflow__"
    try:
        _reset_struct(name, "unsigned __int64 a; _BYTE gap8[8]; unsigned __int64 c;")
        # gap8 spans [0x8, 0x10); an 8-byte member at 0xC would run to 0x14.
        res = struct_member_upsert(
            {"struct": name, "members": [{"offset": "0xC", "name": "toobig", "size": 8}]}
        )
        assert_is_list(res, min_length=1)
        assert res[0]["summary"]["conflicts"] == 1
        assert_error(res[0]["members"][0], contains="fit")
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_dry_run_does_not_mutate():
    """dry_run validates (reports would-be outcome) without changing the struct."""
    name = "__TestUpsertDryRun__"
    try:
        _reset_struct(name, "unsigned __int64 a; _BYTE gap8[8]; unsigned __int64 c;")
        before, _ = _members_by_name(name)

        res = struct_member_upsert(
            {
                "struct": name,
                "dry_run": True,
                "members": [{"offset": "0x8", "name": "g_lo", "size": 4}],
            }
        )
        assert_is_list(res, min_length=1)
        assert res[0]["dry_run"] is True
        assert res[0]["summary"]["created"] == 1

        after, _ = _members_by_name(name)
        assert before["members"] == after["members"]
        assert before["size"] == after["size"]
    finally:
        _delete_type(name)


@test()
def test_struct_member_upsert_struct_not_found():
    """struct_member_upsert reports a missing-struct error."""
    res = struct_member_upsert(
        {"struct": "__NoSuchStruct12345__", "members": [{"offset": 0, "name": "x", "size": 4}]}
    )
    assert_is_list(res, min_length=1)
    assert_error(res[0], contains="not found")
class StructFieldUpsert(TypedDict):
    """Single struct member replace/insert operation.

    Targets the member currently covering `offset` (a gap or a named field) and
    replaces it with a new member. Provide exactly one of `size` or `type`.
    """

    offset: Annotated[str | int, "Byte offset of the member within the struct (hex or int)"]
    name: Annotated[str, "New member name"]
    old_type: NotRequired[
        Annotated[
            str,
            "Type or member name that must currently cover the offset. Required when "
            "the target is a named member (guards against clobbering); optional when "
            "the target is a gap.",
        ]
    ]
    size: NotRequired[
        Annotated[int, "Integer member size: 1/2/4/8 -> uint8/16/32/64 (use size OR type)"]
    ]
    type: NotRequired[
        Annotated[str, "C type name or declaration for the new member (use size OR type)"]
    ]


class StructMemberUpsert(TypedDict):
    """Upsert struct members by offset without shifting existing fields."""

    struct: Annotated[str, "Struct type name"]
    members: Annotated[
        list[StructFieldUpsert] | StructFieldUpsert, "Members to upsert"
    ]
    dry_run: NotRequired[
        Annotated[bool, "Validate only (check offsets/old_type/new type); no changes"]
    ]


