"""Unit tests for the pure jTrans operand normalisation (no IDA)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ida_multi_mcp.tools.jtrans_norm import norm_op


def test_stack_vars_to_placeholder():
    assert norm_op("[rsp+var_8]") == "[rsp+var_xxx]"
    assert norm_op("[rbp+arg_0]") == "[rbp+arg_xxx]"
    assert norm_op("[rbp+var_1C]") == "[rbp+var_xxx]"


def test_immediates_to_const():
    assert norm_op("0x10") == "CONST"
    assert norm_op("1234h") == "CONST"
    assert norm_op("[rsp+8]") == "[rsp+CONST]"
    assert norm_op("[rsp+0x20]") == "[rsp+CONST]"


def test_keeps_scale_and_registers():
    # the index *scale (2/4/8) is preceded by '*' and must be kept; displacement CONST-ed
    assert norm_op("[rcx+rdx*4+8]") == "[rcx+rdx*4+CONST]"
    assert norm_op("[rcx+rdx*4]") == "[rcx+rdx*4]"
    # register names with digits are kept
    assert norm_op("r8d") == "r8d"
    assert norm_op("xmm0") == "xmm0"
    assert norm_op("rax") == "rax"
