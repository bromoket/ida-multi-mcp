"""Pure jTrans operand-token normalisation (no IDA imports).

Shared by the IDA-side tokenizer (``ida_mcp/api_similarity.func_tokens``) and
testable standalone. Matches jTrans's IDA-based vocabulary: IDA stack vars ->
``var_xxx`` / ``arg_xxx``, immediates / displacements -> ``CONST``, while the
index ``*scale`` (2/4/8) is kept (a scale is preceded by ``*``).
"""

import re

_VAR = re.compile(r"\bvar_[0-9A-Fa-f]+")
_ARG = re.compile(r"\barg_[0-9A-Fa-f]+")
_HEXH = re.compile(r"\b[0-9A-Fa-f]+h\b")
_0X = re.compile(r"0x[0-9A-Fa-f]+")
_DEC = re.compile(r"(?<![\w*])[0-9]+")


def norm_op(op: str) -> str:
    """Normalize one IDA operand string into a jTrans-vocabulary token."""
    op = op.replace(" ", "")
    op = _VAR.sub("var_xxx", op)
    op = _ARG.sub("arg_xxx", op)
    op = _HEXH.sub("CONST", op)
    op = _0X.sub("CONST", op)
    op = _DEC.sub("CONST", op)
    return op
