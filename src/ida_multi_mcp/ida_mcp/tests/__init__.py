"""ida-multi-mcp in-IDA test package.

These tests run *inside* an IDA instance (via the ``@test`` framework in
``ida_mcp.framework``), against a real loaded binary — distinct from the
top-level ``tests/`` pytest suite, which exercises the multi-instance
router/proxy layer without IDA.

Importing this package registers every test via the ``@test`` decorator.

Usage from the IDA console::

    from ida_multi_mcp.ida_mcp.tests import run_tests
    run_tests()                        # run all registered tests
    run_tests(category="api_sigmaker") # only the sigmaker tests
"""

from ..framework import run_tests

# Import test modules so their @test-decorated functions register on import.
from . import test_api_sigmaker
from . import test_api_types

__all__ = ["run_tests", "test_api_sigmaker", "test_api_types"]
