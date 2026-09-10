"""OWASP blint — binary linter, disassembler and SBOM generator.

The supported Python surface is deliberately minimal: ``analyze`` plus the
result and error types needed to call it. Everything else is internal and
may change; ``blint.lib.*`` modules are not a compatibility promise.
"""

from blint.api import (
    AnalysisFailedError,
    AnalysisResult,
    BlintApiError,
    NotABinaryError,
    analyze,
)

__all__ = [
    "AnalysisFailedError",
    "AnalysisResult",
    "BlintApiError",
    "NotABinaryError",
    "analyze",
]
