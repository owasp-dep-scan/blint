# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0
"""One hardened XML entry point for blint's untrusted-document readers.

Every XML blint parses comes from an untrusted file (a nuspec, an OOXML or
MSIX part, a PE manifest resource). Stdlib ``xml.etree.ElementTree`` does not
resolve external entities, but it does expand internal entities, so a crafted
document can still drive quadratic/exponential entity expansion (the
"billion laughs" class, CWE-776). ``defusedxml`` forbids entity definitions
outright, so routing every reader through this one function keeps the defense
in a single place instead of four readers each remembering to opt in (the
``android`` and ``clickonce`` readers already used defusedxml; this makes the
rest match).

``safe_fromstring`` returns an ordinary ``ElementTree.Element`` — navigation
(``find``/``iter``/iteration) is unchanged — and raises ``ParseError`` for a
malformed document or a ``defusedxml`` exception (a subclass of
``DefusedXmlException``) for a forbidden-entity document. Readers catch
``(ParseError, DefusedXmlException)`` and name the refusal.
"""

from xml.etree.ElementTree import Element, ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring as _defused_fromstring

__all__ = ["DefusedXmlException", "Element", "ParseError", "safe_fromstring"]


def safe_fromstring(data: str | bytes) -> Element:
    """Parse untrusted XML with entity expansion forbidden."""
    return _defused_fromstring(data)
