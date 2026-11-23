"""Path exclusion globs for the directory walks.

The patterns follow the ``--exclude`` option of cdxgen: a glob is anchored at
the scanned path and matched against the forward-slash path of an entry
relative to it, on every operating system. ``*`` and ``?`` stay inside one
path segment, ``**`` stands for any number of segments (including none), and
``[...]`` and ``{a,b}`` work as in a shell. A pattern that names a directory
(``test/**``, or just ``test``) excludes the directory and everything below
it. A leading ``./`` and a trailing ``/`` are ignored. Matching is case
sensitive.
"""

import re
from collections.abc import Iterable

__all__ = ["ExcludeMatcher", "compile_excludes", "relative_posix"]


def _expand_braces(pattern: str) -> list[str]:
    """Expand the first ``{a,b}`` group (recursively) into plain patterns."""
    start = pattern.find("{")
    if start < 0:
        return [pattern]
    depth = 0
    parts: list[str] = []
    last = start + 1
    for i in range(start, len(pattern)):
        ch = pattern[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                parts.append(pattern[last:i])
                head, tail = pattern[:start], pattern[i + 1 :]
                if len(parts) < 2:
                    # A lone "{x}" is literal text, as in a shell.
                    return [head + "{" + parts[0] + "}" + t for t in _expand_braces(tail)]
                return [h for part in parts for h in _expand_braces(head + part + tail)]
        elif ch == "," and depth == 1:
            parts.append(pattern[last:i])
            last = i + 1
    return [pattern]


def _segment_regex(segment: str) -> str:
    out = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "*":
            while i + 1 < len(segment) and segment[i + 1] == "*":
                i += 1
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            end = segment.find("]", i + 2)
            if end < 0:
                out.append(re.escape(ch))
            else:
                body = segment[i + 1 : end]
                negate = body[:1] in ("!", "^")
                if negate:
                    body = body[1:]
                out.append("[" + ("^" if negate else "") + body.replace("\\", "\\\\") + "]")
                i = end
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _glob_regex(pattern: str) -> re.Pattern[str] | None:
    pattern = pattern.strip().replace("\\", "/")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    pattern = pattern.lstrip("/").rstrip("/")
    if not pattern:
        return None
    segments = pattern.split("/")
    regex = ""
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            # Zero or more whole segments; a trailing "**" also covers the
            # directory itself, so "test/**" excludes "test".
            if not last:
                regex += "(?:[^/]+/)*"
            elif regex:
                regex = regex.rstrip("/") + "(?:/.*)?"
            else:
                regex = ".*"
            continue
        regex += _segment_regex(segment) + ("" if last else "/")
    # An entry below a matched directory is excluded with it.
    return re.compile("^" + regex + "(?:/.*)?$")


def relative_posix(path: str, root: str) -> str | None:
    """The forward-slash path of ``path`` below ``root``, or None outside it.

    Both sides are compared as strings after turning backslashes into
    slashes, so a Windows walk (``C:\\scan\\test\\a.dll`` below ``C:\\scan``)
    gives ``test/a.dll`` on any host. A drive letter compares without regard
    to case.
    """
    p = path.replace("\\", "/")
    r = root.replace("\\", "/").rstrip("/")
    if len(r) > 1 and r[1] == ":" and p[:2].lower() == r[:2].lower():
        p = r[:2] + p[2:]
    if p == r:
        return ""
    if r == "":
        return p.lstrip("/")
    if p.startswith(r + "/"):
        return p[len(r) + 1 :]
    return None


class ExcludeMatcher:
    """Compiled exclusion globs, applied to paths below a scan root."""

    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        self.patterns = [p for p in (patterns or []) if isinstance(p, str) and p.strip()]
        self._regexes: list[re.Pattern[str]] = []
        for pattern in self.patterns:
            for expanded in _expand_braces(pattern):
                if regex := _glob_regex(expanded):
                    self._regexes.append(regex)

    def __bool__(self) -> bool:
        return bool(self._regexes)

    def matches(self, relative: str) -> bool:
        """True when a relative forward-slash path is excluded."""
        if not relative:
            return False
        return any(r.match(relative) for r in self._regexes)

    def is_excluded(self, path: str, root: str) -> bool:
        """True when ``path`` lies below ``root`` and a pattern excludes it."""
        if not self._regexes:
            return False
        relative = relative_posix(path, root)
        return relative is not None and self.matches(relative)


def compile_excludes(patterns: "Iterable[str] | ExcludeMatcher | None") -> ExcludeMatcher:
    """Build a matcher from a list of globs; a matcher passes through."""
    if isinstance(patterns, ExcludeMatcher):
        return patterns
    if isinstance(patterns, str):
        patterns = [patterns]
    return ExcludeMatcher(patterns)


def prune_excluded_dirs(
    root: str, current: str, dirs: list[str], matcher: "ExcludeMatcher | None"
) -> None:
    """Drop the excluded directories from an ``os.walk`` directory list in place."""
    if not matcher:
        return
    for d in list(dirs):
        if matcher.is_excluded(f"{current}/{d}", root):
            dirs.remove(d)


def is_excluded_file(root: str, current: str, name: str, matcher: "ExcludeMatcher | None") -> bool:
    """True when the file ``name`` in ``current`` is excluded below ``root``."""
    return bool(matcher) and matcher.is_excluded(f"{current}/{name}", root)  # type: ignore[union-attr]
