"""Just enough lexing for the regex rule sets: blank out comments, find string literals.

Comments (and Python docstrings) are replaced by spaces, newlines kept, so every offset and line
number in the masked text matches the original file. String literals stay in the text, because
rules read their contents (`Cipher.getInstance("AES")`), but their spans are returned so a rule
match that *starts* inside one (`log("call hashlib.md5()")`) can be ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_START = {
    "python": re.compile(r"[#\"']"),
    "java": re.compile(r"/[/*]|[\"']"),
    "go": re.compile(r"/[/*]|[\"'`]"),
}
# A triple-quoted Python string right after one of these is a value, not a docstring.
_EXPRESSION_END = set("([{,=+-*/%<>|&^~\\")


@dataclass(frozen=True)
class Lexed:
    text: str
    strings: list[tuple[int, int]]  # [start, end) of each string literal, quotes included


def lex(text: str, language: str) -> Lexed:
    out = list(text)
    strings: list[tuple[int, int]] = []
    start = _START[language]
    i, n = 0, len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while (m := start.search(text, i)) is not None:
        i = m.start()
        if text.startswith(("#", "//"), i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(i, j)
        elif text[i] == "`":  # Go raw string: no escapes, may span lines
            j = text.find("`", i + 1)
            j = n if j == -1 else j + 1
            strings.append((i, j))
        elif text.startswith(('"""', "'''"), i) and (language == "python" or text[i] == '"'):
            j = _close(text, i + 3, text[i : i + 3], multiline=True)
            if language == "python" and _is_docstring(out, i):
                blank(i, j)
            else:
                strings.append((i, j))
        else:
            j = _close(text, i + 1, text[i], multiline=False)
            strings.append((i, j))
        i = max(j, i + 1)
    return Lexed("".join(out), strings)


def _close(text: str, i: int, quote: str, *, multiline: bool) -> int:
    """Index just past the closing quote (or the end of the line for an unterminated one)."""
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if text.startswith(quote, i):
            return i + len(quote)
        if c == "\n" and not multiline:
            return i
        i += 1
    return n


def _is_docstring(out: list[str], i: int) -> bool:
    """A triple-quoted string that opens its own line and doesn't continue an expression."""
    k = i - 1
    while k >= 0 and out[k] in "rRbBuUfF":  # string prefix
        k -= 1
    while k >= 0 and out[k] in " \t":
        k -= 1
    if k >= 0 and out[k] != "\n":
        return False  # something else on the line before it: `x = """..."""`
    while k >= 0 and out[k].isspace():
        k -= 1
    return k < 0 or out[k] not in _EXPRESSION_END
