"""A small, dependency-free PHP lexer.

wp-hook-guard does not need a full PHP parser -- it needs to reliably find
function calls, string literals, and matching brace/paren spans while *ignoring*
anything that lives inside comments, strings, or inline HTML.  A naive regex over
raw source produces false positives (a hook name mentioned in a comment, a code
snippet inside a string).  This lexer solves that: it turns source into a flat
list of tokens where strings and comments are their own token kinds, so the
analyzer can safely reason about real code only.

It is intentionally lightweight and forgiving -- it never raises on malformed
input, it just does its best.  See README "Limitations".
"""

from __future__ import annotations

import re

# --- Token kinds -----------------------------------------------------------
# ident        bareword / function name / keyword (may carry a namespace: \Foo\bar)
# var          $variable
# str          '...' or "..." or <<<HEREDOC or `...`
# num          numeric literal
# punct        operator or punctuation, incl. ( ) { } [ ] , ; -> :: => etc.
# comment      // ... , # ... , /* ... */
# ws           whitespace run
# inline_html  text outside <?php ... ?>
# open_tag     <?php / <?= / <?
# close_tag    ?>

_SIGNIFICANT_SKIP = {"ws", "comment", "inline_html", "open_tag", "close_tag"}

RE_WS = re.compile(r"[ \t\r\n]+")
RE_VAR = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
RE_IDENT = re.compile(r"\\?[A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*")
RE_NUM = re.compile(r"0[xX][0-9a-fA-F]+|0[bB][01]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+")
RE_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1\r?\n")

_PUNCT3 = {"===", "!==", "<=>", "**=", "...", "?->", "<<=", ">>=", "&&=", "||=", "??="}
_PUNCT2 = {
    "->", "=>", "::", "==", "!=", "<>", "<=", ">=", "&&", "||", "++", "--",
    "+=", "-=", "*=", "/=", ".=", "%=", "&=", "|=", "^=", "<<", ">>", "??",
    "**", "?:",
}


class Token:
    """A single lexical token.  ``value`` holds the decoded content of a string."""

    __slots__ = ("kind", "text", "pos", "line", "value")

    def __init__(self, kind, text, pos, line, value=None):
        self.kind = kind
        self.text = text
        self.pos = pos
        self.line = line
        self.value = value

    def __repr__(self):  # pragma: no cover - debugging aid
        v = "" if self.value is None else " value=%r" % self.value
        return "Token(%s, %r, line=%d%s)" % (self.kind, self.text, self.line, v)


def _parse_quoted(src, i, quote):
    """Consume a single/double-quote/backtick string starting at ``i``.

    Returns (raw_text, decoded_value, end_index).  Handles backslash escapes so a
    closing quote inside the string is not mistaken for the terminator.
    """
    n = len(src)
    j = i + 1
    buf = []
    while j < n:
        c = src[j]
        if c == "\\" and j + 1 < n:
            buf.append(src[j + 1])
            j += 2
            continue
        if c == quote:
            j += 1
            break
        buf.append(c)
        j += 1
    return src[i:j], "".join(buf), j


def _parse_heredoc(src, i, m):
    """Consume a heredoc/nowdoc beginning at ``i`` (``m`` is the opener match)."""
    n = len(src)
    label = m.group(2)
    content_start = i + m.end()
    close_re = re.compile(r"\n[ \t]*" + re.escape(label) + r"\b")
    mm = close_re.search(src, max(content_start - 1, 0))
    if mm:
        end = mm.end()
        value = src[content_start:mm.start()]
    else:
        end = n
        value = src[content_start:n]
    return src[i:end], value, end


def tokenize(src):
    """Lex PHP ``src`` into a list of :class:`Token`.  Never raises."""
    tokens = []
    n = len(src)
    i = 0
    line = 1
    # If the file contains no PHP open tag at all, treat the whole thing as PHP
    # (covers include-fragments that omit <?php).  Otherwise honour tags.
    in_php = "<?" not in src

    def emit(kind, text, pos, ln, value=None):
        tokens.append(Token(kind, text, pos, ln, value))

    while i < n:
        if not in_php:
            j = src.find("<?", i)
            if j == -1:
                text = src[i:]
                emit("inline_html", text, i, line)
                line += text.count("\n")
                break
            if j > i:
                text = src[i:j]
                emit("inline_html", text, i, line)
                line += text.count("\n")
            low = src[j:j + 5].lower()
            if low == "<?php":
                op = src[j:j + 5]
            elif src[j:j + 3] == "<?=":
                op = src[j:j + 3]
            else:
                op = src[j:j + 2]
            emit("open_tag", op, j, line)
            i = j + len(op)
            in_php = True
            continue

        c = src[i]

        # Close tag -> back to inline HTML (PHP swallows one trailing newline).
        if c == "?" and i + 1 < n and src[i + 1] == ">":
            emit("close_tag", "?>", i, line)
            i += 2
            in_php = False
            if i < n and src[i] == "\n":
                i += 1
                line += 1
            elif i + 1 < n and src[i] == "\r" and src[i + 1] == "\n":
                i += 2
                line += 1
            continue

        # Whitespace
        m = RE_WS.match(src, i)
        if m:
            text = m.group(0)
            emit("ws", text, i, line)
            line += text.count("\n")
            i = m.end()
            continue

        # Line comments: //...  and #...  (but #[ is a PHP 8 attribute)
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            emit("comment", src[i:j], i, line)
            i = j
            continue
        if c == "#" and not (i + 1 < n and src[i + 1] == "["):
            j = src.find("\n", i)
            j = n if j == -1 else j
            emit("comment", src[i:j], i, line)
            i = j
            continue

        # Block comment
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            text = src[i:j]
            emit("comment", text, i, line)
            line += text.count("\n")
            i = j
            continue

        # Strings
        if c == "'" or c == '"' or c == "`":
            text, value, j = _parse_quoted(src, i, c)
            emit("str", text, i, line, value)
            line += text.count("\n")
            i = j
            continue

        # Heredoc / nowdoc
        if c == "<" and src[i:i + 3] == "<<<":
            m = RE_HEREDOC.match(src, i)
            if m:
                text, value, j = _parse_heredoc(src, i, m)
                emit("str", text, i, line, value)
                line += text.count("\n")
                i = j
                continue

        # Variable
        m = RE_VAR.match(src, i)
        if m:
            emit("var", m.group(0), i, line)
            i = m.end()
            continue

        # Identifier (possibly namespaced, possibly leading backslash)
        if c.isalpha() or c == "_" or c == "\\":
            m = RE_IDENT.match(src, i)
            if m:
                emit("ident", m.group(0), i, line)
                i = m.end()
                continue

        # Number
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = RE_NUM.match(src, i)
            if m:
                emit("num", m.group(0), i, line)
                i = m.end()
                continue

        # Punctuation / operators (longest match first)
        three = src[i:i + 3]
        if three in _PUNCT3:
            emit("punct", three, i, line)
            i += 3
            continue
        two = src[i:i + 2]
        if two in _PUNCT2:
            emit("punct", two, i, line)
            i += 2
            continue
        emit("punct", c, i, line)
        i += 1

    return tokens


def significant(tokens):
    """Return only tokens that carry code meaning (no ws/comments/HTML/tags)."""
    return [t for t in tokens if t.kind not in _SIGNIFICANT_SKIP]


# --- Span helpers operating on a *significant* token list ------------------

def match_group(sig, i, open_ch, close_ch):
    """Given ``sig[i]`` == ``open_ch`` punct, return index of the matching close.

    Only the requested delimiter pair is counted; because strings/comments are
    separate token kinds, braces inside them never appear as puncts here.
    """
    depth = 0
    j = i
    n = len(sig)
    while j < n:
        t = sig[j]
        if t.kind == "punct":
            if t.text == open_ch:
                depth += 1
            elif t.text == close_ch:
                depth -= 1
                if depth == 0:
                    return j
        j += 1
    return n - 1


def match_paren(sig, i):
    return match_group(sig, i, "(", ")")


def match_brace(sig, i):
    return match_group(sig, i, "{", "}")


def split_top_commas(sig, lo, hi):
    """Split ``sig[lo:hi]`` on top-level commas.  Returns list of (lo, hi) ranges."""
    parts = []
    depth = 0
    start = lo
    for j in range(lo, hi):
        t = sig[j]
        if t.kind == "punct":
            if t.text in ("(", "[", "{"):
                depth += 1
            elif t.text in (")", "]", "}"):
                depth -= 1
            elif t.text == "," and depth == 0:
                parts.append((start, j))
                start = j + 1
    parts.append((start, hi))
    return [(a, b) for (a, b) in parts if a < b]
