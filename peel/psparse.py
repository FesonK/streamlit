"""
psparse.py — a small PowerShell parser + deobfuscator in pure Python.

Why not regex: obfuscation lives in the *structure* of the code
('Down'+'load', "{1}{0}" -f ..., [char[]](73,69,88) -join '', $ShellId[1]...).
So we tokenize, build a syntax tree for the expression grammar, constant-fold
every sub-expression we can evaluate safely (nothing is ever executed), and
rewrite only those spans of the source. Anything we don't understand is left
exactly as written.

    peel(text)  -> PeelResult(text=deobfuscated, inner=[decoded layers], ...)
    features(text, result) -> dict of obfuscation features (Revoke-Obfuscation style)

Covers the obfuscation-relevant subset of PowerShell: strings (all quote
styles, here-strings, escapes, $var/$() expansion), concatenation, -f, -join,
-split, -replace, -bxor, ranges, casts ([char], [char[]], [string], [int]...),
indexing, string methods (.Replace, .ToLower, .Substring...), static calls
([Convert]::FromBase64String, [Text.Encoding]::Unicode.GetString,
[string]::Join, [scriptblock]::Create...), dynamic invocation (&( ), .( )),
dynamic member names (.('Down'+'loadString').Invoke()), backticks, random case,
aliases, and variables assigned once from constant expressions.

A full parser would use PowerShell's own AST
([System.Management.Automation.Language.Parser]::ParseInput); this one keeps
the app pure-Python so it runs anywhere.
"""
from __future__ import annotations

import base64
import difflib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

# ───────────────────────── tokens ─────────────────────────
ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}

BIN_PREC = {
    "or": 1, "and": 1, "xor": 1,
    "join": 2, "split": 2, "replace": 2, "ireplace": 2, "creplace": 2, "eq": 2, "ne": 2, "gt": 2, "ge": 2,
    "lt": 2, "le": 2, "like": 2, "notlike": 2, "match": 2, "notmatch": 2, "contains": 2, "notcontains": 2,
    "in": 2, "notin": 2, "is": 2, "isnot": 2, "as": 2, "ieq": 2, "ceq": 2, "imatch": 2, "cmatch": 2,
    "isplit": 2, "csplit": 2,
    "band": 3, "bor": 3, "bxor": 3, "shl": 3, "shr": 3,
    "+": 4, "-": 4, "*": 5, "/": 5, "%": 5, "f": 6, "..": 7, ",": 8,
}
UNARY_DASH = {"join", "split", "not", "bnot"}
KEYWORDS = {"if", "elseif", "else", "foreach", "for", "while", "do", "until", "switch", "function", "filter",
            "try", "catch", "finally", "return", "throw", "param", "begin", "process", "end", "trap", "break",
            "continue", "exit", "class", "enum", "using", "in", "dynamicparam", "data"}
TWO_CHAR = ("::", "..", "+=", "-=", "*=", "/=", "%=", "++", "--", ">>", "2>", "&&", "||")
_VAR = re.compile(r"\$(?:(global|script|local|private|env|using|variable):)?([A-Za-z0-9_?]+|\^|\$)")
_TYPE = re.compile(r"\[\s*([A-Za-z_][\w.`]*(?:\s*\[\s*\])?)\s*\]")
_NUM = re.compile(r"0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[kKmMgGtT][bB])?")
_DASHWORD = re.compile(r"-([A-Za-z][\w`]*)")


@dataclass
class Tok:
    kind: str          # str num var type op dash word nl
    text: str
    start: int
    end: int
    value: object = None
    ticks: int = 0      # backticks that do nothing except hide the text
    space_before: bool = False


def _dq_string(src: str, i: int):
    """Parse a double-quoted string starting at src[i] == '"'. Returns (parts, end, ticks)."""
    parts, buf, ticks, j, n = [], [], 0, i + 1, len(src)
    while j < n:
        ch = src[j]
        if ch == "`" and j + 1 < n:
            nx = src[j + 1]
            if nx in ESCAPES:
                buf.append(ESCAPES[nx])
            else:
                if nx not in "`\"$'":
                    ticks += 1
                buf.append(nx)
            j += 2
            continue
        if ch in "\"\u201c\u201d":
            if j + 1 < n and src[j + 1] == '"':
                buf.append('"')
                j += 2
                continue
            j += 1
            break
        if ch == "$" and j + 1 < n:
            if src[j + 1] == "(":
                depth, k = 0, j + 1
                while k < n:
                    if src[k] == "(":
                        depth += 1
                    elif src[k] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    k += 1
                if buf:
                    parts.append(("lit", "".join(buf)))
                    buf = []
                parts.append(("sub", src[j + 2:k]))
                j = k + 1
                continue
            m = _VAR.match(src, j)
            if m and m.group(2) not in ("$",):
                if buf:
                    parts.append(("lit", "".join(buf)))
                    buf = []
                parts.append(("var", ((m.group(1) + ":") if m.group(1) else "") + m.group(2)))
                j = m.end()
                continue
        buf.append(ch)
        j += 1
    if buf or not parts:
        parts.append(("lit", "".join(buf)))
    return parts, j, ticks


def tokenize(src: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n = 0, len(src)
    space = True

    def add(kind, start, end, value=None, ticks=0):
        nonlocal space
        toks.append(Tok(kind, src[start:end], start, end, value, ticks, space))
        space = False

    def prev_value() -> bool:
        if not toks or space:
            return False
        t = toks[-1]
        return t.kind in ("str", "num", "var", "type", "word") or (t.kind == "op" and t.text in (")", "]", "}"))

    def member_ctx() -> bool:
        return bool(toks) and toks[-1].kind == "op" and toks[-1].text in (".", "::") and not space

    while i < n:
        c = src[i]
        if c in " \t\r\u00a0":
            i += 1
            space = True
            continue
        if c == "`" and i + 1 < n and src[i + 1] in "\r\n":
            i += 2 if src[i + 1] == "\n" else 3
            space = True
            continue
        if c == "\n":
            add("nl", i, i + 1)
            i += 1
            space = True
            continue
        if src.startswith("<#", i):
            j = src.find("#>", i + 2)
            i = n if j < 0 else j + 2
            space = True
            continue
        if c == "#":
            j = src.find("\n", i)
            i = n if j < 0 else j
            space = True
            continue
        if src.startswith("@'", i) and src[i + 2:i + 3] in ("\n", "\r"):
            j = src.find("\n'@", i + 2)
            end = n if j < 0 else j + 3
            body = src[src.find("\n", i) + 1: j if j >= 0 else n]
            add("str", i, end, [("lit", body.rstrip("\r"))])
            i = end
            continue
        if src.startswith('@"', i) and src[i + 2:i + 3] in ("\n", "\r"):
            j = src.find('\n"@', i + 2)
            end = n if j < 0 else j + 3
            body = src[src.find("\n", i) + 1: j if j >= 0 else n]
            parts, _, ticks = _dq_string('"' + body.replace('"', '""') + '"', 0)
            add("str", i, end, parts, ticks)
            i = end
            continue
        if c in "'\u2018\u2019":
            j, buf = i + 1, []
            while j < n:
                if src[j] in "'\u2018\u2019":
                    if j + 1 < n and src[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    j += 1
                    break
                buf.append(src[j])
                j += 1
            add("str", i, j, [("lit", "".join(buf))])
            i = j
            continue
        if c in '"\u201c\u201d':
            parts, j, ticks = _dq_string(src, i)
            add("str", i, j, parts, ticks)
            i = j
            continue
        if c == "$":
            if src[i + 1:i + 2] == "(":
                add("op", i, i + 2)
                i += 2
                continue
            if src[i + 1:i + 2] == "{":
                j = src.find("}", i)
                j = n if j < 0 else j + 1
                add("var", i, j, src[i + 2:j - 1].lower())
                i = j
                continue
            m = _VAR.match(src, i)
            if m:
                name = ((m.group(1) + ":") if m.group(1) else "") + m.group(2)
                add("var", i, m.end(), name.lower())
                i = m.end()
                continue
        if c == "@" and src[i + 1:i + 2] in ("(", "{"):
            add("op", i, i + 2)
            i += 2
            continue
        if c == "[":
            if prev_value():
                add("op", i, i + 1)
                i += 1
                continue
            m = _TYPE.match(src, i)
            if m:
                raw = m.group(1)
                add("type", i, m.end(), re.sub(r"\s+", "", raw.replace("`", "")).lower(), raw.count("`"))
                i = m.end()
                continue
            add("op", i, i + 1)
            i += 1
            continue
        if c.isdigit() and not prev_value():
            m = _NUM.match(src, i)
            end = m.end()
            if end >= n or not (src[end].isalnum() or src[end] in "_\\:"):
                t = m.group(0)
                mult = {"kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3, "tb": 1024 ** 4}.get(t[-2:].lower(), 1)
                if mult > 1:
                    t = t[:-2]
                val = int(t, 16) if t.lower().startswith("0x") else (float(t) if "." in t else int(t))
                add("num", i, end, val * mult if mult > 1 else val)
                i = end
                continue
        if c == "-" and not member_ctx():
            m = _DASHWORD.match(src, i)
            if m:
                word = m.group(1)
                add("dash", i, m.end(), word.replace("`", "").lower(), word.count("`"))
                i = m.end()
                continue
        two = src[i:i + 2]
        if two in TWO_CHAR:
            add("op", i, i + 2)
            i += 2
            continue
        if c == ".":
            nx = src[i + 1:i + 2]
            if prev_value() or nx in ("", " ", "\t", "$", "(", "&", "'", '"', "\n"):
                add("op", i, i + 1)
                i += 1
                continue
        if c in "(){};,|&!=+*/%<>]-":
            add("op", i, i + 1)
            i += 1
            continue
        # bareword / member name
        j, buf, ticks = i, [], 0
        member = member_ctx()
        while j < n:
            ch = src[j]
            if ch == "`" and j + 1 < n:
                if src[j + 1] in "\r\n":
                    break
                buf.append(src[j + 1])
                ticks += 1
                j += 2
                continue
            if member:
                if not (ch.isalnum() or ch == "_"):
                    break
            elif ch in " \t\r\n(){};,|&\"'$<>+[]" or (ch == "@" and j > i) or ch == "\u00a0":
                break
            elif ch == "=" and j > i and src[j - 1] != "-":
                break
            buf.append(ch)
            j += 1
        if j == i:
            add("op", i, i + 1)
            i += 1
            continue
        add("word", i, j, "".join(buf), ticks)
        i = j
    return toks


# ───────────────────────── syntax tree ─────────────────────────
@dataclass
class Node:
    kind: str
    start: int
    end: int
    kids: list = field(default_factory=list)
    value: object = None
    tok: Tok | None = None


class Parser:
    def __init__(self, toks: list[Tok]):
        self.t = toks
        self.i = 0

    # helpers
    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else None

    def nxt(self):
        t = self.peek()
        self.i += 1
        return t

    def is_op(self, t, *texts):
        return t is not None and t.kind == "op" and t.text in texts

    def skip_nl(self):
        while self.peek() is not None and self.peek().kind == "nl":
            self.i += 1

    # grammar
    def parse(self) -> Node:
        stmts = self.statements(set())
        end = self.t[-1].end if self.t else 0
        return Node("script", 0, end, stmts)

    def statements(self, closers: set) -> list[Node]:
        out = []
        while self.peek() is not None:
            t = self.peek()
            if t.kind == "nl" or self.is_op(t, ";"):
                self.i += 1
                continue
            if t.kind == "op" and t.text in closers:
                break
            start = self.i
            try:
                s = self.statement()
            except RecursionError:
                s = None
            if s is not None:
                out.append(s)
            if self.i == start:
                self.i += 1
        return out

    def statement(self):
        t = self.peek()
        if t.kind == "word" and t.value.lower() in KEYWORDS:
            self.nxt()
            node = Node("kw", t.start, t.end, value=t.value.lower(), tok=t)
            if node.value in ("function", "filter") and self.peek() is not None and self.peek().kind == "word":
                self.nxt()
            return node
        return self.pipeline()

    def pipeline(self):
        first = self.element()
        if first is None:
            return None
        elems = [first]
        while self.is_op(self.peek(), "|"):
            self.nxt()
            self.skip_nl()
            e = self.element()
            if e is None:
                break
            elems.append(e)
        if len(elems) == 1:
            return first
        return Node("pipeline", elems[0].start, elems[-1].end, elems)

    def element(self):
        t = self.peek()
        if t is None:
            return None
        if self.is_op(t, "&", "."):
            self.nxt()
            name = self.postfix(self.primary())
            if name is None:
                return Node("opaque", t.start, t.end)
            args = self.args()
            end = args[-1].end if args else name.end
            return Node("cmd", t.start, end, [name] + args, value=t.text, tok=t)
        if self.is_op(t, "%"):
            t = Tok("word", "%", t.start, t.end, "%", 0, t.space_before)
            self.t[self.i] = t
        if t.kind == "word" and t.value.lower() not in KEYWORDS:
            nt = self.peek(1)
            if self.is_op(nt, "="):
                self.nxt()
                self.nxt()
                rhs = self.pipeline()
                return Node("kv", t.start, rhs.end if rhs else nt.end, [rhs] if rhs else [], value=t.value)
            self.nxt()
            name = Node("word", t.start, t.end, value=t.value, tok=t)
            args = self.args()
            end = args[-1].end if args else t.end
            return Node("cmd", t.start, end, [name] + args, value="", tok=t)
        e = self.expr(0)
        if e is None:
            return None
        t = self.peek()
        if self.is_op(t, "=", "+=", "-=", "*=", "/=", "%="):
            self.nxt()
            self.skip_nl()
            rhs = self.pipeline()
            if rhs is None:
                return e
            return Node("assign", e.start, rhs.end, [e, rhs], value=t.text)
        return e

    def args(self) -> list[Node]:
        out = []
        while True:
            t = self.peek()
            if t is None or t.kind == "nl" or self.is_op(t, ";", "|", ")", "}", "&&", "||"):
                break
            if t.kind == "dash":
                self.nxt()
                out.append(Node("param", t.start, t.end, value=t.value, tok=t))
            elif t.kind == "word":
                self.nxt()
                out.append(Node("word", t.start, t.end, value=t.value, tok=t))
            elif self.is_op(t, ","):
                self.nxt()
            elif self.is_op(t, ">", ">>", "2>"):
                self.nxt()
                if self.peek() is not None and self.peek().kind != "nl":
                    self.nxt()
            elif t.kind in ("str", "num", "var", "type") or self.is_op(t, "(", "$(", "@(", "{", "@{", "["):
                start = self.i
                node = self.postfix(self.primary())
                if node is None or self.i == start:
                    self.i = start + 1
                    continue
                out.append(node)
            else:
                self.nxt()
        return out

    def binop(self):
        t = self.peek()
        if t is None:
            return None, 0
        if t.kind == "dash" and t.value in BIN_PREC:
            return t.value, BIN_PREC[t.value]
        if t.kind == "op" and t.text in ("+", "-", "*", "/", "%", ",", ".."):
            return t.text, BIN_PREC[t.text]
        return None, 0

    def expr(self, minp: int):
        left = self.unary()
        if left is None:
            return None
        while True:
            op, prec = self.binop()
            if op is None or prec < minp:
                break
            save = self.i
            self.nxt()
            self.skip_nl()
            right = self.expr(prec + 1)
            if right is None:
                self.i = save
                break
            if op == ",":
                kids = left.kids + [right] if left.kind == "array" else [left, right]
                left = Node("array", left.start, right.end, kids)
            else:
                left = Node("bin", left.start, right.end, [left, right], value=op)
        return left

    def _starts_operand(self, t) -> bool:
        if t is None:
            return False
        if t.kind in ("str", "num", "var", "type"):
            return True
        if t.kind == "dash" and t.value in UNARY_DASH:
            return True
        return self.is_op(t, "(", "$(", "@(", "-", "!")

    def unary(self):
        t = self.peek()
        if t is None:
            return None
        if t.kind == "dash" and t.value in UNARY_DASH:
            self.nxt()
            x = self.unary()
            if x is None:
                return None
            return Node("un", t.start, x.end, [x], value=t.value)
        if self.is_op(t, "!", "-", "+"):
            self.nxt()
            x = self.unary()
            if x is None:
                return None
            return Node("un", t.start, x.end, [x], value=t.text)
        if t.kind == "type":
            nt = self.peek(1)
            if nt is not None and not nt.space_before and self.is_op(nt, "::", ".", "["):
                self.nxt()
                return self.postfix(Node("type", t.start, t.end, value=t.value, tok=t))
            if self._starts_operand(nt) and nt.kind != "nl":
                self.nxt()
                x = self.unary()
                if x is None:
                    return Node("type", t.start, t.end, value=t.value, tok=t)
                return Node("cast", t.start, x.end, [x], value=t.value, tok=t)
            self.nxt()
            return Node("type", t.start, t.end, value=t.value, tok=t)
        return self.postfix(self.primary())

    def group(self, kind, open_tok, closer):
        inner = self.statements({closer})
        end_tok = self.peek()
        end = open_tok.end
        if self.is_op(end_tok, closer):
            self.nxt()
            end = end_tok.end
        elif inner:
            end = inner[-1].end
        return Node(kind, open_tok.start, end, inner)

    def primary(self):
        t = self.peek()
        if t is None:
            return None
        if t.kind == "str":
            self.nxt()
            return Node("str", t.start, t.end, value=t.value, tok=t)
        if t.kind == "num":
            self.nxt()
            return Node("num", t.start, t.end, value=t.value, tok=t)
        if t.kind == "var":
            self.nxt()
            return Node("var", t.start, t.end, value=t.value, tok=t)
        if t.kind == "type":
            self.nxt()
            return Node("type", t.start, t.end, value=t.value, tok=t)
        if t.kind == "op":
            if t.text == "(":
                self.nxt()
                return self.group("paren", t, ")")
            if t.text in ("$(", "@("):
                self.nxt()
                return self.group("sub" if t.text == "$(" else "arr", t, ")")
            if t.text == "{":
                self.nxt()
                return self.group("block", t, "}")
            if t.text == "@{":
                self.nxt()
                return self.group("hash", t, "}")
        return None

    def postfix(self, node):
        if node is None:
            return None
        while True:
            t = self.peek()
            if t is None or t.space_before:
                break
            if self.is_op(t, ".", "::"):
                save = self.i
                self.nxt()
                nt = self.peek()
                if nt is None:
                    self.i = save
                    break
                if nt.kind == "word" and not nt.space_before:
                    self.nxt()
                    name = Node("mname", nt.start, nt.end, value=nt.value, tok=nt)
                elif nt.kind in ("str", "var") or self.is_op(nt, "("):
                    name = self.primary()
                else:
                    self.i = save
                    break
                node = Node("member", node.start, name.end, [node, name], value=t.text)
                ct = self.peek()
                if self.is_op(ct, "(") and not ct.space_before:
                    self.nxt()
                    args, end = self.call_args(ct)
                    node = Node("call", node.start, end, [node] + args)
                continue
            if self.is_op(t, "["):
                self.nxt()
                idx = self.expr(0)
                end = t.end
                while self.peek() is not None and not self.is_op(self.peek(), "]"):
                    self.nxt()
                if self.is_op(self.peek(), "]"):
                    end = self.nxt().end
                node = Node("index", node.start, end, [node, idx] if idx is not None else [node])
                continue
            break
        return node

    def call_args(self, open_tok):
        args, end = [], open_tok.end
        while self.peek() is not None:
            t = self.peek()
            if self.is_op(t, ")"):
                end = self.nxt().end
                break
            if t.kind == "nl" or self.is_op(t, ","):
                self.nxt()
                continue
            start = self.i
            e = self.expr(BIN_PREC[","] + 1)
            if e is None or self.i == start:
                self.i = start + 1
                continue
            args.append(e)
            end = e.end
        return args, end


def parse(src: str) -> Node:
    return Parser(tokenize(src)).parse()


def walk(node: Node):
    yield node
    for k in node.kids:
        if k is not None:
            yield from walk(k)


# ───────────────────────── constant folding ─────────────────────────
class _Unknown:
    def __repr__(self):
        return "UNK"


UNK = _Unknown()


class Char(str):
    """A [char]. In PowerShell [char]73+[char]69 is arithmetic (142), not 'IE'."""


@dataclass(frozen=True)
class TypeRef:
    name: str


@dataclass(frozen=True)
class Enc:
    codec: str


@dataclass(frozen=True)
class ScriptText:
    text: str


AUTO_VARS = {
    "shellid": "Microsoft.PowerShell",
    "pshome": r"C:\Windows\System32\WindowsPowerShell\v1.0",
    "env:comspec": r"C:\WINDOWS\system32\cmd.exe",
    "env:public": r"C:\Users\Public",
    "env:windir": r"C:\WINDOWS",
    "env:systemroot": r"C:\WINDOWS",
    "verbosepreference": "SilentlyContinue",
    "debugpreference": "SilentlyContinue",
    "erroractionpreference": "Continue",
    "true": True, "false": False, "null": None,
}
ENCODINGS = {"unicode": "utf-16-le", "utf8": "utf-8", "ascii": "ascii", "default": "latin-1",
             "bigendianunicode": "utf-16-be", "utf32": "utf-32-le", "utf7": "utf-7"}
MAX_STR = 200_000


def _tname(t: str) -> str:
    t = t.lower().replace("`", "")
    return t[7:] if t.startswith("system.") else t


def tostr(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, list):
        return " ".join(tostr(x) for x in v)
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, ScriptText):
        return v.text
    if isinstance(v, (str, int, float)):
        return str.__str__(v) if isinstance(v, str) else str(v)
    raise ValueError("not stringable")


def aslist(v) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, (bytes, bytearray)):
        return list(v)
    return [v]


def toint(v) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(round(v))
    if isinstance(v, Char):
        return ord(v)
    if isinstance(v, str):
        s = v.strip()
        if len(v) == 1 and not v.isdigit():
            return ord(v)
        return int(s, 16) if s.lower().startswith("0x") else int(float(s))
    raise ValueError("not int")


def net_format(fmt: str, args: list) -> str:
    def rep(m):
        if m.group(0) == "{{":
            return "{"
        if m.group(0) == "}}":
            return "}"
        v = tostr(args[int(m.group(1))])
        if m.group(2):
            w = int(m.group(2))
            v = v.rjust(w) if w > 0 else v.ljust(-w)
        return v
    return re.sub(r"\{\{|\}\}|\{(\d+)(?:,(-?\d+))?(?::[^}]*)?\}", rep, fmt)


def _ps_regex_rep(r: str) -> str:
    return re.sub(r"\$(\d+)", r"\\\1", r.replace("\\", "\\\\"))


class Folder:
    def __init__(self, env: dict | None = None, depth: int = 0):
        self.env = env if env is not None else {}
        self.depth = depth

    def fold(self, n: Node):
        try:
            v = self._fold(n)
        except (ValueError, TypeError, IndexError, KeyError, ZeroDivisionError, OverflowError,
                re.error, UnicodeError, base64.binascii.Error, RecursionError, AttributeError):
            return UNK
        if isinstance(v, str) and len(v) > MAX_STR:
            return UNK
        return v

    def var(self, name: str):
        name = name.lower()
        if name in self.env:
            return self.env[name]
        return AUTO_VARS.get(name, UNK)

    def _str(self, parts):
        out = []
        for kind, val in parts:
            if kind == "lit":
                out.append(val)
            elif kind == "var":
                v = self.var(val)
                if v is UNK:
                    return UNK
                out.append(tostr(v))
            else:
                if self.depth > 3:
                    return UNK
                sub = parse(val)
                if len(sub.kids) != 1:
                    return UNK
                v = Folder(self.env, self.depth + 1).fold(sub.kids[0])
                if v is UNK:
                    return UNK
                out.append(tostr(v))
        return "".join(out)

    def _fold(self, n: Node):
        k = n.kind
        if k == "str":
            return self._str(n.value)
        if k == "num":
            return n.value
        if k == "var":
            return self.var(n.value)
        if k == "word":
            return n.value
        if k == "type":
            return TypeRef(_tname(n.value))
        if k in ("paren", "sub", "arr"):
            if len(n.kids) != 1:
                return [] if (k == "arr" and not n.kids) else UNK
            v = self.fold(n.kids[0])
            if v is UNK:
                return UNK
            return aslist(v) if k == "arr" else v
        if k == "pipeline":
            return self._pipeline(n)
        if k == "array":
            vals = [self.fold(x) for x in n.kids]
            return UNK if any(v is UNK for v in vals) else vals
        if k == "un":
            v = self.fold(n.kids[0])
            if v is UNK:
                return UNK
            op = n.value
            if op == "join":
                return "".join(tostr(x) for x in aslist(v))
            if op == "split":
                return tostr(v).split()
            if op == "-":
                return -v if isinstance(v, (int, float)) else -toint(v)
            if op == "+":
                return v
            return UNK
        if k == "bin":
            return self._bin(n)
        if k == "cast":
            return self._cast(n.value, self.fold(n.kids[0]))
        if k == "index":
            if len(n.kids) < 2:
                return UNK
            obj, idx = self.fold(n.kids[0]), self.fold(n.kids[1])
            if obj is UNK or idx is UNK:
                return UNK
            seq = obj if isinstance(obj, (str, list, bytes)) else UNK
            if seq is UNK:
                return UNK
            if isinstance(idx, list):
                return [seq[toint(i)] for i in idx]
            return seq[toint(idx)]
        if k == "member":
            return self._member(n, None)
        if k == "call":
            m = n.kids[0]
            if m.kind != "member":
                return UNK
            args = [self.fold(a) for a in n.kids[1:]]
            if any(a is UNK for a in args):
                return UNK
            return self._member(m, args)
        return UNK

    def _pipeline(self, n: Node):
        cur = self.fold(n.kids[0])
        if cur is UNK:
            return UNK
        for el in n.kids[1:]:
            if el.kind != "cmd" or el.value or len(el.kids) != 2 or el.kids[1].kind != "block":
                return UNK
            name = canonical_command(el.kids[0].value)
            body = el.kids[1].kids
            if name not in ("ForEach-Object", "Where-Object") or len(body) != 1:
                return UNK
            out = []
            for item in aslist(cur):
                sub = Folder({**self.env, "_": item, "psitem": item}, self.depth + 1)
                v = sub.fold(body[0])
                if v is UNK:
                    return UNK
                if name == "ForEach-Object":
                    out.append(v)
                elif v:
                    out.append(item)
            cur = out
        return cur

    def _bin(self, n: Node):
        op = n.value
        a = self.fold(n.kids[0])
        if a is UNK:
            return UNK
        b = self.fold(n.kids[1])
        if b is UNK:
            return UNK
        if op == "+":
            if isinstance(a, Char) and (isinstance(b, (Char, int))):
                return ord(a) + (ord(b) if isinstance(b, Char) else b)
            if isinstance(a, str):
                return a + tostr(b)
            if isinstance(a, list):
                return a + aslist(b)
            if isinstance(a, (int, float)) and not isinstance(a, bool):
                return a + (b if isinstance(b, (int, float)) else toint(b))
            return UNK
        if op == "*":
            if isinstance(a, str):
                return a * toint(b)
            if isinstance(a, list):
                return a * toint(b)
            return a * b
        if op in ("-", "/", "%"):
            a, b = (a if isinstance(a, (int, float)) else toint(a)), (b if isinstance(b, (int, float)) else toint(b))
            if op == "-":
                return a - b
            if op == "%":
                return a % b
            r = a / b
            return int(r) if float(r).is_integer() else r
        if op == "f":
            return net_format(tostr(a), aslist(b))
        if op == "join":
            return tostr(b).join(tostr(x) for x in aslist(a))
        if op in ("split", "isplit", "csplit"):
            flags = 0 if op == "csplit" else re.I
            return re.split(tostr(aslist(b)[0]), tostr(a), flags=flags)
        if op in ("replace", "ireplace", "creplace"):
            bl = aslist(b)
            pat, rep = tostr(bl[0]), (tostr(bl[1]) if len(bl) > 1 else "")
            flags = 0 if op == "creplace" else re.I

            def one(s):
                return re.sub(pat, _ps_regex_rep(rep), tostr(s), flags=flags)
            return [one(x) for x in a] if isinstance(a, list) else one(a)
        if op in ("bxor", "band", "bor", "shl", "shr"):
            if isinstance(a, list):
                return [self._bit(op, toint(x), toint(b)) for x in a]
            return self._bit(op, toint(a), toint(b))
        if op == "..":
            x, y = toint(a), toint(b)
            if abs(y - x) > 100_000:
                return UNK
            return list(range(x, y + 1)) if y >= x else list(range(x, y - 1, -1))
        return UNK

    @staticmethod
    def _bit(op, x, y):
        return {"bxor": x ^ y, "band": x & y, "bor": x | y, "shl": x << y, "shr": x >> y}[op]

    def _cast(self, tname: str, v):
        if v is UNK:
            return UNK
        t = _tname(tname)
        if t == "char":
            if isinstance(v, str) and len(v) == 1:
                return Char(v)
            return Char(chr(toint(v)))
        if t in ("char[]",):
            if isinstance(v, str):
                return [Char(c) for c in v]
            return [Char(x) if isinstance(x, str) and len(x) == 1 else Char(chr(toint(x))) for x in aslist(v)]
        if t == "string":
            if isinstance(v, (bytes, TypeRef, Enc)):
                return UNK
            return str(tostr(v))
        if t in ("int", "int32", "int64", "long", "byte", "int16", "uint32"):
            return toint(v)
        if t in ("byte[]", "int[]"):
            if isinstance(v, (bytes, bytearray)):
                return list(v)
            return [toint(x) for x in aslist(v)]
        if t in ("array", "object[]", "string[]"):
            return [tostr(x) for x in aslist(v)] if t == "string[]" else aslist(v)
        if t == "scriptblock":
            return ScriptText(tostr(v))
        return UNK

    def _member(self, m: Node, args):
        objn, namen = m.kids[0], m.kids[1]
        name = namen.value if namen.kind == "mname" else self.fold(namen)
        if not isinstance(name, str):
            return UNK
        name = name.lower()
        obj = self.fold(objn)
        if obj is UNK:
            return UNK
        if isinstance(obj, TypeRef):
            return self._static(obj.name, name, args)
        if isinstance(obj, Enc):
            if name == "getstring" and args:
                data = args[0]
                b = bytes(data) if isinstance(data, (bytes, bytearray)) else bytes(toint(x) & 0xFF for x in aslist(data))
                return b.decode(obj.codec, errors="replace")
            if name == "getbytes" and args:
                return list(tostr(args[0]).encode(obj.codec))
            return UNK
        if isinstance(obj, ScriptText):
            obj = obj.text
        if isinstance(obj, str):
            if args is None:
                if name == "length":
                    return len(obj)
                return UNK
            a = args
            if name == "replace" and len(a) == 2:
                return obj.replace(tostr(a[0]), tostr(a[1]))
            if name in ("tolower", "tolowerinvariant"):
                return obj.lower()
            if name in ("toupper", "toupperinvariant"):
                return obj.upper()
            if name == "tostring":
                return obj
            if name == "trim":
                return obj.strip(tostr(a[0]) if a else None)
            if name == "trimstart":
                return obj.lstrip(tostr(a[0]) if a else None)
            if name == "trimend":
                return obj.rstrip(tostr(a[0]) if a else None)
            if name == "substring":
                s = toint(a[0])
                return obj[s:s + toint(a[1])] if len(a) > 1 else obj[s:]
            if name == "insert" and len(a) == 2:
                p = toint(a[0])
                return obj[:p] + tostr(a[1]) + obj[p:]
            if name == "remove":
                p = toint(a[0])
                return obj[:p] + obj[p + toint(a[1]):] if len(a) > 1 else obj[:p]
            if name == "split":
                seps = "".join(tostr(x) for x in a) if a else " "
                return re.split("[" + re.escape(seps) + "]", obj) if seps else [obj]
            if name == "tochararray":
                return list(obj)
            if name == "indexof" and a:
                return obj.find(tostr(a[0]))
            if name == "padleft" and a:
                return obj.rjust(toint(a[0]), tostr(a[1]) if len(a) > 1 else " ")
            if name == "padright" and a:
                return obj.ljust(toint(a[0]), tostr(a[1]) if len(a) > 1 else " ")
            return UNK
        if isinstance(obj, list):
            if args is None and name in ("count", "length"):
                return len(obj)
            return UNK
        return UNK

    def _static(self, t: str, name: str, args):
        if t in ("text.encoding",) and args is None and name in ENCODINGS:
            return Enc(ENCODINGS[name])
        if args is None:
            if t == "char" and name == "maxvalue":
                return "\uffff"
            return UNK
        if t == "convert":
            if name == "frombase64string":
                s = re.sub(r"\s", "", tostr(args[0]))
                return base64.b64decode(s + "=" * (-len(s) % 4))
            if name == "tobase64string":
                d = args[0]
                b = bytes(d) if isinstance(d, (bytes, bytearray)) else bytes(toint(x) & 0xFF for x in aslist(d))
                return base64.b64encode(b).decode()
            if name == "tochar":
                return chr(toint(args[0]))
            if name in ("toint32", "toint16", "tobyte") and len(args) == 2:
                return int(tostr(args[0]), toint(args[1]))
        if t == "string" and name == "join" and len(args) >= 2:
            items = args[1] if len(args) == 2 else args[1:]
            return tostr(args[0]).join(tostr(x) for x in aslist(items))
        if t == "string" and name == "concat":
            return "".join(tostr(x) for x in args)
        if t in ("regex", "text.regularexpressions.regex") and name == "replace" and len(args) >= 3:
            return re.sub(tostr(args[1]), _ps_regex_rep(tostr(args[2])), tostr(args[0]))
        if t == "scriptblock" and name == "create" and args:
            return ScriptText(tostr(args[0]))
        if t == "char" and name == "convertfromutf32":
            return chr(toint(args[0]))
        return UNK


# ───────────────────────── rewriting ─────────────────────────
CANON = {
    "iex": "Invoke-Expression", "invoke-expression": "Invoke-Expression",
    "iwr": "Invoke-WebRequest", "invoke-webrequest": "Invoke-WebRequest", "wget": "Invoke-WebRequest",
    "curl": "Invoke-WebRequest", "irm": "Invoke-RestMethod", "invoke-restmethod": "Invoke-RestMethod",
    "icm": "Invoke-Command", "invoke-command": "Invoke-Command", "saps": "Start-Process", "start": "Start-Process",
    "start-process": "Start-Process", "gci": "Get-ChildItem", "get-childitem": "Get-ChildItem",
    "gc": "Get-Content", "get-content": "Get-Content", "sc": "Set-Content", "set-content": "Set-Content",
    "sal": "Set-Alias", "set-alias": "Set-Alias", "sv": "Set-Variable", "set-variable": "Set-Variable",
    "gv": "Get-Variable", "get-variable": "Get-Variable", "%": "ForEach-Object", "foreach-object": "ForEach-Object",
    "?": "Where-Object", "where-object": "Where-Object", "new-object": "New-Object", "out-null": "Out-Null",
    "write-host": "Write-Host", "write-output": "Write-Output", "echo": "Write-Output",
    "select-object": "Select-Object", "select": "Select-Object", "sort-object": "Sort-Object", "sort": "Sort-Object",
    "set-mppreference": "Set-MpPreference", "add-mppreference": "Add-MpPreference",
    "register-scheduledtask": "Register-ScheduledTask", "new-scheduledtaskaction": "New-ScheduledTaskAction",
    "new-scheduledtasktrigger": "New-ScheduledTaskTrigger", "start-bitstransfer": "Start-BitsTransfer",
    "set-itemproperty": "Set-ItemProperty", "new-itemproperty": "New-ItemProperty", "remove-item": "Remove-Item",
    "get-process": "Get-Process", "get-service": "Get-Service", "get-wmiobject": "Get-WmiObject",
    "invoke-wmimethod": "Invoke-WmiMethod", "get-ciminstance": "Get-CimInstance", "add-type": "Add-Type",
    "enter-pssession": "Enter-PSSession", "new-pssession": "New-PSSession", "get-aduser": "Get-ADUser",
    "get-adgroupmember": "Get-ADGroupMember", "get-adcomputer": "Get-ADComputer", "clear-eventlog": "Clear-EventLog",
    "set-executionpolicy": "Set-ExecutionPolicy", "import-module": "Import-Module", "ipmo": "Import-Module",
    "copy-item": "Copy-Item", "cp": "Copy-Item", "move-item": "Move-Item", "mv": "Move-Item",
    "out-file": "Out-File", "test-netconnection": "Test-NetConnection", "get-item": "Get-Item",
}
_IDENT = re.compile(r"^[\w.\-\\:]+$")
_MEMBER_IDENT = re.compile(r"^\w+$")


def ps_literal(v) -> str | None:
    if isinstance(v, ScriptText):
        v = v.text
    if isinstance(v, bool):
        return "$true" if v else "$false"
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list) and v and len(v) <= 64 and all(isinstance(x, (str, int)) for x in v):
        return ",".join(ps_literal(x) for x in v)
    return None


def canonical_command(name: str) -> str:
    return CANON.get(name.lower(), name)


@dataclass
class PeelResult:
    text: str
    inner: list[str] = field(default_factory=list)       # decoded strings handed to IEX / ScriptBlock::Create
    edits: int = 0
    passes: int = 0
    dyn_invokes: int = 0


class _Rewriter:
    def __init__(self, src: str, tree: Node, env: dict):
        self.src = src
        self.f = Folder(env)
        self.edits: list[tuple[int, int, str]] = []
        self.inner: list[str] = []
        self.dyn = 0

    def edit(self, s, e, text):
        if self.src[s:e] != text:
            self.edits.append((s, e, text))

    def trivial(self, n: Node) -> bool:
        if n.kind == "num":
            return True
        if n.kind == "str":
            t = n.tok
            plain = len(n.value) == 1 and n.value[0][0] == "lit"
            return plain and t.ticks == 0 and (t.text.startswith("'") or "`" not in t.text)
        return False

    def foldable_kind(self, n: Node) -> bool:
        return n.kind in ("bin", "un", "cast", "index", "call", "member", "paren", "str", "sub", "array", "pipeline")

    def try_literal(self, n: Node) -> bool:
        if self.trivial(n) or not self.foldable_kind(n):
            return False
        if n.kind == "array" and all(self.trivial(k) for k in n.kids):
            return False
        v = self.f.fold(n)
        if v is UNK:
            return False
        if isinstance(v, list):
            return False
        lit = ps_literal(v)
        if lit is None:
            return False
        self.edit(n.start, n.end, lit)
        return True

    def name_value(self, n: Node):
        if n.kind == "word":
            return n.value
        v = self.f.fold(n)
        return v if isinstance(v, str) else None

    def visit(self, n: Node | None, role: str = "expr"):
        if n is None:
            return
        k = n.kind
        if k == "cmd":
            self.visit_cmd(n)
            return
        if k == "pipeline":
            v = self.f.fold(n)
            if isinstance(v, (str, int)) and self.try_literal(n):
                return
            for e in n.kids:
                self.visit(e)
            last = n.kids[-1]
            if last.kind == "cmd" and self.cmd_name(last) == "Invoke-Expression" and len(last.kids) == 1:
                v = self.f.fold(n.kids[-2]) if len(n.kids) >= 2 else UNK
                if isinstance(v, (str, ScriptText)):
                    self.inner.append(tostr(v))
            return
        if k == "assign":
            self.visit(n.kids[1])
            return
        if k == "member":
            self.visit_member(n)
            return
        if k == "call":
            self.visit_call(n)
            return
        if k in ("word", "param"):
            if n.tok is not None and n.tok.ticks:
                self.edit(n.start, n.end, ("-" if k == "param" else "") + n.value)
            return
        if k == "type":
            if n.tok is not None and n.tok.ticks:
                self.edit(n.start, n.end, "[" + n.tok.text[1:-1].replace("`", "") + "]")
            return
        if k == "var":
            return
        if self.try_literal(n):
            return
        for c in n.kids:
            self.visit(c)

    def cmd_name(self, cmd: Node) -> str | None:
        v = self.name_value(cmd.kids[0])
        return canonical_command(v) if isinstance(v, str) else None

    def visit_cmd(self, n: Node):
        name = n.kids[0]
        args = n.kids[1:]
        if n.value in ("&", "."):
            v = self.name_value(name)
            if name.kind != "word":
                self.dyn += 1
            if isinstance(v, str) and _IDENT.match(v):
                self.edit(n.start, name.end, canonical_command(v))
            else:
                self.visit(name)
        else:
            canon = canonical_command(name.value)
            self.edit(name.start, name.end, canon)
        cname = self.cmd_name(n)
        for a in args:
            self.visit(a, "arg")
        if cname == "Invoke-Expression" or (cname or "").lower() in ("invoke-command",):
            for a in args:
                if a.kind in ("param", "word"):
                    continue
                v = self.f.fold(a)
                if isinstance(v, ScriptText):
                    v = v.text
                if isinstance(v, str) and v.strip():
                    self.inner.append(v)
                elif a.kind == "block" and cname == "Invoke-Command":
                    pass
                break

    def visit_member(self, n: Node):
        obj, name = n.kids
        if self.try_literal(n):
            return
        self.visit(obj)
        if name.kind != "mname":
            self.dyn += 1
            v = self.f.fold(name)
            if isinstance(v, str) and _MEMBER_IDENT.match(v):
                self.edit(obj.end, name.end, n.value + v)
            else:
                self.visit(name)
        elif name.tok is not None and name.tok.ticks:
            self.edit(name.start, name.end, name.value)

    def visit_call(self, n: Node):
        m = n.kids[0]
        args = n.kids[1:]
        v = self.f.fold(n)
        if isinstance(v, ScriptText):
            self.inner.append(v.text)
        if v is not UNK and self.try_literal(n):
            return
        inner_m = m.kids[0] if m.kind == "member" else None
        if (m.kind == "member" and m.kids[1].kind == "mname" and m.kids[1].value.lower() == "invoke"
                and inner_m is not None and inner_m.kind == "member" and inner_m.kids[1].kind != "mname"):
            nm = self.f.fold(inner_m.kids[1])
            if isinstance(nm, str) and _MEMBER_IDENT.match(nm):
                self.dyn += 1
                self.visit(inner_m.kids[0])
                self.edit(inner_m.kids[0].end, m.end, inner_m.value + nm)
                for a in args:
                    self.visit(a)
                return
        self.visit(m)
        for a in args:
            self.visit(a)

    def apply(self) -> str:
        out, pos = [], 0
        for s, e, text in sorted(self.edits, key=lambda x: (x[0], -x[1])):
            if s < pos:
                continue
            out.append(self.src[pos:s])
            out.append(text)
            pos = e
        out.append(self.src[pos:])
        return "".join(out)


def _build_env(tree: Node) -> dict:
    counts = Counter()
    for n in walk(tree):
        if n.kind == "assign" and n.kids[0].kind == "var":
            counts[n.kids[0].value] += 1
    env: dict = {}
    f = Folder(env)

    def run(node: Node):
        for n in node.kids:
            if n is None:
                continue
            if n.kind == "assign" and n.kids[0].kind == "var" and n.value == "=" and counts[n.kids[0].value] == 1:
                v = f.fold(n.kids[1])
                if v is not UNK and not isinstance(v, (TypeRef,)):
                    env[n.kids[0].value] = v
            elif (n.kind == "call" and n.kids[0].kind == "member" and n.kids[0].kids[0].kind == "type"
                  and _tname(n.kids[0].kids[0].value) == "array" and n.kids[0].kids[1].kind == "mname"
                  and n.kids[0].kids[1].value.lower() == "reverse" and len(n.kids) == 2
                  and n.kids[1].kind == "var" and isinstance(env.get(n.kids[1].value), list)):
                env[n.kids[1].value] = list(reversed(env[n.kids[1].value]))
            run(n)
    run(tree)
    return env


def peel(src: str, max_passes: int = 4) -> PeelResult:
    """Deobfuscate one script block. Never executes anything."""
    text, inner, total_edits, dyn, passes = src, [], 0, 0, 0
    for passes in range(1, max_passes + 1):
        tree = parse(text)
        rw = _Rewriter(text, tree, _build_env(tree))
        rw.visit(tree)
        new = rw.apply()
        for s in rw.inner:
            if s not in inner:
                inner.append(s)
        dyn = max(dyn, rw.dyn) if passes > 1 else rw.dyn
        total_edits += len(rw.edits)
        if new == text:
            break
        text = new
    return PeelResult(text=text, inner=inner, edits=total_edits, passes=passes, dyn_invokes=dyn)


def commands(src: str) -> list[tuple[str, list[tuple[str, str]]]]:
    """Commands in a script with their parameters: [(Name, [(param, value), ...])] (after peeling)."""
    tree = parse(src)
    f = Folder(_build_env(tree))
    out = []
    for n in walk(tree):
        if n.kind != "cmd":
            continue
        nm = n.kids[0].value if n.kids[0].kind == "word" else f.fold(n.kids[0])
        if not isinstance(nm, str):
            continue
        params, pending = [], None
        for a in n.kids[1:]:
            if a.kind == "param":
                if pending is not None:
                    params.append((pending, "True"))
                pending = a.tok.text[1:].replace("`", "") if a.tok is not None else a.value
            else:
                v = f.fold(a)
                val = tostr(v) if v is not UNK and not isinstance(v, (bytes, TypeRef, Enc)) else src[a.start:a.end]
                params.append((pending or "", val))
                pending = None
        if pending is not None:
            params.append((pending, "True"))
        out.append((canonical_command(nm), params))
    return out


# ───────────────────────── -EncodedCommand on a command line ─────────────────────────
_ENC_ARG = re.compile(r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+['\"]?([A-Za-z0-9+/=]{8,})", re.I)
_CMD_ARG = re.compile(r"(?:^|\s)[-/](?:c|co|com|comm|comma|comman|command)\s+(.+)$", re.I | re.S)
_VERSION_ARG = re.compile(r"(?:^|\s)[-/](?:v|ve|ver|vers|versi|versio|version)\s+([\d.]+)", re.I)


def script_from_command_line(cmdline: str) -> tuple[str | None, str]:
    """powershell.exe ... -enc <b64> | -c <script>  →  (script, how)."""
    if not cmdline:
        return None, ""
    m = _ENC_ARG.search(cmdline)
    if m:
        try:
            b = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
            return b.decode("utf-16-le"), "-EncodedCommand (Base64, UTF-16LE)"
        except Exception:
            return None, "-EncodedCommand (undecodable)"
    m = _CMD_ARG.search(cmdline)
    if m:
        s = m.group(1).strip()
        if len(s) >= 2 and s[0] == s[-1] == '"':
            s = s[1:-1]
        return s, "-Command"
    return None, ""


def requested_version(cmdline: str) -> str | None:
    m = _VERSION_ARG.search(cmdline or "")
    return m.group(1) if m else None


# ───────────────────────── obfuscation features ─────────────────────────
FEATURES = ["entropy", "special_ratio", "tick_density", "concat_depth", "fragment_ratio",
            "obf_ops", "case_noise", "dyn_invoke", "peel_delta", "long_token"]
FEATURE_LABELS = {
    "entropy": "Character entropy",
    "special_ratio": "Special-character ratio",
    "tick_density": "Backtick density",
    "concat_depth": "Concatenation depth",
    "fragment_ratio": "Tiny string fragments",
    "obf_ops": "Obfuscation operators",
    "case_noise": "rAnDoM case",
    "dyn_invoke": "Dynamic invocation",
    "peel_delta": "How much peeling changed it",
    "long_token": "Longest token",
}
_ALT_CASE = re.compile(r"[a-z][A-Z][a-z][A-Z]|[A-Z][a-z][A-Z][a-z][A-Z]")


def _concat_leaves(n: Node) -> int:
    if n.kind == "bin" and n.value == "+":
        return _concat_leaves(n.kids[0]) + _concat_leaves(n.kids[1])
    if n.kind == "paren" and len(n.kids) == 1:
        return _concat_leaves(n.kids[0])
    return 1 if n.kind in ("str", "var", "cast", "index") else 0


def features(src: str, result: PeelResult | None = None) -> dict:
    result = result or peel(src)
    toks = tokenize(src)
    tree = Parser(toks).parse()
    body = src.strip()
    n = max(1, len(re.sub(r"\s", "", body)))

    counts = Counter(body)
    total = sum(counts.values()) or 1
    entropy = -sum(c / total * math.log2(c / total) for c in counts.values())

    special = sum(1 for ch in body if not ch.isalnum() and not ch.isspace()) / n
    ticks = sum(t.ticks for t in toks)

    depth = 0
    strs = []
    ops = 0
    for node in walk(tree):
        if node.kind == "bin" and node.value == "+":
            depth = max(depth, _concat_leaves(node))
        if node.kind == "str" and node.value and node.value[0][0] == "lit" and len(node.value) == 1:
            strs.append(len(node.value[0][1]))
        if node.kind == "bin" and node.value in ("f", "join", "replace", "creplace", "ireplace", "bxor", "split"):
            ops += 1
        if node.kind == "un" and node.value in ("join", "split"):
            ops += 1
        if node.kind == "cast" and _tname(node.value) in ("char", "char[]", "byte[]"):
            ops += 1
        if node.kind == "call" and node.kids[0].kind == "member" and node.kids[0].kids[1].kind == "mname":
            if node.kids[0].kids[1].value.lower() in ("replace", "frombase64string", "getstring", "reverse", "invoke"):
                ops += 1
        if node.kind == "index" and len(node.kids) == 2 and node.kids[1].kind in ("bin", "array"):
            ops += 1
    frag = (sum(1 for s in strs if s <= 3) / len(strs)) if len(strs) >= 3 else 0.0

    idents = [t.value for t in toks if t.kind in ("word", "dash") and isinstance(t.value, str)]
    idents = [w for w in idents if sum(ch.isalpha() for ch in w) >= 4]
    case_noise = (sum(1 for w in idents if _ALT_CASE.search(w)) / len(idents)) if idents else 0.0

    a = re.sub(r"\s", "", body.lower())[:6000]
    b = re.sub(r"\s", "", result.text.lower())[:6000]
    delta = 1 - difflib.SequenceMatcher(None, a, b, autojunk=False).ratio() if a else 0.0

    longest = max((t.end - t.start for t in toks), default=0)
    return {
        "entropy": entropy,
        "special_ratio": special,
        "tick_density": 100 * ticks / n,
        "concat_depth": math.log1p(depth if depth >= 3 else 0),
        "fragment_ratio": frag,
        "obf_ops": math.log1p(ops),
        "case_noise": case_noise,
        "dyn_invoke": math.log1p(result.dyn_invokes),
        "peel_delta": delta,
        "long_token": math.log1p(longest),
    }
