"""
obfuscator.py — a tiny Invoke-Obfuscation-style obfuscator.

Used for two things only:
  1. building realistic obfuscated script blocks for the mock data, and
  2. generating labelled examples to train the obfuscation score
     (and to round-trip test the deobfuscator: peel(obfuscate(x)) ≈ x).

Works on the syntax tree from psparse, so it only rewrites command names,
member names and string literals — the script stays valid PowerShell.
"""
from __future__ import annotations

import base64
import random

from psparse import parse, walk

SAFE_TICK = set("bcdeghijklmopqsuwxyzBCDEGHIJKLMOPQSUWXYZ")  # never before 0abfnrtv (those are escapes)


def _lit(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def ticks(word: str, rng: random.Random, p: float = 0.45) -> str:
    out = []
    for i, ch in enumerate(word):
        if i > 0 and ch in SAFE_TICK and rng.random() < p:
            out.append("`")
        out.append(ch)
    return "".join(out)


def rand_case(word: str, rng: random.Random) -> str:
    return "".join(ch.upper() if rng.random() < 0.5 else ch.lower() for ch in word)


def concat(s: str, rng: random.Random) -> str:
    if len(s) < 4:
        return _lit(s)
    k = rng.randint(2, min(5, len(s) - 1))
    cuts = sorted(rng.sample(range(1, len(s)), k - 1))
    pieces = [s[a:b] for a, b in zip([0] + cuts, cuts + [len(s)])]
    return "(" + "+".join(_lit(p) for p in pieces) + ")"


def fmt(s: str, rng: random.Random) -> str:
    if len(s) < 4:
        return _lit(s)
    k = rng.randint(2, min(5, len(s) - 1))
    cuts = sorted(rng.sample(range(1, len(s)), k - 1))
    pieces = [s[a:b] for a, b in zip([0] + cuts, cuts + [len(s)])]
    order = list(range(len(pieces)))
    rng.shuffle(order)
    template = "".join("{" + str(order.index(i)) + "}" for i in range(len(pieces)))
    args = ",".join(_lit(pieces[i]) for i in order)
    return f'("{template}" -f {args})'


def chars(s: str, rng: random.Random) -> str:
    codes = ",".join(str(ord(c)) for c in s)
    return f"([char[]]({codes}) -join '')" if rng.random() < 0.5 else f"(({codes} | % {{ [char]$_ }}) -join '')"


def reverse(s: str, rng: random.Random) -> str:
    return f"(-join ({_lit(s[::-1])}[-1..-{len(s)}]))"


def replace_trick(s: str, rng: random.Random) -> str:
    if len(s) < 3:
        return _lit(s)
    junk = rng.choice(["QZ", "xK", "~~", "@!", "%^"])
    if junk in s:
        return _lit(s)
    p = rng.randint(1, len(s) - 1)
    return f"({_lit(s[:p] + junk + s[p:])}.Replace({_lit(junk)},''))"


STRING_TRICKS = [concat, fmt, chars, reverse, replace_trick]


def b64_wrap(script: str, rng: random.Random) -> str:
    b = base64.b64encode(script.encode("utf-16-le")).decode()
    iex = rng.choice(["iex", "IEX", "I`E`X", "Invoke-Expression", "&($ShellId[1]+$ShellId[13]+'x')",
                      ".($PSHome[4]+$PSHome[30]+'x')"])
    return f"{iex} ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{b}')))"


def obfuscate(src: str, rng: random.Random, level: float = 0.7, wrap_b64: float = 0.15) -> str:
    """Rewrite command names, member names and string literals with random tricks."""
    tree = parse(src)
    edits = []
    use_ticks = rng.random() < 0.6
    use_case = rng.random() < 0.5
    tricks = rng.sample(STRING_TRICKS, rng.randint(1, 3))
    called = {id(n.kids[0]) for n in walk(tree) if n.kind == "call"}
    for n in walk(tree):
        if n.kind == "cmd" and not n.value and n.kids[0].kind == "word":
            w = n.kids[0].value
            if rng.random() < level and len(w) >= 3 and w.replace("-", "").isalpha():
                choice = rng.random()
                if choice < 0.35 and len(w) >= 4:
                    edits.append((n.kids[0].start, n.kids[0].end, "&" + rng.choice(tricks)(w, rng)))
                else:
                    x = w
                    if use_case:
                        x = rand_case(x, rng)
                    if use_ticks or x == w:
                        x = ticks(x, rng)
                    edits.append((n.kids[0].start, n.kids[0].end, x))
        elif n.kind == "member" and n.kids[1].kind == "mname":
            name = n.kids[1].value
            if rng.random() < level * 0.6 and len(name) >= 4:
                tail = ").Invoke" if id(n) in called else ")"
                edits.append((n.kids[1].start, n.kids[1].end, "(" + rng.choice(tricks)(name, rng) + tail))
        elif n.kind == "str" and n.tok is not None and len(n.value) == 1 and n.value[0][0] == "lit":
            s = n.value[0][1]
            if 3 <= len(s) <= 120 and "\n" not in s and rng.random() < level:
                edits.append((n.start, n.end, rng.choice(tricks)(s, rng)))
    out, pos = [], 0
    for s, e, t in sorted(edits, key=lambda x: (x[0], -x[1])):
        if s < pos:
            continue
        out.append(src[pos:s])
        out.append(t)
        pos = e
    out.append(src[pos:])
    result = "".join(out)
    if rng.random() < wrap_b64:
        result = b64_wrap(result, rng)
    return result
