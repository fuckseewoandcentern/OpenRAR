#!/usr/bin/env python3
"""Embed a language pack into a C++ string table.

English (lang/en.txt) is the fallback. Keys in the selected language file
override it. Each non-comment line is: key<TAB>value
Value escapes: \\ \\n \\t \\r
"""

import sys


def unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(n, n))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def load(path: str) -> dict:
    table = {}
    order = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            if not line or line.startswith("#"):
                continue
            if "\t" not in line:
                raise SystemExit(f"{path}: missing tab in line: {line[:80]}")
            key, val = line.split("\t", 1)
            if key not in table:
                order.append(key)
            table[key] = unescape(val)
    return table, order


def cpp_string(s: str) -> str:
    o = ['"']
    for ch in s:
        if ch == "\\":
            o.append("\\\\")
        elif ch == '"':
            o.append('\\"')
        elif ch == "\n":
            o.append("\\n")
        elif ch == "\t":
            o.append("\\t")
        elif ch == "\r":
            o.append("\\r")
        elif ord(ch) < 32:
            o.append("\\x%02x" % ord(ch))
        else:
            o.append(ch)
    o.append('"')
    return "".join(o)


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: embed_lang.py lang/en.txt lang/<code>.txt output.inc")
    base, _order = load(sys.argv[1])
    overlay, overlay_order = load(sys.argv[2])
    # Preserve English key order, then any extra keys from the overlay.
    keys = list(base.keys())
    for k in overlay_order:
        if k not in base:
            keys.append(k)
    merged = dict(base)
    merged.update(overlay)
    lines = []
    for k in keys:
        lines.append("    {%s, %s}," % (cpp_string(k), cpp_string(merged[k])))
    with open(sys.argv[3], "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
        f.write("\n")


if __name__ == "__main__":
    main()
