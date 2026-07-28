#!/usr/bin/env python3
"""Fetches the latest WAProto.proto from Baileys and patches proto3-illegal
enums (first value must be 0) by inserting a synthetic `_UNSPECIFIED = 0`
member — this only adds an unused alias value, it never renumbers or removes
any existing enum member, so wire compatibility with WhatsApp is unaffected.
"""
import re
import subprocess
import sys
from pathlib import Path

URL = "https://raw.githubusercontent.com/WhiskeySockets/Baileys/master/WAProto/WAProto.proto"
DEST = Path(__file__).parent / "WAProto.proto"


def main() -> None:
    subprocess.run(["curl", "-fsSL", URL, "-o", str(DEST)], check=True)
    lines = DEST.read_text().splitlines(keepends=True)

    out: list[str] = []
    i, n, patched = 0, len(lines), 0
    while i < n:
        line = lines[i]
        m = re.match(r"^(\s*)enum\s+(\w+)\s*\{\s*$", line)
        if not m:
            out.append(line)
            i += 1
            continue
        indent, name = m.groups()
        j = i + 1
        body: list[str] = []
        while j < n and not re.match(rf"^{indent}\}}\s*$", lines[j]):
            body.append(lines[j])
            j += 1
        has_zero = any(re.search(r"=\s*0\s*;", bl) for bl in body)
        out.append(line)
        if not has_zero:
            out.append(f"{indent}    {name.upper()}_UNSPECIFIED = 0;\n")
            patched += 1
        out.extend(body)
        out.append(lines[j])
        i = j + 1

    DEST.write_text("".join(out))
    print(f"patched {patched} enum(s) missing a zero value", file=sys.stderr)


if __name__ == "__main__":
    main()
