"""Helpers for safely showing text that came from a hostile file."""
from __future__ import annotations


def safe(text: str | None, limit: int = 300) -> str:
    """Printable, bounded text: control and invisible characters become \\xNN / \\u{NNNN}.

    `limit` counts characters of the input; "..." is added only when something was actually cut off.
    """
    out = []
    for i, ch in enumerate(str(text or "")):
        if i >= limit:
            out.append("...")
            break
        c = ord(ch)
        hidden = c < 32 or c == 127 or 0x200B <= c <= 0x200F or 0x202A <= c <= 0x202E or 0x2066 <= c <= 0x2069 or c in (0xFEFF, 0xAD)
        out.append((f"\\x{c:02x}" if c < 256 else f"\\u{{{c:x}}}") if hidden else ch)
    return "".join(out)
