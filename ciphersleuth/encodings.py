"""Simple encodings that look like codes but aren't real ciphers.

Binary, hex, Base64, Morse and ROT13 are *encodings* — deterministic,
reversible transforms with no secret key. They are included so the toolkit can
recognise and strip them (they frequently wrap the "real" cipher in puzzles
and CTFs). They carry no cryptographic strength and exist purely for
convenience.

Every decoder returns ``(decoded_text, note)`` where ``note`` explains what
was done. Decoders never raise on malformed input; they return the input
unchanged with an explanatory note.
"""

from __future__ import annotations

import base64
import binascii
import re

__all__ = ["decode_base64", "decode_binary", "decode_hex", "decode_morse", "decode_rot13"]


def decode_binary(text: str) -> tuple[str, str]:
    """Decode a run of 8-bit binary (space- or fixed-width grouped)."""
    body = re.sub(r"\s+", "", text)
    if not body or not set(body) <= {"0", "1"}:
        return text, "not binary"
    # group by 8 (or 7) bits
    for width in (8, 7):
        if len(body) % width != 0:
            continue
        try:
            out = "".join(
                chr(int(body[i:i + width], 2))
                for i in range(0, len(body), width)
            )
            # sanity: printable-ish
            if all(32 <= ord(c) <= 126 or c in "\n\r\t" for c in out):
                return out, f"decoded {width}-bit binary"
        except ValueError:
            continue
    return text, "binary but not 7/8-bit ASCII"


def decode_hex(text: str) -> tuple[str, str]:
    """Decode a hex string to bytes -> text."""
    body = re.sub(r"\s+", "", text)
    if not body or not set(body) <= set("0123456789abcdefABCDEF") or len(body) % 2:
        return text, "not even-length hex"
    try:
        raw = binascii.unhexlify(body)
        return raw.decode("utf-8", "replace"), f"decoded {len(raw)} bytes of hex"
    except binascii.Error:
        return text, "invalid hex"


def decode_base64(text: str) -> tuple[str, str]:
    """Decode Base64 to text."""
    body = text.strip()
    if not body:
        return text, "empty"
    # strip surrounding whitespace/newlines that padding might misalign
    body = re.sub(r"\s+", "", body)
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", body):
        return text, "not Base64 alphabet"
    try:
        raw = base64.b64decode(body, validate=True)
        return raw.decode("utf-8", "replace"), f"decoded Base64 ({len(raw)} bytes)"
    except (binascii.Error, ValueError):
        return text, "Base64 but failed to decode"


#: Morse mapping (letters + digits).
_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9",
}


def decode_morse(text: str) -> tuple[str, str]:
    """Decode Morse: letters separated by spaces, words by ``/`` or multiple spaces."""
    if not set(text.strip()) <= set(".-/ "):
        return text, "not Morse characters"
    words = text.strip().replace("  ", " / ").replace("\t", " / ").split("/")
    out_words = []
    for word in words:
        letters = []
        for sym in word.split():
            letters.append(_MORSE.get(sym, "?"))
        out_words.append("".join(letters))
    return " ".join(out_words).strip(), "decoded Morse"


def decode_rot13(text: str) -> tuple[str, str]:
    """Decode ROT13 (self-inverse)."""
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out), "ROT13 applied"
