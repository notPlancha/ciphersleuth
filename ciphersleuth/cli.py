"""Command-line interface for ciphersleuth.

Usage examples::

    # analyse and break a ciphertext
    ciphersleuth break "GUR PENML PBQR"

    # just fingerprint the likely cipher
    ciphersleuth fingerprint "GUR PENML PBQR"

    # encipher / decipher a known cipher with a key
    ciphersleuth encipher caesar --key 3 "HELLO WORLD"
    ciphersleuth decipher vigenere --key SECRET "..."

    # list supported ciphers
    ciphersleuth list

    # read ciphertext from a file
    ciphersleuth break --file message.txt
"""

from __future__ import annotations

import argparse
import sys

from . import ciphers as C
from .breaker import break_cipher, list_ciphers
from .detectors import fingerprint
from .ngram import load_model

_MODEL = load_model()


def _parse_text(args) -> str:
    if args.file:
        return open(args.file, encoding="utf-8").read().strip()
    return args.text or ""


def cmd_fingerprint(args) -> int:
    text = _parse_text(args)
    print(fingerprint(text))
    return 0


def cmd_break(args) -> int:
    text = _parse_text(args)
    res = break_cipher(text, model=_MODEL, candidates=args.ciphers,
                       verbose=args.verbose, restarts=args.restarts)
    if res is None:
        print("No cipher could be identified or broken.", file=sys.stderr)
        return 1
    print(f"Cipher : {res.cipher}")
    if res.key is not None:
        print(f"Key    : {res.key!r}")
    print(f"Score  : {res.score:.4f}")
    if res.method:
        print(f"Method : {res.method}")
    print("-" * 40)
    print(res.plaintext)
    return 0


def cmd_list(args) -> int:
    print("Supported ciphers:")
    for name in list_ciphers():
        print(f"  {name}")
    print("\nSupported encodings:")
    for name in ("binary", "hex", "base64", "morse", "rot13"):
        print(f"  {name}")
    return 0


def cmd_encipher(args) -> int:
    text = _parse_text(args)
    cls = C.get_cipher(args.cipher)
    if cls is None:
        print(f"Unknown cipher: {args.cipher}", file=sys.stderr)
        return 1
    key = _key(args)
    print(cls.encipher(text, **key))
    return 0


def cmd_decipher(args) -> int:
    text = _parse_text(args)
    cls = C.get_cipher(args.cipher)
    if cls is None:
        print(f"Unknown cipher: {args.cipher}", file=sys.stderr)
        return 1
    key = _key(args)
    print(cls.decipher(text, **key))
    return 0


def _key(args) -> dict:
    """Map the CLI ``--key`` string to the kwargs the target cipher expects."""
    if args.cipher in ("atbash", "bacon"):
        return {}                       # these ciphers take no key
    if args.key is None:
        return {}                       # let the cipher use its default key
    if args.cipher == "caesar":
        return {"shift": int(args.key) % 26}
    if args.cipher == "affine":
        parts = args.key.split(",")
        if len(parts) != 2:
            raise SystemExit("affine --key must be of the form 'a,b'")
        return {"a": int(parts[0]), "b": int(parts[1])}
    if args.cipher == "rail_fence":
        return {"rails": int(args.key)}
    # vigenere, substitution, columnar, simple_columnar, playfair: string key
    return {"key": args.key}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="ciphersleuth",
        description="Automatic cryptanalysis of classical ciphers.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_text(sp, required=True):
        # ``nargs='?'`` on a positional that follows another positional makes
        # argparse choke on ``--key N <text>`` (the documented invocation), so
        # text is required for encipher/decipher and only optional (nargs='?')
        # for the single-positional break/fingerprint commands.
        sp.add_argument("text", nargs=None if required else "?",
                        help="text to process (or use --file)")
        sp.add_argument("--file", help="read text from a file")

    b = sub.add_parser("break", help="fingerprint and break a ciphertext")
    add_text(b, required=False)
    b.add_argument("--ciphers", nargs="*", help="restrict to these ciphers")
    b.add_argument("--verbose", action="store_true", help="show each candidate")
    b.add_argument("--restarts", type=int, default=5, help="substitution hill-climb restarts")
    b.set_defaults(func=cmd_break)

    f = sub.add_parser("fingerprint", help="detect the likely cipher type")
    add_text(f, required=False)
    f.set_defaults(func=cmd_fingerprint)

    l = sub.add_parser("list", help="list supported ciphers and encodings")
    l.set_defaults(func=cmd_list)

    en = sub.add_parser("encipher", help="encipher text with a known cipher")
    en.add_argument("cipher")
    en.add_argument("--key", default=None)
    add_text(en)
    en.set_defaults(func=cmd_encipher)

    de = sub.add_parser("decipher", help="decipher text with a known cipher")
    de.add_argument("cipher")
    de.add_argument("--key", default=None)
    add_text(de)
    de.set_defaults(func=cmd_decipher)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
