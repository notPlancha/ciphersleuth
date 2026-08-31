"""The orchestrator: turn raw ciphertext into a best-guess plaintext.

:func:`break_cipher` is the "press the button" entry point. It:

1. Fingerprints the ciphertext to get a ranked shortlist of candidate ciphers.
2. For each candidate, runs that cipher's automated attack against the
   bundled English n-gram model.
3. Also tries decoding common encodings (binary/hex/Base64/Morse/ROT13), which
   are often layered in front of the real cipher.
4. Returns the single best :class:`~ciphersleuth.ciphers.AttackResult`.

The result carries the recovered plaintext, the cipher name, the recovered
key (if any), and the language-model score used to rank candidates — so you
can see *why* one candidate beat the others and judge whether the answer is
actually plausible.
"""

from __future__ import annotations

from . import ciphers as C
from . import encodings as E
from .detectors import detect_charset, fingerprint
from .ngram import load_model

__all__ = ["CIPHERS", "break_cipher", "break_encoding"]

#: Alias so ``from ciphersleuth.breaker import CIPHERS`` works.
CIPHERS = C.CIPHERS


def break_encoding(text: str):
    """Try the simple encodings in order; return the first that clearly decodes.

    Returns ``(decoded_text, encoding_name)`` or ``(text, None)`` if nothing
    looks like a recognised encoding. Binary is handled before Base64 (a pure
    0/1 string is also valid Base64 alphabet, so order matters), and a 5-bit
    binary pattern is recognised as Bacon.
    """
    charset, _ = detect_charset(text)
    if charset == "binary":
        dec, note = E.decode_binary(text)
        if "not" not in note:
            return dec, "binary"
        # not 7/8-bit -> try Bacon (5-bit) decode
        from .ciphers import Bacon
        pt = Bacon.decipher(text)
        if pt:
            return pt, "bacon"
        return text, None
    if charset == "hex":
        dec, note = E.decode_hex(text)
        return (dec, "hex") if "not" not in note else (text, None)
    if charset == "base64":
        dec, note = E.decode_base64(text)
        return (dec, "base64") if "not" not in note else (text, None)
    if charset == "morse":
        dec, note = E.decode_morse(text)
        return (dec, "morse") if "not" not in note else (text, None)
    dec, note = E.decode_rot13(text)
    return (dec, "rot13") if "applied" in note else (text, None)


def break_cipher(text: str, model=None, candidates=None, verbose: bool = False, **opts):
    """Break *text* automatically. Returns the best :class:`AttackResult`.

    Parameters
    ----------
    text : str
        The ciphertext to analyse.
    model : NgramModel, optional
        Language model used for scoring (default: bundled English quadgrams).
    candidates : list[str], optional
        Restrict the attack to these cipher names (skip fingerprinting).
    verbose : bool
        Print each candidate's result as it is tried.
    opts
        Forwarded to individual attacks (e.g. ``restarts``, ``max_key_len``).
    """
    if model is None:
        model = load_model()

    if candidates:
        shortlist = [(name, 1.0, "user-specified") for name in candidates]
    else:
        fp = fingerprint(text)
        shortlist = fp.candidates

    best: C.AttackResult | None = None

    # Heavy search-based attacks overfit short ciphertexts into plausible-
    # sounding garbage that can out-score the true decode. They need enough
    # text to be reliable, and the amount scales with the key's degrees of
    # freedom. On very short input we only run the low-DOF brute-force ciphers
    # and encodings. Users can force any cipher with explicit ``candidates``.
    from .ngram import clean_text
    auto_len = len(clean_text(text)) if candidates is None else 1 << 30
    MIN_LENGTH = {
        "vigenere": 40,        # needs ~several key-lengths of text
        "rail_fence": 20,
        "columnar": 20,
        "substitution": 120,   # ~26 degrees of freedom
        "playfair": 220,       # hardest; digraph key square
    }

    # always try encodings first — cheap and often the key is wrapped
    dec, enc = break_encoding(text)
    if enc:
        res = C.AttackResult("encoding:" + enc, dec, score=model.score_avg(dec),
                             method=f"decoded as {enc}")
        best = res
        if verbose:
            print(f"[candidate] {res.cipher} score={res.score:.3f}")

    for name, conf, evidence in shortlist:
        cipher_cls = C.get_cipher(name)
        if cipher_cls is None:
            continue
        if auto_len < MIN_LENGTH.get(name, 0):
            if verbose:
                print(f"[candidate] {name:<12} skipped (ciphertext too short for reliable break)")
            continue
        try:
            res = cipher_cls.attack(text, model, **opts)
        except Exception as exc:  # noqa: BLE001 - defensive: one failing attack shouldn't kill all
            if verbose:
                print(f"[candidate] {name} FAILED: {exc}")
            continue
        # Normalise: every candidate's plaintext is re-scored with the primary
        # (quadgram) model so cross-cipher scores are directly comparable.
        if res.plaintext:
            res.score = model.score_avg(res.plaintext)
        if verbose:
            print(f"[candidate] {name:<12} score={res.score:.3f} key={res.key!r}")
        if best is None or res.score > best.score:
            best = res

    return best


def list_ciphers() -> list[str]:
    """Return the names of all registered ciphers (for the CLI)."""
    return list(C.CIPHERS.keys())
