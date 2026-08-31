"""Tests for ciphersleuth.

Run with:  python3 -m pytest tests/ -q
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ciphersleuth import break_cipher, fingerprint, list_ciphers
from ciphersleuth import ciphers as C
from ciphersleuth.encodings import (
    decode_base64,
    decode_binary,
    decode_hex,
    decode_morse,
    decode_rot13,
)
from ciphersleuth.ngram import NgramModel, clean_text

#: A comfortably long, natural English plaintext for break tests.
MSG = (
    "Cryptography is the art of writing or solving codes. The word itself "
    "comes from the Greek kruptos meaning hidden and graphein meaning to "
    "write. Throughout history people have devised ever more clever ways to "
    "hide their meanings from unauthorized eyes, and every time they did, "
    "others rose to the challenge of unraveling those secrets again and "
    "again. From Caesar's simple shift to the elegant Vigenere table, the "
    "story of codes is really the story of minds at work."
)

LONG_PLAYFAIR = MSG + " " + (
    "The playfair cipher was a notable step forward from earlier "
    "monoalphabetic substitution because it enciphers pairs of letters at "
    "once, thus hiding the single-letter frequencies that made older ciphers "
    "so easy to break with simple frequency analysis of the ciphertext alone."
)


@pytest.fixture(scope="module")
def model():
    from ciphersleuth.ngram import load_model

    return load_model()


# --------------------------------------------------------------------------
# n-gram model
# --------------------------------------------------------------------------

def test_clean_text():
    assert clean_text("Hello, World! 123") == "HELLOWORLD"


def test_ngram_roundtrip(tmp_path):
    m = NgramModel(n=3)
    m.build(["the quick brown fox jumps over the lazy dog the end"])
    m.finalize()
    p = tmp_path / "model.json"
    m.save(p)
    m2 = NgramModel.load(p)
    assert m2.n == 3
    assert m2.score("THE QUICK BROWN FOX") == pytest.approx(m.score("THE QUICK BROWN FOX"))


def test_english_text_scores_higher_than_junk(model):
    english = model.score_avg("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG")
    junk = model.score_avg("QXZJVWMKPLNFDTGHRYCIUBSEOAQZXWVTSRPNMLKJHGFD")
    assert english > junk


# --------------------------------------------------------------------------
# encipher / decipher round trips
# --------------------------------------------------------------------------

ROUNDTRIP = [
    ("caesar", {"shift": 7}),
    ("affine", {"a": 5, "b": 8}),
    ("vigenere", {"key": "LEMON"}),
    ("substitution", {"key": "QWERTYUIOPASDFGHJKLZXCVBNM"}),
    ("rail_fence", {"rails": 4}),
    ("columnar", {"key": "ZEBRA"}),
    ("playfair", {"key": "MONARCHY"}),
    ("bacon", {}),
]


@pytest.mark.parametrize("name,kwargs", ROUNDTRIP)
def test_roundtrip(name, kwargs):
    cls = C.get_cipher(name)
    # Playfair merges I/J, pads odd length, and splits doubled letters with a
    # filler X, so its roundtrip is only lossless on clean even-length text
    # without consecutive repeated letters or J. Use one for it.
    source = "THE QUICK BROWN FOX LAZY DOGS MOVE" if name == "playfair" else MSG
    enc = cls.encipher(source, **kwargs) if kwargs else cls.encipher(source)
    dec = cls.decipher(enc, **kwargs) if kwargs else cls.decipher(enc)
    assert clean_text(dec) == clean_text(source)


def test_atbash_self_inverse():
    ct = C.Atbash.encipher(MSG)
    # atbash is an involution: decipher(encipher(x)) == x
    assert C.Atbash.decipher(ct) == MSG.upper()


# --------------------------------------------------------------------------
# automatic breaking
# --------------------------------------------------------------------------

BREAK_TESTS = [
    ("caesar", {"shift": 9}),
    ("affine", {"a": 5, "b": 8}),
    ("vigenere", {"key": "CRYPTO"}),
    ("rail_fence", {"rails": 5}),
    ("columnar", {"key": "ZEBRA"}),
    ("substitution", {"key": "QWERTYUIOPASDFGHJKLZXCVBNM"}),
]


@pytest.mark.parametrize("name,kwargs", BREAK_TESTS)
def test_break(name, kwargs):
    cls = C.get_cipher(name)
    ct = cls.encipher(MSG, **kwargs) if kwargs else cls.encipher(MSG)
    res = break_cipher(ct)
    acc = sum(1 for a, b in zip(clean_text(res.plaintext), clean_text(MSG)) if a == b)
    assert acc / len(clean_text(MSG)) >= 0.98, f"{name} decoded wrong: {res.plaintext[:60]}"


def test_break_atbash():
    res = break_cipher(C.Atbash.encipher(MSG))
    # The plaintext should come back essentially correct (a substitution attack
    # may recover an equivalent key rather than the literal atbash alphabet).
    acc = sum(1 for a, b in zip(clean_text(res.plaintext), clean_text(MSG)) if a == b)
    assert acc / len(clean_text(MSG)) >= 0.98


def test_break_bacon():
    res = break_cipher(C.Bacon.encipher(MSG))
    assert clean_text(res.plaintext) == clean_text(MSG)


def test_break_short_text_prefers_simple(model):
    # A short ROT13 snippet must not be "solved" into garbage by heavy attacks.
    res = break_cipher("Gur penml pbqr vf uvqqra")
    assert "rot13" in res.cipher
    assert res.plaintext.replace(" ", "").upper() == "THECRAZYCODEISHIDDEN"


def test_break_playfair_best_effort_does_not_crash(model):
    ct = C.Playfair.encipher(LONG_PLAYFAIR, "MONARCHY")
    res = break_cipher(ct, candidates=["playfair"])
    assert res.plaintext


# --------------------------------------------------------------------------
# fingerprinting
# --------------------------------------------------------------------------

def test_fingerprint_returns_candidates():
    ct = C.Vigenere.encipher(MSG, "SECRET")
    fp = fingerprint(ct)
    names = [c[0] for c in fp.candidates]
    assert "vigenere" in names
    assert fp.ic > 0


def test_fingerprint_detects_charset():
    assert fingerprint("010000010100001001000011").charset == "binary"
    assert fingerprint("48656c6c6f").charset == "hex"


# --------------------------------------------------------------------------
# encodings
# --------------------------------------------------------------------------

def test_decode_hex():
    assert decode_hex("48656c6c6f")[0] == "Hello"


def test_decode_base64():
    assert decode_base64("aXRzIGEgc2VjcmV0")[0] == "its a secret"


def test_decode_binary():
    assert decode_binary("01000001 01010100 01010100 01000001 01000011 01001011")[0] == "ATTACK"


def test_decode_morse():
    assert decode_morse(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")[0] == "HELLO WORLD"


def test_decode_rot13():
    assert decode_rot13("Gur penml pbqr")[0] == "The crazy code"


# --------------------------------------------------------------------------
# registry / API
# --------------------------------------------------------------------------

def test_list_ciphers():
    names = list_ciphers()
    for expected in ("caesar", "vigenere", "substitution", "rail_fence", "playfair"):
        assert expected in names
