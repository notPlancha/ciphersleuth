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
    ("simple_columnar", {"key": "ZEBRA"}),
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
    for expected in ("caesar", "vigenere", "substitution", "rail_fence", "playfair", "columnar", "simple_columnar"):
        assert expected in names


# --------------------------------------------------------------------------
# adversarial / contract tests (the bugs ChatGPT's review flagged)
# --------------------------------------------------------------------------


def test_cli_key_mapping_all_ciphers(capsys):
    """The CLI key parser must pass the right kwargs to every registered
    encipher/decipher, not just caesar. (Regression: affine/rail_fence/columnar
    used to receive a spurious ``shift=`` and crash.)"""
    from ciphersleuth.cli import main as cli_main

    # caesar
    assert cli_main(["encipher", "caesar", "--key", "7", "HELLO WORLD"]) == 0
    assert capsys.readouterr().out.strip().startswith("OLSSV")
    # affine (a,b)
    assert cli_main(["encipher", "affine", "--key", "5,8", "HELLO"]) == 0
    assert "RCLLA" in capsys.readouterr().out
    # rail_fence numeric
    assert cli_main(["encipher", "rail_fence", "--key", "3", "HELLO"]) == 0
    assert capsys.readouterr().out.strip()  # no TypeError
    # columnar string key
    assert cli_main(["encipher", "columnar", "--key", "ZEBRA", "HELLO"]) == 0
    assert capsys.readouterr().out.strip()
    # vigenere
    assert cli_main(["encipher", "vigenere", "--key", "LEMON", "HELLO"]) == 0
    assert "SIXZB" in capsys.readouterr().out


def test_friedman_estimates_true_key_length():
    """Friedman must return a sane, positive key-length estimate close to the
    true one, not a negative value clamped to 1."""
    from ciphersleuth.ciphers import Vigenere, _friedman_key_length

    for key in ("TEST", "CRYPTO", "SECRETKEY"):
        ct = Vigenere.encipher(MSG, key)
        est = _friedman_key_length(ct)
        assert est >= 1.0, f"non-positive estimate for key {key}: {est}"
        # Friedman is an estimate that degrades for longer keys; allow a
        # relative tolerance around the true length.
        tol = max(2.0, 0.4 * len(key))
        assert abs(est - len(key)) <= tol, f"key {key}: estimated {est:.2f}"


def test_recombination_combines_parents():
    """OX1 crossover must yield a valid permutation of the same set that is
    NOT just a copy of parent b (regression: it returned parent b verbatim)."""
    import random as _r

    from ciphersleuth.optim import recombination

    a = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    b = list("ZYXWVUTSRQPONMLKJIHGFEDCBA")
    mixed = False
    for seed in range(200):
        child = recombination(a, b, rng=_r.Random(seed))
        assert set(child) == set(a) == set(b)
        if child != a and child != b:
            mixed = True
            break
    assert mixed, "recombination never produced a child different from both parents"


def test_recombination_preserves_string_type():
    import random as _r

    from ciphersleuth.optim import recombination

    a, b = "ABCDE", "EDCBA"
    child = recombination(a, b, rng=_r.Random(3))
    assert isinstance(child, str)
    assert set(child) == set(a)


def test_random_seed_makes_runs_reproducible():
    """Seeding a search must fully pin the run (regression: hillclimb ignored
    the seed and mutate used the module-global RNG)."""
    from ciphersleuth.ciphers import Substitution
    from ciphersleuth.ngram import load_model

    m = load_model()
    ct = Substitution.encipher(MSG, "QWERTYUIOPASDFGHJKLZXCVBNM")
    r1 = Substitution.attack(ct, m, random_seed=42)
    r2 = Substitution.attack(ct, m, random_seed=42)
    assert r1.plaintext == r2.plaintext
    assert r1.key == r2.key
    # a different seed should (overwhelmingly) take a different trajectory
    r3 = Substitution.attack(ct, m, random_seed=7)
    assert (r1.plaintext != r3.plaintext) or (r1.key != r3.key)


def test_genetic_substitution_backend():
    """The genetic backend is wired in: it must always produce a valid
    permutation key (the hard invariant), and on a good seed it must actually
    recover the plaintext (proving it is functional, not a no-op). It is not
    expected to be as reliable as the default SA+hill-climb path."""
    from ciphersleuth.ciphers import Substitution
    from ciphersleuth.ngram import load_model

    m = load_model()
    ct = Substitution.encipher(MSG, "QWERTYUIOPASDFGHJKLZXCVBNM")
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    best_acc = 0.0
    for seed in range(8):
        res = Substitution.attack(ct, m, optimizer="genetic", random_seed=seed)
        # invariant: the recovered key is always a full 26-letter permutation
        assert set(res.key) == alphabet and len(res.key) == 26, f"invalid key {res.key!r}"
        acc = sum(1 for a, b in zip(clean_text(res.plaintext), clean_text(MSG)) if a == b)
        best_acc = max(best_acc, acc / len(clean_text(MSG)))
    # functional: at least one seed recovers a large fraction of the plaintext
    assert best_acc >= 0.9, f"genetic never reached usable accuracy, best={best_acc:.2f}"


def test_keyed_columnar_differs_from_simple():
    """The keyed columnar must actually reorder columns (regression: it was
    width-only identity order) and still round-trip."""
    from ciphersleuth.ciphers import Columnar, SimpleColumnar

    src = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    keyed_ct = Columnar.encipher(src, "ZEBRA")
    simple_ct = SimpleColumnar.encipher(src, "ZEBRA")
    assert keyed_ct != simple_ct, "keyed columnar does not reorder columns"
    assert clean_text(Columnar.decipher(keyed_ct, "ZEBRA")) == src


def test_break_keyed_columnar():
    ct = C.Columnar.encipher(MSG, "ZEBRA")
    res = break_cipher(ct, candidates=["columnar"])
    acc = sum(1 for a, b in zip(clean_text(res.plaintext), clean_text(MSG)) if a == b)
    assert acc / len(clean_text(MSG)) >= 0.98, f"keyed columnar broke wrong: {res.plaintext[:60]}"
