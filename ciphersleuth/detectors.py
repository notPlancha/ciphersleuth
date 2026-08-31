"""Cipher fingerprinting — "what kind of code is this?"

Before we can break a ciphertext we want a short list of likely candidates.
Fingerprinting answers that with a battery of cheap statistical tests:

* **Character-set detection** — is it only ``0/1`` (binary)? only ``0-9``
  (digits)? only ``A-F`` (hex)? A ``.``/``-`` mix (Morse)? a Base64 alphabet
  (``A-Za-z0-9+/=``)? These narrow the field instantly.
* **Index of coincidence** — high IC (near English's ~0.0667) suggests a
  monoalphabetic substitution (Caesar/affine/simple substitution); low IC
  suggests polyalphabetic (Vigenère) or a transposition.
* **Chi-square vs English monograms** — how close are the ciphertext letter
  frequencies to English's? Close -> monoalphabetic substitution.
* **Kasiski / Friedman** — estimate a Vigenère key length.

The module exposes :func:`fingerprint`, which returns a ranked list of
``(cipher_name, confidence, evidence)`` tuples, and a batch of individual
detectors you can compose yourself.
"""

from __future__ import annotations

import re

from .ciphers import (
    ENGLISH_FREQS,
    _chi2,
    _friedman_key_length,
    _index_of_coincidence,
    _kasiski_key_lengths,
)
from .ngram import clean_text, monogram_frequencies

__all__ = [
    "FingerprintResult",
    "chi_square_english",
    "detect_charset",
    "fingerprint",
    "friedman",
    "index_of_coincidence",
    "kasiski",
]


class FingerprintResult:
    """A ranked list of cipher candidates with confidence and evidence."""

    def __init__(self, candidates, charset, ic, chi2):
        self.candidates = candidates      # list[(name, confidence, evidence)]
        self.charset = charset            # detected character-set family
        self.ic = ic                      # index of coincidence
        self.chi2 = chi2                  # chi-square vs English monograms

    def __repr__(self) -> str:
        lines = [f"charset={self.charset}  ic={self.ic:.4f}  chi2={self.chi2:.2f}"]
        for name, conf, ev in self.candidates:
            lines.append(f"  {name:<12} conf={conf:.2f}  {ev}")
        return "\n".join(lines)


#: English index of coincidence reference.
_ENGLISH_IC = 0.0667
#: Random-letter IC.
_RANDOM_IC = 1.0 / 26.0  # ~0.0385


def detect_charset(text: str) -> tuple[str, dict]:
    """Return (family, details) describing the character set of *text*."""
    stripped = text.replace("\n", "").replace("\r", "")
    s = stripped.strip()
    if not s:
        return "empty", {}
    # what characters are present, ignoring separators
    body = re.sub(r"[\s]+", "", s)
    letters = re.findall(r"[A-Za-z]", body)
    digits = re.findall(r"[0-9]", body)
    other = re.sub(r"[A-Za-z0-9\s]", "", s)
    hex_only = re.fullmatch(r"[0-9A-Fa-f]+", body) is not None
    binary = re.fullmatch(r"[01]+", body) is not None
    morse = set(body) <= set(".-/ ") and bool(re.fullmatch(r"[.\-/ ]+", s))

    fam = "text"
    details = {}
    if binary:
        fam, details = "binary", {"bits": len(body)}
    elif hex_only and len(body) % 2 == 0:
        fam, details = "hex", {"bytes": len(body) // 2}
    elif re.fullmatch(r"[0-9]+", body):
        fam, details = "digits", {"length": len(body)}
    elif morse and ("." in body or "-" in body):
        fam, details = "morse", {}
    elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) and len(body) % 4 == 0 and letters and digits:
        fam, details = "base64", {}
    elif letters and not other:
        fam = "text"
    else:
        fam = "symbols" if other else "text"
    return fam, details


def index_of_coincidence(text: str) -> float:
    """Index of coincidence: ~0.067 (English monoalphabetic) vs ~0.038 (random)."""
    return _index_of_coincidence(text)


def chi_square_english(text: str) -> float:
    """Chi-square of the ciphertext monogram distribution vs English frequencies."""
    return _chi2(monogram_frequencies(text), ENGLISH_FREQS)


def kasiski(text: str, max_len: int = 20) -> list[int]:
    """Top key-length candidates from repeated substrings."""
    return _kasiski_key_lengths(clean_text(text), max_len)


def friedman(text: str) -> float:
    """Key-length estimate from the index of coincidence."""
    return _friedman_key_length(text)


#: Simple encoding families -> handling hint (decoded via ciphers/encodings).
_ENCODING_DECODE = {
    "binary": "binary bits -> text",
    "hex": "hex -> ASCII text",
    "base64": "Base64 -> text",
    "morse": "Morse -> letters",
}


def fingerprint(text: str, top: int = 8) -> FingerprintResult:
    """Rank likely cipher types for *text* using statistical tests.

    Returns a :class:`FingerprintResult` whose ``candidates`` are ordered by
    descending confidence.
    """
    charset, _ = detect_charset(text)

    # 1) explicit encodings first
    if charset in _ENCODING_DECODE:
        candidates = [(charset, 1.0, _ENCODING_DECODE[charset])]
        return FingerprintResult(candidates, charset, 0.0, 0.0)

    ic = index_of_coincidence(text)
    chi2 = chi_square_english(text)
    clean = clean_text(text)

    candidates: list[tuple[str, float, str]] = []
    n = len(clean)

    if n == 0:
        return FingerprintResult([], "empty", 0.0, 0.0)

    # 2) monoalphabetic vs polyalphabetic by IC
    mono_strong = ic > 0.055
    mono_weak = ic > 0.048

    if mono_strong:
        candidates.append(("caesar", 0.75, f"IC {ic:.3f} suggests monoalphabetic"))
        candidates.append(("substitution", 0.85, f"IC {ic:.3f} + close to English (chi2={chi2:.1f})"))
        candidates.append(("affine", 0.60, "monoalphabetic; try affine if Caesar fails"))
        candidates.append(("atbash", 0.40, "monoalphabetic; trivial transform possible"))
        # A transposition PRESERVES the exact letter multiset, so its IC and
        # monogram stats look English even though the order is scrambled.
        candidates.append(("rail_fence", 0.55, "high IC but possibly transposition (order scrambled)"))
        candidates.append(("columnar", 0.60, "high IC but possibly transposition (order scrambled)"))
    elif mono_weak:
        candidates.append(("substitution", 0.50, f"IC {ic:.3f} borderline monoalphabetic"))
        candidates.append(("caesar", 0.45, f"IC {ic:.3f} borderline"))
        candidates.append(("affine", 0.40, "borderline monoalphabetic"))
        candidates.append(("columnar", 0.50, "borderline; transposition still possible"))
        candidates.append(("rail_fence", 0.45, "borderline; transposition still possible"))
        candidates.append(("playfair", 0.35, "digraph cipher; low-ish IC"))
    else:
        # 3) polyalphabetic / transposition territory
        kk = kasiski(text)[:3]
        fried = friedman(text)
        candidates.append(
            ("vigenere", 0.80, f"IC {ic:.3f} low (polyalphabetic); Kasiski key-lengths {kk}, Friedman ~{fried:.0f}")
        )
        candidates.append(("rail_fence", 0.55, "low IC; transposition candidates"))
        candidates.append(("columnar", 0.60, "low IC; transposition candidates"))
        candidates.append(("playfair", 0.45, "low IC; digraph cipher"))

    # 4) note Bacon if only A/B-like tokens present
    if set(clean) <= {"A", "B"}:
        candidates.insert(0, ("bacon", 0.95, "only A/B letters present -> Bacon cipher"))

    # trim
    seen, ordered = set(), []
    for name, conf, ev in candidates:
        if name not in seen:
            seen.add(name)
            ordered.append((name, conf, ev))
    candidates = ordered[:top]

    return FingerprintResult(candidates, charset, ic, chi2)
