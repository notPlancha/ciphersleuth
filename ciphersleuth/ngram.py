"""N-gram language models used to score candidate plaintexts.

The whole toolkit rests on one idea: of all the decodings of a piece of
ciphertext, the one that "reads" most like natural language is almost always
the right one. We quantify "reads like language" with an n-gram model built
from a plain (public-domain) English corpus.

An n-gram model stores the relative frequency of every sequence of ``n``
consecutive letters (default 4-grams, "quadgrams"). To score a candidate
plaintext we take the log of each quadgram's probability and sum them. Longer
texts get more negative raw scores (more terms), so callers that compare
candidates of *different* lengths should use :meth:`NgramModel.score_avg`,
which normalises per n-gram.

Design notes
------------
* The alphabet is normalised to the 26 letters A-Z (case-folded, all other
  characters stripped). This keeps scoring fast and language-agnostic enough
  for the classical ciphers we target.
* Unknown n-grams are scored with a small floor probability rather than 0
  (a single unseen quadgram would otherwise zero out the whole sum).
* Tables are stored as JSON (dict ``{gram: log10(p)}``) so models can be
  regenerated from any corpus with ``scripts/build_ngrams.py``.

>>> from ciphersleuth.ngram import NgramModel
>>> m = NgramModel(n=4)
>>> m.build(["The quick brown fox jumps over the lazy dog"])
>>> m.finalize()
>>> m.score_avg("THE QUICK BROWN FOX")
"""

from __future__ import annotations

import importlib.resources
import json
import math
import re
from collections import Counter
from pathlib import Path

__all__ = ["NgramModel", "clean_text", "load_model", "monogram_frequencies"]

#: Everything that isn't A-Z is stripped before scoring.
_ALPHA_RE = re.compile(r"[^A-Z]")
#: Small pseudo-probability assigned to n-grams absent from the training data.
_FLOOR_FRACTION = 0.01

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_SIZE = len(ALPHABET)


def clean_text(text: str) -> str:
    """Return *text* as uppercase A-Z only, in the same order."""
    return _ALPHA_RE.sub("", text.upper())


class NgramModel:
    """A statistical model of letter sequences.

    Build one from a corpus (or several documents) with :meth:`add` and
    :meth:`finalize`, then score candidate plaintexts with :meth:`score` or
    :meth:`score_avg`. A model can be persisted to and loaded from JSON.
    """

    def __init__(self, n: int = 4):
        self.n = n
        self._counts: Counter[str] = Counter()
        self._total = 0
        self._logprob: dict[str, float] = {}
        self._floor_log = -1.0

    # -- construction ---------------------------------------------------
    def add(self, text: str) -> None:
        """Count the n-grams occurring in *text* (noise characters ignored)."""
        text = clean_text(text)
        n = self.n
        if len(text) < n:
            return
        for i in range(len(text) - n + 1):
            self._counts[text[i : i + n]] += 1
            self._total += 1

    def build(self, texts) -> None:
        """Add every document in the iterable *texts*."""
        for t in texts:
            self.add(t)

    def finalize(self) -> None:
        """Convert raw counts into a log-probability table (call once)."""
        if not self._total:
            # No grams were ever observed: there is no distribution to model.
            self._logprob = {}
            self._floor_log = -1.0
            return
        self._logprob = {
            gram: math.log10(count / self._total)
            for gram, count in self._counts.items()
        }
        # A single unseen gram gets a tiny (non-fatal) probability.
        self._floor_log = math.log10(_FLOOR_FRACTION / self._total)

    # -- scoring -------------------------------------------------------
    def score(self, text: str) -> float:
        """Sum of per-n-gram log-probabilities over *text* (raw, length-dependent)."""
        text = clean_text(text)
        n, lp, fl = self.n, self._logprob, self._floor_log
        if len(text) < n:
            # Too short to contain a single n-gram. Use -inf (a neutral
            # "cannot score" sentinel) rather than 0.0, which would outrank
            # every legitimate (negative) score and wrongly win comparisons.
            return -math.inf
        total = 0.0
        for i in range(len(text) - n + 1):
            total += lp.get(text[i : i + n], fl)
        return total

    def score_avg(self, text: str) -> float:
        """Per-n-gram average score — comparable across different lengths.

        This is the value optimisers should maximise.
        """
        text = clean_text(text)
        if len(text) < self.n:
            return -math.inf
        return self.score(text) / (len(text) - self.n + 1)

    # -- persistence ---------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "n": self.n,
            "total": self._total,
            "logprob": self._logprob,
        }

    @classmethod
    def from_dict(cls, data: dict) -> NgramModel:
        m = cls(n=int(data["n"]))
        m._total = int(data["total"])
        m._logprob = {k: float(v) for k, v in data["logprob"].items()}
        m._floor_log = math.log10(_FLOOR_FRACTION / m._total) if m._total else -1.0
        return m

    def save(self, path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), separators=(",", ":")), encoding="utf-8"
        )

    @classmethod
    def load(cls, path) -> NgramModel:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def load_model(path=None) -> NgramModel:
    """Load the bundled English quadgram model (or the one at *path*)."""
    if path is None:
        data = importlib.resources.files("ciphersleuth").joinpath("data/ngrams")
        for name in ("english_4grams.json", "english_quadgrams.json"):
            candidate = data.joinpath(name)
            if candidate.is_file():
                return NgramModel.load(candidate)
        raise FileNotFoundError(
            f"No bundled n-gram model found in {data}. Run "
            "scripts/build_ngrams.py on a corpus first."
        )
    return NgramModel.load(path)


def _bigram_dir():
    """Absolute path to the bundled English bigram model (used by Playfair)."""
    return importlib.resources.files("ciphersleuth").joinpath(
        "data/ngrams/english_2grams.json"
    )


def monogram_frequencies(text: str) -> list[float]:
    """Return a 26-length list of letter frequencies in *text* (A..Z order)."""
    counts = Counter(clean_text(text))
    total = sum(counts.values()) or 1
    return [counts[ch] / total for ch in ALPHABET]
