"""Classical cipher primitives: encipher, decipher, and automatic attacks.

Every cipher in this module is *historic* — Caesar, Atbash, affine, Vigenère,
simple substitution, rail fence, columnar transposition, Playfair, Bacon,
homophonic. None of them offer real security today; they are studied for
history, puzzles, and as gentle introductions to cryptanalysis. They are
exactly the kind of scheme that this toolkit can be pointed at and *break*
automatically.

Each cipher is a class exposing:

* ``name``           — human-readable identifier.
* ``encipher(text)`` — plaintext -> ciphertext.
* ``decipher(text)`` — ciphertext -> plaintext (requires the key).
* ``attack(text, model, **opts)`` — attempt to recover plaintext with no key.

``attack`` returns an :class:`AttackResult`. The language ``model`` is an
:class:`~ciphersleuth.ngram.NgramModel` used to score candidate plaintexts.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass, field

from .ngram import ALPHABET, ALPHABET_SIZE, NgramModel, clean_text, monogram_frequencies
from .optim import genetic, hillclimb, recombination, simulated_annealing

__all__ = [
    "CIPHERS",
    "Affine",
    "Atbash",
    "AttackResult",
    "Bacon",
    "Caesar",
    "Columnar",
    "Homophonic",
    "Playfair",
    "RailFence",
    "SimpleColumnar",
    "Substitution",
    "Vigenere",
    "get_cipher",
]


@dataclass
class AttackResult:
    """The outcome of an automated attack on a ciphertext."""

    cipher: str                      # cipher name that produced this
    plaintext: str                   # recovered plaintext (A-Z, uppercase)
    key: object = None               # recovered key (cipher-specific)
    score: float = float("-inf")     # language-model score of the plaintext
    method: str = ""                 # short note on how it was broken
    #: extra diagnostics the caller may want (e.g. detected key length)
    details: dict = field(default_factory=dict)

    def __str__(self) -> str:
        head = f"[{self.cipher}] score={self.score:.3f} key={self.key!r}"
        if self.method:
            head += f" ({self.method})"
        return f"{head}\n{self.plaintext}"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _chr_shift(text: str, shift: int) -> str:
    return "".join(
        ALPHABET[(ord(ch) - 65 + shift) % ALPHABET_SIZE] if "A" <= ch <= "Z" else ch
        for ch in text.upper()
    )


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _modinv(a: int, m: int) -> int:
    # modular inverse of a mod m (m prime-power not required; a coprime to m)
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"{a} is not invertible mod {m}")


def _chi2(observed: list[float], expected: list[float]) -> float:
    return sum((o - e) ** 2 / e for o, e in zip(observed, expected))


def _index_of_coincidence(text: str) -> float:
    counts = {c: 0 for c in ALPHABET}
    total = 0
    for ch in clean_text(text):
        counts[ch] += 1
        total += 1
    if total < 2:
        return 0.0
    pairs = sum(n * (n - 1) for n in counts.values())
    return pairs / (total * (total - 1))


def _kasiski_key_lengths(text: str, max_len: int = 20) -> list[int]:
    """Estimate Vigenère key lengths from repeated substrings (Kasiski test).

    Repeated 3+ character sequences are more likely to align to key boundaries;
    the gaps between repeats share the key length as a factor. We tally factor
    votes and return the most frequent key lengths first.
    """
    clean = clean_text(text)
    scores: dict[int, int] = {}
    seen: set[str] = set()
    for length in (3, 4, 5):
        for i in range(len(clean) - length):
            gram = clean[i : i + length]
            if gram in seen:
                continue
            # find all occurrences
            start = clean.find(gram, i + 1)
            while start != -1:
                gap = start - i
                for f in range(2, max_len + 1):
                    if gap % f == 0:
                        scores[f] = scores.get(f, 0) + 1
                start = clean.find(gram, start + 1)
            seen.add(gram)
    return [k for k, _ in sorted(scores.items(), key=lambda kv: -kv[1])]


def _friedman_key_length(text: str) -> float:
    """Estimate Vigenère key length from the index of coincidence (Friedman).

    Standard Friedman formula::

        m = N·(kp − kr) / (IC·(N − 1) + kp − N·kr)

    where ``kp ≈ 0.0667`` (English monographic coincidence), ``kr = 1/26``
    (random coincidence), ``N`` is the text length and ``IC`` its index of
    coincidence. For random text (IC ≈ kr) this grows toward ``N``; for
    monoalphabetic English (IC ≈ kp) it collapses to 1. Clamped to >= 1.
    """
    ic = _index_of_coincidence(text)
    N = len(clean_text(text))
    if N < 2:
        return 1.0
    kp, kr = 0.0667, 1.0 / ALPHABET_SIZE
    denom = ic * (N - 1) + kp - N * kr
    if abs(denom) < 1e-12:
        return 1.0
    return max(1.0, N * (kp - kr) / denom)


#: Reference English monogram frequencies (A-Z), used by frequency-based attacks.
ENGLISH_FREQS = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
]


#: Bacon cipher 5-bit mapping (A-Z -> 0/1 string).
_BACON_MAP = {ALPHABET[i]: format(i, "05b") for i in range(26)}


def _best_caesar_shift(text: str) -> tuple[int, float]:
    """Return the shift (0..25) whose decoding best matches English monograms."""
    freqs = monogram_frequencies(text)
    best, best_score = 0, float("inf")
    for shift in range(ALPHABET_SIZE):
        rotated = freqs[shift:] + freqs[:shift]
        score = _chi2(rotated, ENGLISH_FREQS)
        if score < best_score:
            best, best_score = shift, score
    return best, best_score


# --------------------------------------------------------------------------
# ciphers
# --------------------------------------------------------------------------

class Caesar:
    name = "caesar"

    @staticmethod
    def encipher(text: str, shift: int = 3) -> str:
        return _chr_shift(text, shift % ALPHABET_SIZE)

    @staticmethod
    def decipher(text: str, shift: int = 3) -> str:
        return _chr_shift(text, (-shift) % ALPHABET_SIZE)

    @staticmethod
    def attack(text: str, model, **opts) -> AttackResult:
        best_shift, _ = _best_caesar_shift(text)
        best_score = float("-inf")
        best_pt = ""
        for shift in range(ALPHABET_SIZE):
            pt = Caesar.decipher(text, shift)
            s = model.score_avg(pt)
            if s > best_score:
                best_score, best_pt, best_shift = s, pt, shift
        return AttackResult(
            "caesar", best_pt, key=best_shift, score=best_score,
            method="brute-force all 26 shifts, scored by n-gram model",
        )


class Atbash:
    name = "atbash"

    @staticmethod
    def encipher(text: str) -> str:
        return "".join(
            ALPHABET[ALPHABET_SIZE - 1 - (ord(ch) - 65)] if "A" <= ch <= "Z" else ch
            for ch in text.upper()
        )

    @staticmethod
    def decipher(text: str) -> str:
        return Atbash.encipher(text)

    @staticmethod
    def attack(text: str, model, **opts) -> AttackResult:
        pt = Atbash.decipher(text)
        return AttackResult("atbash", pt, key="atbash",
                            score=model.score_avg(pt), method="fixed substitution")


class Affine:
    name = "affine"

    @staticmethod
    def _transform(text: str, a: int, b: int) -> str:
        out = []
        for ch in text.upper():
            if not ("A" <= ch <= "Z"):
                out.append(ch)
                continue
            idx = ord(ch) - 65
            out.append(ALPHABET[(a * idx + b) % ALPHABET_SIZE])
        return "".join(out)

    @staticmethod
    def encipher(text: str, a: int = 5, b: int = 8) -> str:
        return Affine._transform(text, a % ALPHABET_SIZE, b % ALPHABET_SIZE)

    @staticmethod
    def decipher(text: str, a: int = 5, b: int = 8) -> str:
        a_inv = _modinv(a % ALPHABET_SIZE, ALPHABET_SIZE)
        return Affine._transform(text, a_inv, (-a_inv * b) % ALPHABET_SIZE)

    @staticmethod
    def attack(text: str, model, **opts) -> AttackResult:
        best = None
        for a in range(1, ALPHABET_SIZE):
            if _gcd(a, ALPHABET_SIZE) != 1:
                continue
            for b in range(ALPHABET_SIZE):
                pt = Affine.decipher(text, a, b)
                s = model.score_avg(pt)
                if best is None or s > best[0]:
                    best = (s, pt, (a, b))
        return AttackResult("affine", best[1], key=best[2], score=best[0],
                            method="brute-force 12x26 valid keys")


class Vigenere:
    name = "vigenere"

    @staticmethod
    def encipher(text: str, key: str = "KEY") -> str:
        key = clean_text(key) or "A"
        out = []
        i = 0
        for ch in text.upper():
            if not ("A" <= ch <= "Z"):
                out.append(ch)
                continue
            shift = ord(key[i % len(key)]) - 65
            out.append(ALPHABET[(ord(ch) - 65 + shift) % ALPHABET_SIZE])
            i += 1
        return "".join(out)

    @staticmethod
    def decipher(text: str, key: str = "KEY") -> str:
        key = clean_text(key) or "A"
        out = []
        i = 0
        for ch in text.upper():
            if not ("A" <= ch <= "Z"):
                out.append(ch)
                continue
            shift = ord(key[i % len(key)]) - 65
            out.append(ALPHABET[(ord(ch) - 65 - shift) % ALPHABET_SIZE])
            i += 1
        return "".join(out)

    @staticmethod
    def _recover_key(text: str, key_len: int, model) -> str:
        """Recover a Vigenère key of length ``key_len`` by coordinate ascent.

        Start from a frequency-seeded guess, then repeatedly optimise one key
        letter at a time (all 26 candidates, others fixed) against the full
        quadgram score of the decoded text, until no letter improves. This is
        the classic, robust way to break Vigenère once the key length is known.
        """
        clean = clean_text(text)
        columns = [clean[i::key_len] for i in range(key_len)]
        # seed each position with the shift that best matches English monograms
        key = [_best_caesar_shift(col)[0] % ALPHABET_SIZE for col in columns]

        def decode_key(shifts) -> str:
            k = "".join(ALPHABET[s % ALPHABET_SIZE] for s in shifts)
            return Vigenere.decipher(text, k)

        improved = True
        while improved:
            improved = False
            for pos in range(key_len):
                original = key[pos]
                best_shift, best_score = original, float("-inf")
                for shift in range(ALPHABET_SIZE):
                    key[pos] = shift
                    s = model.score_avg(decode_key(key))
                    if s > best_score:
                        best_score, best_shift = s, shift
                if best_shift != original:
                    improved = True
                key[pos] = best_shift  # always restore the best value
        return "".join(ALPHABET[s % ALPHABET_SIZE] for s in key)

    @staticmethod
    def attack(text: str, model, max_key_len: int = 20, **opts) -> AttackResult:
        clean = clean_text(text)
        # 1) hypothesise key lengths from Kasiski and Friedman
        candidates: list[int] = []
        kasiski = _kasiski_key_lengths(clean, max_len=max_key_len)
        candidates.extend(kasiski)
        fried = max(1, round(_friedman_key_length(clean)))
        candidates.append(fried)
        candidates.extend([2, 3, 4, 5, 6, 7, 8])
        # de-duplicate preserving order
        seen, ordered = set(), []
        for c in candidates:
            if 1 <= c <= max_key_len and c not in seen:
                seen.add(c)
                ordered.append(c)

        best = None
        for key_len in ordered:
            # longer keys have more degrees of freedom and overfit; require a
            # modest minimum of text per key letter before bothering.
            if len(clean) < key_len * 8:
                continue
            key = Vigenere._recover_key(text, key_len, model)
            pt = Vigenere.decipher(text, key)
            s = model.score_avg(pt)
            if best is None or s > best[0]:
                best = (s, pt, key, key_len)
        if best is None:
            return AttackResult(
                "vigenere", clean, key="", score=float("-inf"),
                method="no key length had enough text to attack",
            )
        return AttackResult(
            "vigenere", best[1], key=best[2], score=best[0],
            method="Kasiski+Friedman key-length estimate, then coordinate ascent on key",
            details={"key_length": best[3]},
        )


class Substitution:
    name = "substitution"

    @staticmethod
    def encipher(text: str, key: str = ALPHABET) -> str:
        """key[i] is the letter that plaintext letter i maps to."""
        key = clean_text(key).ljust(ALPHABET_SIZE, ALPHABET[0])[:ALPHABET_SIZE]
        if len(set(key)) != ALPHABET_SIZE:
            raise ValueError(
                "Substitution key must map each letter to a distinct letter "
                "(a permutation of A-Z). Duplicates: "
                + ",".join(sorted(c for c in set(key) if key.count(c) > 1))
            )
        table = {ALPHABET[i]: key[i] for i in range(ALPHABET_SIZE)}
        return "".join(table.get(ch, ch) for ch in text.upper())

    @staticmethod
    def decipher(text: str, key: str = ALPHABET) -> str:
        key = clean_text(key).ljust(ALPHABET_SIZE, ALPHABET[0])[:ALPHABET_SIZE]
        if len(set(key)) != ALPHABET_SIZE:
            raise ValueError(
                "Substitution key must map each letter to a distinct letter "
                "(a permutation of A-Z). Duplicates: "
                + ",".join(sorted(c for c in set(key) if key.count(c) > 1))
            )
        inv = {key[i]: ALPHABET[i] for i in range(ALPHABET_SIZE)}
        return "".join(inv.get(ch, ch) for ch in text.upper())

    @staticmethod
    def attack(text: str, model, restarts: int = 4, anneal_iters: int = 30000,
               optimizer: str = "sa", random_seed: int | None = None, **opts) -> AttackResult:
        """Break a simple substitution cipher via simulated annealing + hill climbing.

        The classic technique: start from a frequency-seeded key, then search the
        space of 26-letter permutations, scoring each candidate plaintext against
        the n-gram language model. Simulated annealing tolerates the temporarily
        worse moves needed to escape the many local maxima this landscape has.
        """
        # 1) seed: map the most frequent ciphertext letters to the most frequent
        #    English letters, then complete into a valid permutation.
        freqs = monogram_frequencies(text)
        ranked_ct = [ALPHABET[i] for i in sorted(range(ALPHABET_SIZE), key=lambda i: -freqs[i])]
        ranked_en = sorted(ALPHABET, key=lambda c: -ENGLISH_FREQS[ord(c) - 65])
        init = [None] * ALPHABET_SIZE
        for ct_letter, en_letter in zip(ranked_ct, ranked_en):
            init[ord(ct_letter) - 65] = en_letter
        used = {v for v in init if v is not None}
        missing = [c for c in ALPHABET if c not in used]
        key0 = []
        for v in init:
            if v is None:
                key0.append(missing.pop(0))
            else:
                key0.append(v)
        key = "".join(key0)

        def score(key):
            return model.score_avg(Substitution.decipher(text, key))

        rng = random.Random(random_seed)

        def mutate(key, rng):
            k = list(key)
            i, j = rng.randrange(0, 26), rng.randrange(0, 26)
            while j == i:
                j = rng.randrange(0, 26)
            k[i], k[j] = k[j], k[i]
            return "".join(k)

        best_key, best_score = key, score(key)
        if optimizer == "genetic":
            # a population around the frequency-seeded key, evolved by
            # order-preserving crossover + mutation
            pop = [key]
            for _ in range(9):
                k = list(key)
                for _ in range(2):
                    i, j = rng.randrange(0, 26), rng.randrange(0, 26)
                    k[i], k[j] = k[j], k[i]
                pop.append("".join(k))
            gk, gs = genetic(
                pop, score, mutate, crossover=recombination,
                generations=300, keep=0.2, mutation_rate=0.2,
                random_seed=rng.randint(0, 2**32),
            )
            gk, gs = hillclimb(gk, mutate, score, max_iters=4000, patience=600,
                               random_seed=rng.randint(0, 2**32))
            if gs > best_score:
                best_key, best_score = gk, gs
        else:
            # 2) a few hill-climbing runs, each started from a randomised key
            for r in range(restarts):
                if r > 0:
                    k = list(best_key)
                    for _ in range(3):  # perturb a few pairs for a fresh basin
                        i, j = rng.randrange(0, 26), rng.randrange(0, 26)
                        k[i], k[j] = k[j], k[i]
                    start = "".join(k)
                else:
                    start = best_key
                k, s = hillclimb(start, mutate, score, max_iters=3000, patience=250,
                                 random_seed=rng.randint(0, 2**32))
                if s > best_score:
                    best_key, best_score = k, s
            # 3) simulated annealing for the harder escape from deep local maxima
            k, s = simulated_annealing(
                best_key, mutate, score, iters=anneal_iters, t_start=1.0, t_end=0.005,
                random_seed=rng.randint(0, 2**32),
            )
            if s > best_score:
                best_key, best_score = k, s
        pt = Substitution.decipher(text, best_key)
        return AttackResult("substitution", pt, key=best_key, score=best_score,
                            method="frequency-seeded SA + hill-climb over key permutation")


class RailFence:
    name = "rail_fence"

    @staticmethod
    def encipher(text: str, rails: int = 3) -> str:
        clean = clean_text(text)
        if rails <= 1 or len(clean) == 0:
            return clean
        fence = [[] for _ in range(rails)]
        row, down = 0, True
        for ch in clean:
            fence[row].append(ch)
            if down:
                if row == rails - 1:
                    down, row = False, row - 1
                else:
                    row += 1
            else:
                if row == 0:
                    down, row = True, row + 1
                else:
                    row -= 1
        return "".join("".join(r) for r in fence)

    @staticmethod
    def decipher(text: str, rails: int = 3) -> str:
        clean = clean_text(text)
        if rails <= 1 or len(clean) == 0:
            return clean
        # reconstruct the zigzag pattern of positions
        pattern = []
        row, down = 0, True
        for _ in clean:
            pattern.append(row)
            if down:
                if row == rails - 1:
                    down, row = False, row - 1
                else:
                    row += 1
            else:
                if row == 0:
                    down, row = True, row + 1
                else:
                    row -= 1
        # distribute ciphertext characters back to rails in order
        rail_len = [0] * rails
        for r in pattern:
            rail_len[r] += 1
        rails_text = []
        idx = 0
        for r in range(rails):
            rails_text.append(clean[idx:idx + rail_len[r]])
            idx += rail_len[r]
        cursor = [0] * rails
        out = []
        for r in pattern:
            out.append(rails_text[r][cursor[r]])
            cursor[r] += 1
        return "".join(out)

    @staticmethod
    def attack(text: str, model, max_rails: int = 15, **opts) -> AttackResult:
        clean = clean_text(text)
        best = None
        for rails in range(2, min(max_rails, len(clean)) + 1):
            pt = RailFence.decipher(text, rails)
            s = model.score_avg(pt)
            if best is None or s > best[0]:
                best = (s, pt, rails)
        if best is None:
            return AttackResult(
                "rail_fence", clean, key=1, score=float("-inf"),
                method="text too short for any rail count",
            )
        return AttackResult("rail_fence", best[1], key=best[2], score=best[0],
                            method=f"try all rail counts 2..{min(max_rails, len(clean))}")


class SimpleColumnar:
    """Unkeyed columnar transposition: write rows, read columns in order.

    The key only sets the column *width*; columns are never reordered. Kept
    under its own name so it is not mistaken for a keyed columnar cipher.
    """

    name = "simple_columnar"

    @staticmethod
    def encipher(text: str, key: str = "KEY") -> str:
        clean = clean_text(text)
        width = len(clean_text(key)) or 1
        rows = (len(clean) + width - 1) // width
        padded = clean.ljust(rows * width, "X")
        grid = [list(padded[i * width:(i + 1) * width]) for i in range(rows)]
        out = []
        for col in range(width):
            for row in range(rows):
                out.append(grid[row][col])
        return "".join(out)

    @staticmethod
    def decipher(text: str, key: str = "KEY") -> str:
        clean = clean_text(text)
        width = len(clean_text(key)) or 1
        rows = (len(clean) + width - 1) // width
        col_len = [len(clean[i::width]) for i in range(width)]
        cols = []
        idx = 0
        for c in range(width):
            cols.append(clean[idx:idx + col_len[c]])
            idx += col_len[c]
        out = []
        for r in range(rows):
            for c in range(width):
                if r < len(cols[c]):
                    out.append(cols[c][r])
        return "".join(out)

    @staticmethod
    def attack(text: str, model, max_width: int = 12, **opts) -> AttackResult:
        """Try every plausible column width; score the identity-order decode.

        A simple (unkeyed) columnar transposition writes row-by-row into
        ``width`` columns and reads them top-to-bottom with no reordering, so
        breaking it is just a search over the width.
        """
        clean = clean_text(text)
        best = None
        for width in range(2, min(max_width, len(clean)) + 1):
            pt = SimpleColumnar.decipher(text, "A" * width)
            s = model.score_avg(pt)
            if best is None or s > best[0]:
                best = (s, pt, width)
        if best is None:
            return AttackResult(
                "simple_columnar", clean, key="", score=float("-inf"),
                method="text too short for any column width",
            )
        return AttackResult("simple_columnar", best[1], key=best[2], score=best[0],
                            method="try every column width; identity column order")


class Columnar:
    """Keyed columnar transposition: write rows, read columns in key order."""

    name = "columnar"

    @staticmethod
    def _transpose(clean: str, width: int, order) -> str:
        rows = (len(clean) + width - 1) // width
        padded = clean.ljust(rows * width, "X")
        grid = [list(padded[i * width:(i + 1) * width]) for i in range(rows)]
        out = []
        for col in order:
            for row in range(rows):
                out.append(grid[row][col])
        return "".join(out)

    @staticmethod
    def _restore(clean: str, width: int, order) -> str:
        rows = (len(clean) + width - 1) // width
        cols = [None] * width
        idx = 0
        for col in order:
            cols[col] = clean[idx:idx + rows]
            idx += rows
        out = []
        for r in range(rows):
            for c in range(width):
                if r < len(cols[c]):
                    out.append(cols[c][r])
        return "".join(out).rstrip("X")

    @staticmethod
    def encipher(text: str, key: str = "KEY") -> str:
        clean = clean_text(text)
        width = len(clean_text(key)) or 1
        return Columnar._transpose(clean, width, _column_order(key))

    @staticmethod
    def decipher(text: str, key: str = "KEY") -> str:
        clean = clean_text(text)
        width = len(clean_text(key)) or 1
        return Columnar._restore(clean, width, _column_order(key))

    @staticmethod
    def attack(text: str, model, max_width: int = 7, **opts) -> AttackResult:
        """Best-effort keyed columnar break: search width and column ordering.

        For each plausible width we try every column read-order (permutation),
        score the decode and keep the best. The true key maps to exactly one
        such ordering, so this is exact for the encipherment convention here;
        the factorial cost caps the width at ``max_width``.
        """
        clean = clean_text(text)
        best = None
        limit = min(max_width, len(clean))
        for width in range(2, limit + 1):
            for order in itertools.permutations(range(width)):
                pt = Columnar._restore(clean, width, order)
                s = model.score_avg(pt)
                if best is None or s > best[0]:
                    best = (s, pt, (width, order))
        if best is None:
            return AttackResult(
                "columnar", clean, key="", score=float("-inf"),
                method="text too short for any column width",
            )
        return AttackResult("columnar", best[1], key=best[2], score=best[0],
                            method=f"brute-force widths 2..{limit} x all column orderings")


def _column_order(key: str) -> list[int]:
    """Column read/write order for a keyed columnar transposition.

    Columns are reordered by the alphabetical rank of the key letters, with
    ties broken by original position — the standard keyed columnar convention.
    """
    width = len(clean_text(key)) or 1
    base = clean_text(key).ljust(width, "A")[:width]
    return sorted(range(width), key=lambda i: (base[i], i))


class Playfair:
    name = "playfair"

    @staticmethod
    def _square(key: str = "PLAYFAIR") -> list[list[str]]:
        key = clean_text(key).replace("J", "I")
        seen = []
        for ch in (key + ALPHABET):
            if ch == "J":
                ch = "I"
            if ch not in seen:
                seen.append(ch)
        return [seen[i:i + 5] for i in range(0, 25, 5)]

    @staticmethod
    def _digraphs(clean: str) -> list[str]:
        """Split into digraphs, splitting double letters with a filler X."""
        dg = []
        i = 0
        while i < len(clean):
            a = clean[i]
            if i + 1 < len(clean) and clean[i + 1] != a:
                b = clean[i + 1]
                i += 2
            else:
                b = "X" if a != "X" else "Q"
                i += 1
            dg.append(a + b)
        return dg

    @staticmethod
    def encipher(text: str, key: str = "PLAYFAIR") -> str:
        clean = clean_text(text).replace("J", "I")
        sq = Playfair._square(key)
        pos = {sq[r][c]: (r, c) for r in range(5) for c in range(5)}
        out = []
        for digraph in Playfair._digraphs(clean):
            a, b = digraph[0], digraph[1]
            ar, ac = pos[a]
            br, bc = pos[b]
            if ar == br:
                out.append(sq[ar][(ac + 1) % 5])
                out.append(sq[br][(bc + 1) % 5])
            elif ac == bc:
                out.append(sq[(ar + 1) % 5][ac])
                out.append(sq[(br + 1) % 5][bc])
            else:
                out.append(sq[ar][bc])
                out.append(sq[br][ac])
        return "".join(out)

    @staticmethod
    def decipher(text: str, key: str = "PLAYFAIR") -> str:
        clean = clean_text(text).replace("J", "I")
        sq = Playfair._square(key)
        pos = {sq[r][c]: (r, c) for r in range(5) for c in range(5)}
        out = []
        # ciphertext must be even-length; a trailing odd letter is malformed and
        # is dropped rather than raised on.
        for i in range(0, len(clean) - 1, 2):
            a, b = clean[i], clean[i + 1]
            ar, ac = pos[a]
            br, bc = pos[b]
            if ar == br:
                out.append(sq[ar][(ac - 1) % 5])
                out.append(sq[br][(bc - 1) % 5])
            elif ac == bc:
                out.append(sq[(ar - 1) % 5][ac])
                out.append(sq[(br - 1) % 5][bc])
            else:
                out.append(sq[ar][bc])
                out.append(sq[br][ac])
        return "".join(out)

    @staticmethod
    def attack(text: str, model, iters: int = 60000, restarts: int = 2,
               random_seed: int | None = None, **opts) -> AttackResult:
        """Recover the Playfair key square via simulated annealing on a bigram model.

        Playfair encrypts *digraphs*, so a bigram (2-letter) language model is a
        better scoring function than quadgrams here. This is **best-effort**:
        automatic Playfair breaking is a hard problem and typically only
        resolves long ciphertexts (several hundred characters or more) with
        favourable luck. On short ciphertexts it often stalls and the tool will
        report whatever candidate scored highest.
        """
        from .ngram import _bigram_dir
        bigram = NgramModel.load(_bigram_dir())
        clean = clean_text(text).replace("J", "I")
        letters = list("ABCDEFGHIKLMNOPQRSTUVWXYZ")  # 25 letters, I/J merged

        def decrypt(ordering):
            sq = [ordering[i:i + 5] for i in range(0, 25, 5)]
            pos = {sq[r][c]: (r, c) for r in range(5) for c in range(5)}
            out = []
            # tolerate a trailing odd letter rather than raising on malformed input
            for i in range(0, len(clean) - 1, 2):
                a, b = clean[i], clean[i + 1]
                ar, ac = pos[a]
                br, bc = pos[b]
                if ar == br:
                    out.append(sq[ar][(ac - 1) % 5]); out.append(sq[br][(bc - 1) % 5])
                elif ac == bc:
                    out.append(sq[(ar - 1) % 5][ac]); out.append(sq[(br - 1) % 5][bc])
                else:
                    out.append(sq[ar][bc]); out.append(sq[br][ac])
            return "".join(out)

        def score(ordering):
            return bigram.score_avg(decrypt(ordering))

        rng = random.Random(random_seed)

        def mutate(ordering, rng):
            o = list(ordering)
            i, j = rng.randrange(0, 25), rng.randrange(0, 25)
            o[i], o[j] = o[j], o[i]
            return o

        best_ord, best_s = None, float("-inf")
        for r in range(restarts):
            o, s = simulated_annealing(
                letters, mutate, score, iters=iters, t_start=2.0, t_end=0.005,
                random_seed=rng.randint(0, 2**32),
            )
            o, s = hillclimb(o, mutate, score, max_iters=4000, patience=600,
                             random_seed=rng.randint(0, 2**32))
            if s > best_s:
                best_ord, best_s = o, s
        if best_ord is None:  # restarts=0 (or all restarts failed): nothing decoded
            best_ord = list(letters)
            best_s = float("-inf")
        pt = decrypt(best_ord)
        return AttackResult("playfair", pt, key="".join(best_ord), score=best_s,
                            method="simulated annealing over key square, bigram scoring")


class Bacon:
    name = "bacon"

    @staticmethod
    def encipher(text: str) -> str:
        out = []
        for ch in clean_text(text):
            if ch in _BACON_MAP:
                out.append(_BACON_MAP[ch])
        return "".join(out)

    @staticmethod
    def decipher(text: str) -> str:
        # normalise either A/B or 0/1 representation to 0/1, then group by 5
        t = text.upper().replace("B", "1").replace("A", "0")
        clean = "".join(c for c in t if c in "01")
        out = []
        for i in range(0, len(clean) - 4, 5):
            value = int(clean[i:i + 5], 2)
            # five bits encode 0..31 but the alphabet has only 26 letters;
            # values >= 26 are invalid and mapped to '?' rather than raising.
            out.append(ALPHABET[value] if value < ALPHABET_SIZE else "?")
        return "".join(out)

    @staticmethod
    def attack(text: str, model, **opts) -> AttackResult:
        pt = Bacon.decipher(text)
        return AttackResult("bacon", pt, score=model.score_avg(pt),
                            method="binary decode (A/B -> 0/1 -> 5-bit letters)")


class Homophonic:
    name = "homophonic"

    @staticmethod
    def encipher(text: str) -> str:
        """Encode to a toy homophonic code: each letter becomes its 2-digit code.

        ``A``->``01`` .. ``Z``->``26``, space-separated. This is a simple,
        invertible homophone code that pairs with :meth:`decipher`.
        """
        return " ".join(f"{ord(ch) - 64:02d}" for ch in clean_text(text))

    @staticmethod
    def decipher(text: str) -> str:
        """Invert a toy homophonic code produced by :meth:`encipher`.

        Tokens that are not a valid 1..26 code are skipped.
        """
        out = []
        for tok in text.strip().split():
            if tok.isdigit() and 1 <= int(tok) <= ALPHABET_SIZE:
                out.append(ALPHABET[int(tok) - 1])
        return "".join(out)

    @staticmethod
    def attack(text: str, model, **opts) -> AttackResult:
        """Frequency-based solve: assign ciphertext symbols to letters by frequency.

        Works best when symbol frequency ranks with letter frequency (common in
        toy homophonic codes). Not guaranteed for adversarial homophones.
        """
        # treat whitespace-separated tokens as symbols if present, else chars
        if len(text) > 0 and " " in text.strip():
            tokens = text.strip().split()
        else:
            tokens = list(text)
        from collections import Counter
        counts = Counter(tokens)
        ranked_tokens = [t for t, _ in counts.most_common()]
        ranked_letters = sorted(ALPHABET, key=lambda c: -ENGLISH_FREQS[ord(c) - 65])
        mapping = {t: lett for t, lett in zip(ranked_tokens, ranked_letters)}
        pt = "".join(mapping.get(t, "?") for t in tokens)
        return AttackResult("homophonic", pt, key=mapping, score=model.score_avg(pt),
                            method="symbol frequency -> English letter frequency")


#: Registry of all known ciphers, keyed by name.
CIPHERS: dict[str, type] = {
    c.name: c
    for c in (
        Caesar, Atbash, Affine, Vigenere, Substitution, RailFence,
        SimpleColumnar, Columnar, Playfair, Bacon, Homophonic,
    )
}


def get_cipher(name: str):
    """Return the cipher class registered under *name*, or None."""
    return CIPHERS.get(name)
