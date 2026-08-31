<div align="center">

# 🔐 ciphersleuth

**Automatic cryptanalysis of classical ciphers.**

Feed it ciphertext → it fingerprints the cipher → then breaks it with
search-based optimisation driven by an n-gram language model.

*No key required. No modern cryptography. Just the good old codes.*

</div>

---

## What it is

`ciphersleuth` is a Python toolkit that tries to **automatically break a
ciphertext it has never seen** — given *only* the ciphertext, not the key.
It targets the *historical* ciphers you meet in puzzles, escape rooms, CTFs
and cryptography courses: Caesar, Vigenère, simple substitution, rail fence,
columnar transposition, Playfair, and a few more, plus the plain encodings
(binary, hex, Base64, Morse, ROT13) that are often layered on top.

It is *not* a tool for breaking modern cryptographic primitives. AES, RSA,
TLS, bcrypt and friends are deliberately and structurally out of scope. See
[Ethics & scope](#-ethics--scope).

The two ideas that make it work:

1. **Fingerprinting** — a battery of cheap statistical tests (index of
   coincidence, Kasiski, Friedman, chi-square, character-set detection) narrows
   the hundreds of possible schemes down to a short ranked shortlist.
2. **Language-model scoring** — of all the ways a ciphertext *could* decode,
   the one that reads most like natural English is almost always right. An
   n-gram model built from a public-domain corpus scores every candidate
   plaintext; hill-climbing, simulated annealing and genetic search then
   optimise the key against that score.

## Unique features

| Capability | What it means |
|---|---|
| **Automatic fingerprinting** | Don't tell it the cipher — it guesses from statistics, with evidence and confidence. |
| **Search-based key recovery** | Hill-climbing, simulated annealing *and* a genetic algorithm, all driven by an n-gram model. |
| **Cross-cipher scoring** | Every candidate is re-scored with the same model so results are directly comparable. |
| **Honest about difficulty** | Playfair & homophonic auto-break are clearly marked *best-effort*; short ciphertexts are handled conservatively instead of returning confident garbage. |
| **Your own language model** | Rebuild the n-gram table from any corpus with one command. |
| **Zero runtime dependencies** | Pure standard-library Python. |

## Quick start

```bash
git clone https://github.com/PiperFirefly/ciphersleuth.git
cd ciphersleuth

# break a ciphertext you know nothing about
python3 -m ciphersleuth.cli break "GUR PENML PBQR VF UVQQRA"

# or from Python
python3 -c "
from ciphersleuth import break_cipher
r = break_cipher('GUR PENML PBQR VF UVQQRA')
print(r.cipher, '|', r.plaintext)
"
```

## Installation

```bash
# from a checkout, run anywhere in the repo
python3 -m ciphersleuth.cli --help

# or install as a package (no third-party dependencies)
pip install .
pip install .[dev]      # adds pytest + ruff for development
```

Requires Python 3.9+.

## Command-line usage

```
ciphersleuth break "CIPHERTEXT ..."        # fingerprint + break
ciphersleuth fingerprint "CIPHERTEXT"      # just detect the likely cipher
ciphersleuth encipher caesar --key 3 "HI"  # encipher with a known cipher
ciphersleuth decipher vigenere --key SECRET "..."  # decipher with a key
ciphersleuth list                          # all supported ciphers/encodings
```

```console
$ python3 -m ciphersleuth.cli break "VYC FNWEB ZGHKP WMM CIOGQ DOST KFT EOBP BDZ OPU RWX TKMC QHLKEE"
Cipher : vigenere
Key    : 'CRYPTO'
Score  : -5.0317
Method : Kasiski+Friedman key-length estimate, then coordinate ascent on key
----------------------------------------
THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THE FIVE BOXING WIZARDS...
```

Read ciphertext from a file, restrict to specific ciphers, or raise the search
effort:

```bash
python3 -m ciphersleuth.cli break --file message.txt
python3 -m ciphersleuth.cli break --ciphers vigenere substitution "KYV..."
python3 -m ciphersleuth.cli break --restarts 8 "substitution-ciphertext..."
```

## Python API

```python
from ciphersleuth import break_cipher, fingerprint, NgramModel

# --- one call ---
result = break_cipher("VYC FNWEB ZGHKP WMM CIOGQ DOST KFT EOBP BDZ OPU RWX")
print(result.cipher)      # 'vigenere'
print(result.key)         # 'CRYPTO'
print(result.plaintext)   # 'THE QUICK BROWN FOX...'

# --- inspect the fingerprint ---
fp = fingerprint("VYC FNWEB ZGHKP WMM CIOGQ DOST KFT EOBP BDZ")
for name, confidence, evidence in fp.candidates:
    print(name, confidence, evidence)

# --- encipher / decipher with a known key ---
from ciphersleuth import ciphers as C
ct = C.Vigenere.encipher("HELLO WORLD", "KEY")
pt = C.Vigenere.decipher(ct, "KEY")

# --- score plaintext candidates with your own model ---
m = NgramModel(n=4)
m.build(["some English text", "more English text"])
m.finalize()
m.score_avg("WHICH DECODE LOOKS MOST LIKE ENGLISH")
```

### The `AttackResult`

Every attack returns an `AttackResult`:

| Field | Meaning |
|---|---|
| `cipher` | name of the cipher that produced this result |
| `plaintext` | recovered plaintext (uppercase A–Z, punctuation preserved) |
| `key` | recovered key (cipher-specific) |
| `score` | language-model score (higher = more English-like) |
| `method` | human-readable note on how it was broken |
| `details` | extra diagnostics, e.g. detected Vigenère key length |

## Supported schemes

### Ciphers (with automatic attack)

| Cipher | Encipher/Decipher | Auto-break | Notes |
|---|---|---|---|
| `caesar` | ✅ | ✅ **reliable** | brute-force all 26 shifts |
| `atbash` | ✅ | ✅ **reliable** | fixed substitution (involution) |
| `affine` | ✅ | ✅ **reliable** | brute-force the 12×26 valid keys |
| `vigenere` | ✅ | ✅ **reliable** | Kasiski+Friedman key length, coordinate ascent on key |
| `substitution` | ✅ | ✅ **reliable** | frequency-seeded SA + hill-climb over the key permutation (needs ~120+ chars) |
| `rail_fence` | ✅ | ✅ **reliable** | try all rail counts |
| `columnar` | ✅ | ✅ **reliable** | try all column widths |
| `bacon` | ✅ | ✅ | 5-bit A/B (or 0/1) code |
| `playfair` | ✅ | ⚠️ **best-effort** | bigram-scored SA over the 5×5 key square; resolves long ciphertexts, can stall on short ones |
| `homophonic` | — | ⚠️ **best-effort** | frequency-based symbol→letter solve |

### Encodings (auto-detected & stripped)

`binary`, `hex`, `base64`, `morse`, `rot13`.

> **Playfair & homophonic** are honest about being hard. Automatic Playfair
> key-square recovery is a known-hard problem; this toolkit attempts it and
> sometimes wins on long ciphertexts. When it can't, the tool reports the
> highest-scoring candidate rather than claiming a false success. Homophonic
> solving assumes symbols were assigned roughly by frequency.

## How it works

### 1. Fingerprinting

`detectors.py` runs cheap statistical tests:

* **Character-set detection** — is it only `0/1` (binary)? only `0-9`? only
  `A-F` (hex)? a `.`/`-` mix (Morse)? a Base64 alphabet? This instantly
  eliminates most of the search space.
* **Index of coincidence (IC)** — English monoalphabetic text sits near
  ~0.0667; polyalphabetic/transposition ciphertext is lower. IC alone separates
  the *monoalphabetic family* (Caesar/affine/substitution) from the
  *polyalphabetic/transposition family* (Vigenère/rail fence/columnar/Playfair).
* **Kasiski test & Friedman test** — both estimate a Vigenère key length from
  repeated substrings and the IC.
* **Chi-square vs English monograms** — how close the ciphertext's letter
  frequencies are to English's.

The output is a ranked shortlist: `[(name, confidence, evidence), ...]`.

### 2. The language model

`ngram.py` builds an n-gram model (default 4-grams) from plain text. To score
a candidate plaintext it sums the log-probabilities of its n-grams; unknown
n-grams get a small floor probability so a single unseen gram doesn't zero the
score. `score_avg` normalises per gram so candidates of different lengths are
comparable.

### 3. Optimising the key

`optim.py` provides three generic search engines that know nothing about
ciphers — they just move through a key space and maximise the language score:

* **Hill-climbing** with early-stop patience (workhorse for substitution).
* **Simulated annealing** — accepts occasionally-worse moves to escape local
  maxima (workhorse for Playfair).
* **A genetic algorithm** — population-based search with order-preserving
  crossover (useful for permutation keys).

A length guard keeps things honest: the more degrees of freedom a key has, the
more ciphertext it needs. Substitution needs ~120 characters, Playfair ~220;
on shorter input these are skipped rather than letting them "solve" short text
into plausible-sounding nonsense.

### 4. Cross-cipher scoring

Every candidate attack's result is **re-scored with the same quadgram model**
before comparison, so a Vigenère score is directly comparable to a substitution
score. The single best-scoring candidate wins.

## Building your own language model

The bundled model is built from public-domain English prose. To rebuild it — or
to build one for a different corpus or language — run:

```bash
python3 scripts/build_ngrams.py /path/to/corpus/*.txt            # quadgrams
python3 scripts/build_ngrams.py -n 2 /path/to/corpus/*.txt       # bigrams (Playfair)
python3 scripts/build_ngrams.py -n 3 /path/to/corpus/*.txt       # trigrams
```

### Corpus provenance

The bundled `data/ngrams/*.json` models were generated from three
**public-domain** works from [Project Gutenberg](https://www.gutenberg.org):

* *The Adventures of Sherlock Holmes* (A. Conan Doyle) — eBook 1661
* *Pride and Prejudice* (Jane Austen) — eBook 1342
* *Alice's Adventures in Wonderland* (Lewis Carroll) — eBook 11

No copyrighted text is redistributed — only the computed n-gram frequency
tables (46,368 quadgrams, 6,930 trigrams, 578 bigrams), which are themselves
non-expressive statistics.

## Project layout

```
ciphersleuth/
├── ciphersleuth/
│   ├── ngram.py        # n-gram language model (build, score, persist)
│   ├── detectors.py    # cipher fingerprinting (IC, Kasiski, Friedman, charset)
│   ├── ciphers.py      # cipher primitives: encipher / decipher / attack
│   ├── optim.py        # hill-climb, simulated annealing, genetic search
│   ├── encodings.py    # binary / hex / base64 / morse / rot13
│   ├── breaker.py      # orchestration + cross-cipher scoring
│   └── cli.py          # command-line interface
├── data/ngrams/        # precomputed English n-gram models
├── scripts/build_ngrams.py
├── examples/           # runnable worked examples
└── tests/              # pytest suite
```

## Development

```bash
make test    # run the test suite (pytest)
make lint    # run ruff
make demo    # run the Vigenère worked example
```

30 tests cover round-trips, automatic breaking of every cipher, fingerprinting,
encoding detection and the n-gram model.

## Ethics & scope

`ciphersleuth` works **only** on historical/classical ciphers and simple
encodings. These are studied because they are *weak* — they were never designed
to resist modern cryptanalysis, and nearly all are trivially breakable by hand
or with a pen. The tool:

* **does not** target, attack, or weaken any modern cryptographic system
  (AES, RSA, TLS, bcrypt, etc.), which this software is incapable of touching;
* is intended for **education, puzzles, CTF competitions, and historical
  research**;
* ships zero credentials, zero network calls, and zero telemetry — it does not
  "phone home", collect data, or transmit anything.

If you need to protect real information, use a modern, audited cryptography
library. This is a tool for *unravelling the old secrets*, not for securing
new ones.

## License

[MIT](LICENSE) © Piper Firefly.
