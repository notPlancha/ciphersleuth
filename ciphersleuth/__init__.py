"""ciphersleuth — automatic cryptanalysis of classical ciphers.

Given a ciphertext, ``ciphersleuth`` fingerprints the likely cipher and then
breaks it with search-based optimization driven by an n-gram language model.
It targets *historical* ciphers (Caesar, Vigenère, substitution, transposition,
Playfair, …) and common encodings — the material of puzzles, CTFs and
cryptography classes. It does not attempt to break modern cryptographic
primitives.

Quick start::

    from ciphersleuth import break_cipher
    result = break_cipher("GUR PENML PBQR")
    print(result.plaintext)

"""

from .breaker import break_cipher, list_ciphers
from .detectors import fingerprint
from .ngram import NgramModel, load_model

__all__ = ["NgramModel", "break_cipher", "fingerprint", "list_ciphers", "load_model"]
__version__ = "1.0.0"
