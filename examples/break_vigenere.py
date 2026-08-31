"""Example: break a Vigenère cipher automatically, step by step.

Run:  python3 examples/break_vigenere.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ciphersleuth import break_cipher, fingerprint
from ciphersleuth import ciphers as C
from ciphersleuth.ngram import clean_text

# 1. A plaintext message worth hiding...
plain = (
    "The quick brown fox jumps over the lazy dog. Pack my box with five "
    "dozen liquor jugs, and how vexingly quick daft zebras jump. Sphinx of "
    "black quartz, judge my vow: the five boxing wizards jump quickly. "
    "We promptly judged antique ivory buckles for the next prize."
)

# 2. ...enciphered with a Vigenère key.
key = "CRYPTO"
ciphertext = C.Vigenere.encipher(plain, key)
print("Ciphertext:", ciphertext[:80], "...\n")

# 3. What does the fingerprint think it is?
print("=== fingerprint ===")
print(fingerprint(ciphertext))
print()

# 4. Just press the button.
print("=== break_cipher ===")
result = break_cipher(ciphertext)
print(f"Detected cipher : {result.cipher}")
print(f"Recovered key   : {result.key!r}")
print(f"Language score  : {result.score:.4f}")
print()
print("Recovered plaintext:")
print(result.plaintext[:160], "...")
print()

# 5. Verify how close we got.
recovered = clean_text(result.plaintext)
original = clean_text(plain)
acc = sum(1 for a, b in zip(recovered, original) if a == b) / len(original)
print(f"Accuracy: {acc * 100:.1f}%  (key recovered = {result.key == key})")
