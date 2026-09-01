#!/usr/bin/env python3
"""Build the n-gram language model from a plain-text corpus.

Run from the repository root::

    python3 scripts/build_ngrams.py /path/to/corpus/*.txt

The output is written to ``data/ngrams/english_<n>grams.json`` (overwriting
the bundled model by default). The bundled model was built from public-domain
texts (Project Gutenberg: The Adventures of Sherlock Holmes, Pride and
Prejudice, Alice's Adventures in Wonderland) — see README.md for provenance.

You can point this at any corpus you like. For best cryptanalysis results use
several hundred kilobytes or more of clean English prose.

Options:
  -n, --n      n-gram order (default 4)
  -o, --out    output path (default data/ngrams/english_<n>grams.json)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ciphersleuth.ngram import NgramModel


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs", nargs="+", help="corpus files (plain text)")
    p.add_argument("-n", "--n", type=int, default=4, help="n-gram order")
    p.add_argument("-o", "--out", default=None, help="output JSON path")
    args = p.parse_args()

    out = args.out or (
        Path(__file__).parent.parent / "ciphersleuth" / "data" / "ngrams"
        / f"english_{args.n}grams.json"
    )

    model = NgramModel(n=args.n)
    total_chars = 0
    for path in args.inputs:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        model.add(text)
        total_chars += len(text)
        print(f"  added {Path(path).name} ({len(text):,} chars)")

    model.finalize()
    out.parent.mkdir(parents=True, exist_ok=True)
    model.save(out)
    print(f"\nBuilt {args.n}-gram model from {total_chars:,} chars -> {out}")
    print(f"  {len(model._counts):,} distinct {args.n}-grams")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
