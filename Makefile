.PHONY: test lint run

test:
	python3 -m pytest tests/ -q

lint:
	python3 -m ruff check ciphersleuth/ tests/ examples/

run:
	python3 -m ciphersleuth.cli --help

demo:
	python3 examples/break_vigenere.py
