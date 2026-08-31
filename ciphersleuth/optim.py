"""Generic search optimisers for cryptanalysis.

Breaking a classical cipher usually means searching a space of *keys* for the
one whose decoding best matches the language model. These engines are the
workhorses: steepest/random hill-climbing (good for substitution ciphers),
simulated annealing (good for rugged landscapes like Playfair key squares),
and a simple genetic algorithm (useful when a permutation must be assembled
from good pieces).

Every engine follows the same contract:

* ``state``    — an opaque candidate solution (a list, tuple, dict, …).
* ``mutate``   — ``(state, rng) -> state``, a small random change to a candidate.
* ``score``    — ``state -> float``, a fitness to **maximise**.

The engines never know anything about ciphers; they only move through the
state space you give them and report the best state+score they found.

Every engine owns a :class:`random.Random` seeded from ``random_seed`` and
hands it to ``mutate`` (and ``crossover``) as the ``rng`` argument, so all
randomness flows through the seeded generator and a run is fully
reproducible: pass the same ``random_seed`` and you get the same result.
"""

from __future__ import annotations

import math
import random

__all__ = [
    "genetic",
    "hillclimb",
    "recombination",
    "simulated_annealing",
]


def hillclimb(
    initial,
    mutate,
    score,
    max_iters=5000,
    patience=200,
    random_seed=None,
):
    """First-ascent hill climbing with an early-stop patience.

    Repeatedly applies ``mutate`` and keeps the change when it improves the
    score. If no improvement is found for ``patience`` consecutive mutations
    the climb stops and returns the best state seen.

    ``mutate(state, rng)`` receives a :class:`random.Random` seeded from
    ``random_seed``, so seeding the run makes the climb reproducible.
    Returns ``(best_state, best_score)``.
    """
    rng = random.Random(random_seed)
    state = initial
    best = state
    best_score = score(state)
    cur = best_score
    stall = 0

    for _ in range(max_iters):
        candidate = mutate(state, rng)
        cand_score = score(candidate)
        if cand_score > cur:
            state = candidate
            cur = cand_score
            if cur > best_score:
                best, best_score = state, cur
            stall = 0
        else:
            stall += 1
            if stall >= patience:
                break
    return best, best_score


def simulated_annealing(
    initial,
    mutate,
    score,
    iters=20000,
    t_start=2.0,
    t_end=0.01,
    random_seed=None,
):
    """Simulated annealing: occasionally accepts worse moves to escape local maxima.

    Temperature decays exponentially from ``t_start`` to ``t_end`` over
    ``iters`` steps. The seeded ``rng`` drives both the mutation and the
    acceptance decision, so ``random_seed`` makes the run reproducible.
    Returns ``(best_state, best_score)`` (best ever seen, not the final state).
    """
    rng = random.Random(random_seed)
    state = initial
    cur = score(state)
    best, best_score = state, cur

    for step in range(iters):
        alpha = step / max(iters - 1, 1)
        temp = t_start * (t_end / t_start) ** alpha
        candidate = mutate(state, rng)
        cand_score = score(candidate)
        delta = cand_score - cur
        if delta > 0 or rng.random() < math.exp(delta / temp if temp > 0 else -1e9):
            state = candidate
            cur = cand_score
            if cur > best_score:
                best, best_score = state, cur
    return best, best_score


def genetic(
    population,
    score,
    mutate,
    crossover=None,
    generations=200,
    keep=0.2,
    mutation_rate=0.2,
    random_seed=None,
):
    """A compact generational genetic algorithm.

    ``population`` is the initial list of states. Each generation the best
    ``keep`` fraction survive, the rest are replaced by crossover (if
    ``crossover`` is given) or mutation. ``mutate`` is applied with
    probability ``mutation_rate`` to each survivor. The seeded ``rng`` drives
    selection, crossover and mutation, so ``random_seed`` makes the run
    reproducible; ``crossover(a, b, rng)`` and ``mutate(state, rng)`` receive
    it. Returns ``(best_state, best_score)``.
    """
    rng = random.Random(random_seed)
    pop = list(population)
    n_keep = max(1, int(len(pop) * keep))

    def fitness(s):
        return score(s)

    best = max(pop, key=fitness)
    best_score = fitness(best)

    for _ in range(generations):
        ranked = sorted(pop, key=fitness, reverse=True)
        if fitness(ranked[0]) > best_score:
            best, best_score = ranked[0], fitness(ranked[0])
        survivors = ranked[:n_keep]
        next_gen = list(survivors)
        while len(next_gen) < len(pop):
            if crossover is not None and rng.random() < 0.7:
                a = rng.choice(survivors)
                b = rng.choice(survivors)
                child = crossover(a, b, rng)
            else:
                child = rng.choice(survivors)
            if rng.random() < mutation_rate:
                child = mutate(child, rng)
            next_gen.append(child)
        pop = next_gen
    return best, best_score


def recombination(a, b, rng=None):
    """Order-preserving OX1 crossover for two permutations of the same set.

    Keeps a contiguous segment from parent ``a`` in place, then fills the
    remaining positions with the items of ``b`` (in ``b``'s order, skipping
    any already placed). Because both parents are permutations of the same
    set, the child is again a valid permutation, and it usually differs from
    both parents. Pass the optimizer's ``rng`` (or omit for a fresh one).

    The child satisfies ``set(child) == set(a) == set(b)`` and, for most
    draws, ``child`` is not identical to either parent.
    """
    n = len(a)
    if n < 2:
        return list(a)
    rng = rng or random.Random()
    start = rng.randrange(n)
    end = rng.randrange(start + 1, n + 1)   # start < end, non-empty segment
    segment = set(a[start:end])
    child = [None] * n
    child[start:end] = a[start:end]
    b_iter = (x for x in b if x not in segment)
    for i in range(n):
        if child[i] is None:
            child[i] = next(b_iter)
    # preserve input type (strings in, string out) so mixed state types work
    return "".join(child) if isinstance(a, str) else child
