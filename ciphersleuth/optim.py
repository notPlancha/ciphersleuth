"""Generic search optimisers for cryptanalysis.

Breaking a classical cipher usually means searching a space of *keys* for the
one whose decoding best matches the language model. These engines are the
workhorses: steepest/random hill-climbing (good for substitution ciphers),
simulated annealing (good for rugged landscapes like Playfair key squares),
and a simple genetic algorithm (useful when a permutation must be assembled
from good pieces).

Every engine follows the same contract:

* ``state``    — an opaque candidate solution (a list, tuple, dict, …).
* ``mutate``   — ``state -> state``, a small random change to a candidate.
* ``score``    — ``state -> float``, a fitness to **maximise**.

The engines never know anything about ciphers; they only move through the
state space you give them and report the best state+score they found.
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

    Returns ``(best_state, best_score)``.
    """
    state = initial
    best = state
    best_score = score(state)
    cur = best_score
    stall = 0

    for _ in range(max_iters):
        candidate = mutate(state)
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
    ``iters`` steps. Returns ``(best_state, best_score)`` (best ever seen,
    not the final state).
    """
    rng = random.Random(random_seed)
    state = initial
    cur = score(state)
    best, best_score = state, cur

    for step in range(iters):
        alpha = step / max(iters - 1, 1)
        temp = t_start * (t_end / t_start) ** alpha
        candidate = mutate(state)
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
    probability ``mutation_rate`` to each survivor. Returns
    ``(best_state, best_score)``.
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
                child = crossover(a, b)
            else:
                child = rng.choice(survivors)
            if rng.random() < mutation_rate:
                child = mutate(child)
            next_gen.append(child)
        pop = next_gen
    return best, best_score


def recombination(a, b):
    """Order-preserving recombination for two sequences of distinct items.

    Used for permutation keys (e.g. a substitution alphabet or a columnar
    ordering): the child keeps item order mostly from ``a`` while absorbing
    items from ``b`` that ``a`` lacks. Assumes both parents are permutations
    of the same set.
    """
    child = []
    bset = set(b)
    for item in a:
        if item not in bset:
            child.append(item)
    # fill remaining positions with b's items not yet placed
    seen = set(child)
    child.extend(x for x in b if x not in seen)
    return child
