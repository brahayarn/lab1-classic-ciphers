"""Додаткові завдання: частотний аналіз та оцінка довжини ключа Віженера."""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Tuple

from .text import ALPHABET, M, letters_only, prepare

RANDOM_IC = 1 / M


def letter_counts(text: str) -> Dict[str, int]:
    counts = Counter(letters_only(prepare(text)))
    return {letter: counts.get(letter, 0) for letter in ALPHABET}


def index_of_coincidence(text: str) -> float:
    """Імовірність, що дві випадково взяті літери тексту збігаються."""
    counts = Counter(letters_only(prepare(text)))
    total = sum(counts.values())
    if total < 2:
        return 0.0
    return sum(c * (c - 1) for c in counts.values()) / (total * (total - 1))


def key_length_scores(ciphertext: str, max_length: int = 16) -> List[Tuple[int, float]]:
    """Середній індекс збігів підпослідовностей із кроком L для кожного L."""
    letters = letters_only(prepare(ciphertext))
    scores = []
    for length in range(1, max_length + 1):
        if len(letters) < 2 * length:
            break
        columns = [letters[offset::length] for offset in range(length)]
        scores.append((length, sum(map(index_of_coincidence, columns)) / length))
    return scores


def estimate_key_length(ciphertext: str, max_length: int = 16, tolerance: float = 0.9) -> int:
    """Найменша довжина, чий IC близький до максимального.

    Кратні справжньої довжини дають схожий IC, тому беремо найменшого кандидата.
    """
    scores = key_length_scores(ciphertext, max_length)
    if not scores:
        return 0
    best = max(score for _, score in scores)
    return next(length for length, score in scores if score >= tolerance * best)


def format_histogram(counts: Dict[str, int], width: int = 40) -> str:
    total = sum(counts.values()) or 1
    peak = max(counts.values(), default=0) or 1
    lines = []
    for letter, count in counts.items():
        bar = "#" * round(width * count / peak)
        lines.append(f"{letter} {count:4d} {100 * count / total:5.1f}% {bar}")
    return "\n".join(lines)
