"""Блокова перестановка: y = (x_perm1, ..., x_permn) для кожного повного блока.

Політика неповного блока: останній блок довжини < n залишається без змін.
"""
from __future__ import annotations

from typing import Sequence

from .permutation import PermutationKey, invert, parse_permutation
from .text import PRESERVE, prepare_for_transposition


def encrypt(text: str, key: PermutationKey, mode: str = PRESERVE) -> str:
    perm = parse_permutation(key)
    return _apply(prepare_for_transposition(text, mode), perm)


def decrypt(text: str, key: PermutationKey, mode: str = PRESERVE) -> str:
    perm = parse_permutation(key)
    return _apply(prepare_for_transposition(text, mode), invert(perm))


def _apply(text: str, perm: Sequence[int]) -> str:
    n = len(perm)
    blocks = []
    for start in range(0, len(text), n):
        block = text[start:start + n]
        if len(block) < n:
            blocks.append(block)
        else:
            blocks.append("".join(block[source - 1] for source in perm))
    return "".join(blocks)
