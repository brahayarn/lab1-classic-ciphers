"""Шифр Віженера над алфавітом із 33 літер.

C_i = (P_i + K_(i mod l)) mod m,  P_i = (C_i - K_(i mod l)) mod m,
де i рахує лише літери алфавіту: інші символи копіюються і ключ не просувають.
"""
from __future__ import annotations

from typing import List

from .errors import InvalidKeyError
from .text import ALPHABET, INDEX, M, normalize, prepare


def parse_key(key: str) -> List[int]:
    word = normalize(key).strip()
    if not word:
        raise InvalidKeyError("ключ Віженера порожній.")
    for char in word:
        if char not in INDEX:
            raise InvalidKeyError(f"ключ Віженера містить символ {char!r} поза алфавітом {ALPHABET}.")
    return [INDEX[char] for char in word]


def encrypt(text: str, key: str) -> str:
    return _shift(text, parse_key(key), direction=1)


def decrypt(text: str, key: str) -> str:
    return _shift(text, parse_key(key), direction=-1)


def _shift(text: str, shifts: List[int], direction: int) -> str:
    result = []
    letter_position = 0
    for char in prepare(text):
        index = INDEX.get(char)
        if index is None:
            result.append(char)
            continue
        shift = shifts[letter_position % len(shifts)]
        # У Python остача від додатного модуля завжди в [0, m), тож
        # від'ємна різниця при розшифруванні приводиться автоматично.
        result.append(ALPHABET[(index + direction * shift) % M])
        letter_position += 1
    return "".join(result)
