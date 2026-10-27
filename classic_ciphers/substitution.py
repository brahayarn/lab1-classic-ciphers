"""Проста одноалфавітна підстановка: ALPHABET[i] -> table[i]."""
from __future__ import annotations

from collections import Counter

from .errors import InvalidKeyError
from .text import ALPHABET, INDEX, M, normalize, prepare


def build_table(keyword: str) -> str:
    """Ключове слово без повторів, далі невикористані літери алфавіту за порядком."""
    word = normalize(keyword).strip()
    if not word:
        raise InvalidKeyError("ключове слово порожнє.")
    for char in word:
        if char not in INDEX:
            raise InvalidKeyError(
                f"ключове слово містить символ {char!r} поза алфавітом {ALPHABET}."
            )
    head = "".join(dict.fromkeys(word))
    table = head + "".join(letter for letter in ALPHABET if letter not in head)
    return validate_table(table)


def table_from_string(raw: str) -> str:
    """Готова таблиця B, введена користувачем (регістр не важливий)."""
    return validate_table(normalize(raw).strip())


def validate_table(table: str) -> str:
    if len(table) != M:
        raise InvalidKeyError(f"таблиця підстановки має містити {M} літери, а містить {len(table)}.")
    foreign = sorted({char for char in table if char not in INDEX})
    if foreign:
        raise InvalidKeyError(f"таблиця містить символи поза алфавітом: {' '.join(foreign)}.")
    repeated = sorted(char for char, count in Counter(table).items() if count > 1)
    if repeated:
        missing = [letter for letter in ALPHABET if letter not in table]
        raise InvalidKeyError(
            f"таблиця не є перестановкою: повторюються {' '.join(repeated)}, "
            f"відсутні {' '.join(missing)}."
        )
    return table


def encrypt(text: str, table: str) -> str:
    table = validate_table(table)
    return prepare(text).translate(str.maketrans(ALPHABET, table))


def decrypt(text: str, table: str) -> str:
    table = validate_table(table)
    return prepare(text).translate(str.maketrans(table, ALPHABET))
