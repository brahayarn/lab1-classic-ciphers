"""Вертикальна перестановка: запис по рядках, читання стовпців у порядку ключа.

Якщо довжина не кратна k, останній рядок доповнюється службовою літерою.
Кількість доданих символів повертається окремо й потрібна для розшифрування:
вилучаються рівно стільки символів, а не всі схожі літери наприкінці.
"""
from __future__ import annotations

from typing import NamedTuple

from .errors import InvalidCiphertextError, InvalidKeyError
from .permutation import PermutationKey, parse_permutation
from .text import ALPHABET, INDEX, PRESERVE, normalize, prepare_for_transposition

DEFAULT_PAD_CHAR = "Х"


class Encrypted(NamedTuple):
    text: str
    padding: int


def validate_pad_char(pad_char: str) -> str:
    # Вимагаємо літеру алфавіту, щоб доповнення пережило і режим letters.
    pad = normalize(pad_char)
    if len(pad) != 1 or pad not in INDEX:
        raise InvalidKeyError(f"службовий символ має бути однією літерою алфавіту {ALPHABET}.")
    return pad


def validate_padding(padding: int, columns: int) -> int:
    if isinstance(padding, bool) or not isinstance(padding, int):
        raise InvalidKeyError("кількість доданих символів має бути цілим числом.")
    if not 0 <= padding < columns:
        raise InvalidKeyError(
            f"кількість доданих символів {padding} має бути в межах 0..{columns - 1} "
            f"(менша за кількість стовпців {columns})."
        )
    return padding


def encrypt(
    text: str, key: PermutationKey, mode: str = PRESERVE, pad_char: str = DEFAULT_PAD_CHAR
) -> Encrypted:
    order = parse_permutation(key)
    pad = validate_pad_char(pad_char)
    columns = len(order)
    prepared = prepare_for_transposition(text, mode)
    padding = -len(prepared) % columns
    grid = prepared + pad * padding
    # Стовпець c (1..k) прямокутника — це кожен k-й символ, починаючи з c-1.
    return Encrypted("".join(grid[column - 1::columns] for column in order), padding)


def decrypt(text: str, key: PermutationKey, padding: int, mode: str = PRESERVE) -> str:
    order = parse_permutation(key)
    columns = len(order)
    validate_padding(padding, columns)
    prepared = prepare_for_transposition(text, mode)
    if len(prepared) % columns:
        raise InvalidCiphertextError(
            f"довжина шифротексту {len(prepared)} не кратна кількості стовпців {columns}."
        )
    if padding > len(prepared):
        raise InvalidCiphertextError("кількість доданих символів більша за довжину шифротексту.")
    rows = len(prepared) // columns
    column_text = {
        column: prepared[i * rows:(i + 1) * rows] for i, column in enumerate(order)
    }
    grid = "".join(
        column_text[column][row] for row in range(rows) for column in range(1, columns + 1)
    )
    return grid[:len(grid) - padding]
