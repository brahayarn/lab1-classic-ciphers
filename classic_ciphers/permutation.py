"""Розбір і перевірка ключів-перестановок (1-індексація, як у методичці)."""
from __future__ import annotations

import re
from collections import Counter
from typing import Sequence, Tuple, Union

from .errors import InvalidKeyError

PermutationKey = Union[str, Sequence[int]]
_SEPARATORS = re.compile(r"[\s,;]+")


def parse_permutation(key: PermutationKey) -> Tuple[int, ...]:
    """Приймає рядок на кшталт "3 2 5 1 4" / "3,2,5,1,4" або послідовність чисел."""
    if isinstance(key, str):
        tokens = [token for token in _SEPARATORS.split(key.strip()) if token]
        if not tokens:
            raise InvalidKeyError("ключ перестановки порожній.")
        numbers = []
        for token in tokens:
            if not token.isdecimal():
                raise InvalidKeyError(
                    f"ключ перестановки містить {token!r}, що не є додатним цілим числом. "
                    "Розділяйте числа пробілами або комами."
                )
            numbers.append(int(token))
        key = numbers
    return validate_permutation(key)


def validate_permutation(numbers: Sequence[int]) -> Tuple[int, ...]:
    perm = tuple(numbers)
    n = len(perm)
    if n == 0:
        raise InvalidKeyError("ключ перестановки порожній.")
    for value in perm:
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidKeyError(f"елемент ключа {value!r} не є цілим числом.")
        if not 1 <= value <= n:
            raise InvalidKeyError(
                f"число {value} поза діапазоном 1..{n} для ключа довжини {n}. "
                "Розділяйте числа пробілами або комами."
            )
    repeated = sorted(value for value, count in Counter(perm).items() if count > 1)
    if repeated:
        missing = sorted(set(range(1, n + 1)) - set(perm))
        raise InvalidKeyError(
            f"ключ не є перестановкою: повторюються {repeated}, відсутні {missing}."
        )
    return perm


def invert(perm: Sequence[int]) -> Tuple[int, ...]:
    """Якщо y_j = x_(perm_j), то x_i = y_(inverse_i)."""
    inverse = [0] * len(perm)
    for target, source in enumerate(perm, start=1):
        inverse[source - 1] = target
    return tuple(inverse)
