"""Єдина специфікація алфавіту та підготовки тексту для всіх алгоритмів.

Підготовка = NFC -> верхній регістр -> NFC -> перевірка допустимих символів.
Повторна NFC потрібна тому, що upper() для окремих символів може повернути
розкладену послідовність.
"""
from __future__ import annotations

import unicodedata

from .errors import UnsupportedCharacterError

ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
M = len(ALPHABET)
INDEX = {letter: i for i, letter in enumerate(ALPHABET)}

PRESERVE = "preserve"
LETTERS = "letters"
TRANSPOSITION_MODES = (PRESERVE, LETTERS)

# Український апостроф U+02BC формально є літерою-модифікатором (Lm),
# але в тексті відіграє роль розділового знака, тому дозволений явно.
_APOSTROPHES = frozenset("'ʼ’`")
_ALLOWED_SYMBOLS = frozenset("№")
_ALLOWED_CONTROLS = frozenset("\n\r\t")
_ALLOWED_CATEGORIES = frozenset(
    {"Zs", "Zl", "Zp", "Nd", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po", "Sm", "Sc"}
)

RULES = f"""\
Правила підготовки тексту (базовий рівень)
  Кодування:     файли читаються і записуються як UTF-8 (BOM на вході ігнорується).
  Нормалізація:  Unicode NFC до і після зміни регістру.
  Регістр:       усі літери переводяться у верхній регістр.
  Алфавіт (m={M}): {ALPHABET}
  Допустимі символи: літери алфавіту, пробіли, табуляція, переноси рядків,
                 цифри, розділові знаки, апострофи (' ʼ ’), знаки №, + - = < > та валют.
  Інші символи (латиниця, російські Ы Э Ё Ъ, емодзі, комбіновані знаки)
                 відхиляються з повідомленням про позицію.
  Підстановки:   символи поза алфавітом зберігаються на місці
                 і не зсувають позицію ключа Віженера.
  Перестановки:  режим preserve переставляє весь нормалізований текст
                 (зворотний); режим letters спершу вилучає все, крім літер
                 (незворотний щодо пробілів і розділових знаків).
  Блокова:       неповний останній блок залишається без змін.
  Вертикальна:   останній рядок доповнюється службовою літерою; кількість
                 доданих символів повідомляється і потрібна для розшифрування.
"""


def normalize(text: str) -> str:
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", text).upper())


def is_supported(char: str) -> bool:
    return (
        char in INDEX
        or char in _APOSTROPHES
        or char in _ALLOWED_SYMBOLS
        or char in _ALLOWED_CONTROLS
        or unicodedata.category(char) in _ALLOWED_CATEGORIES
    )


def validate_text(text: str) -> None:
    for position, char in enumerate(text, start=1):
        if not is_supported(char):
            name = unicodedata.name(char, "без назви")
            raise UnsupportedCharacterError(
                f"непідтримуваний символ {char!r} (U+{ord(char):04X}, {name}) "
                f"у позиції {position}. Дозволено літери українського алфавіту, "
                "пробіли, переноси рядків, цифри та розділові знаки."
            )


def prepare(text: str) -> str:
    """Нормалізує текст і перевіряє, що він складається з допустимих символів."""
    prepared = normalize(text)
    validate_text(prepared)
    return prepared


def letters_only(text: str) -> str:
    return "".join(char for char in text if char in INDEX)


def prepare_for_transposition(text: str, mode: str) -> str:
    if mode not in TRANSPOSITION_MODES:
        raise ValueError(f"невідомий режим перестановки {mode!r}")
    prepared = prepare(text)
    return letters_only(prepared) if mode == LETTERS else prepared
