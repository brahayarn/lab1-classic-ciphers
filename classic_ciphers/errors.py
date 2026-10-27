"""Ієрархія помилок, які інтерфейс показує користувачу без трасування стека."""


class CipherError(ValueError):
    """Базова передбачувана помилка: некоректний ключ, текст або файл."""


class InvalidKeyError(CipherError):
    """Ключ не відповідає умовам прийняття для обраного алгоритму."""


class UnsupportedCharacterError(CipherError):
    """Текст містить символ поза задокументованою множиною допустимих."""


class InvalidCiphertextError(CipherError):
    """Шифротекст структурно не може бути результатом зашифрування."""


class TextFileError(CipherError):
    """Файл неможливо прочитати чи записати як UTF-8 текст."""
