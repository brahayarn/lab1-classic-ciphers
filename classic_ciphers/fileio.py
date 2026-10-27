"""Читання і запис UTF-8 файлів без зміни переносів рядків."""
from __future__ import annotations

import os
import tempfile

from .errors import TextFileError


def read_text(path: str) -> str:
    # newline="" зберігає \n і \r\n як є; utf-8-sig прибирає BOM, якщо він є.
    try:
        with open(path, encoding="utf-8-sig", newline="") as file:
            return file.read()
    except FileNotFoundError:
        raise TextFileError(f"файл {path!r} не знайдено.") from None
    except IsADirectoryError:
        raise TextFileError(f"{path!r} є каталогом, а не файлом.") from None
    except PermissionError:
        raise TextFileError(f"немає дозволу на читання {path!r}.") from None
    except UnicodeDecodeError as error:
        raise TextFileError(
            f"файл {path!r} не є коректним UTF-8 (байт {error.start})."
        ) from None


def write_text_atomic(path: str, text: str) -> None:
    """Пише у тимчасовий файл і атомарно підміняє ціль: без частково записаних результатів."""
    directory = os.path.dirname(os.path.abspath(path))
    try:
        descriptor, temp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".txt")
    except OSError as error:
        raise TextFileError(f"не вдалося записати у каталог {directory!r}: {error.strerror}.") from None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
    except OSError as error:
        os.unlink(temp_path)
        raise TextFileError(f"не вдалося записати {path!r}: {error.strerror}.") from None
