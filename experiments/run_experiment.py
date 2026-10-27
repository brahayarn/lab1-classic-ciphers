"""Відтворюваний експеримент: контрольні вектори та власний текст для звіту.

Запуск з кореня проєкту:  python3 experiments/run_experiment.py
Результати: experiments/results/ (шифротексти, розшифрування, summary.md).
"""
from __future__ import annotations

import hashlib
import os
import platform
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from classic_ciphers import __version__, analysis, block, columnar, substitution, vigenere  # noqa: E402
from classic_ciphers.fileio import read_text, write_text_atomic  # noqa: E402
from classic_ciphers.text import ALPHABET, LETTERS, PRESERVE, letters_only, prepare  # noqa: E402

SAMPLE_PATH = os.path.join(ROOT, "samples", "message.txt")
RESULTS = os.path.join(ROOT, "experiments", "results")

VECTORS = [
    ("Зворотний алфавіт", "B = A у зворотному порядку", "СЛАВА УКРАЇНІ", "ІНЯЬЯ ЗОЇЯРЛС",
     lambda t: substitution.encrypt(t, ALPHABET[::-1]),
     lambda c: substitution.decrypt(c, ALPHABET[::-1]), "СЛАВА УКРАЇНІ"),
    ("Віженер", "КЛЮЧ", "СЛАВА УКРАЇНІ", "ВЬЮЩК ДЇККЧЛД",
     lambda t: vigenere.encrypt(t, "КЛЮЧ"),
     lambda c: vigenere.decrypt(c, "КЛЮЧ"), "СЛАВА УКРАЇНІ"),
    ("Блокова перестановка", "3 2 5 1 4", "СЛАВА УКРАЇНІ (letters)", "АЛАСВРКЇУАНІ",
     lambda t: block.encrypt("СЛАВА УКРАЇНІ", "3 2 5 1 4", LETTERS),
     lambda c: block.decrypt(c, "3 2 5 1 4", LETTERS), "СЛАВАУКРАЇНІ"),
    ("Вертикальна перестановка", "3 1 4 2", "КРИПТОГРАФІЯ", "ИГІКТАПРЯРОФ",
     lambda t: columnar.encrypt(t, "3 1 4 2").text,
     lambda c: columnar.decrypt(c, "3 1 4 2", 0), "КРИПТОГРАФІЯ"),
]

SAMPLE_KEYS = {
    "substitution": "КРИПТОГРАФІЯ",
    "vigenere": "ЗАХИСТ",
    "block": "3 2 5 1 4",
    "columnar": "4 1 3 7 2 6 5",
}


def status(ok: bool) -> str:
    return "OK" if ok else "FAIL"


def vectors_table() -> list:
    lines = ["| Алгоритм | Ключ | Відкритий текст | Очікуваний | Фактичний | Розшифровано | Статус |",
             "|---|---|---|---|---|---|---|"]
    for name, key, plain, expected, encrypt, decrypt, prepared in VECTORS:
        actual = encrypt(plain)
        restored = decrypt(actual)
        ok = actual == expected and restored == prepared
        lines.append(f"| {name} | {key} | {plain} | {expected} | {actual} | {restored} | {status(ok)} |")
    return lines


def run_sample(text: str) -> tuple:
    table = substitution.build_table(SAMPLE_KEYS["substitution"])
    col_encrypted = columnar.encrypt(text, SAMPLE_KEYS["columnar"], PRESERVE)
    runs = {
        "substitution": (substitution.encrypt(text, table), lambda c: substitution.decrypt(c, table)),
        "vigenere": (vigenere.encrypt(text, SAMPLE_KEYS["vigenere"]),
                     lambda c: vigenere.decrypt(c, SAMPLE_KEYS["vigenere"])),
        "block": (block.encrypt(text, SAMPLE_KEYS["block"], PRESERVE),
                  lambda c: block.decrypt(c, SAMPLE_KEYS["block"], PRESERVE)),
        "columnar": (col_encrypted.text,
                     lambda c: columnar.decrypt(c, SAMPLE_KEYS["columnar"], col_encrypted.padding, PRESERVE)),
    }
    lines = ["| Алгоритм | Ключ | Режим | SHA-256 шифротексту (16 символів) | D(E(x)) = x |",
             "|---|---|---|---|---|"]
    for name, (encrypted, decrypt) in runs.items():
        restored = decrypt(encrypted)
        write_text_atomic(os.path.join(RESULTS, f"{name}.enc.txt"), encrypted)
        write_text_atomic(os.path.join(RESULTS, f"{name}.dec.txt"), restored)
        mode = "preserve" if name in ("block", "columnar") else "—"
        digest = hashlib.sha256(encrypted.encode("utf-8")).hexdigest()[:16]
        lines.append(f"| {name} | {SAMPLE_KEYS[name]} | {mode} | `{digest}` | "
                     f"{status(restored == prepare(text))} |")
    extra = [f"Таблиця підстановки для ключа {SAMPLE_KEYS['substitution']}: `{table}`",
             f"Вертикальна перестановка: додано службових символів — {col_encrypted.padding}."]
    return lines, extra, runs["substitution"][0], runs["vigenere"][0]


def frequency_table(plain: str, cipher: str) -> list:
    plain_counts = analysis.letter_counts(plain)
    cipher_counts = analysis.letter_counts(cipher)
    top_plain = sorted(plain_counts.items(), key=lambda item: -item[1])[:10]
    top_cipher = sorted(cipher_counts.items(), key=lambda item: -item[1])[:10]
    lines = ["| Ранг | Відкритий текст | Шифротекст підстановки |", "|---|---|---|"]
    for rank, ((p, pc), (c, cc)) in enumerate(zip(top_plain, top_cipher), start=1):
        lines.append(f"| {rank} | {p} — {pc} | {c} — {cc} |")
    return lines


def main() -> int:
    os.makedirs(RESULTS, exist_ok=True)
    text = read_text(SAMPLE_PATH)
    sample_lines, sample_extra, substituted, vigenere_cipher = run_sample(text)
    scores = analysis.key_length_scores(vigenere_cipher, 12)
    report = [
        "# Результати експерименту",
        "",
        f"- Версія програми: {__version__}",
        f"- Python: {platform.python_version()} ({platform.python_implementation()})",
        f"- Платформа: {platform.system()} {platform.release()} {platform.machine()}",
        f"- Вхідний файл: samples/message.txt, SHA-256 "
        f"`{hashlib.sha256(text.encode('utf-8')).hexdigest()}`",
        f"- Літер алфавіту у власному тексті: {len(letters_only(prepare(text)))}, "
        f"символів усього: {len(prepare(text))}",
        "",
        "## Контрольні вектори",
        "",
        *vectors_table(),
        "",
        "## Власний текст",
        "",
        *sample_lines,
        "",
        *[f"- {line}" for line in sample_extra],
        "",
        "## Частоти: проста підстановка (10 найчастіших літер)",
        "",
        *frequency_table(text, substituted),
        "",
        f"Індекс збігів: відкритий текст {analysis.index_of_coincidence(text):.4f}, "
        f"підстановка {analysis.index_of_coincidence(substituted):.4f}, "
        f"Віженер {analysis.index_of_coincidence(vigenere_cipher):.4f}, "
        f"випадковий текст {analysis.RANDOM_IC:.4f}.",
        "",
        f"## Оцінка довжини ключа Віженера (ключ {SAMPLE_KEYS['vigenere']}, довжина "
        f"{len(SAMPLE_KEYS['vigenere'])})",
        "",
        "| L | Середній IC |", "|---|---|",
        *[f"| {length} | {score:.4f} |" for length, score in scores],
        "",
        f"Оцінка: {analysis.estimate_key_length(vigenere_cipher, 12)}",
        "",
    ]
    write_text_atomic(os.path.join(RESULTS, "summary.md"), "\n".join(report))
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
