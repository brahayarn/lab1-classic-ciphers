"""Консольний інтерфейс. Уся криптографія — у модулях пакета, тут лише введення/виведення."""
from __future__ import annotations

import argparse
import sys
from typing import Callable, List, Optional, Tuple

from . import __version__, analysis, block, columnar, substitution, vigenere
from .errors import CipherError
from .fileio import read_text, write_text_atomic
from .permutation import parse_permutation
from .text import PRESERVE, RULES, TRANSPOSITION_MODES

EXIT_OK = 0
EXIT_ERROR = 1

CIPHERS = {
    "substitution": "проста одноалфавітна підстановка (ключ: ключове слово або --table)",
    "vigenere": "шифр Віженера (ключ: слово з літер алфавіту)",
    "block": "блокова перестановка (ключ: перестановка, напр. \"3 2 5 1 4\")",
    "columnar": "вертикальна перестановка (ключ: порядок стовпців, напр. \"3 1 4 2\")",
}
TRANSPOSITIONS = ("block", "columnar")

# Перетворення повертає результат і службові повідомлення для stderr.
Transform = Callable[[str], Tuple[str, List[str]]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m classic_ciphers",
        description="Навчальні шифри заміни та перестановки для українського тексту. "
        "Не використовуйте їх для захисту реальних даних.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Приклади:\n"
        "  python -m classic_ciphers encrypt -c vigenere -k КЛЮЧ -t \"Слава Україні\"\n"
        "  python -m classic_ciphers decrypt -c columnar -k \"3 1 4 2\" --pad 2 -i in.txt -o out.txt\n"
        "  python -m classic_ciphers rules",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="КОМАНДА")

    for name, title in (("encrypt", "зашифрувати"), ("decrypt", "розшифрувати")):
        command = commands.add_parser(name, help=title, description=f"{title.capitalize()} текст.")
        command.add_argument("-c", "--cipher", required=True, choices=CIPHERS,
                             help="алгоритм: " + "; ".join(f"{k} — {v}" for k, v in CIPHERS.items()))
        command.add_argument("-k", "--key", help="ключ (обов'язковий, крім substitution з --table)")
        command.add_argument("--table", help="substitution: готова таблиця B із 33 літер")
        command.add_argument("--mode", choices=TRANSPOSITION_MODES,
                             help="block/columnar: preserve (за замовчуванням) або letters")
        if name == "encrypt":
            command.add_argument("--pad-char", default=columnar.DEFAULT_PAD_CHAR,
                                 help="columnar: службова літера доповнення (за замовчуванням %(default)s)")
        else:
            command.add_argument("--pad", type=int,
                                 help="columnar: кількість доданих при зашифруванні символів")
        _add_io_arguments(command, with_output=True)

    commands.add_parser("rules", help="показати правила підготовки тексту")

    analyze = commands.add_parser("analyze", help="частоти літер, індекс збігів, довжина ключа Віженера")
    analyze.add_argument("--max-key-length", type=int, default=16,
                         help="найбільша довжина ключа для перевірки (за замовчуванням %(default)s)")
    _add_io_arguments(analyze, with_output=False)
    return parser


def _add_io_arguments(command: argparse.ArgumentParser, with_output: bool) -> None:
    source = command.add_mutually_exclusive_group()
    source.add_argument("-t", "--text", help="текст у командному рядку")
    source.add_argument("-i", "--input", metavar="ФАЙЛ", help="вхідний UTF-8 файл")
    if with_output:
        command.add_argument("-o", "--output", metavar="ФАЙЛ",
                             help="вихідний UTF-8 файл (інакше результат виводиться на екран)")


def build_transform(args: argparse.Namespace) -> Transform:
    """Перевіряє ключ і параметри ще до читання тексту та повертає перетворення."""
    _reject_irrelevant_options(args)
    encrypting = args.command == "encrypt"

    if args.cipher == "substitution":
        if args.table is not None and args.key is not None:
            raise CipherError("вкажіть або --key (ключове слово), або --table, але не обидва.")
        if args.table is not None:
            table = substitution.table_from_string(args.table)
        else:
            table = substitution.build_table(_require_key(args))
        operation = substitution.encrypt if encrypting else substitution.decrypt
        return lambda text: (operation(text, table), [])

    key = _require_key(args)
    if args.cipher == "vigenere":
        vigenere.parse_key(key)
        operation = vigenere.encrypt if encrypting else vigenere.decrypt
        return lambda text: (operation(text, key), [])

    perm = parse_permutation(key)
    mode = args.mode or PRESERVE
    if args.cipher == "block":
        operation = block.encrypt if encrypting else block.decrypt
        return lambda text: (operation(text, perm, mode), [])

    if encrypting:
        pad_char = columnar.validate_pad_char(args.pad_char)

        def encrypt_columnar(text: str) -> Tuple[str, List[str]]:
            result = columnar.encrypt(text, perm, mode, pad_char)
            return result.text, [
                f"Додано службових символів: {result.padding}. "
                f"Для розшифрування вкажіть --pad {result.padding}."
            ]
        return encrypt_columnar

    if args.pad is None:
        raise CipherError("для розшифрування вертикальної перестановки потрібен параметр --pad "
                          "(кількість доданих при зашифруванні символів).")
    padding = columnar.validate_padding(args.pad, len(perm))
    return lambda text: (columnar.decrypt(text, perm, padding, mode), [])


def _require_key(args: argparse.Namespace) -> str:
    if args.key is None:
        raise CipherError(f"для алгоритму {args.cipher} потрібен ключ --key.")
    return args.key


def _reject_irrelevant_options(args: argparse.Namespace) -> None:
    if args.table is not None and args.cipher != "substitution":
        raise CipherError("параметр --table застосовується лише до substitution.")
    if args.mode is not None and args.cipher not in TRANSPOSITIONS:
        raise CipherError("параметр --mode застосовується лише до block і columnar; "
                          "підстановки завжди зберігають символи поза алфавітом.")
    if getattr(args, "pad", None) is not None and args.cipher != "columnar":
        raise CipherError("параметр --pad застосовується лише до columnar.")


def read_input(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.input is not None:
        return read_text(args.input)
    if sys.stdin.isatty():
        print("Введіть текст і завершіть введення Ctrl-D (Windows: Ctrl-Z, Enter):",
              file=sys.stderr)
    return sys.stdin.read()


def write_output(args: argparse.Namespace, result: str) -> None:
    if args.output is not None:
        write_text_atomic(args.output, result)
        print(f"Результат записано у {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(result if result.endswith("\n") else result + "\n")


def run_cipher(args: argparse.Namespace) -> None:
    transform = build_transform(args)
    result, notes = transform(read_input(args))
    write_output(args, result)
    for note in notes:
        print(note, file=sys.stderr)


def run_analyze(args: argparse.Namespace) -> None:
    if args.max_key_length < 1:
        raise CipherError("--max-key-length має бути додатним.")
    text = read_input(args)
    counts = analysis.letter_counts(text)
    print(f"Літер алфавіту: {sum(counts.values())}")
    print(analysis.format_histogram(counts))
    print(f"\nІндекс збігів: {analysis.index_of_coincidence(text):.4f} "
          f"(випадковий текст: {analysis.RANDOM_IC:.4f})")
    scores = analysis.key_length_scores(text, args.max_key_length)
    if scores:
        print("\nДовжина ключа L : середній IC стовпців")
        for length, score in scores:
            print(f"  {length:2d} : {score:.4f}")
        print(f"Оцінка довжини ключа Віженера: "
              f"{analysis.estimate_key_length(text, args.max_key_length)}")


def _use_utf8_streams() -> None:
    # Консоль Windows може мати іншу кодову сторінку; вимога роботи — UTF-8.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    _use_utf8_streams()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "rules":
            print(RULES, end="")
        elif args.command == "analyze":
            run_analyze(args)
        else:
            run_cipher(args)
    except CipherError as error:
        print(f"Помилка: {error}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK
