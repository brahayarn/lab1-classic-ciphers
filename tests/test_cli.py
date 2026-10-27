"""Консольний інтерфейс: коди завершення, повідомлення, робота з файлами."""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from classic_ciphers.cli import EXIT_ERROR, EXIT_OK, main


def run(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch("sys.stdin", io.StringIO(stdin)):
        try:
            code = main(list(argv))
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()



class CliCommandsTest(unittest.TestCase):
    def test_all_vectors_via_cli(self):
        cases = [
            (["-c", "substitution", "--table", "ЯЮЬЩШЧЦХФУТСРПОНМЛКЙЇІИЗЖЄЕДҐГВБА"],
             "СЛАВА УКРАЇНІ", "ІНЯЬЯ ЗОЇЯРЛС"),
            (["-c", "vigenere", "-k", "КЛЮЧ"], "СЛАВА УКРАЇНІ", "ВЬЮЩК ДЇККЧЛД"),
            (["-c", "block", "-k", "3 2 5 1 4", "--mode", "letters"], "СЛАВА УКРАЇНІ", "АЛАСВРКЇУАНІ"),
            (["-c", "columnar", "-k", "3 1 4 2"], "КРИПТОГРАФІЯ", "ИГІКТАПРЯРОФ"),
        ]
        for options, plain, cipher in cases:
            with self.subTest(cipher=options[1]):
                code, out, _ = run("encrypt", *options, "-t", plain)
                self.assertEqual((code, out), (EXIT_OK, cipher + "\n"))
                decrypt_options = options + (["--pad", "0"] if options[1] == "columnar" else [])
                code, out, _ = run("decrypt", *decrypt_options, "-t", cipher)
                self.assertEqual(code, EXIT_OK)
                self.assertEqual(out, plain.replace(" ", "") + "\n" if "letters" in options
                                 else plain + "\n")

    def test_columnar_reports_padding(self):
        code, out, err = run("encrypt", "-c", "columnar", "-k", "3 1 4 2", "-t", "КРИПТОГРАФ")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("--pad 2", err)
        code, out, _ = run("decrypt", "-c", "columnar", "-k", "3 1 4 2", "--pad", "2", "-t", out.rstrip("\n"))
        self.assertEqual(out, "КРИПТОГРАФ\n")

    def test_stdin_input(self):
        code, out, _ = run("encrypt", "-c", "vigenere", "-k", "Б", stdin="абв\n")
        self.assertEqual((code, out), (EXIT_OK, "БВГ\n"))

    def test_rules_and_help(self):
        code, out, _ = run("rules")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("NFC", out)
        code, out, _ = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("encrypt", out)

    def test_analyze(self):
        code, out, _ = run("analyze", "-t", "ААБ ВГ")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Індекс збігів", out)


class CliErrorsTest(unittest.TestCase):
    def assert_error(self, *argv, message):
        code, out, err = run(*argv)
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("Помилка:", err)
        self.assertIn(message, err)
        self.assertNotIn("Traceback", err)

    def test_invalid_keys(self):
        self.assert_error("encrypt", "-c", "vigenere", "-k", "", "-t", "А", message="порожній")
        self.assert_error("encrypt", "-c", "block", "-k", "1 1 2", "-t", "А", message="повторюються")
        self.assert_error("encrypt", "-c", "columnar", "-k", "1 5", "-t", "А", message="поза діапазоном")
        self.assert_error("encrypt", "-c", "substitution", "-k", "KEY", "-t", "А", message="поза алфавітом")

    def test_missing_or_conflicting_options(self):
        self.assert_error("encrypt", "-c", "vigenere", "-t", "А", message="потрібен ключ")
        self.assert_error("decrypt", "-c", "columnar", "-k", "2 1", "-t", "АБ", message="--pad")
        self.assert_error("decrypt", "-c", "columnar", "-k", "2 1", "--pad", "2", "-t", "АБ",
                          message="0..1")
        self.assert_error("encrypt", "-c", "vigenere", "-k", "А", "--mode", "letters", "-t", "А",
                          message="--mode")
        self.assert_error("decrypt", "-c", "block", "-k", "2 1", "--pad", "1", "-t", "А",
                          message="--pad")
        self.assert_error("encrypt", "-c", "substitution", "-k", "А", "--table", "Б", "-t", "А",
                          message="не обидва")

    def test_unsupported_text(self):
        self.assert_error("encrypt", "-c", "vigenere", "-k", "КЛЮЧ", "-t", "Hello",
                          message="U+0048")

    def test_usage_error_has_nonzero_code(self):
        code, _, err = run("encrypt", "-c", "unknown", "-k", "1")
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", err)


class CliFilesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.plain = os.path.join(self.directory.name, "plain.txt")
        self.cipher = os.path.join(self.directory.name, "cipher.txt")
        self.back = os.path.join(self.directory.name, "back.txt")

    def test_file_round_trip_for_every_cipher(self):
        text = "Рядок один: Ґанок.\nРядок два — Їжак, Єнот, Іволга!\n"
        with open(self.plain, "w", encoding="utf-8", newline="") as file:
            file.write(text)
        configs = [
            (["-c", "substitution", "-k", "ЗАХИСТ"], []),
            (["-c", "vigenere", "-k", "ҐРУНТ"], []),
            (["-c", "block", "-k", "4 1 3 2"], []),
            (["-c", "columnar", "-k", "2 4 1 3"], None),
        ]
        for options, decrypt_extra in configs:
            with self.subTest(cipher=options[1]):
                code, _, err = run("encrypt", *options, "-i", self.plain, "-o", self.cipher)
                self.assertEqual(code, EXIT_OK)
                if decrypt_extra is None:
                    padding = err.split("--pad ")[1].split(".")[0]
                    decrypt_extra = ["--pad", padding]
                code, _, _ = run("decrypt", *options, *decrypt_extra, "-i", self.cipher, "-o", self.back)
                self.assertEqual(code, EXIT_OK)
                with open(self.back, encoding="utf-8", newline="") as file:
                    self.assertEqual(file.read(), text.upper())

    def test_error_does_not_create_output(self):
        with open(self.plain, "w", encoding="utf-8") as file:
            file.write("Text latin")
        code, _, _ = run("encrypt", "-c", "vigenere", "-k", "А", "-i", self.plain, "-o", self.cipher)
        self.assertEqual(code, EXIT_ERROR)
        self.assertFalse(os.path.exists(self.cipher))

    def test_missing_input_file(self):
        code, _, err = run("encrypt", "-c", "vigenere", "-k", "А", "-i", self.plain)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("не знайдено", err)


if __name__ == "__main__":
    unittest.main()
