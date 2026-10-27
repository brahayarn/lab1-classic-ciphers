"""Читання і запис UTF-8 файлів."""
import os
import tempfile
import unittest
from unittest import mock

from classic_ciphers import columnar, vigenere
from classic_ciphers.errors import TextFileError
from classic_ciphers.fileio import read_text, write_text_atomic

MULTILINE = "Перший рядок: Ґ, Є, І, Ї.\nДругий рядок — 2026 рік.\r\nТретій із завершальним переносом\n"


class FileIOTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def path(self, name):
        return os.path.join(self.directory.name, name)

    def test_round_trip_preserves_newlines_exactly(self):
        write_text_atomic(self.path("a.txt"), MULTILINE)
        self.assertEqual(read_text(self.path("a.txt")), MULTILINE)
        with open(self.path("a.txt"), "rb") as file:
            self.assertEqual(file.read(), MULTILINE.encode("utf-8"))

    def test_bom_is_ignored(self):
        with open(self.path("bom.txt"), "wb") as file:
            file.write(b"\xef\xbb\xbf" + "Їжак".encode("utf-8"))
        self.assertEqual(read_text(self.path("bom.txt")), "Їжак")

    def test_encrypt_file_and_decrypt_back(self):
        with open(self.path("plain.txt"), "w", encoding="utf-8", newline="") as file:
            file.write(MULTILINE)
        encrypted = vigenere.encrypt(read_text(self.path("plain.txt")), "КЛЮЧ")
        write_text_atomic(self.path("cipher.txt"), encrypted)
        decrypted = vigenere.decrypt(read_text(self.path("cipher.txt")), "КЛЮЧ")
        self.assertEqual(decrypted, MULTILINE.upper())
        self.assertTrue(decrypted.endswith("\n"))
        self.assertEqual(decrypted.count("\n"), 3)

    def test_columnar_preserve_mode_restores_multiline_text(self):
        encrypted, padding = columnar.encrypt(MULTILINE, "4 2 1 3")
        self.assertEqual(columnar.decrypt(encrypted, "4 2 1 3", padding), MULTILINE.upper())

    def test_invalid_utf8(self):
        with open(self.path("cp1251.txt"), "wb") as file:
            file.write("Привіт".encode("cp1251"))
        with self.assertRaisesRegex(TextFileError, "UTF-8"):
            read_text(self.path("cp1251.txt"))

    def test_missing_file_and_directory(self):
        with self.assertRaisesRegex(TextFileError, "не знайдено"):
            read_text(self.path("missing.txt"))
        with self.assertRaisesRegex(TextFileError, "каталогом"):
            read_text(self.directory.name)

    def test_failed_write_leaves_existing_file_untouched(self):
        target = self.path("out.txt")
        write_text_atomic(target, "СТАРИЙ ВМІСТ")
        with mock.patch("classic_ciphers.fileio.os.replace", side_effect=OSError(28, "No space")):
            with self.assertRaises(TextFileError):
                write_text_atomic(target, "НОВИЙ ВМІСТ")
        self.assertEqual(read_text(target), "СТАРИЙ ВМІСТ")
        self.assertEqual(os.listdir(self.directory.name), ["out.txt"])

    def test_write_into_missing_directory(self):
        with self.assertRaises(TextFileError):
            write_text_atomic(self.path("no/such/dir.txt"), "А")


if __name__ == "__main__":
    unittest.main()
