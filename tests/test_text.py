"""Unicode, українські літери та політика форматування."""
import unicodedata
import unittest

from classic_ciphers import block, columnar, substitution, vigenere
from classic_ciphers.errors import UnsupportedCharacterError
from classic_ciphers.text import ALPHABET, LETTERS, M, letters_only, normalize, prepare


class AlphabetTest(unittest.TestCase):
    def test_alphabet_has_33_unique_letters(self):
        self.assertEqual(M, 33)
        self.assertEqual(len(set(ALPHABET)), 33)

    def test_alphabet_is_nfc(self):
        self.assertEqual(unicodedata.normalize("NFC", ALPHABET), ALPHABET)


class NormalizationTest(unittest.TestCase):
    def test_decomposed_letters_are_composed(self):
        decomposed = "Й" + "Ї"  # Й та Ї як база + комбінований знак
        self.assertEqual(normalize(decomposed), "ЙЇ")
        self.assertEqual(vigenere.encrypt(decomposed, "Б"), vigenere.encrypt("ЙЇ", "Б"))

    def test_lowercase_specific_letters_are_uppercased(self):
        self.assertEqual(normalize("ґєії"), "ҐЄІЇ")


class UkrainianLettersTest(unittest.TestCase):
    SPECIFIC = "ҐЄІЇ"

    def assert_intact(self, text):
        self.assertEqual(unicodedata.normalize("NFC", text), text)
        self.assertNotIn("�", text)
        self.assertTrue(set(letters_only(text)) <= set(ALPHABET))

    def test_specific_letters_through_every_cipher(self):
        table = substitution.build_table("ҐЄІЇ")
        self.assertEqual(table[:4], "ҐЄІЇ")
        outputs = [
            substitution.encrypt(self.SPECIFIC, table),
            vigenere.encrypt(self.SPECIFIC, "ЇЖАК"),
            block.encrypt(self.SPECIFIC, "2 1"),
            columnar.encrypt(self.SPECIFIC, "3 1 2").text,
        ]
        for output in outputs:
            with self.subTest(output=output):
                self.assert_intact(output)
                # Вертикальна перестановка додає службові літери.
                self.assertGreaterEqual(len(letters_only(output)), 4)

    def test_substitution_maps_specific_letters(self):
        table = ALPHABET[::-1]
        # Індекси 4, 7, 11, 12 переходять у 28, 25, 21, 20.
        self.assertEqual(substitution.encrypt("ґєії", table), "ШХСР")


class FormattingPolicyTest(unittest.TestCase):
    TEXT = "Ми — 2 студенти!\nДругий рядок, 3-й?\n"

    def test_substitution_keeps_non_letters_in_place(self):
        encrypted = substitution.encrypt(self.TEXT, substitution.build_table("ЗАХИСТ"))
        for position, char in enumerate(prepare(self.TEXT)):
            if char not in ALPHABET:
                self.assertEqual(encrypted[position], char)

    def test_vigenere_key_does_not_advance_on_non_letters(self):
        self.assertEqual(vigenere.encrypt("А А", "БВ"), "Б В")
        self.assertEqual(vigenere.encrypt("А, 1\nА", "БВ"), "Б, 1\nВ")

    def test_letters_mode_drops_formatting(self):
        self.assertEqual(block.encrypt("А Б, В!", "1 2 3", LETTERS), "АБВ")

    def test_apostrophes_are_allowed(self):
        self.assertEqual(prepare("п'ять сімʼя м’ята"), "П'ЯТЬ СІМʼЯ М’ЯТА")


class UnsupportedCharactersTest(unittest.TestCase):
    def test_rejected_characters(self):
        for char in ("Q", "ы", "Ё", "Ъ", "😀", "‍", "̆", "\x00"):
            with self.subTest(char=repr(char)):
                with self.assertRaises(UnsupportedCharacterError):
                    vigenere.encrypt("А" + char, "КЛЮЧ")

    def test_message_reports_position(self):
        with self.assertRaisesRegex(UnsupportedCharacterError, "позиції 3"):
            prepare("АБWГ")


if __name__ == "__main__":
    unittest.main()
