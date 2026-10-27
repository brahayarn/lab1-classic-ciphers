"""Граничні випадки довжини тексту та доповнення."""
import unittest

from classic_ciphers import block, columnar, substitution, vigenere
from classic_ciphers.text import ALPHABET

KEY = "3 2 5 1 4"  # n = 5
SAMPLE = "АБВГҐДЕЄЖЗИ"


class EmptyAndSingleTest(unittest.TestCase):
    def test_empty_text(self):
        self.assertEqual(substitution.encrypt("", ALPHABET[::-1]), "")
        self.assertEqual(vigenere.encrypt("", "КЛЮЧ"), "")
        self.assertEqual(block.encrypt("", KEY), "")
        self.assertEqual(columnar.encrypt("", KEY), ("", 0))
        self.assertEqual(columnar.decrypt("", KEY, 0), "")

    def test_single_character(self):
        self.assertEqual(substitution.encrypt("а", ALPHABET[::-1]), "Я")
        self.assertEqual(vigenere.encrypt("Я", "Б"), "А")  # перехід через межу алфавіту
        self.assertEqual(vigenere.decrypt("А", "Б"), "Я")  # від'ємна різниця
        self.assertEqual(block.encrypt("Ж", KEY), "Ж")
        self.assertEqual(columnar.encrypt("Ж", KEY), ("ХХХЖХ", 4))
        self.assertEqual(columnar.decrypt("ХХХЖХ", KEY, 4), "Ж")


class BlockLengthTest(unittest.TestCase):
    def test_length_equal_to_block(self):
        self.assertEqual(block.encrypt(SAMPLE[:5], KEY), "ВБҐАГ")

    def test_length_one_less_than_block_is_unchanged(self):
        self.assertEqual(block.encrypt(SAMPLE[:4], KEY), SAMPLE[:4])

    def test_length_one_more_than_block(self):
        self.assertEqual(block.encrypt(SAMPLE[:6], KEY), "ВБҐАГД")
        self.assertEqual(block.decrypt("ВБҐАГД", KEY), SAMPLE[:6])

    def test_identity_permutation(self):
        self.assertEqual(block.encrypt(SAMPLE, "1 2 3"), SAMPLE)


class ColumnarLengthTest(unittest.TestCase):
    def test_lengths_around_column_count(self):
        expected_padding = {4: 1, 5: 0, 6: 4}
        for length, padding in expected_padding.items():
            with self.subTest(length=length):
                encrypted = columnar.encrypt(SAMPLE[:length], KEY)
                self.assertEqual(encrypted.padding, padding)
                self.assertEqual(len(encrypted.text), length + padding)
                self.assertEqual(columnar.decrypt(encrypted.text, KEY, padding), SAMPLE[:length])


class PaddingRemovalTest(unittest.TestCase):
    def test_only_known_number_of_pad_chars_removed(self):
        # Відкритий текст сам закінчується службовою літерою Х.
        plaintext = "ПОРОХ ХХ"
        encrypted, padding = columnar.encrypt(plaintext, "3 1 2")
        self.assertEqual(padding, 1)
        self.assertEqual(columnar.decrypt(encrypted, "3 1 2", padding), plaintext)

    def test_custom_pad_char(self):
        encrypted, padding = columnar.encrypt("АБВГД", "2 1 3", pad_char="я")
        self.assertEqual((encrypted, padding), ("БДАГВЯ", 1))
        self.assertEqual(columnar.decrypt(encrypted, "2 1 3", padding), "АБВГД")

    def test_wrong_padding_changes_result(self):
        encrypted, padding = columnar.encrypt("АБВГД", "2 1 3")
        self.assertNotEqual(columnar.decrypt(encrypted, "2 1 3", 0), "АБВГД")


if __name__ == "__main__":
    unittest.main()
