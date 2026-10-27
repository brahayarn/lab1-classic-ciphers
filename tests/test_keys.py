"""Негативні сценарії: перевірка ключів до початку обробки."""
import unittest

from classic_ciphers import block, columnar, substitution, vigenere
from classic_ciphers.errors import InvalidCiphertextError, InvalidKeyError
from classic_ciphers.permutation import invert, parse_permutation
from classic_ciphers.text import ALPHABET


class SubstitutionKeyTest(unittest.TestCase):
    def test_keyword_table_construction(self):
        table = substitution.build_table("криптографія")
        self.assertTrue(table.startswith("КРИПТОГАФІЯ"))
        self.assertEqual(sorted(table), sorted(ALPHABET))

    def test_empty_keyword(self):
        for keyword in ("", "   "):
            with self.assertRaisesRegex(InvalidKeyError, "порожнє"):
                substitution.build_table(keyword)

    def test_keyword_with_foreign_letter(self):
        for keyword in ("KEY", "ЗАХИСТ1", "ЁЖИК", "ДВА СЛОВА"):
            with self.subTest(keyword=keyword), self.assertRaises(InvalidKeyError):
                substitution.build_table(keyword)

    def test_table_wrong_length(self):
        with self.assertRaisesRegex(InvalidKeyError, "33"):
            substitution.table_from_string(ALPHABET[:-1])

    def test_table_with_repeat_reports_missing_letter(self):
        with self.assertRaisesRegex(InvalidKeyError, "повторюються А.*відсутні Я"):
            substitution.table_from_string(ALPHABET[:-1] + "А")

    def test_table_with_foreign_symbol(self):
        with self.assertRaisesRegex(InvalidKeyError, "поза алфавітом"):
            substitution.table_from_string(ALPHABET[:-1] + "Z")

    def test_encrypt_validates_table(self):
        with self.assertRaises(InvalidKeyError):
            substitution.encrypt("ТЕКСТ", "АБВ")


class VigenereKeyTest(unittest.TestCase):
    def test_empty_key(self):
        for key in ("", " \n"):
            with self.assertRaisesRegex(InvalidKeyError, "порожній"):
                vigenere.encrypt("ТЕКСТ", key)

    def test_key_with_letter_outside_alphabet(self):
        for key in ("KEY", "КЛЮЧ!", "ЫЫ", "КЛ ЮЧ"):
            with self.subTest(key=key), self.assertRaisesRegex(InvalidKeyError, "поза алфавітом"):
                vigenere.decrypt("ТЕКСТ", key)

    def test_key_is_case_insensitive(self):
        self.assertEqual(vigenere.parse_key("ключ"), vigenere.parse_key("КЛЮЧ"))


class PermutationKeyTest(unittest.TestCase):
    def test_parsing_formats(self):
        for raw in ("3 2 5 1 4", "3,2,5,1,4", " 3, 2; 5 1\t4 "):
            self.assertEqual(parse_permutation(raw), (3, 2, 5, 1, 4))

    def test_inverse_from_manual(self):
        self.assertEqual(invert((3, 2, 5, 1, 4)), (4, 2, 1, 5, 3))

    def test_empty(self):
        for raw in ("", "  ", []):
            with self.assertRaisesRegex(InvalidKeyError, "порожній"):
                parse_permutation(raw)

    def test_repeats(self):
        with self.assertRaisesRegex(InvalidKeyError, r"повторюються \[2\], відсутні \[3\]"):
            parse_permutation("1 2 2")

    def test_out_of_range(self):
        for raw in ("0 1 2", "1 2 4", "32514"):
            with self.subTest(raw=raw), self.assertRaisesRegex(InvalidKeyError, "поза діапазоном"):
                parse_permutation(raw)

    def test_not_a_number(self):
        for raw in ("1 2 x", "1 -2 3", "1.5 2", "один"):
            with self.subTest(raw=raw), self.assertRaises(InvalidKeyError):
                parse_permutation(raw)

    def test_non_integer_sequence(self):
        for raw in ([1, 2.0], [True, 2]):
            with self.subTest(raw=raw), self.assertRaises(InvalidKeyError):
                parse_permutation(raw)

    def test_ciphers_validate_before_processing(self):
        # Некоректний ключ відхиляється навіть для порожнього тексту.
        with self.assertRaises(InvalidKeyError):
            block.encrypt("", "1 1")
        with self.assertRaises(InvalidKeyError):
            columnar.encrypt("", "2 3")


class PaddingKeyTest(unittest.TestCase):
    def test_padding_must_be_less_than_columns(self):
        for padding in (-1, 4, 10):
            with self.subTest(padding=padding), self.assertRaises(InvalidKeyError):
                columnar.decrypt("ИГІКТАПРЯРОФ", "3 1 4 2", padding)

    def test_padding_must_be_integer(self):
        with self.assertRaises(InvalidKeyError):
            columnar.decrypt("ИГІКТАПРЯРОФ", "3 1 4 2", "1")

    def test_ciphertext_length_must_be_multiple_of_columns(self):
        with self.assertRaisesRegex(InvalidCiphertextError, "не кратна"):
            columnar.decrypt("ИГІКТАПРЯРО", "3 1 4 2", 0)

    def test_padding_for_empty_ciphertext(self):
        with self.assertRaises(InvalidCiphertextError):
            columnar.decrypt("", "3 1 4 2", 1)

    def test_pad_char_must_be_single_alphabet_letter(self):
        for pad in ("", "XX", "_", "Z", "АБ"):
            with self.subTest(pad=pad), self.assertRaises(InvalidKeyError):
                columnar.encrypt("ТЕКСТ", "2 1", pad_char=pad)


if __name__ == "__main__":
    unittest.main()
