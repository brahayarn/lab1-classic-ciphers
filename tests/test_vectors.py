"""Обов'язкові контрольні вектори з розділу 7 методички."""
import unittest

from classic_ciphers import block, columnar, substitution, vigenere
from classic_ciphers.text import ALPHABET, LETTERS


class ControlVectorsTest(unittest.TestCase):
    def test_reversed_alphabet_substitution(self):
        table = ALPHABET[::-1]
        self.assertEqual(substitution.encrypt("СЛАВА УКРАЇНІ", table), "ІНЯЬЯ ЗОЇЯРЛС")
        self.assertEqual(substitution.decrypt("ІНЯЬЯ ЗОЇЯРЛС", table), "СЛАВА УКРАЇНІ")

    def test_reversed_alphabet_built_from_keyword_gives_same_table(self):
        self.assertEqual(substitution.build_table(ALPHABET[::-1]), ALPHABET[::-1])

    def test_vigenere(self):
        self.assertEqual(vigenere.encrypt("СЛАВА УКРАЇНІ", "КЛЮЧ"), "ВЬЮЩК ДЇККЧЛД")
        self.assertEqual(vigenere.decrypt("ВЬЮЩК ДЇККЧЛД", "КЛЮЧ"), "СЛАВА УКРАЇНІ")

    def test_block_transposition_letters_only(self):
        self.assertEqual(block.encrypt("СЛАВА УКРАЇНІ", "3 2 5 1 4", LETTERS), "АЛАСВРКЇУАНІ")
        self.assertEqual(block.encrypt("СЛАВАУКРАЇНІ", "3 2 5 1 4"), "АЛАСВРКЇУАНІ")
        # Еталоном зворотності є підготовлений рядок без пробілу.
        self.assertEqual(block.decrypt("АЛАСВРКЇУАНІ", "3 2 5 1 4"), "СЛАВАУКРАЇНІ")

    def test_columnar_transposition(self):
        result = columnar.encrypt("КРИПТОГРАФІЯ", "3 1 4 2")
        self.assertEqual(result, ("ИГІКТАПРЯРОФ", 0))
        self.assertEqual(columnar.decrypt("ИГІКТАПРЯРОФ", "3 1 4 2", 0), "КРИПТОГРАФІЯ")

    def test_lowercase_input_is_normalized_to_vector(self):
        self.assertEqual(vigenere.encrypt("слава україні", "ключ"), "ВЬЮЩК ДЇККЧЛД")


if __name__ == "__main__":
    unittest.main()
