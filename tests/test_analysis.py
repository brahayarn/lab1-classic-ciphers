"""Додаткові завдання: частоти, індекс збігів, оцінка довжини ключа Віженера."""
import os
import unittest

from classic_ciphers import analysis, substitution, vigenere
from classic_ciphers.fileio import read_text

SAMPLE = read_text(os.path.join(os.path.dirname(__file__), os.pardir, "samples", "message.txt"))


class FrequencyTest(unittest.TestCase):
    def test_sample_size_is_within_lab_requirement(self):
        self.assertTrue(300 <= sum(analysis.letter_counts(SAMPLE).values()) <= 500)

    def test_substitution_preserves_frequency_distribution(self):
        encrypted = substitution.encrypt(SAMPLE, substitution.build_table("ЗАХИСТ"))
        plain = sorted(analysis.letter_counts(SAMPLE).values())
        cipher = sorted(analysis.letter_counts(encrypted).values())
        self.assertEqual(plain, cipher)
        self.assertAlmostEqual(analysis.index_of_coincidence(SAMPLE),
                               analysis.index_of_coincidence(encrypted))

    def test_vigenere_flattens_distribution(self):
        encrypted = vigenere.encrypt(SAMPLE, "ЗАХИСТ")
        self.assertLess(analysis.index_of_coincidence(encrypted),
                        analysis.index_of_coincidence(SAMPLE))

    def test_index_of_coincidence_edge_cases(self):
        self.assertEqual(analysis.index_of_coincidence(""), 0.0)
        self.assertEqual(analysis.index_of_coincidence("АААА"), 1.0)

    def test_histogram_lists_every_letter(self):
        self.assertEqual(len(analysis.format_histogram(analysis.letter_counts("АБ")).splitlines()), 33)


class KeyLengthTest(unittest.TestCase):
    def test_estimates_key_length_on_sample(self):
        for key in ("КЛЮЧ", "ҐРУНТ", "ЗАХИСТ"):
            with self.subTest(key=key):
                encrypted = vigenere.encrypt(SAMPLE, key)
                self.assertEqual(analysis.estimate_key_length(encrypted, 12), len(key))

    def test_too_short_text(self):
        self.assertEqual(analysis.estimate_key_length("А"), 0)


if __name__ == "__main__":
    unittest.main()
