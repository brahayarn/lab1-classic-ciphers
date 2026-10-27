"""Зворотність D_k(E_k(x)) = підготовлений x, включно з генеративними тестами."""
import random
import unittest

from classic_ciphers import block, columnar, substitution, vigenere
from classic_ciphers.text import ALPHABET, LETTERS, PRESERVE, prepare, prepare_for_transposition

from .helpers import MESSAGES

SEED = 20261012
FILLER = " ,.!?-'\n0123456789"


def random_text(rng, length):
    pool = ALPHABET + ALPHABET.lower() + FILLER
    return "".join(rng.choice(pool) for _ in range(length))


def random_permutation(rng, n):
    perm = list(range(1, n + 1))
    rng.shuffle(perm)
    return perm


class FixedMessagesRoundTripTest(unittest.TestCase):
    def test_at_least_ten_messages(self):
        self.assertGreaterEqual(len(MESSAGES), 10)

    def test_substitution(self):
        table = substitution.build_table("ШИФРУВАННЯ")
        for message in MESSAGES:
            with self.subTest(message=message):
                encrypted = substitution.encrypt(message, table)
                self.assertEqual(substitution.decrypt(encrypted, table), prepare(message))

    def test_vigenere(self):
        for message in MESSAGES:
            with self.subTest(message=message):
                encrypted = vigenere.encrypt(message, "ҐЕЄІЇ")
                self.assertEqual(vigenere.decrypt(encrypted, "ҐЕЄІЇ"), prepare(message))

    def test_block(self):
        for mode in (PRESERVE, LETTERS):
            for message in MESSAGES:
                with self.subTest(mode=mode, message=message):
                    encrypted = block.encrypt(message, "3 2 5 1 4", mode)
                    self.assertEqual(block.decrypt(encrypted, "3 2 5 1 4", mode),
                                     prepare_for_transposition(message, mode))

    def test_columnar(self):
        for mode in (PRESERVE, LETTERS):
            for message in MESSAGES:
                with self.subTest(mode=mode, message=message):
                    encrypted, padding = columnar.encrypt(message, "3 1 4 2", mode)
                    self.assertEqual(columnar.decrypt(encrypted, "3 1 4 2", padding, mode),
                                     prepare_for_transposition(message, mode))

    def test_preserve_mode_keeps_every_character(self):
        message = "Рядок 1,\nрядок 2!"
        self.assertEqual(sorted(block.encrypt(message, "2 1 3")), sorted(prepare(message)))
        self.assertEqual(sorted(columnar.encrypt(message, "2 1 3").text.replace("Х", "")),
                         sorted(prepare(message).replace("Х", "")))


class PropertyBasedRoundTripTest(unittest.TestCase):
    """Генеративні тести з фіксованим зерном — результати відтворювані."""

    ITERATIONS = 300

    def setUp(self):
        self.rng = random.Random(SEED)

    def test_substitution_random_keys(self):
        for _ in range(self.ITERATIONS):
            table = "".join(self.rng.sample(ALPHABET, len(ALPHABET)))
            text = random_text(self.rng, self.rng.randint(0, 60))
            self.assertEqual(substitution.decrypt(substitution.encrypt(text, table), table),
                             prepare(text))

    def test_vigenere_random_keys(self):
        for _ in range(self.ITERATIONS):
            key = "".join(self.rng.choice(ALPHABET) for _ in range(self.rng.randint(1, 12)))
            text = random_text(self.rng, self.rng.randint(0, 60))
            self.assertEqual(vigenere.decrypt(vigenere.encrypt(text, key), key), prepare(text))

    def test_block_random_permutations(self):
        for _ in range(self.ITERATIONS):
            perm = random_permutation(self.rng, self.rng.randint(1, 10))
            mode = self.rng.choice((PRESERVE, LETTERS))
            text = random_text(self.rng, self.rng.randint(0, 60))
            self.assertEqual(block.decrypt(block.encrypt(text, perm, mode), perm, mode),
                             prepare_for_transposition(text, mode))

    def test_columnar_random_permutations(self):
        for _ in range(self.ITERATIONS):
            perm = random_permutation(self.rng, self.rng.randint(1, 10))
            mode = self.rng.choice((PRESERVE, LETTERS))
            text = random_text(self.rng, self.rng.randint(0, 60))
            encrypted, padding = columnar.encrypt(text, perm, mode)
            self.assertLess(padding, len(perm))
            self.assertEqual(columnar.decrypt(encrypted, perm, padding, mode),
                             prepare_for_transposition(text, mode))


if __name__ == "__main__":
    unittest.main()
