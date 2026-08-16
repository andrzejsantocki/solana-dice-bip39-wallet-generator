import ast
import io
import random
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import generate_wallet as gw


class OperationalSafetyTests(unittest.TestCase):
    def test_generator_does_zero_runtime_package_installation(self):
        tree = ast.parse(Path('generate_wallet.py').read_text(encoding='utf-8'))
        imports = {alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        self.assertNotIn('subprocess', imports)
        self.assertNotIn('os', imports)
        text = Path('generate_wallet.py').read_text(encoding='utf-8').lower()
        self.assertNotIn('--force-reinstall', text)
        self.assertNotIn('pip install', text)

    def test_unused_crypto_and_ascii_dependencies_removed(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8').lower()
        req = Path('requirements-hashes.txt').read_text(encoding='utf-8').lower()
        self.assertNotIn('pyfiglet', text + req)
        self.assertNotIn('ecdsa', text + req)
        self.assertNotIn('ripemd160', text)
        self.assertNotIn('secp256k1', text)

    def test_gap_check_does_not_reprint_or_echo_correct_words(self):
        words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        answers = iter(['wrong'] * 5)
        with patch('generate_wallet.random.sample', return_value=[0, 1, 2, 3, 4]), patch('generate_wallet.getpass.getpass', lambda _prompt: next(answers)):
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit):
                gw.mnemonic_gap_check(words)
        out = buf.getvalue()
        self.assertIn('Mnemonic is not reprinted here', out)
        self.assertNotIn(words, out)
        self.assertNotIn('abandon abandon', out)
        self.assertNotIn('-> abandon', out)

    def test_hash_roll_count_has_safe_minimum(self):
        with self.assertRaises(SystemExit):
            gw.parse_args(['--entropy-mode', 'hash-rolls', '--roll-count', '1'])

    def test_suspect_entropy_aborts(self):
        q = gw.analyze_roll_quality([1, 2] * 20, [(1, 2)] * 20, 16)
        with self.assertRaises(SystemExit):
            gw.abort_if_not_good(q)

    def test_bip39_passphrase_is_explicit_opt_in(self):
        args = gw.parse_args([])
        self.assertFalse(args.bip39_passphrase)
        args = gw.parse_args(['--bip39-passphrase'])
        self.assertTrue(args.bip39_passphrase)

    def test_die_roll_input_uses_hidden_getpass(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8')
        self.assertIn('def hidden_die_roll', text)
        self.assertIn('getpass.getpass(prompt)', text)
        self.assertNotIn('raw = input(', text)

    def test_fair_von_neumann_sessions_mostly_pass_gate(self):
        random.seed(1234)
        passes = 0
        trials = 200
        for _ in range(trials):
            rolls = []
            pairs = []
            bits = 0
            while bits < 256:
                a = random.randint(1, 6); b = random.randint(1, 6)
                rolls.extend([a, b]); pairs.append((a, b))
                if a != b: bits += 1
            q = gw.analyze_roll_quality(rolls, pairs, 256)
            if not q['warnings']:
                passes += 1
        self.assertGreaterEqual(passes / trials, 0.90)

    def test_import_location_verification_exists(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8')
        self.assertIn('def verify_import_locations', text)
        self.assertIn('Path(sys.prefix).resolve()', text)


if __name__ == '__main__':
    unittest.main()
