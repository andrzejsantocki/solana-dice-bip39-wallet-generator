import ast
import io
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

    def test_pyfiglet_dependency_removed_from_wallet_process(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8').lower()
        req = Path('requirements-hashes.txt').read_text(encoding='utf-8').lower()
        self.assertNotIn('pyfiglet', text)
        self.assertNotIn('pyfiglet', req)

    def test_gap_check_does_not_reprint_mnemonic_context(self):
        words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        answers = iter(['abandon'] * 5)
        with patch('generate_wallet.random.sample', return_value=[0, 1, 2, 3, 4]), patch('builtins.input', lambda _prompt: next(answers)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                gw.mnemonic_gap_check(words)
        out = buf.getvalue()
        self.assertIn('Mnemonic was shown once above', out)
        self.assertNotIn(words, out)
        self.assertNotIn('____', out)


if __name__ == '__main__':
    unittest.main()
