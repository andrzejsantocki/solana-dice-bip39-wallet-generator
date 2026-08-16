import unittest
from pathlib import Path


class ReadmeAccuracyTests(unittest.TestCase):
    def test_readme_matches_dependency_runtime_model(self):
        text = Path('README.md').read_text(encoding='utf-8').lower()
        self.assertIn('wallet generation performs zero package installation', text)
        self.assertIn('setup_env.bat', text)
        self.assertNotIn('--force-reinstall', text)
        self.assertNotIn('startup performs a pip reinstall', text)
        self.assertIn('bip39 passphrase compatibility', text)
        self.assertIn('by default, this tool uses no bip39 passphrase', text)
        self.assertIn('--bip39-passphrase', text)
        self.assertIn('phantom/solflare recovery flows that ask for only the 12/24 words', text)


if __name__ == '__main__':
    unittest.main()
