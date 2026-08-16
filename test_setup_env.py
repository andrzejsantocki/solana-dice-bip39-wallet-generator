import unittest
from pathlib import Path


class SetupEnvTests(unittest.TestCase):
    def test_setup_env_never_upgrades_pip_online(self):
        text = Path('setup_env.bat').read_text(encoding='utf-8').lower()
        self.assertNotIn('install --upgrade pip', text)
        self.assertIn('--no-index', text)
        self.assertIn('--require-hashes', text)
        self.assertIn('missing pkgs folder. refusing online install.', text)


if __name__ == '__main__':
    unittest.main()
