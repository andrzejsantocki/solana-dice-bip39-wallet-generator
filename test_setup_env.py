import unittest
from pathlib import Path


class SetupEnvTests(unittest.TestCase):
    def test_setup_env_never_upgrades_pip_online(self):
        text = Path('setup_env.bat').read_text(encoding='utf-8').lower()
        self.assertNotIn('install --upgrade pip', text)
        self.assertIn('--no-index', text)
        self.assertIn('--require-hashes', text)
        self.assertIn('missing pkgs folder. refusing online install.', text)

    def test_setup_env_requires_python_310_x64_for_bundled_wheels(self):
        text = Path('setup_env.bat').read_text(encoding='utf-8').lower()
        self.assertIn('py -3.10', text)
        self.assertNotIn('py -3 -m venv', text)
        self.assertNotIn('python -m venv', text)
        self.assertIn('requires 64-bit cpython 3.10', text)
        self.assertIn("sys.version_info[:2] == (3, 10)", text)
        self.assertIn("struct.calcsize('p')*8 == 64", text)


if __name__ == '__main__':
    unittest.main()
