import re
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

    def test_setup_env_uses_explicit_venv_interpreter_for_pip(self):
        text = Path('setup_env.bat').read_text(encoding='utf-8')
        self.assertIn('"%VENV%\\Scripts\\python.exe" -m pip install', text)
        # No PATH-dependent bare pip/python install anywhere.
        self.assertIsNone(re.search(r'^\s*pip\s+install', text, re.M))
        self.assertIsNone(re.search(r'^\s*python\s+-m\s+pip', text, re.M))
        # No activation-based install step.
        self.assertNotIn('activate.bat', text)


if __name__ == '__main__':
    unittest.main()
