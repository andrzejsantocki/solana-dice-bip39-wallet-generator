import unittest
from pathlib import Path


class ReadmeAccuracyTests(unittest.TestCase):
    def test_readme_matches_dependency_runtime_model(self):
        text = Path('README.md').read_text(encoding='utf-8').lower()
        self.assertIn('wallet generation performs zero package installation', text)
        self.assertIn('setup_env.bat', text)
        self.assertNotIn('--force-reinstall', text)
        self.assertNotIn('startup performs a pip reinstall', text)


if __name__ == '__main__':
    unittest.main()
