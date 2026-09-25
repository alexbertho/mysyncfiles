import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HOOK_PATH = ROOT / "deploy" / "mkdocs_hooks.py"
SPEC = importlib.util.spec_from_file_location("mkdocs_hooks", HOOK_PATH)
HOOKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOOKS)


class PublishedDocsTest(unittest.TestCase):
    def test_published_install_command_uses_configured_origin(self):
        with patch.dict(os.environ, {"MYSYNC_PUBLIC_URL": "https://files.example.test"}):
            for page in ("index.md", "install-client.md"):
                with self.subTest(page=page):
                    source = (ROOT / "docs" / page).read_text()
                    published = HOOKS.on_page_markdown(source)
                    self.assertIn(
                        "curl -fsS --proto '=https' --max-redirs 0 https://files.example.test/install.sh | sh",
                        published,
                    )
                    self.assertNotIn("sync.example.org", published)

    def test_source_preview_keeps_generic_example(self):
        source = "https://sync.example.org/install.sh"
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(HOOKS.on_page_markdown(source), source)


if __name__ == "__main__":
    unittest.main()
