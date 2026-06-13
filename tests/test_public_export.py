import ast
from pathlib import Path


def test_public_export_has_no_private_runtime_files():
    root = Path(__file__).resolve().parents[1]
    blocked = [
        "config.toml",
        "spam_rules.toml",
        "spamfighter_state.sqlite3",
        "runtime-data",
        "spamfighter_full_regex_export.txt",
        "spamfighter_full_regex_singleline.txt",
    ]
    for name in blocked:
        assert not (root / name).exists()


def test_public_spamfighter_python_is_valid():
    root = Path(__file__).resolve().parents[1]
    ast.parse((root / "SpamFighter.py").read_text(encoding="utf-8"))
