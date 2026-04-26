"""
Repo-root conftest.py.

Adds the repository root to sys.path so tests can import top-level
modules like `sandbox` and `varek_warden` without requiring the
project to be installed as a package. This matches the behavior
of running pytest interactively from the repo root.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
