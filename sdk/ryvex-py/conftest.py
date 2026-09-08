"""Pytest bootstrap: put src/ on sys.path so the tests import the local
package without requiring a pip install first."""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
