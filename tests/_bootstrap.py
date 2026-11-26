"""Put the hunter, matrix and tools modules on sys.path for tests.

Works under both `python -m unittest discover -s tests` and `pytest`.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "src" / "hunt", ROOT / "src" / "matrix", ROOT / "tools"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
