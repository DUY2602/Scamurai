"""Compatibility wrapper for the URL training entrypoint."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from .train_models import main
except ImportError:  # pragma: no cover - direct script execution fallback
    from URL.training.train_models import main


if __name__ == "__main__":
    main()
