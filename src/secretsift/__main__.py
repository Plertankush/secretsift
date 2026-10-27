"""``python -m secretsift`` entry point."""

from __future__ import annotations

import sys

from secretsift.cli import main

if __name__ == "__main__":
    sys.exit(main())
