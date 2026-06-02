"""Back-compat shim: the CLI now lives in netsleuth.cli.

Prefer the installed `netsleuth` command or `python -m netsleuth`. This wrapper
keeps `python main.py …` working for anyone used to it.
"""

from __future__ import annotations

from netsleuth.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
