"""
NebulaForge command-line entry point.

This module is the script entry point declared in pyproject.toml under
``[project.scripts]``. Keeping it inside the package ensures it works
regardless of where the user invokes ``nebulaforge`` from.
"""
from __future__ import annotations

import sys

from nebulaforge import __version__

try:
    from nebulaforge.core.interactive_cli import run_interactive_cli
    from nebulaforge.interfaces.cli import NebulaForgeCLI
    from nebulaforge.interfaces.tui import run_tui
except ImportError as exc:
    print(f"Import error: {exc}")
    sys.exit(1)


CLI_COMMANDS = {
    'list', 'create', 'install', 'remove', 'info', 'update',
    'backup', 'diagnostics', 'audit', 'config',
}


def main() -> int:
    """Route invocation to TUI, interactive CLI, or one-shot CLI."""
    print(f"Starting NebulaForge v{__version__}...")

    if len(sys.argv) <= 1:
        return run_tui()

    command = sys.argv[1]

    if command == "interactive":
        return run_interactive_cli()
    if command in ("--help", "-h", "help"):
        print("See README.md for full usage")
        return 0
    if command in CLI_COMMANDS:
        cli = NebulaForgeCLI(production_mode=False)
        return cli.run_from_args(sys.argv[1:])

    print(f"Unknown command: {command}")
    print("See --help for usage")
    return 1


if __name__ == "__main__":
    sys.exit(main())
