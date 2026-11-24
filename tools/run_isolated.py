"""Run the index tools with point imports from this checkout's protected package."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from runpy import run_module
import sys


COMMANDS = {"index", "schema_check", "stage_release", "verify_release", "tests"}


def main():
    if not sys.flags.isolated:
        raise SystemExit("Run License Index with Python's -I isolation flag.")
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        raise SystemExit("Select one License Index command: " + ", ".join(sorted(COMMANDS)))

    command = sys.argv.pop(1)
    package = Path(__file__).resolve().parent
    spec = spec_from_file_location("tools", package / "__init__.py", submodule_search_locations=[str(package)])
    tools = module_from_spec(spec)
    sys.modules["tools"] = tools
    spec.loader.exec_module(tools)

    if command == "tests":
        if len(sys.argv) != 1:
            raise SystemExit("The tests command takes no arguments.")
        import unittest

        # Discovery puts only the separately protected tests directory on the path.
        suite = unittest.TestLoader().discover(str(package.parent / "tests"))
        return int(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
    run_module(f"tools.{command}", run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
