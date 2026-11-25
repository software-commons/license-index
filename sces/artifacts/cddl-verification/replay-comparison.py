"""Replay the Python CDDL comparison against controlled copies of both pinned inputs."""

from hashlib import sha256
import json
from pathlib import Path
import runpy
import sys


def replay(method, receipt, publisher, spdx):
    pins = receipt["inputs"]
    bodies = {}
    for alias, path in (("publisher", publisher), ("spdx", spdx)):
        raw = path.read_bytes()
        if len(raw) != pins[alias]["bytes"] or sha256(raw).hexdigest() != pins[alias]["sha256"]:
            raise ValueError(f"{alias} differs from the exact acquired body")
        bodies[alias] = raw
    implementation = method.read_bytes()
    if sha256(implementation).hexdigest() != receipt["python_method"]["sha256"]:
        raise ValueError("Python method bytes differ from the recorded method")
    comparison = runpy.run_path(str(method))["compare"]
    return comparison(bodies["publisher"], bodies["spdx"])


if __name__ == "__main__":
    method, recipe, publisher, spdx = map(Path, sys.argv[1:])
    data = json.loads(recipe.read_bytes())
    print(json.dumps(replay(method, data, publisher, spdx), sort_keys=True, separators=(",", ":")))