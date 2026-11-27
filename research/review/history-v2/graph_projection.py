"""Static v1 graph-verifier projection. Scratch-only; separately review before use."""
from io import BytesIO
from zipfile import ZipFile
from hashlib import sha256
import json
from solid_history_v2 import MAX_RAW,MAX_MANIFEST,MAX_COUNT,canonical as canonical_json, object_hash, require
FORMAT="license-index-history-v1"
REPOSITORY="https://github.com/software-commons/license-index"
CURRENT="registry/coverage/current.json"

import re
def oid_valid(oid):
    return re.fullmatch(r"[0-9a-f]{40}", oid) is not None


def commit_links(raw):
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    tree = headers[0].removeprefix(b"tree ").decode("ascii")
    parents = tuple(line[7:].decode("ascii") for line in headers if line.startswith(b"parent "))
    require(headers[0].startswith(b"tree ") and oid_valid(tree) and all(oid_valid(oid) for oid in parents),
            "invalid commit tree or parent")
    return tree, parents


def tree_entries(raw):
    entries = {}
    offset = 0
    modes = {b"40000": "tree", b"100644": "blob", b"100755": "blob", b"120000": "blob"}
    while offset < len(raw):
        end = raw.index(b"\0", offset)
        mode, name = raw[offset:end].split(b" ", 1)
        require(mode in modes and name and b"/" not in name and name not in entries
                and end + 21 <= len(raw), "invalid regular Git tree entry")
        entries[name] = modes[mode], raw[end + 1:end + 21].hex()
        offset = end + 21
    return entries


def verify_projection(payload, base, head):
    with ZipFile(BytesIO(payload), "r") as archive:
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        objects = manifest["objects"]
        require(manifest_bytes == canonical_json(manifest), "history manifest is not canonical")
        require((manifest["format"], manifest["repository"], manifest["object_format"],
                 manifest["base"], manifest["head"]) == (FORMAT, REPOSITORY, "sha1", base, head),
                "history manifest pins differ")
        require(archive.namelist() == ["manifest.json", *[f"objects/{oid}" for oid in sorted(objects)]],
                "unexpected history ZIP members")
        require(sum(entry["size"] for entry in objects.values()) <= MAX_RAW and len(payload) <= MAX_RAW + MAX_MANIFEST + MAX_COUNT * 256,
                "history ZIP exceeds size limits")
        commits = {}
        trees = {}
        for oid, entry in objects.items():
            raw = archive.read(f"objects/{oid}")
            kind = entry["type"]
            require(len(raw) == entry["size"] and sha256(raw).hexdigest() == entry["sha256"]
                    and object_hash(kind, raw) == oid, f"history ZIP object mismatch: {oid}")
            if kind == "commit":
                commits[oid] = commit_links(raw)
            elif kind == "tree":
                trees[oid] = tree_entries(raw)
            else:
                require(kind == "blob", f"unexpected history object type: {oid}")

        def descendants(origin, only_commits):
            stack = [("commit", origin)]
            visited = set()
            while stack:
                kind, oid = stack.pop()
                require(objects[oid]["type"] == kind, f"wrong history object type: {oid}")
                if oid in visited:
                    continue
                visited.add(oid)
                if kind == "commit":
                    tree, parents = commits[oid]
                    stack.extend(("commit", parent) for parent in parents)
                    if not only_commits:
                        stack.append(("tree", tree))
                elif kind == "tree":
                    stack.extend(trees[oid].values())
            return visited

        def path_at(commit, path):
            kind, oid = "tree", commits[commit][0]
            for part in path.split("/"):
                require(kind == "tree", f"non-directory parent: {commit}:{path}")
                kind, oid = trees[oid][part.encode("utf-8")]
            return kind, oid

        require(descendants(head, False) == set(objects), "history object graph is incomplete or includes unseen objects")
        head_commits = descendants(head, True)
        require(base in head_commits, "base is not an ancestor of the archived head")
        incoming = head_commits - descendants(base, True)
        for path, association in manifest["snapshots"].items():
            commit, blob = association["commit"], association["blob"]
            require(commit in incoming, f"snapshot commit is outside the requested range: {path}")
            require(path_at(commit, CURRENT) == path_at(commit, path) == path_at(head, path) == ("blob", blob),
                    f"snapshot does not resolve to exact current/archived bytes: {path}")
            snapshot = json.loads(archive.read(f"objects/{blob}"))
            source = association["source_manifest"]
            require(snapshot["snapshot"] == path and snapshot["source_manifest"] == source
                    and snapshot["schema_version"] == association["schema_version"],
                    f"snapshot declaration differs from manifest: {path}")
            require(path_at(commit, source) == path_at(head, source) == ("blob", association["source_blob"]),
                    f"source manifest does not resolve to the same exact bytes: {path}")
        return manifest


