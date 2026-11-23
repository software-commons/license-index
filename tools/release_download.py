"""Read and verify the public GitHub attachment for an approved release."""

from hashlib import sha256
from http.client import HTTPException
from io import BytesIO
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urljoin, urlsplit
from urllib.request import Request, build_opener

from .records import DATA_COMMIT, HEX_256, DataError, NoRedirects, encode, require
from .review_snapshot import REPOSITORY, REPOSITORY_ID, SnapshotError
from .stage_release import valid_archive_name, valid_archive_size

_API = "https://api.github.com"
_WEB = f"https://github.com/{REPOSITORY}"
_REPO_PATH = f"/repos/{REPOSITORY}"
_CDN_HOSTS = {
    "github-releases.githubusercontent.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
_DOWNLOAD_HEADERS = {
    "Accept": "application/octet-stream",
    "Accept-Encoding": "identity",
    "Cache-Control": "no-cache",
    "User-Agent": "software-commons-release-verifier",
}
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5
_MAX_TAG_OBJECTS = 16
_DOWNLOAD_TIMEOUT = 20


def _valid_tag(tag):
    return (isinstance(tag, str) and bool(tag)
            and not any(ord(character) < 33 or ord(character) == 127 or character in "~^:?*[\\"
                        for character in tag)
            and ".." not in tag and "@{" not in tag and not tag.endswith(".")
            and all(part and not part.startswith(".") and not part.endswith(".lock")
                    for part in tag.split("/")))


def _get_object(github, path):
    try:
        item = github._get_json(path)
    except SnapshotError as error:
        raise DataError(f"Could not read public GitHub release metadata ({error})") from None
    require(isinstance(item, dict), "GitHub returned malformed public release metadata")
    return item


def _tag_objects(github, tag, expected_commit):
    reference = _get_object(github, f"{_REPO_PATH}/git/ref/tags/{quote(tag, safe='/')}")
    require(reference.get("ref") == f"refs/tags/{tag}", "GitHub returned a different release tag")
    target = reference.get("object")
    objects = []
    while isinstance(target, dict) and target.get("type") == "tag":
        object_sha = target.get("sha")
        require(isinstance(object_sha, str) and DATA_COMMIT.fullmatch(object_sha),
                "GitHub returned an invalid annotated tag object identifier")
        require(object_sha not in objects and len(objects) < _MAX_TAG_OBJECTS,
                "GitHub returned a cyclic or too deeply nested release tag")
        objects.append(object_sha)
        annotation = _get_object(github, f"{_REPO_PATH}/git/tags/{object_sha}")
        require(annotation.get("sha") == object_sha, "GitHub returned a different annotated tag object")
        target = annotation.get("object")
    require(isinstance(target, dict) and target.get("type") == "commit" and target.get("sha") == expected_commit,
            "Public GitHub release tag does not resolve to the approved integrated commit")
    return tuple(objects)


def _same_github_url(observed, canonical):
    if not isinstance(observed, str) or any(ord(character) < 33 for character in observed):
        return False
    try:
        observed = urlsplit(observed)
        canonical = urlsplit(canonical)
        return (observed.scheme == canonical.scheme and observed.netloc == canonical.netloc
                and not observed.query and not observed.fragment
                and unquote(observed.path, errors="strict") == unquote(canonical.path, errors="strict"))
    except ValueError:
        return False


def _public_identity(github, tag, expected_commit, descriptor, notes_sha256):
    repository = _get_object(github, _REPO_PATH)
    require(repository.get("full_name") == REPOSITORY and repository.get("id") == REPOSITORY_ID
            and type(repository["id"]) is int and repository.get("private") is False,
            "Expected the canonical public License Index repository")
    tag_objects = _tag_objects(github, tag, expected_commit)
    escaped_tag = quote(tag, safe="")
    release_url = f"{_WEB}/releases/tag/{escaped_tag}"
    release = _get_object(github, f"{_REPO_PATH}/releases/tags/{escaped_tag}")
    release_id = release.get("id")
    published_at = release.get("published_at")
    require(type(release_id) is int and release_id > 0 and release.get("tag_name") == tag
            and release.get("url") == f"{_API}{_REPO_PATH}/releases/{release_id}"
            and _same_github_url(release.get("html_url"), release_url),
            "GitHub returned a different release")
    require(release.get("draft") is False and isinstance(published_at, str) and published_at.strip(),
            "Expected a published GitHub release")
    notes = {key: release.get(key) for key in ("name", "body")}
    require(all(isinstance(value, str) and value.strip() for value in notes.values())
            and sha256(encode(notes)).hexdigest() == notes_sha256,
            "Public GitHub release title or body differs from the approved release notes")

    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == 1 and isinstance(assets[0], dict),
            "Expected exactly one public GitHub release attachment")
    asset = assets[0]
    asset_id = asset.get("id")
    name = descriptor["name"]
    asset_url = f"{_WEB}/releases/download/{escaped_tag}/{quote(name, safe='')}"
    require(type(asset_id) is int and asset_id > 0 and asset.get("name") == name and asset.get("state") == "uploaded"
            and asset.get("url") == f"{_API}{_REPO_PATH}/releases/assets/{asset_id}"
            and _same_github_url(asset.get("browser_download_url"), asset_url),
            "GitHub did not identify the expected uploaded release archive")
    require(asset.get("label") in (None, "", name), "GitHub release archive has an unapproved display label")
    require(type(asset.get("size")) is int and asset["size"] == descriptor["bytes"],
            "GitHub release archive size differs from the approved archive")
    digest = asset.get("digest")
    require(digest is None or isinstance(digest, str) and digest.lower() == f"sha256:{descriptor['sha256']}",
            "GitHub release archive digest differs from the approved archive")
    metadata = {
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "tag": tag,
        "commit": expected_commit,
        "release_id": release_id,
        "release_url": release_url,
        "asset_id": asset_id,
        "asset_url": asset_url,
        "notes_sha256": notes_sha256,
    }
    return metadata, (tag_objects, published_at, digest)


def _redirect(url, location):
    require(isinstance(location, str) and location and not any(ord(character) < 33 for character in location),
            "GitHub archive download returned a malformed redirect")
    try:
        target = urljoin(url, location)
        parts = urlsplit(target)
    except ValueError:
        raise DataError("GitHub archive download returned a malformed redirect") from None
    require(parts.scheme == "https" and parts.netloc.lower() in _CDN_HOSTS and not parts.fragment,
            "GitHub archive download redirected outside the HTTPS release asset hosts")
    return target


def _read_archive(response, size):
    require(response.status == 200, "GitHub archive download did not return a complete response")
    advertised = response.headers.get("Content-Length")
    require(advertised is None or advertised.lstrip("0") == str(size),
            "GitHub archive download declared a different size")
    buffer = BytesIO()
    remaining = size + 1
    while remaining:
        piece = response.read(min(remaining, 65536))
        if not piece:
            break
        buffer.write(piece)
        remaining -= len(piece)
    return buffer.getvalue()


def _download_archive(url, size):
    opener = build_opener(NoRedirects())
    for _ in range(_MAX_REDIRECTS + 1):
        request = Request(url, headers=_DOWNLOAD_HEADERS, method="GET")
        try:
            with opener.open(request, timeout=_DOWNLOAD_TIMEOUT) as response:
                return _read_archive(response, size)
        except HTTPError as error:
            with error:
                require(error.code in _REDIRECT_CODES, f"Could not download public GitHub archive (HTTP {error.code})")
                url = _redirect(url, error.headers.get("Location"))
        except (OSError, HTTPException):
            raise DataError("Could not read the public GitHub release archive") from None
    raise DataError("GitHub archive download exceeded the redirect limit")


def fetch_public_archive(github, tag, expected_commit, descriptor, *, notes_sha256):
    """Verify the tag and release notes, then fetch and verify the archive anonymously."""
    require(_valid_tag(tag), "Expected a valid GitHub release tag")
    require(isinstance(expected_commit, str) and DATA_COMMIT.fullmatch(expected_commit),
            "Expected the full approved integrated commit SHA")
    require(isinstance(notes_sha256, str) and HEX_256.fullmatch(notes_sha256),
            "Expected the approved release notes SHA-256")
    require(isinstance(descriptor, dict) and set(descriptor) == {"name", "bytes", "sha256"},
            "Expected the approved release archive descriptor")
    name, size, digest = descriptor["name"], descriptor["bytes"], descriptor["sha256"]
    require(valid_archive_name(name) and valid_archive_size(size)
            and isinstance(digest, str) and HEX_256.fullmatch(digest),
            "Invalid approved release archive descriptor")
    identity = _public_identity(github, tag, expected_commit, descriptor, notes_sha256)
    metadata, _ = identity
    archive = _download_archive(metadata["asset_url"], size)
    require(len(archive) == size and sha256(archive).hexdigest() == digest,
            "Public GitHub release archive bytes differ from the approved archive")
    require(_public_identity(github, tag, expected_commit, descriptor, notes_sha256) == identity,
            "Public GitHub release, tag, or archive changed during verification")
    return archive, metadata
