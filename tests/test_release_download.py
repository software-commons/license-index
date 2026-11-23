"""Verify the public release transport with synthetic GitHub and HTTP responses."""

from email.message import Message
from hashlib import sha256
from io import BytesIO
from types import SimpleNamespace
from urllib.error import HTTPError
import unittest
from unittest.mock import Mock, patch

from tools.records import DataError, encode
from tools.release_download import _download_archive, fetch_public_archive
from tools.review_snapshot import REPOSITORY, REPOSITORY_ID


class PublicReleaseTests(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.tag = "qualified/v1.0+scope"
        self.ref = f"refs/tags/{self.tag}"
        self.archive = b"synthetic archive bytes"
        self.descriptor = {"name": "license-scope.ZIP", "bytes": len(self.archive),
                           "sha256": sha256(self.archive).hexdigest()}
        self.api = f"https://api.github.com/repos/{REPOSITORY}"
        self.web = f"https://github.com/{REPOSITORY}"
        self.repo_path = f"/repos/{REPOSITORY}"
        self.ref_path = f"{self.repo_path}/git/ref/tags/qualified/v1.0%2Bscope"
        self.release_path = f"{self.repo_path}/releases/tags/qualified%2Fv1.0%2Bscope"
        self.release_url = f"{self.web}/releases/tag/qualified%2Fv1.0%2Bscope"
        self.asset_url = f"{self.web}/releases/download/qualified%2Fv1.0%2Bscope/license-scope.ZIP"
        self.notes = {"name": "Qualified release v1.0", "body": "Data license, scope, and provenance.\n"}
        self.notes_digest = sha256(encode(self.notes)).hexdigest()
        self.asset_record = {"id": 123, "name": self.descriptor["name"], "state": "uploaded",
                             "url": f"{self.api}/releases/assets/123", "browser_download_url": self.asset_url,
                             "size": self.descriptor["bytes"], "digest": f"sha256:{self.descriptor['sha256']}"}
        self.release = {**self.notes, "id": 53, "draft": False, "published_at": "2026-01-02T03:04:05Z",
                        "tag_name": self.tag, "target_commitish": "b" * 40, "html_url": self.release_url,
                        "url": f"{self.api}/releases/53", "assets": [self.asset_record]}
        self.reference = {"ref": self.ref, "object": {"type": "commit", "sha": self.commit}}
        self.responses = {
            self.repo_path: {"full_name": REPOSITORY, "id": REPOSITORY_ID, "private": False},
            self.ref_path: self.reference,
            self.release_path: self.release,
        }
        self.github = SimpleNamespace(_get_json=Mock(side_effect=self.responses.__getitem__))
        download = patch("tools.release_download._download_archive", return_value=self.archive)
        self.download = download.start()
        self.addCleanup(download.stop)

    def fetch(self):
        return fetch_public_archive(self.github, self.tag, self.commit, self.descriptor,
                                    notes_sha256=self.notes_digest)

    def test_verifies_anonymous_asset_and_rechecks_public_identity(self):
        contents, metadata = self.fetch()
        self.assertEqual(contents, self.archive)
        self.assertEqual(metadata, {
            "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "commit": self.commit, "tag": self.tag,
            "asset_id": 123, "asset_url": self.asset_url, "release_id": 53, "release_url": self.release_url,
            "notes_sha256": self.notes_digest,
        })
        self.download.assert_called_once_with(self.asset_url, len(self.archive))
        self.assertEqual([call.args[0] for call in self.github._get_json.call_args_list],
                         [self.repo_path, self.ref_path, self.release_path] * 2)

    def test_resolves_nested_annotated_objects_and_allows_a_missing_advertised_digest(self):
        first, second = "b" * 40, "c" * 40
        self.reference["object"] = {"type": "tag", "sha": first}
        self.responses[f"{self.repo_path}/git/tags/{first}"] = {
            "sha": first, "object": {"type": "tag", "sha": second},
        }
        self.responses[f"{self.repo_path}/git/tags/{second}"] = {
            "sha": second, "object": {"type": "commit", "sha": self.commit},
        }
        del self.asset_record["digest"]
        self.assertEqual(self.fetch()[0], self.archive)
        self.responses[f"{self.repo_path}/git/tags/{second}"]["object"] = {"type": "tag", "sha": first}
        self.download.reset_mock()
        with self.assertRaisesRegex(DataError, "cyclic or too deeply nested"):
            self.fetch()
        self.download.assert_not_called()

    def test_requires_public_canonical_repository_and_exact_attachment(self):
        cases = (
            (self.repo_path, {"id": REPOSITORY_ID + 1}, "canonical public"),
            (self.repo_path, {"private": True}, "canonical public"),
            (self.release_path, {"draft": True}, "published GitHub release"),
            (self.release_path, {"published_at": None}, "published GitHub release"),
            (self.release_path, {"html_url": self.release_url + "?preview=true"}, "different release"),
            (self.release_path, {"body": "Changed notes"}, "approved release notes"),
            (self.release_path, {"assets": [self.asset_record, self.asset_record]}, "exactly one"),
            (self.ref_path, {"object": {"type": "commit", "sha": "c" * 40}}, "approved integrated commit"),
        )
        for path, fields, message in cases:
            with self.subTest(fields=fields):
                original = self.responses[path]
                self.responses[path] = {**original, **fields}
                with self.assertRaisesRegex(DataError, message):
                    self.fetch()
                self.responses[path] = original
        self.download.assert_not_called()

    def test_checks_asset_name_state_url_advertised_size_and_digest_before_download(self):
        changes = (
            ({"name": "wrong.zip"}, "expected uploaded release archive"),
            ({"state": "starter"}, "expected uploaded release archive"),
            ({"browser_download_url": self.asset_url.replace("github.com", "other.invalid")},
             "expected uploaded release archive"),
            ({"size": self.descriptor["bytes"] + 1}, "size differs"),
            ({"digest": f"sha256:{'c' * 64}"}, "digest differs"),
            ({"label": "Unapproved public wording"}, "unapproved display label"),
        )
        for fields, message in changes:
            with self.subTest(fields=fields):
                self.release["assets"] = [{**self.asset_record, **fields}]
                with self.assertRaisesRegex(DataError, message):
                    self.fetch()
        self.download.assert_not_called()

    def test_rejects_replaced_archive_even_when_metadata_looks_correct(self):
        self.download.return_value = b"X" + self.archive[1:]
        with self.assertRaisesRegex(DataError, "archive bytes differ"):
            self.fetch()

    def test_rejects_replaced_asset_or_tag_during_download(self):
        def replace_asset(*_args):
            self.release["assets"] = [{**self.asset_record, "id": 456, "url": f"{self.api}/releases/assets/456"}]
            return self.archive

        self.download.side_effect = replace_asset
        with self.assertRaisesRegex(DataError, "changed during verification"):
            self.fetch()

        def replace_tag(*_args):
            self.reference["object"]["sha"] = "f" * 40
            return self.archive

        self.download.side_effect = replace_tag
        with self.assertRaisesRegex(DataError, "approved integrated commit"):
            self.fetch()

    def test_invalid_input_never_contacts_github(self):
        cases = (
            ("../main", self.commit, self.descriptor, self.notes_digest),
            (self.tag, "a" * 7, self.descriptor, self.notes_digest),
            (self.tag, self.commit, {**self.descriptor, "name": "../bad.zip"}, self.notes_digest),
            (self.tag, self.commit, {**self.descriptor, "bytes": True}, self.notes_digest),
            (self.tag, self.commit, {**self.descriptor, "bytes": 2 * 1024 ** 3}, self.notes_digest),
            (self.tag, self.commit, self.descriptor, "invalid"),
        )
        for tag, commit, descriptor, notes in cases:
            with self.subTest(tag=tag, commit=commit, descriptor=descriptor, notes=notes):
                with self.assertRaises(DataError):
                    fetch_public_archive(self.github, tag, commit, descriptor, notes_sha256=notes)
        self.github._get_json.assert_not_called()
        self.download.assert_not_called()


class ArchiveTransportTests(unittest.TestCase):
    url = f"https://github.com/{REPOSITORY}/releases/download/v1.0/archive.zip"

    def setUp(self):
        self.opener = Mock()
        builder = patch("tools.release_download.build_opener", return_value=self.opener)
        builder.start()
        self.addCleanup(builder.stop)

    def redirect(self, location):
        headers = Message()
        headers["Location"] = location
        return HTTPError(self.url, 302, "Redirect", headers, BytesIO(b"unread redirect body"))

    def response(self, data, headers=None):
        response = BytesIO(data)
        response.status = 200
        response.headers = headers or {}
        response.read = Mock(wraps=response.read)
        return response

    def test_allowed_https_redirect_uses_fresh_requests_without_authentication(self):
        location = "https://release-assets.githubusercontent.com/github-production-release-asset?sig=synthetic"
        redirect = self.redirect(location)
        redirect.fp.read = Mock(wraps=redirect.fp.read)
        response = self.response(b"binary", {"Content-Length": "6"})
        self.opener.open.side_effect = (redirect, response)
        self.assertEqual(_download_archive(self.url, 6), b"binary")
        requests = [call.args[0] for call in self.opener.open.call_args_list]
        self.assertEqual([request.full_url for request in requests], [self.url, location])
        for request in requests:
            self.assertEqual(request.get_method(), "GET")
            self.assertTrue({"authorization", "cookie", "proxy-authorization"}.isdisjoint(
                name.lower() for name, _ in request.header_items()))
        redirect.fp.read.assert_not_called()
        self.assertTrue(redirect.fp.closed)

    def test_unsafe_redirect_ends_download_before_second_request(self):
        for location in ("http://release-assets.githubusercontent.com/file",
                         "https://release-assets.githubusercontent.com.other.invalid/file",
                         "https://user@release-assets.githubusercontent.com/file",
                         "https://release-assets.githubusercontent.com:9999/file",
                         "/different-public-file"):
            with self.subTest(location=location):
                self.opener.reset_mock()
                self.opener.open.side_effect = self.redirect(location)
                with self.assertRaisesRegex(DataError, "outside the HTTPS release asset hosts"):
                    _download_archive(self.url, 6)
                self.opener.open.assert_called_once()

    def test_reads_at_most_the_approved_size_plus_one_byte(self):
        response = self.response(b"oversized" * 20_000)
        self.opener.open.return_value = response
        self.assertEqual(len(_download_archive(self.url, 65536)), 65537)
        self.assertEqual([call.args[0] for call in response.read.call_args_list], [65536, 1])

    def test_rejects_wrong_http_content_length_before_reading_body(self):
        response = self.response(b"wrong", {"Content-Length": "5"})
        self.opener.open.return_value = response
        with self.assertRaisesRegex(DataError, "declared a different size"):
            _download_archive(self.url, 6)
        response.read.assert_not_called()
