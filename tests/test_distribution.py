"""Test exact publisher rights bytes without acquiring or distributing real statements."""

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from tools.distribution import (
    CC_RIGHTS, POLYFORM_RIGHTS, RIGHTS_DOCUMENTS, RIGHTS_MAX_BYTES, read_rights_document, validate_texts,
)
from tools.records import Catalog, DataError, NoRedirects


class RightsTests(unittest.TestCase):
    def test_custody_reader_rejects_wrong_bytes_locator_and_missing_digest(self):
        catalog = Catalog()
        identifier = "CC-BY-SA-4.0"
        fixture = b"Synthetic rights statement.\n"
        row = {**catalog.packaged[identifier], "rights_sha256": sha256(fixture).hexdigest()}
        catalog.packaged = {identifier: row}
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / RIGHTS_DOCUMENTS[CC_RIGHTS]
            path.write_bytes(fixture)

            def read(url):
                return read_rights_document(url, root=root)

            validate_texts(catalog, rights_reader=read)
            path.write_bytes(fixture.lower())
            with self.assertRaisesRegex(DataError, "publisher rights SHA-256 mismatch"):
                validate_texts(catalog, rights_reader=read)
            row["rights"] = POLYFORM_RIGHTS
            with self.assertRaisesRegex(DataError, "unapproved publisher rights locator"):
                validate_texts(catalog, rights_reader=read)
            row["rights"] = CC_RIGHTS
            del row["rights_sha256"]
            with self.assertRaisesRegex(DataError, "invalid rights digest"):
                validate_texts(catalog, rights_reader=read)

    def test_network_reader_is_allowlisted_bounded_and_redirect_free(self):
        body = MagicMock(status=200)
        body.__enter__.return_value = body
        body.geturl.return_value = CC_RIGHTS
        body.read.return_value = b"Synthetic document"
        with patch("tools.distribution.build_opener") as opener:
            opener.return_value.open.return_value = body
            with self.assertRaisesRegex(DataError, "unapproved publisher rights locator"):
                read_rights_document("https://example.invalid/backup")
            opener.assert_not_called()
            self.assertEqual(read_rights_document(CC_RIGHTS), b"Synthetic document")
            request, = opener.return_value.open.call_args.args
            handler, = opener.call_args.args
            self.assertEqual(request.full_url, CC_RIGHTS)
            self.assertEqual(request.get_method(), "GET")
            self.assertIsInstance(handler, NoRedirects)
            self.assertIsNone(handler.redirect_request(request, None, 302, None, None, POLYFORM_RIGHTS))
            body.read.assert_called_once_with(RIGHTS_MAX_BYTES + 1)
            body.read.return_value = bytes(RIGHTS_MAX_BYTES + 1)
            with self.assertRaisesRegex(DataError, "invalid size"):
                read_rights_document(CC_RIGHTS)


if __name__ == "__main__":
    unittest.main()
