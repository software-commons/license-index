"""Synthetic HTTPS responses for the byte-preserving source capture command."""

from contextlib import redirect_stderr
from email.message import Message
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.request import HTTPSHandler
from urllib.response import addinfourl

from tools.capture_source import capture, main, verify
from tools.li_install import InstallError
from tools.records import DataError, encode


URL = "https://example.invalid/license.txt"
BODY = b"\xef\xbb\xbf\xc3\xa9\r\n\xff"
DIGEST = sha256(BODY).hexdigest()


class SourceCaptureTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.artifact = self.root / "artifact.bin"
        self.observation = self.root / "observation.json"

    def response(self, body=BODY, *headers, status=200):
        message = Message()
        for name, value in headers:
            message[name] = value
        stream = addinfourl(BytesIO(body), message, URL, code=status)
        stream.msg = "fixture"
        return stream

    def capture_fixture(self, **options):
        response = self.response(BODY, ("Content-Length", str(len(BODY))), ("Content-Type", "text/plain"))
        with patch.object(HTTPSHandler, "https_open", return_value=response) as get:
            report = capture(URL, self.artifact, **options)
            get.assert_called_once()
        self.observation.write_bytes(encode(report))
        return report

    def test_exact_binary_capture_and_half_open_ranges_are_rechecked_offline(self):
        report = self.capture_fixture(expected_digest=DIGEST, expected_size=len(BODY),
                                      ranges=iter([(4, 6), (len(BODY) - 1, len(BODY))]))
        self.assertEqual(self.artifact.read_bytes(), BODY)
        self.assertEqual(report["bytes"], len(BODY))
        self.assertEqual(report["sha256"], DIGEST)
        self.assertEqual(report["media_type"], "text/plain")
        self.assertEqual(report["ranges"], [
            {"start": 4, "end": 6, "sha256": sha256(BODY[4:6]).hexdigest()},
            {"start": len(BODY) - 1, "end": len(BODY), "sha256": sha256(BODY[-1:]).hexdigest()},
        ])
        expected = sha256(self.observation.read_bytes()).hexdigest()
        with patch("tools.capture_source.build_opener") as network:
            verified = verify(self.artifact, self.observation, expected)
            network.assert_not_called()
        self.assertEqual(verified["ranges"], report["ranges"])
        self.assertTrue(verified["observation_pin_checked"])
        self.assertFalse(verify(self.artifact, self.observation)["observation_pin_checked"])

    def test_rejects_redirects_without_a_follow_up_request(self):
        response = self.response(BODY, ("Location", "https://example.invalid/elsewhere"), status=302)
        response.read = Mock(wraps=response.read)
        with patch.object(HTTPSHandler, "https_open", return_value=response) as get:
            with self.assertRaisesRegex(DataError, "HTTP 302"):
                capture(URL, self.artifact)
            get.assert_called_once()
        response.read.assert_not_called()
        self.assertFalse(self.artifact.exists())

    def test_rejects_unapproved_source_forms_and_invalid_ranges_before_network(self):
        with patch("tools.capture_source.build_opener") as network:
            for url in ("http://example.invalid/", "https://@example.invalid/", "https://example.invalid:99999/",
                        " https://example.invalid/", "https://example.invalid/#section",
                        "https://example.invalid/?signed=private-fixture"):
                with self.subTest(url=url), self.assertRaises(DataError):
                    capture(url, self.artifact)
            for bounds in ((0, 0), (-1, 2), (True, 2), (4, 3), (0, len(BODY) + 1)):
                with self.subTest(bounds=bounds), self.assertRaisesRegex(DataError, "source range"):
                    capture(URL, self.artifact, max_bytes=len(BODY), ranges=[bounds])
            network.assert_not_called()

    def test_capture_rejects_output_inside_tool_checkout_before_network(self):
        target = self.root / "sces" / "publication.json"
        with patch("tools.capture_source.ROOT", self.root), patch("tools.capture_source.build_opener") as network:
            with self.assertRaisesRegex(DataError, "outside the tool checkout"):
                capture(URL, target)
            network.assert_not_called()
        self.assertFalse(target.exists())

    def test_incomplete_or_transformed_responses_leave_no_artifact(self):
        cases = (
            (self.response(BODY[:-1], ("Content-Length", str(len(BODY)))), "size differs"),
            (self.response(BODY, ("Content-Length", "eight")), "invalid Content-Length"),
            (self.response(BODY, ("Content-Length", "8"), ("Content-Length", "8")), "invalid Content-Length"),
            (self.response(BODY, ("Content-Encoding", "gzip")), "unsupported content encoding"),
            (self.response(BODY, ("Transfer-Encoding", "gzip, chunked")), "transfer framing"),
            (self.response(BODY, ("Transfer-Encoding", "chunked"), ("Content-Length", "8")), "transfer framing"),
            (self.response(BODY, ("Content-Range", "bytes 0-7/8")), "complete source response"),
            (self.response(BODY + b"!",), "exceeds the byte limit"),
        )
        for response, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic), patch.object(HTTPSHandler, "https_open", return_value=response):
                with self.assertRaisesRegex(DataError, diagnostic):
                    capture(URL, self.artifact, max_bytes=len(BODY))
                self.assertFalse(self.artifact.exists())

    def test_pins_are_checked_before_the_target_is_written(self):
        for options in ({"expected_digest": "a" * 64}, {"expected_size": len(BODY) + 1}, {"ranges": [(0, 20)]}):
            with self.subTest(options=options), patch.object(
                HTTPSHandler, "https_open", return_value=self.response(BODY)
            ):
                with self.assertRaises(DataError):
                    capture(URL, self.artifact, **options)
            self.assertFalse(self.artifact.exists())

    def test_existing_target_remains_unchanged(self):
        self.artifact.write_bytes(b"existing")
        with patch.object(HTTPSHandler, "https_open", return_value=self.response(BODY)):
            with self.assertRaises(InstallError):
                capture(URL, self.artifact)
        self.assertEqual(self.artifact.read_bytes(), b"existing")

    def test_offline_verifier_rejects_tampered_observation_and_artifact(self):
        original = self.capture_fixture(ranges=[(1, 3)])
        original_digest = sha256(self.observation.read_bytes()).hexdigest()
        original["ranges"][0]["sha256"] = "a" * 64
        self.observation.write_bytes(encode(original))
        with self.assertRaisesRegex(DataError, "independent pin"):
            verify(self.artifact, self.observation, original_digest)
        with self.assertRaisesRegex(DataError, "source range SHA-256"):
            verify(self.artifact, self.observation)
        self.artifact.write_bytes(BODY[:-1] + b"!")
        with self.assertRaisesRegex(DataError, "source bytes differ"):
            verify(self.artifact, self.observation)

    def test_cli_does_not_echo_malformed_observation_contents(self):
        self.observation.write_bytes(b'{"private-content":1,"private-content":2}')
        output = StringIO()
        with redirect_stderr(output), self.assertRaises(SystemExit) as error:
            main(["verify", str(self.artifact), str(self.observation)])
        self.assertEqual(error.exception.code, 1)
        self.assertIn("observation contains invalid JSON", output.getvalue())
        self.assertNotIn("private-content", output.getvalue())
