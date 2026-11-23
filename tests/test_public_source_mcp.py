"""Exercise fixed-source configuration, retrieval, and MCP stdio responses."""

from base64 import b64decode
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import call, patch

from tools.public_source_mcp import load_manifest, respond, serve, source_spec
from tools.records import DataError


URL = "https://example.invalid/pinned/license.txt"
BODY = b"\xef\xbb\xbfEvidence\xc3\xa9\r\n"
SHA = sha256(BODY).hexdigest()


def rpc(method, request_id, params):
    return (json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n").encode()


def open_source(name, request_id=9):
    return rpc("tools/call", request_id, {"name": "open_original_source", "arguments": {"source": name}})


class PublicSourceTests(unittest.TestCase):
    def test_full_receipts_preserve_bytes_and_record_each_fresh_call(self):
        sources = {"publisher": source_spec({"url": URL, "ranges": [[3, 11]],
                                              "expected_bytes": len(BODY), "expected_sha256": SHA})}
        input_stream = BytesIO(rpc("initialize", 1, {"protocolVersion": "2025-06-18"}) +
                               rpc("tools/list", 2, {}) + open_source("publisher", 3) + open_source("publisher", 4))
        output = BytesIO()
        with patch("tools.public_source_mcp.download", return_value=(BODY, "text/plain")) as download:
            serve(input_stream, output, sources)
        self.assertEqual(download.call_args_list, [call(URL, len(BODY), direct=True)] * 2)
        init, listing, *responses = map(json.loads, output.getvalue().splitlines())
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        tool, = listing["result"]["tools"]
        self.assertEqual(tool["inputSchema"]["properties"]["source"]["enum"], ["publisher"])
        self.assertTrue(tool["annotations"]["readOnlyHint"])
        first, second = (json.loads(res["result"]["content"][0]["text"]) for res in responses)
        self.assertNotEqual(first["acquisition_id"], second["acquisition_id"])
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(b64decode(first["body_base64"], validate=True), BODY)
        self.assertEqual(first["source_text"].encode("utf-8"), BODY)
        self.assertEqual(first["ranges"], [{"start": 3, "end": 11, "sha256": sha256(BODY[3:11]).hexdigest()}])

    def test_comparison_excerpts_exclude_the_complete_body(self):
        sources = {"control": source_spec({"url": URL, "mode": "excerpts", "ranges": [[3, 11]]})}
        with patch("tools.public_source_mcp.download", return_value=(BODY, "text/plain")):
            result = respond(open_source("control"), sources)["result"]
        self.assertFalse(result["isError"])
        data = json.loads(result["content"][0]["text"])
        self.assertEqual(data["sha256"], SHA)
        self.assertEqual(data["excerpts"], [{"start": 3, "end": 11, "text": "Evidence"}])
        self.assertNotIn("body_base64", data)
        self.assertNotIn("source_text", data)

    def test_rejects_model_overrides_and_duplicate_fields_without_fetching(self):
        sources = {"publisher": source_spec({"url": URL})}
        override = rpc("tools/call", 2, {"name": "open_original_source",
                                         "arguments": {"source": "publisher", "url": URL}})
        duplicate = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"source":"secret","source":"public"}}'
        with patch("tools.public_source_mcp.download") as download:
            self.assertEqual(respond(override, sources)["error"]["code"], -32602)
            self.assertEqual(respond(open_source("unknown"), sources)["error"]["code"], -32602)
            self.assertEqual(respond(duplicate, sources)["error"]["code"], -32700)
            download.assert_not_called()

    def test_manifest_pins_and_limits_are_validated_before_any_acquisition(self):
        with TemporaryDirectory() as directory, patch("tools.public_source_mcp.download") as download:
            path = Path(directory).resolve() / "sources.json"
            path.write_bytes(json.dumps({"version": 1, "sources": {"publisher": {"url": URL}}}).encode())
            self.assertEqual(load_manifest(path, sha256(path.read_bytes()).hexdigest())["publisher"].url, URL)
            with self.assertRaisesRegex(DataError, "manifest differs"):
                load_manifest(path, "a" * 64)
            path.write_bytes(b" " * (64 * 1024 + 1))
            with self.assertRaisesRegex(DataError, "manifest is too large"):
                load_manifest(path)
            for options in ({"url": URL + "?secret=query"}, {"ranges": [[0, True]]},
                            {"mode": "excerpts"}, {"mode": "excerpts", "ranges": [[0, 20000]]},
                            {"expected_bytes": 13, "max_bytes": 12}):
                with self.subTest(options=options), self.assertRaises(DataError):
                    source_spec({"url": URL, **options})
            download.assert_not_called()

    def test_invalid_request_identifier_leaves_the_stream_usable(self):
        input_stream = BytesIO(b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}\n' + rpc("ping", 2, {}))
        output = BytesIO()
        serve(input_stream, output, {})
        invalid, valid = map(json.loads, output.getvalue().splitlines())
        self.assertEqual(invalid["error"]["code"], -32600)
        self.assertEqual(valid, {"jsonrpc": "2.0", "id": 2, "result": {}})

    def test_mismatched_pin_and_invalid_utf8_do_not_deliver_evidence(self):
        for options, body in (({"expected_sha256": "a" * 64}, BODY), ({}, b"\xff")):
            sources = {"publisher": source_spec({"url": URL, **options})}
            with self.subTest(options=options), patch("tools.public_source_mcp.download", return_value=(body, None)):
                result = respond(open_source("publisher"), sources)["result"]
                self.assertTrue(result["isError"])
                self.assertEqual(result["content"][0]["text"], "Public source acquisition failed.")


if __name__ == "__main__":
    unittest.main()
