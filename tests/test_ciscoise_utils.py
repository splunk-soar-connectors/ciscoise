# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import json
import unittest
from pathlib import Path

from ciscoise_utils import (
    build_ers_update,
    encode_path_segment,
    read_bounded_xml_response,
    validate_next_page_href,
    validate_page_count,
    validate_xml_document,
)


class FakeResponse:
    def __init__(self, chunks, *, content_length=None):
        self._chunks = chunks
        self.encoding = "utf-8"
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def iter_content(self, **_kwargs):
        return iter(self._chunks)


class TestCiscoISEUtils(unittest.TestCase):
    def test_encode_path_segment_contains_url_delimiters(self):
        self.assertEqual(encode_path_segment("../adminuser?#"), "..%2Fadminuser%3F%23")

    def test_tls_verification_is_enabled_by_default(self):
        manifest = json.loads((Path(__file__).parents[1] / "ciscoise.json").read_text())

        self.assertIs(manifest["configuration"]["verify_server_cert"]["default"], True)

    def test_validate_next_page_href_keeps_same_asset_ers_url(self):
        endpoint = validate_next_page_href(
            "https://ise.example:9060/ers/config/endpoint?page=2",
            ["https://ise.example"],
        )

        self.assertEqual(endpoint, "/ers/config/endpoint?page=2")

    def test_validate_next_page_href_rejects_untrusted_urls(self):
        hrefs = [
            "https://ise.example:9060@attacker.example/ers/config/endpoint?page=2",
            "//attacker.example/ers/config/endpoint?page=2",
            "https://ise.example:9060/ers/config/../adminuser",
        ]
        for href in hrefs:
            with self.subTest(href=href), self.assertRaises(ValueError):
                validate_next_page_href(href, ["https://ise.example"])

    def test_validate_page_count_rejects_another_page_at_limit(self):
        validate_page_count(999)

        with self.assertRaisesRegex(ValueError, "1000-page safety limit"):
            validate_page_count(1000)

    def test_read_bounded_xml_response_rejects_oversized_body(self):
        response = FakeResponse([b"<root/>"])

        with self.assertRaisesRegex(ValueError, "6-byte limit"):
            read_bounded_xml_response(response, max_bytes=6)

    def test_validate_xml_document_rejects_entity_declarations(self):
        with self.assertRaisesRegex(ValueError, "prohibited DTD"):
            validate_xml_document('<!DOCTYPE root [<!ENTITY x "value">]><root attr="&x;"/>')

    def test_build_ers_update_preserves_quarantine_state_and_strips_link(self):
        current = {
            "ERSEndPoint": {
                "description": "old",
                "groupId": "blocked-list",
                "staticGroupAssignment": True,
                "link": {"href": "https://ise.example/resource"},
                "customAttributes": {"customAttributes": {"owner": "soc"}},
            }
        }

        payload = build_ers_update(
            current,
            "ERSEndPoint",
            {"description": "new"},
            ("case", "1234"),
        )

        self.assertEqual(payload["ERSEndPoint"]["groupId"], "blocked-list")
        self.assertIs(payload["ERSEndPoint"]["staticGroupAssignment"], True)
        self.assertNotIn("link", payload["ERSEndPoint"])
        self.assertEqual(
            payload["ERSEndPoint"]["customAttributes"]["customAttributes"],
            {"owner": "soc", "case": "1234"},
        )
        self.assertEqual(current["ERSEndPoint"]["description"], "old")
