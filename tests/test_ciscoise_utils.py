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
from pathlib import Path

import pytest

from ciscoise_utils import encode_path_segment, validate_next_page_href


def test_encode_path_segment_contains_url_delimiters():
    assert encode_path_segment("../adminuser?#") == "..%2Fadminuser%3F%23"


def test_tls_verification_is_enabled_by_default():
    manifest = json.loads((Path(__file__).parents[1] / "ciscoise.json").read_text())

    assert manifest["configuration"]["verify_server_cert"]["default"] is True


def test_validate_next_page_href_keeps_same_asset_ers_url():
    endpoint = validate_next_page_href(
        "https://ise.example:9060/ers/config/endpoint?page=2",
        ["https://ise.example"],
    )

    assert endpoint == "/ers/config/endpoint?page=2"


@pytest.mark.parametrize(
    "href",
    [
        "https://ise.example:9060@attacker.example/ers/config/endpoint?page=2",
        "//attacker.example/ers/config/endpoint?page=2",
        "https://ise.example:9060/ers/config/../adminuser",
    ],
)
def test_validate_next_page_href_rejects_untrusted_urls(href):
    with pytest.raises(ValueError):
        validate_next_page_href(href, ["https://ise.example"])
