# File: ciscoise_utils.py
#
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

import re
import uuid
from copy import deepcopy
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


DEFAULT_MAX_PAGES = 1000
DEFAULT_MAX_TOTAL_RESULTS = 10_000
MAX_ERS_ACCUMULATED_BYTES = 20 * 1024 * 1024
MAX_ERS_RESOURCE_BYTES = 1024 * 1024
MAX_ERS_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_XML_RESPONSE_BYTES = 20 * 1024 * 1024
UNSAFE_XML_DECLARATION = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def encode_ers_resource_id(value: object) -> str:
    """Validate and encode a Cisco ISE ERS UUID as one URL path segment."""
    if not isinstance(value, str):
        raise ValueError("Cisco ISE resource identifiers must be strings")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Cisco ISE resource identifiers must be UUIDs") from exc
    if str(parsed) != value.casefold():
        raise ValueError("Cisco ISE resource identifiers must use canonical UUID syntax")
    return quote(value, safe="")


def validate_next_page_href(href: object, allowed_base_urls: list[str]) -> str:
    """Return a relative ERS endpoint after validating an upstream continuation URL."""
    if not isinstance(href, str) or not href.strip():
        raise ValueError("Cisco ISE returned an invalid nextPage URL")

    allowed_origins: set[tuple[str, str, int]] = set()
    join_base = ""
    for base_url in allowed_base_urls:
        parsed_base = urlsplit(base_url)
        if not parsed_base.scheme or not parsed_base.hostname:
            continue
        allowed_origins.add((parsed_base.scheme.casefold(), parsed_base.hostname.casefold(), 9060))
        if not join_base:
            host = f"[{parsed_base.hostname}]" if ":" in parsed_base.hostname else parsed_base.hostname
            join_base = f"{parsed_base.scheme}://{host}:9060/"

    if not join_base:
        raise ValueError("Cisco ISE asset URL is invalid")

    parsed = urlsplit(urljoin(join_base, href))
    try:
        origin = (parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port or 0)
    except ValueError as exc:
        raise ValueError("Cisco ISE returned an invalid nextPage URL") from exc

    if parsed.username is not None or parsed.password is not None or origin not in allowed_origins:
        raise ValueError("Cisco ISE nextPage URL points outside the configured asset")
    if parsed.fragment:
        raise ValueError("Cisco ISE returned an invalid nextPage URL")

    decoded_segments = unquote(parsed.path).split("/")
    if not parsed.path.startswith("/ers/config/") or any(segment in {".", ".."} for segment in decoded_segments):
        raise ValueError("Cisco ISE nextPage URL is outside the ERS configuration API")

    relative_target = urlunsplit(("", "", parsed.path, parsed.query, ""))
    return f":9060{relative_target}"


def validate_page_count(page_count: int, max_pages: int = DEFAULT_MAX_PAGES) -> None:
    """Reject another upstream-driven request after the connector safety limit."""
    if page_count >= max_pages:
        raise ValueError(f"Cisco ISE pagination exceeded the {max_pages}-page safety limit")


def read_bounded_response(response: object, max_bytes: int, response_kind: str) -> str:
    """Read an HTTP response without accepting an unbounded body."""
    content_length = getattr(response, "headers", {}).get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise ValueError(f"Cisco ISE {response_kind} response exceeds the {max_bytes}-byte limit")
        except ValueError as exc:
            if "exceeds" in str(exc):
                raise

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024, decode_unicode=False):
        if not chunk:
            continue
        if isinstance(chunk, str):
            chunk = chunk.encode(getattr(response, "encoding", None) or "utf-8")
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"Cisco ISE {response_kind} response exceeds the {max_bytes}-byte limit")
        chunks.append(chunk)

    encoding = getattr(response, "encoding", None) or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


def read_bounded_ers_response(response: object) -> str:
    """Read a bounded ERS JSON response body."""
    return read_bounded_response(response, MAX_ERS_RESPONSE_BYTES, "ERS")


def read_bounded_xml_response(response: object) -> str:
    """Read a bounded MnT XML response body."""
    return read_bounded_response(response, MAX_XML_RESPONSE_BYTES, "MnT")


def validate_xml_document(xml: str) -> None:
    """Reject XML declarations that can define or expand external entities."""
    if UNSAFE_XML_DECLARATION.search(xml):
        raise ValueError("Cisco ISE XML response contains a prohibited DTD or entity declaration")


def build_ers_update(
    current_response: object,
    resource_key: str,
    updates: dict[str, object],
    custom_attribute: tuple[str, object] | None = None,
) -> dict[str, dict[str, object]]:
    """Merge requested changes into a full ERS object for replace-style PUT APIs."""
    if not isinstance(current_response, dict) or not isinstance(current_response.get(resource_key), dict):
        raise ValueError(f"Cisco ISE response is missing the {resource_key} resource")

    resource = deepcopy(current_response[resource_key])
    resource.pop("link", None)
    resource.update(updates)

    if custom_attribute:
        name, value = custom_attribute
        custom_wrapper = resource.setdefault("customAttributes", {})
        if not isinstance(custom_wrapper, dict):
            raise ValueError("Cisco ISE response contains invalid custom attributes")
        custom_values = custom_wrapper.setdefault("customAttributes", {})
        if not isinstance(custom_values, dict):
            raise ValueError("Cisco ISE response contains invalid custom attributes")
        custom_values[name] = value

    return {resource_key: resource}
