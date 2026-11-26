# Copyright (c) 2026 EmailBadger, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""``get timeline`` and ``get evidence package`` — the evidence reads.

The timeline's ``gaps`` are the point: a playbook that reads ``entries`` as the
whole story is wrong whenever EmailBadger could not look somewhere, so the
message counts the gaps rather than leaving them in the data. The evidence
package is a file, not JSON — it goes into the vault with its manifest hash,
and the one refusal specific to it (the key's user is not a Tenant Admin or
Platform Admin) is said in those words.
"""

from __future__ import annotations


import pytest

from .fakes import APP_ERROR, APP_SUCCESS, FakeHTTPResponse, action_error
from .fakes import scope_refusal
from .recorded import NOT_FOUND, ROUTE_ABSENT, TIMELINE

ZIP = b"PK\x03\x04" + b"\x00" * 60


def _timeline(eb, **overrides):
    eb.run("get_timeline", {"email_id": 1042, **overrides})
    return eb.results[-1]


def _package(eb, **overrides):
    eb.run("get_evidence_package", {"email_id": 1042, **overrides})
    return eb.results[-1]


class TestGetTimeline:
    def test_reads_the_timeline_route(self, eb, http):
        calls = http((200, TIMELINE))
        result = _timeline(eb)

        assert calls[0]["method"] == "GET"
        assert calls[0]["url"] == "https://eb.example.test/api/v1/emails/1042/timeline"
        assert result.status is APP_SUCCESS, result.message
        assert result.data == [TIMELINE]

    def test_the_message_counts_entries_and_the_gaps(self, eb, http):
        http((200, TIMELINE))
        result = _timeline(eb)

        assert result.summary == {"total_objects": 1, "total": 3, "gaps": 1}
        assert (
            result.message
            == "3 timeline entries for email 1042, 1 gap(s) where EmailBadger could not look"
        )

    def test_a_complete_timeline_mentions_no_gaps(self, eb, http):
        http(
            (
                200,
                {
                    **TIMELINE,
                    "gaps": [],
                    "entries": TIMELINE["entries"][:1],
                    "total": 1,
                },
            )
        )
        result = _timeline(eb)
        assert result.message == "1 timeline entry for email 1042"

    def test_a_bad_email_id_never_reaches_emailbadger(self, eb, http):
        calls = http((200, TIMELINE))
        result = _timeline(eb, email_id="-4")
        assert result.status is APP_ERROR
        assert calls == []

    @pytest.mark.parametrize(
        "status, code, detail, expected",
        [
            (401, "unauthorized", "Invalid API key", "wrong, revoked, or disabled"),
            (
                402,
                "license_required",
                "Enterprise tier required",
                "requires Enterprise tier",
            ),
            (
                403,
                "api_key_scope_missing",
                scope_refusal("evidence:read"),
                "lacks the scope this action needs. This API key does not carry the 'evidence:read' scope",
            ),
        ],
    )
    def test_each_refusal_has_its_own_message(
        self, eb, http, status, code, detail, expected
    ):
        http(action_error(status, code, detail))
        result = _timeline(eb)
        assert result.status is APP_ERROR
        assert expected in result.message

    def test_the_two_kinds_of_404(self, eb, http):
        http(action_error(404, *NOT_FOUND))
        assert "No email with id 1042 is visible" in _timeline(eb).message
        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        assert "does not serve /api/v1/emails/1042/timeline" in _timeline(eb).message


@pytest.fixture
def vault_add(eb):
    """Every attachment the action created in the vault."""
    return eb.vault.added


class TestGetEvidencePackage:
    def _zip(self, **headers):
        return FakeHTTPResponse(
            200,
            content=ZIP,
            headers={
                "Content-Type": "application/zip",
                "X-Manifest-SHA256": "f" * 64,
                **headers,
            },
        )

    def test_the_zip_goes_into_the_vault_of_the_current_container(
        self, eb, http, vault_add
    ):
        calls = http(self._zip())
        result = _package(eb)

        assert (
            calls[0]["url"]
            == "https://eb.example.test/api/v1/emails/1042/evidence-package"
        )
        assert calls[0]["timeout"] == 120, (
            "a package export is slow; the default 30 s is for JSON"
        )
        assert result.status is APP_SUCCESS, result.message

        (added,) = vault_add
        assert added["container_id"] == 7
        assert added["file_name"] == "emailbadger-evidence-1042.zip"
        assert added["content"] == ZIP

    def test_the_manifest_hash_rides_with_the_vault_entry(self, eb, http, vault_add):
        http(self._zip())
        result = _package(eb)

        assert result.data == [
            {
                "vault_id": "vault-id-evidence",
                "file_name": "emailbadger-evidence-1042.zip",
                "size": len(ZIP),
                "manifest_sha256": "f" * 64,
                "email_id": 1042,
            }
        ]
        assert result.summary["manifest_sha256"] == "f" * 64
        assert vault_add[0]["metadata"] == {"manifest_sha256": "f" * 64}
        assert f"({len(ZIP)} bytes)" in result.message

    def test_a_non_admin_key_is_told_so(self, eb, http, vault_add):
        http(
            action_error(403, "forbidden", "Administrator access required")
        )  # the core's text today
        result = _package(eb)

        assert result.status is APP_ERROR
        assert "an admin's export" in result.message
        assert (
            "Mint the key under a Tenant Admin or Platform Admin account"
            in result.message
        )
        assert "(request id req-0001)" in result.message
        assert vault_add == []

    def test_a_missing_scope_is_still_the_scope_message(self, eb, http, vault_add):
        http(action_error(403, "api_key_scope_missing", scope_refusal("evidence:read")))
        result = _package(eb)
        assert "'evidence:read' scope" in result.message

    def test_the_per_address_rate_limit_is_reported_with_retry_after(
        self, eb, http, vault_add
    ):
        http(
            action_error(
                429,
                "rate_limited",
                "Rate limit exceeded: 10 per 1 minute",
                **{"Retry-After": "41"},
            )
        )
        result = _package(eb)
        assert result.status is APP_ERROR
        assert "retry after 41 seconds" in result.message

    def test_a_body_that_is_not_a_zip_is_a_failure_not_a_vault_entry(
        self, eb, http, vault_add
    ):
        http(
            FakeHTTPResponse(
                200,
                headers={"Content-Type": "text/html"},
                content=b"<html>login</html>",
            )
        )
        result = _package(eb)

        assert result.status is APP_ERROR
        assert "text/html" in result.message
        assert "not a ZIP" in result.message
        assert vault_add == []

    def test_a_vault_refusal_is_reported(self, eb, http):
        eb.vault.refuse_with = "vault is read-only"
        http(self._zip())
        result = _package(eb)
        assert result.status is APP_ERROR
        assert "vault is read-only" in result.message

    def test_an_export_failure_names_the_request_id(self, eb, http, vault_add):
        http(
            action_error(
                500,
                "server_error",
                "Evidence package export failed",
                request_id="req-500",
            )
        )
        result = _package(eb)
        assert "Unexpected HTTP 500" in result.message
        assert "Evidence package export failed" in result.message
        assert "req-500" in result.message

    def test_the_two_kinds_of_404(self, eb, http, vault_add):
        http(action_error(404, *NOT_FOUND))
        assert "No email with id 1042 is visible" in _package(eb).message
        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        assert (
            "does not serve /api/v1/emails/1042/evidence-package"
            in _package(eb).message
        )
