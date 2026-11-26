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
"""``update ticket`` — write a SOAR ticket's state back onto the email's case.

The identity is in the path and only the given fields travel in the body: the
route refuses an empty PATCH and refuses a body that renames the ticket, so a
connector that always sent every field would turn a status update into a 422.
"""

from __future__ import annotations

import pytest

from .fakes import (
    APP_ERROR,
    APP_SUCCESS,
    FakeHTTPResponse,
    action_error,
    refused_by_validation,
)
from .fakes import scope_refusal
from .recorded import NOT_FOUND, ROUTE_ABSENT, TICKET_PATCHED

PARAM = {
    "email_id": 1042,
    "system": "splunk_soar",
    "ticket_id": "4411",
    "status": "closed",
}


def _run(eb, **overrides):
    eb.run("update_ticket", {**PARAM, **overrides})
    return eb.results[-1]


class TestTheRequest:
    def test_patches_the_ticket_route_with_only_the_fields_given(self, eb, http):
        calls = http((200, TICKET_PATCHED))
        _run(eb)

        call = calls[0]
        assert call["method"] == "PATCH"
        assert (
            call["url"]
            == "https://eb.example.test/api/v1/emails/1042/external-tickets/splunk_soar/4411"
        )
        assert call["json"] == {"status": "closed"}

    def test_every_field_the_contract_allows_can_travel(self, eb, http):
        calls = http((200, TICKET_PATCHED))
        _run(
            eb,
            ticket_url="https://soar.example.test/mission/4411",
            opened_at="2026-10-24T20:00:00Z",
        )
        assert calls[0]["json"] == {
            "status": "closed",
            "ticket_url": "https://soar.example.test/mission/4411",
            "opened_at": "2026-10-24T20:00:00Z",
        }

    def test_a_ticket_id_with_slashes_is_kept_and_a_system_name_is_escaped(
        self, eb, http
    ):
        """The contract declares ``ticket_id`` as a path tail, so a Jira-style
        ``PROJ/123`` or a URL fragment id passes through; the system segment is
        a single path element and must not be able to escape into another."""
        calls = http((200, TICKET_PATCHED))
        _run(eb, system="service now", ticket_id="INC/0001 234")
        assert calls[0]["url"].endswith(
            "/external-tickets/service%20now/INC/0001%20234"
        )

    def test_nothing_to_update_never_reaches_emailbadger(self, eb, http):
        calls = http((200, TICKET_PATCHED))
        result = _run(eb, status="  ")

        assert result.status is APP_ERROR
        assert "at least one of status, ticket_url, opened_at" in result.message
        assert calls == []

    @pytest.mark.parametrize(
        "overrides, expected",
        [
            ({"system": ""}, "system and ticket_id are required"),
            ({"ticket_id": ""}, "system and ticket_id are required"),
        ],
    )
    def test_bad_identity_never_reaches_emailbadger(
        self, eb, http, overrides, expected
    ):
        calls = http((200, TICKET_PATCHED))
        result = _run(eb, **overrides)
        assert result.status is APP_ERROR
        assert expected in result.message
        assert calls == []

    def test_an_email_id_that_is_not_a_number_never_reaches_the_action(self, eb, http):
        calls = http((200, TICKET_PATCHED))
        assert refused_by_validation(_run(eb, email_id="x"), "email_id")
        assert calls == []


class TestItNeverCreates:
    def test_a_ticket_nobody_reported_is_a_404_not_a_post(self, eb, http):
        """``report ticket`` is the only action that creates one. A connector that
        fell back to it on a 404 would make a typo in a ticket id open a second
        ticket, and would hide that the playbook skipped the report."""
        calls = http(
            action_error(404, "not_found", "No splunk_soar ticket 4411 on this email")
        )
        result = _run(eb)

        assert result.status is APP_ERROR
        assert [call["method"] for call in calls] == ["PATCH"]

    def test_the_ticket_record_is_the_data(self, eb, http):
        http((200, TICKET_PATCHED))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.data == [TICKET_PATCHED["ticket"]]
        assert result.summary["created"] is False
        assert result.summary["status"] == "closed"
        assert result.summary["ticket_url"] == "https://soar.example.test/mission/4411"
        assert result.message == "Ticket splunk_soar/4411 on email 1042 updated: status"


class TestWhenEmailBadgerRefuses:
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
                scope_refusal("external_tickets:write"),
                "lacks the scope this action needs. This API key does not carry the 'external_tickets:write' scope",
            ),
            (
                422,
                "validation_error",
                "ticket_url: String should have at most 2048 characters",
                "at most 2048",
            ),
        ],
    )
    def test_each_refusal_has_its_own_message(
        self, eb, http, status, code, detail, expected
    ):
        http(action_error(status, code, detail))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert expected in result.message, result.message

    def test_404_for_the_email_404_for_the_ticket_and_404_for_the_route_are_three_messages(
        self, eb, http
    ):
        http(action_error(404, *NOT_FOUND))
        assert "No email with id 1042 is visible" in _run(eb).message

        http(action_error(404, "not_found", "No splunk_soar ticket 4411 on this email"))
        assert "No splunk_soar ticket 4411 on this email" in _run(eb).message

        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        assert (
            "does not serve /api/v1/emails/1042/external-tickets/splunk_soar/4411"
            in _run(eb).message
        )
