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
"""``report ticket`` — the one action that creates a ticket on an email.

``update ticket`` is a ``PATCH`` and never creates one, so a ticket the SOAR
opened is a 404 there until this has reported it. The route is keyed by
(email, system, ticket id): the first report is a ``201`` with ``created`` true
and needs ``opened_at``, a later one is a ``200`` that updates only the fields
sent.
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
from .recorded import NOT_FOUND, ROUTE_ABSENT, TICKET_PATCHED, TICKET_REPORTED

PARAM = {
    "email_id": 1042,
    "system": "splunk_soar",
    "ticket_id": "4411",
    "opened_at": "2026-10-24T20:00:00Z",
    "status": "open",
}


def _run(eb, **overrides):
    eb.run("report_ticket", {**PARAM, **overrides})
    return eb.results[-1]


class TestTheRequest:
    def test_posts_the_identity_in_the_body_to_the_collection_route(self, eb, http):
        calls = http((201, TICKET_REPORTED))
        _run(eb)

        call = calls[0]
        assert call["method"] == "POST"
        assert (
            call["url"] == "https://eb.example.test/api/v1/emails/1042/external-tickets"
        )
        assert call["json"] == {
            "system": "splunk_soar",
            "ticket_id": "4411",
            "opened_at": "2026-10-24T20:00:00Z",
            "status": "open",
        }

    def test_a_field_left_blank_is_left_out_not_sent_as_null_or_empty(self, eb, http):
        """The route leaves an omitted or null field as it was, but an empty string
        would be written, and ``ticket_url`` would fail its URL rule."""
        calls = http((200, TICKET_PATCHED))
        _run(eb, opened_at="", status="  ", ticket_url="")
        assert calls[0]["json"] == {"system": "splunk_soar", "ticket_id": "4411"}

    def test_the_url_travels_when_given(self, eb, http):
        calls = http((201, TICKET_REPORTED))
        _run(eb, ticket_url="https://soar.example.test/mission/4411")
        assert (
            calls[0]["json"]["ticket_url"] == "https://soar.example.test/mission/4411"
        )

    def test_a_ticket_id_with_slashes_travels_in_the_body_unescaped(self, eb, http):
        """Unlike ``update ticket`` the identity is not in the path, so a Jira-style
        ``PROJ/123`` needs no escaping and cannot reshape the URL."""
        calls = http((201, TICKET_REPORTED))
        _run(eb, system="service now", ticket_id="INC/0001 234")
        assert calls[0]["url"].endswith("/api/v1/emails/1042/external-tickets")
        assert calls[0]["json"]["system"] == "service now"
        assert calls[0]["json"]["ticket_id"] == "INC/0001 234"

    def test_no_idempotency_key_is_derived(self, eb, http):
        """The route is idempotent on what it names. A derived key would replay the
        stored answer for 24 hours, so a status reported again after it changed
        would be answered from the cache and never written."""
        calls = http((201, TICKET_REPORTED))
        _run(eb)
        assert "Idempotency-Key" not in (calls[0].get("headers") or {})

    def test_the_playbooks_own_idempotency_key_goes_out(self, eb, http):
        calls = http((201, TICKET_REPORTED))
        _run(eb, idempotency_key=" soar-4411-open ")
        assert calls[0]["headers"]["Idempotency-Key"] == "soar-4411-open"

    @pytest.mark.parametrize(
        "overrides, expected",
        [
            ({"email_id": 0}, "positive integer"),
            ({"system": ""}, "system and ticket_id are required"),
            ({"ticket_id": "  "}, "system and ticket_id are required"),
        ],
    )
    def test_bad_identity_never_reaches_emailbadger(
        self, eb, http, overrides, expected
    ):
        calls = http((201, TICKET_REPORTED))
        result = _run(eb, **overrides)
        assert result.status is APP_ERROR
        assert expected in result.message
        assert calls == []

    def test_an_email_id_that_is_not_a_number_never_reaches_the_action(self, eb, http):
        calls = http((201, TICKET_REPORTED))
        assert refused_by_validation(_run(eb, email_id="x"), "email_id")
        assert calls == []


class TestTheAnswer:
    def test_the_first_report_creates_the_record(self, eb, http):
        http((201, TICKET_REPORTED))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.data == [TICKET_REPORTED["ticket"]]
        assert result.summary["created"] is True
        assert result.summary["status"] == "open"
        assert result.summary["replayed"] is False
        assert result.message == "Ticket splunk_soar/4411 reported on email 1042"

    def test_a_repeat_is_a_success_that_says_it_updated_an_existing_ticket(
        self, eb, http
    ):
        """Idempotent on (email, system, ticket id): a playbook retried after a
        timeout, or two playbooks reporting one ticket, must not see a failure."""
        http((200, TICKET_PATCHED))
        result = _run(eb, ticket_url="")

        assert result.status is APP_SUCCESS, result.message
        assert result.summary["created"] is False
        assert result.message == (
            "Ticket splunk_soar/4411 was already reported on email 1042; updated: opened_at, status"
        )

    def test_a_repeat_with_nothing_new_says_so(self, eb, http):
        http((200, TICKET_PATCHED))
        result = _run(eb, opened_at="", status="")
        assert result.status is APP_SUCCESS
        assert "updated: nothing but the report time" in result.message

    def test_a_replayed_answer_is_surfaced(self, eb, http):
        http(
            FakeHTTPResponse(
                201, TICKET_REPORTED, headers={"Idempotent-Replay": "true"}
            )
        )
        result = _run(eb, idempotency_key="k1")
        assert result.summary["replayed"] is True
        assert result.message.endswith(
            "Replayed from an identical request within the last 24 hours"
        )

    def test_a_non_json_answer_is_a_failure(self, eb, http):
        http(
            FakeHTTPResponse(
                200, content=b"<html>", headers={"Content-Type": "text/html"}
            )
        )
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "non-JSON" in result.message


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
                403,
                "write_back_disabled",
                "SOAR write-back is off for this tenant.",
                "SOAR write-back is off for this tenant",
            ),
            (
                409,
                "idempotency_conflict",
                "Idempotency-Key reused",
                "different request",
            ),
            (409, "idempotency_in_progress", "Still running", "still being processed"),
            (429, "rate_limited", "Over the limit", "Rate limited"),
        ],
    )
    def test_each_refusal_has_its_own_message(
        self, eb, http, status, code, detail, expected
    ):
        http(action_error(status, code, detail))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert expected in result.message, result.message

    def test_a_first_report_without_opened_at_says_which_field(self, eb, http):
        """``opened_at`` is required only the first time, so the playbook cannot know
        until it asks; the refusal has to name it."""
        http(
            action_error(
                422,
                "validation_error",
                "opened_at is required the first time a ticket is reported",
            )
        )
        result = _run(eb, opened_at="")
        assert result.status is APP_ERROR
        assert "opened_at is required the first time" in result.message

    def test_404_for_the_email_and_404_for_the_route_are_two_messages(self, eb, http):
        http(action_error(404, *NOT_FOUND))
        assert "No email with id 1042 is visible" in _run(eb).message

        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        assert "does not serve /api/v1/emails/1042/external-tickets" in _run(eb).message
