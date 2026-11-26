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
"""``reanalyze`` — queue a fresh analysis of an email and return the job id.

The job deletes the existing analysis and the new one has a new email id, so
the action says so every time. It returns at the ``202``: a repeat while the
job runs joins it (the same job id, ``already_running``), which is a success.
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
from .recorded import NOT_FOUND, REANALYZE_JOINED, REANALYZE_QUEUED, ROUTE_ABSENT

PARAM = {"email_id": 1042}


def _run(eb, **overrides):
    eb.run("reanalyze", {**PARAM, **overrides})
    return eb.results[-1]


class TestTheRequest:
    def test_posts_to_the_reanalyze_route_with_no_body(self, eb, http):
        calls = http((202, REANALYZE_QUEUED))
        _run(eb)

        call = calls[0]
        assert call["method"] == "POST"
        assert call["url"] == "https://eb.example.test/api/v1/emails/1042/reanalyze"
        assert call.get("json") is None, "the contract says the body is empty"
        assert call.get("data") is None

    def test_no_idempotency_key_is_derived(self, eb, http):
        """A derived key would replay the stored answer for 24 hours, so a second
        re-analysis after the first settled would answer with the old job id and
        never start."""
        calls = http((202, REANALYZE_QUEUED))
        _run(eb)
        assert "Idempotency-Key" not in (calls[0].get("headers") or {})

    def test_the_playbooks_own_idempotency_key_goes_out(self, eb, http):
        calls = http((202, REANALYZE_QUEUED))
        _run(eb, idempotency_key=" reanalyze-4411 ")
        assert calls[0]["headers"]["Idempotency-Key"] == "reanalyze-4411"

    @pytest.mark.parametrize("email_id", [0, -3, 1042.5])
    def test_bad_email_id_never_reaches_emailbadger(self, eb, http, email_id):
        calls = http((202, REANALYZE_QUEUED))
        result = _run(eb, email_id=email_id)
        assert result.status is APP_ERROR
        assert "positive integer" in result.message
        assert calls == []

    @pytest.mark.parametrize("email_id", ["x", ""])
    def test_an_email_id_that_is_not_a_number_never_reaches_the_action(
        self, eb, http, email_id
    ):
        calls = http((202, REANALYZE_QUEUED))
        assert refused_by_validation(_run(eb, email_id=email_id), "email_id")
        assert calls == []


class TestTheAnswer:
    def test_the_job_id_is_the_result(self, eb, http):
        http((202, REANALYZE_QUEUED))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.data == [REANALYZE_QUEUED]
        assert result.summary["job_id"] == 77
        assert result.summary["status"] == "queued"
        assert result.summary["already_running"] is False
        assert result.summary["replayed"] is False

    def test_the_message_says_the_analysis_is_deleted_and_the_id_changes(
        self, eb, http
    ):
        http((202, REANALYZE_QUEUED))
        message = _run(eb).message
        assert "queued as job 77" in message
        assert "deleted" in message
        assert "new email id" in message

    def test_a_repeat_while_it_runs_joins_the_job_and_is_a_success(self, eb, http):
        """The contract: the same ``job_id`` with ``already_running: true`` and no
        second audit row. A playbook retried after a timeout must not see a failure."""
        http((202, REANALYZE_JOINED))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.summary["job_id"] == 77
        assert result.summary["already_running"] is True
        assert "already running as job 77" in result.message
        assert "queued nothing new" in result.message

    def test_a_replayed_answer_is_surfaced(self, eb, http):
        http(
            FakeHTTPResponse(
                202, REANALYZE_QUEUED, headers={"Idempotent-Replay": "true"}
            )
        )
        result = _run(eb, idempotency_key="k1")
        assert result.summary["replayed"] is True
        assert result.message.endswith(
            "Replayed from an identical request within the last 24 hours"
        )

    def test_an_answer_without_a_job_id_is_a_failure_not_a_silent_success(
        self, eb, http
    ):
        http((202, {"status": "queued"}))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "job id" in result.message


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
                scope_refusal("analysis:write"),
                "lacks the scope this action needs. This API key does not carry the 'analysis:write' scope",
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

    def test_410_source_unavailable_tells_the_playbook_to_upload_again(self, eb, http):
        """Nothing is queued. Reporting it as a stale request would send an analyst
        looking at the key; the remedy is a fresh upload."""
        http(
            action_error(
                410,
                "source_unavailable",
                "The stored source file is no longer available.",
            )
        )
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "nothing was queued" in result.message
        assert "Upload the email again" in result.message
        assert "stale" not in result.message

    def test_404_for_the_email_and_404_for_the_route_are_two_messages(self, eb, http):
        http(action_error(404, *NOT_FOUND))
        message = _run(eb).message
        assert "No email with id 1042 is visible" in message
        assert "re-analysed under a new id" in message

        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        assert "does not serve /api/v1/emails/1042/reanalyze" in _run(eb).message
