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
"""``set verdict`` — a SOAR decision recorded as one, retry-safe.

Two things make this action different from an analyst clicking a verdict in
the UI, and both are what the tests pin. The verdict carries who decided and
where the decision lives in SOAR, so the ``verdict.changed`` event and the
audit row tell the two apart. And no ``Idempotency-Key`` is derived:
the route is already idempotent on the email and the
``external_reference``, and a key derived from the body replayed a
suspicious -> malicious -> suspicious sequence's third call from the first.
"""

from __future__ import annotations

import pytest
import requests

from .fakes import (
    APP_ERROR,
    APP_SUCCESS,
    FakeHTTPResponse,
    action_error,
    refused_by_validation,
)
from .fakes import scope_refusal
from .recorded import NOT_FOUND, ROUTE_ABSENT, VERDICT_SET, VERDICT_UNCHANGED

PARAM = {
    "email_id": 1042,
    "verdict": "malicious",
    "external_actor": "soar-playbook:phish-triage",
    "external_reference": "container 4411",
}


def _run(eb, **overrides):
    eb.run("set_verdict", {**PARAM, **overrides})
    return eb.results[-1]


class TestTheRequest:
    def test_posts_the_contract_body_to_the_email_route(self, eb, http):
        calls = http((200, VERDICT_SET))
        _run(eb)

        call = calls[0]
        assert call["method"] == "POST"
        assert call["url"] == "https://eb.example.test/api/v1/emails/1042/verdict"
        assert call["json"] == {
            "verdict": "malicious",
            "external_actor": "soar-playbook:phish-triage",
            "external_reference": "container 4411",
        }, "the route refuses unknown fields; nothing extra may go"
        assert call["headers"]["Authorization"] == "Bearer eb_test_key"

    def test_a_reason_goes_along_when_given(self, eb, http):
        calls = http((200, VERDICT_SET))
        _run(eb, reason="Analyst confirmed credential harvest")
        assert calls[0]["json"]["reason"] == "Analyst confirmed credential harvest"

    def test_no_idempotency_key_is_derived(self, eb, http):
        """The route dedups on (email, external_reference) by itself. A key
        derived from the body would replay a stored answer the case has since
        changed its mind about."""
        calls = http((200, VERDICT_SET))
        _run(eb)
        assert "Idempotency-Key" not in (calls[0].get("headers") or {})

    def test_a_flip_back_goes_to_the_route_every_time(self, eb, http):
        """suspicious -> malicious -> suspicious under one reference.
        Each call must reach the route as itself; with a derived key the third
        carried the first one's key and was answered from storage."""
        calls = http((200, VERDICT_SET))
        for verdict in ("suspicious", "malicious", "suspicious"):
            _run(eb, verdict=verdict)

        assert [c["json"]["verdict"] for c in calls] == [
            "suspicious",
            "malicious",
            "suspicious",
        ]
        assert all("Idempotency-Key" not in (c.get("headers") or {}) for c in calls)

    def test_the_playbooks_own_key_wins(self, eb, http):
        calls = http((200, VERDICT_SET))
        _run(eb, idempotency_key="playbook-run-77")
        assert calls[0]["headers"]["Idempotency-Key"] == "playbook-run-77"

    def test_the_verdict_is_normalised_before_it_is_sent(self, eb, http):
        calls = http((200, VERDICT_SET))
        _run(eb, verdict=" Malicious ")
        assert calls[0]["json"]["verdict"] == "malicious"


class TestBadParametersNeverReachEmailBadger:
    @pytest.mark.parametrize(
        "overrides, expected",
        [
            ({"email_id": 1042.5}, "positive integer"),
            ({"email_id": 0}, "positive integer"),
            ({"verdict": "clean"}, "malicious, suspicious, benign"),
            (
                {"external_actor": ""},
                "external_actor and external_reference are required",
            ),
            (
                {"external_reference": "  "},
                "external_actor and external_reference are required",
            ),
        ],
    )
    def test_the_message_names_the_parameter(self, eb, http, overrides, expected):
        calls = http((200, VERDICT_SET))
        result = _run(eb, **overrides)

        assert result.status is APP_ERROR
        assert expected in result.message
        assert calls == []

    def test_an_email_id_that_is_not_a_number_never_reaches_the_action(self, eb, http):
        calls = http((200, VERDICT_SET))
        assert refused_by_validation(_run(eb, email_id="abc"), "email_id")
        assert calls == []


class TestTheAnswer:
    def test_a_change_is_reported_with_the_previous_verdict(self, eb, http):
        http((200, VERDICT_SET))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.data == [VERDICT_SET]
        assert result.summary["changed"] is True
        assert result.summary["previous"] == "suspicious"
        assert result.summary["current"] == "malicious"
        assert result.summary["replayed"] is False
        assert (
            result.message == "Verdict on email 1042 set to malicious (was suspicious)"
        )

    def test_setting_the_verdict_it_already_has_is_a_success_that_says_nothing_changed(
        self, eb, http
    ):
        http((200, VERDICT_UNCHANGED))
        result = _run(eb)

        assert result.status is APP_SUCCESS
        assert result.summary["changed"] is False
        assert "nothing changed" in result.message

    def test_a_replayed_answer_is_marked_as_one(self, eb, http):
        """The retry after a timeout: EmailBadger answers from its 24-hour
        store with ``Idempotent-Replay: true``. The verdict did flip — once,
        on the first request — so this is a success, flagged."""
        http(FakeHTTPResponse(200, VERDICT_SET, headers={"Idempotent-Replay": "true"}))
        result = _run(eb)

        assert result.status is APP_SUCCESS
        assert result.summary["replayed"] is True
        assert "Replayed" in result.message

    def test_the_key_used_is_in_the_summary_for_the_next_retry(self, eb, http):
        http((200, VERDICT_SET))
        result = _run(eb, idempotency_key="playbook-run-77")
        assert result.summary["idempotency_key"] == "playbook-run-77"

    def test_with_no_key_supplied_the_summary_names_none(self, eb, http):
        http((200, VERDICT_SET))
        result = _run(eb)
        assert result.summary["idempotency_key"] is None


class TestWhenEmailBadgerRefuses:
    """The tier gate and the scope gate answer with their own statuses, and
    none of them means the key is bad. Each message must send the analyst to
    the right place."""

    @pytest.mark.parametrize(
        "status, code, detail, expected",
        [
            (401, "unauthorized", "Invalid API key", "wrong, revoked, or disabled"),
            (
                402,
                "license_required",
                "Enterprise tier required",
                "requires Enterprise tier or above",
            ),
            (
                403,
                "api_key_scope_missing",
                scope_refusal("verdicts:write"),
                "lacks the scope this action needs. This API key does not carry the 'verdicts:write' scope",
            ),
            (
                409,
                "verdict_not_rendered",
                "Email has no verdict yet",
                "no verdict or risk score yet",
            ),
            (
                409,
                "idempotency_conflict",
                "Key reused with a different body",
                "different request",
            ),
            (
                409,
                "idempotency_in_progress",
                "Request in flight",
                "still being processed",
            ),
            (
                422,
                "validation_error",
                "external_actor: String should have at most 255 characters",
                "rejected the request: external_actor: String should have at most 255 characters",
            ),
            (
                400,
                "idempotency_key_invalid",
                "Idempotency-Key must be printable ASCII",
                "(idempotency_key_invalid): Idempotency-Key must be printable ASCII",
            ),
        ],
    )
    def test_each_refusal_has_its_own_message(
        self, eb, http, status, code, detail, expected
    ):
        http(action_error(status, code, detail, request_id="req-77"))
        result = _run(eb)

        assert result.status is APP_ERROR
        assert expected in result.message, result.message
        assert "(request id req-77)" in result.message

    def test_a_404_for_the_email_is_told_apart_from_a_404_for_the_route(self, eb, http):
        http(action_error(404, *NOT_FOUND))
        missing = _run(eb)
        assert (
            "No email with id 1042 is visible to this API key's user" in missing.message
        )

        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        absent = _run(eb)
        assert "does not serve /api/v1/emails/1042/verdict" in absent.message

    def test_a_429_carries_retry_after(self, eb, http):
        http(
            action_error(
                429, "rate_limited", "Too many requests", **{"Retry-After": "12"}
            )
        )
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "retry after 12 seconds" in result.message

    def test_tls_failures_point_at_the_ca_not_at_disabling_verification(self, eb, http):
        http(requests.exceptions.SSLError("certificate verify failed"))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "install it on the SOAR host" in result.message

    def test_a_non_json_200_is_a_failure(self, eb, http):
        http(
            FakeHTTPResponse(
                200, headers={"Content-Type": "text/html"}, content=b"<html>"
            )
        )
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "non-JSON" in result.message
