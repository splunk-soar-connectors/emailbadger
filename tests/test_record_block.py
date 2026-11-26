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
"""``record block`` — a block written through the Block dialog's own guardrails.

The route behind it (``POST /api/v1/blocks``) never bypasses
approval mode: when a guardrail wants an acknowledgement it answers 409
``conflict`` with the findings and nothing is written. From a playbook that
is not an error to retry; it is a state to branch on, so the action reports
it as a *success* with ``summary.outcome == "acknowledgement_required"`` and
the exact ``acknowledge`` value that would write the block. These tests pin
the three outcomes apart, the one refusal that stays a failure, and the
request shape the route accepts.
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
from .recorded import (
    ALREADY_BLOCKED,
    BLOCK_WRITTEN,
    BLOCK_WRITTEN_PERMANENT,
    BLOCKS_SCOPE_MISSING,
    FINDING_PUBLIC_SUFFIX,
    FINDING_SAFELISTED,
    FINDING_WOULD_HAVE_CAUGHT,
    ROUTE_ABSENT,
    block_conflict,
)

PARAM = {
    "block_type": "sender_domain",
    "value": "sender.example",
    "reason": "Credential-harvest campaign, container 4411",
    "source_email_id": 1042,
}


def _run(eb, **overrides):
    eb.run("record_block", {**PARAM, **overrides})
    return eb.results[-1]


class TestTheRequest:
    def test_posts_the_contract_body_to_the_blocks_route(self, eb, http):
        calls = http((200, BLOCK_WRITTEN))
        _run(eb)

        call = calls[0]
        assert call["method"] == "POST"
        assert call["url"] == "https://eb.example.test/api/v1/blocks"
        assert call["json"] == {
            "block_type": "sender_domain",
            "value": "sender.example",
            "reason": "Credential-harvest campaign, container 4411",
            "source_email_id": 1042,
        }, (
            "blank optional fields stay out so the route's defaults (install expiry, no acknowledgements) apply"
        )
        assert call["headers"]["Authorization"] == "Bearer eb_test_key"

    def test_the_minimal_request_is_type_and_value_only(self, eb, http):
        calls = http((200, BLOCK_WRITTEN))
        _run(
            eb,
            reason="",
            source_email_id="",
            expires_in_days="",
            never_expires=False,
            acknowledge="",
        )
        assert calls[0]["json"] == {
            "block_type": "sender_domain",
            "value": "sender.example",
        }

    def test_expiry_goes_as_a_whole_number_of_days(self, eb, http):
        calls = http((200, BLOCK_WRITTEN))
        _run(eb, expires_in_days="7")
        assert calls[0]["json"]["expires_in_days"] == 7
        assert "never_expires" not in calls[0]["json"]

    def test_never_expires_goes_as_a_boolean(self, eb, http):
        calls = http((200, BLOCK_WRITTEN_PERMANENT))
        _run(eb, never_expires=True)
        assert calls[0]["json"]["never_expires"] is True
        assert "expires_in_days" not in calls[0]["json"]

    def test_acknowledgements_go_as_the_list_the_route_takes(self, eb, http):
        """``summary.acknowledge`` from the previous run is a csv, because
        SOAR has no list parameter type; the route wants a list."""
        calls = http((200, BLOCK_WRITTEN))
        _run(eb, acknowledge=" would_have_caught, safelisted ,would_have_caught")
        assert calls[0]["json"]["acknowledge"] == ["safelisted", "would_have_caught"]

    def test_block_type_is_normalised_before_it_is_sent(self, eb, http):
        calls = http((200, BLOCK_WRITTEN))
        _run(eb, block_type=" Sender_Domain ", value="  sender.example ")
        assert calls[0]["json"]["block_type"] == "sender_domain"
        assert calls[0]["json"]["value"] == "sender.example"

    def test_no_idempotency_key_is_derived(self, eb, http):
        """A retry is safe without one (the live block answers
        already_blocked). A derived key replayed the stored ``written`` for 24
        hours, so a block an analyst lifted and the playbook recorded again
        was never written."""
        calls = http((200, BLOCK_WRITTEN))
        _run(eb)
        _run(eb)
        assert all("Idempotency-Key" not in (c.get("headers") or {}) for c in calls)

    def test_the_acknowledged_re_run_carries_no_key_either(self, eb, http):
        """The acknowledged re-send differs from the first only in
        ``acknowledge``, and reaches the route as a request of its own."""
        calls = http(
            (409, {"error": "conflict", "detail": block_conflict(FINDING_SAFELISTED)}),
            (200, BLOCK_WRITTEN),
        )
        first = _run(eb)
        _run(eb, acknowledge=first.summary["acknowledge"])
        assert calls[1]["json"]["acknowledge"] == first.summary["acknowledge"].split(
            ","
        )
        assert all("Idempotency-Key" not in (c.get("headers") or {}) for c in calls)

    def test_the_playbooks_own_key_wins(self, eb, http):
        calls = http((200, BLOCK_WRITTEN))
        _run(eb, idempotency_key="playbook-run-77")
        assert calls[0]["headers"]["Idempotency-Key"] == "playbook-run-77"


class TestBadParametersNeverReachEmailBadger:
    @pytest.mark.parametrize(
        "overrides, expected",
        [
            (
                {"block_type": "mailbox"},
                "block_type must be one of sender_address, sender_domain, url, domain, ip, hash",
            ),
            ({"block_type": ""}, "block_type must be one of"),
            ({"value": "   "}, "value is required"),
            ({"source_email_id": 0}, "source_email_id must be a positive integer"),
            (
                {"expires_in_days": "0"},
                "expires_in_days must be a whole number of days, at least 1",
            ),
            (
                {"expires_in_days": 2.5},
                "expires_in_days must be a whole number of days, at least 1",
            ),
            ({"expires_in_days": 7, "never_expires": True}, "not both"),
        ],
    )
    def test_the_message_names_the_parameter(self, eb, http, overrides, expected):
        calls = http((200, BLOCK_WRITTEN))
        result = _run(eb, **overrides)

        assert result.status is APP_ERROR
        assert expected in result.message, result.message
        assert calls == []

    @pytest.mark.parametrize(
        "parameter, raw", [("source_email_id", "abc"), ("expires_in_days", "soon")]
    )
    def test_a_number_that_is_not_one_never_reaches_the_action(
        self, eb, http, parameter, raw
    ):
        calls = http((200, BLOCK_WRITTEN))
        assert refused_by_validation(_run(eb, **{parameter: raw}), parameter)
        assert calls == []


class TestWritten:
    def test_a_written_block_reports_how_far_it_is_enforced(self, eb, http):
        http((200, BLOCK_WRITTEN))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.data == [BLOCK_WRITTEN]
        assert result.summary["outcome"] == "written"
        assert result.summary["written"] is True
        assert result.summary["block_id"] == 31
        assert result.summary["badge_state"] == "partly_blocked"
        assert result.summary["expires_at"] == "2026-11-23T22:12:00Z"
        assert result.summary["targets"] == 2
        assert result.summary["replayed"] is False
        assert result.message == (
            "Blocked sender_domain sender.example (block id 31, enforcement partly_blocked, "
            "expires 2026-11-23T22:12:00Z); targets: 1 applied, 1 pending"
        )

    def test_a_permanent_block_with_no_target_says_it_is_a_record_only(self, eb, http):
        http((200, BLOCK_WRITTEN_PERMANENT))
        result = _run(eb, never_expires=True)

        assert result.status is APP_SUCCESS
        assert result.summary["expires_at"] is None
        assert "expires never" in result.message
        assert "record only" in result.message

    def test_a_replayed_answer_is_marked_as_one(self, eb, http):
        http(
            FakeHTTPResponse(200, BLOCK_WRITTEN, headers={"Idempotent-Replay": "true"})
        )
        result = _run(eb)

        assert result.status is APP_SUCCESS
        assert result.summary["replayed"] is True
        assert "Replayed" in result.message

    def test_the_key_used_is_in_the_summary_for_the_next_retry(self, eb, http):
        http((200, BLOCK_WRITTEN))
        result = _run(eb, idempotency_key="playbook-run-77")
        assert result.summary["idempotency_key"] == "playbook-run-77"

    def test_with_no_key_supplied_the_summary_names_none(self, eb, http):
        http((200, BLOCK_WRITTEN))
        result = _run(eb)
        assert result.summary["idempotency_key"] is None


class TestApprovalModeIsAResultNotAFailure:
    """EmailBadger's Block dialog shows an analyst these findings and asks
    them to tick each one. The route does the same over the API: 409
    ``conflict`` with the findings, nothing written. A playbook needs to
    branch on that (prompt a human, or re-send with the codes), which it
    cannot do from a failed action, so it is a success with its own outcome."""

    def test_acknowledgeable_findings_are_a_distinct_success_carrying_the_codes_to_re_send(
        self, eb, http
    ):
        http(
            action_error(
                409,
                "conflict",
                block_conflict(FINDING_WOULD_HAVE_CAUGHT, FINDING_SAFELISTED),
                "req-9",
            )
        )
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.summary["outcome"] == "acknowledgement_required"
        assert result.summary["written"] is False
        assert result.summary["findings"] == 2
        assert result.summary["acknowledge"] == "safelisted,would_have_caught"
        assert result.data == [
            {
                "findings": [FINDING_WOULD_HAVE_CAUGHT, FINDING_SAFELISTED],
                "acknowledge": "safelisted,would_have_caught",
            }
        ]
        assert result.message.startswith(
            "Not written: EmailBadger asks the playbook to acknowledge 2 finding(s)"
        )
        assert "safelisted (sender.example is on the safelist.)" in result.message
        assert 'acknowledge="safelisted,would_have_caught"' in result.message
        assert "(request id req-9)" in result.message

    def test_the_acknowledge_value_handed_back_writes_the_block_when_re_sent(
        self, eb, http
    ):
        calls = http(
            (409, {"error": "conflict", "detail": block_conflict(FINDING_SAFELISTED)}),
            (200, BLOCK_WRITTEN),
        )
        first = _run(eb)
        second = _run(eb, acknowledge=first.summary["acknowledge"])

        assert calls[1]["json"]["acknowledge"] == ["safelisted"]
        assert second.summary["outcome"] == "written"

    def test_a_refuse_finding_is_the_failure_no_acknowledgement_can_clear(
        self, eb, http
    ):
        http(
            action_error(
                409,
                "conflict",
                block_conflict(FINDING_PUBLIC_SUFFIX, FINDING_WOULD_HAVE_CAUGHT),
                "req-10",
            )
        )
        result = _run(eb, block_type="sender_domain", value="gmail.com")

        assert result.status is APP_ERROR
        assert "no acknowledgement can change that" in result.message
        assert (
            "wrong_layer_public_suffix: gmail.com is a public mail provider"
            in result.message
        )
        assert "would_have_caught" not in result.message, (
            "the acknowledgeable finding is moot; naming it misleads"
        )
        assert "(request id req-10)" in result.message

    def test_a_conflict_with_no_findings_is_a_failure_quoting_the_detail(
        self, eb, http
    ):
        """Defensive: the route always sends findings with ``conflict``, but a
        shape change must not turn into a silent 'acknowledge nothing' success."""
        http(action_error(409, "conflict", "This block was not written.", "req-11"))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "This block was not written." in result.message

    def test_an_indicator_already_blocked_is_its_own_outcome(self, eb, http):
        http(action_error(409, *ALREADY_BLOCKED, request_id="req-12"))
        result = _run(eb)

        assert result.status is APP_SUCCESS
        assert result.summary["outcome"] == "already_blocked"
        assert result.summary["written"] is False
        assert result.message == (
            "sender_domain sender.example is already blocked; nothing was written. (request id req-12)"
        )


class TestWhenEmailBadgerRefuses:
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
                *BLOCKS_SCOPE_MISSING,
                "lacks the scope this action needs. This API key does not carry the 'blocks:write' scope",
            ),
            (
                400,
                "bad_request",
                "Unknown block type 'mailbox'. One of: sender_address, sender_domain, url, domain, ip, hash",
                "rejected the request (bad_request): Unknown block type 'mailbox'",
            ),
            (
                400,
                "idempotency_key_invalid",
                "Idempotency-Key must be printable ASCII",
                "(idempotency_key_invalid): Idempotency-Key must be printable ASCII",
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
                "value: String should have at most 2048 characters",
                "rejected the request: value: String should have at most 2048 characters",
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

    def test_a_404_names_the_route_the_deployment_lacks(self, eb, http):
        """There is no per-email 404 here: the only 404 is a deployment without
        the route (a release before it, or a tier below Enterprise)."""
        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "does not serve /api/v1/blocks" in result.message

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
