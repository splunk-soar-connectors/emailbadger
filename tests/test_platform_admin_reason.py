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
"""``platform_admin_reason`` — a Platform Admin's key's reason for reading a customer.

On an install that separates tenants, a Platform Admin's key's call that loads a
customer's records must carry ``X-Platform-Admin-Reason``, or it reads nothing and
answers ``428 operator_reason_required`` (the SOAR contract's "Giving a
reason"). Four properties are load-bearing here:

- the header goes on **every** call when a reason is set, whether or not the call
  names a tenant, because the rule follows the row the call loads and not the
  parameter;
- nothing is sent when no reason is set, so a key bound to one tenant works as
  before, and the reason never becomes part of what is written;
- a 428 is **named**, in both of the shapes it comes in: the action API puts the
  code in ``error``, a core route has no ``error`` and nests it under ``detail``;
- a value that cannot travel in a header is refused before any call. A header is
  the one place a playbook's text can raise inside the HTTP client.

The shapes below are the core's own, read from its source.
"""

from __future__ import annotations

import json

import pytest
import requests

from .fakes import APP_ERROR, APP_SUCCESS, FakeHTTPResponse, action_error
from .recorded import (
    BLOCK_WRITTEN,
    REANALYZE_QUEUED,
    TICKET_PATCHED,
    TICKET_REPORTED,
    TIMELINE,
    VERDICT_SET,
    cursor,
    page,
)

REASON = "platform_admin_reason"
HEADER = "X-Platform-Admin-Reason"
TENANT = "target_tenant_id"
WHY = "Case 4411: phishing triage for Acme"
MESSAGE = "A reason is required to load this customer's records (tenant 7)."
VERDICT = {
    "email_id": 1042,
    "message_id": "<m@x>",
    "verdict": "malicious",
    "confidence": 0.9,
    "confidence_label": "high",
    "risk_score": 90,
    "risk_level": "high",
    "coverage_complete": True,
}
JOB = {"id": 55, "kind": "reanalyze", "status": "queued", "settled": False}

# Each action on the requests.request path, with the smallest parameters it
# accepts and a reply that succeeds. get verdict and the uploads use requests.get
# and requests.post, and are exercised on their own below.
ACTIONS = {
    "set_verdict": (
        {
            "email_id": 1042,
            "verdict": "malicious",
            "external_actor": "soar",
            "external_reference": "c-1",
        },
        VERDICT_SET,
    ),
    "record_block": (
        {
            "block_type": "sender_domain",
            "value": "sender.example",
            "reason": "campaign",
        },
        BLOCK_WRITTEN,
    ),
    "update_ticket": (
        {
            "email_id": 1042,
            "system": "splunk_soar",
            "ticket_id": "4411",
            "status": "closed",
        },
        TICKET_PATCHED,
    ),
    "report_ticket": (
        {
            "email_id": 1042,
            "system": "splunk_soar",
            "ticket_id": "4411",
            "opened_at": "2026-10-24T20:00:00Z",
        },
        TICKET_REPORTED,
    ),
    "reanalyze": ({"email_id": 1042}, REANALYZE_QUEUED),
    "get_timeline": ({"email_id": 1042}, TIMELINE),
    "get_job": ({"job_id": 55}, JOB),
}


def _action_428(tenant=7, request_id="req-428"):
    """The action API's 428, as ``action_api/errors.py`` shapes it."""
    return action_error(
        428,
        "operator_reason_required",
        {
            "code": "operator_reason_required",
            "tenant_id": tenant,
            "header": HEADER,
            "message": MESSAGE,
        },
        request_id=request_id,
    )


def _core_428(tenant=7):
    """A core route's 428: FastAPI's ``{"detail": ...}``, with no ``error`` field."""
    return {
        "detail": {
            "code": "operator_reason_required",
            "tenant_id": tenant,
            "header": HEADER,
            "message": MESSAGE,
        }
    }


def _act(eb, identifier, **extra):
    base, _ = ACTIONS[identifier]
    eb.run(identifier, {**base, **extra})
    return eb.results[-1]


def _poll(eb):
    eb.poll_now = False
    eb.run("on_poll", {})
    return eb.results[-1]


def _asset(eb, **settings):
    eb.config.update(settings)


@pytest.fixture
def get_reply(monkeypatch):
    """Script ``requests.get``, the one call ``get verdict`` makes; every call is kept."""
    calls = []

    def _set(status, payload):
        def fake_get(url, **kwargs):
            calls.append({"url": url, **kwargs})
            return FakeHTTPResponse(status, payload)

        monkeypatch.setattr(requests, "get", fake_get)
        return calls

    return _set


class TestTheHeaderGoesOnEveryCall:
    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_the_action_parameter_goes_as_the_header(self, eb, http, identifier):
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier, platform_admin_reason=WHY)

        assert calls[0]["headers"][HEADER] == WHY

    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_the_asset_setting_goes_when_the_action_names_none(
        self, eb, http, identifier
    ):
        _asset(eb, platform_admin_reason=WHY)
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier)

        assert calls[0]["headers"][HEADER] == WHY

    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_the_action_parameter_overrides_the_asset(self, eb, http, identifier):
        _asset(eb, platform_admin_reason="Standing triage reason")
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier, platform_admin_reason=WHY)

        assert calls[0]["headers"][HEADER] == WHY

    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_no_reason_sends_no_header(self, eb, http, identifier):
        """A key bound to one tenant must behave exactly as before this change."""
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier)

        assert HEADER not in calls[0]["headers"]

    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_it_goes_with_no_tenant_named(self, eb, http, identifier):
        """The rule follows the row, so a Platform Admin's key naming no tenant can still
        load a customer's. Tying the header to the tenant would refuse that call."""
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier, platform_admin_reason=WHY)

        assert TENANT not in (calls[0].get("params") or {})
        assert calls[0]["headers"][HEADER] == WHY

    def test_the_poll_sends_the_assets(self, eb, http):
        _asset(eb, platform_admin_reason=WHY, target_tenant_id=7)
        calls = http((200, page([], cursor(0))))
        _poll(eb)

        assert calls[0]["headers"][HEADER] == WHY

    def test_the_evidence_package_sends_it(self, eb, http):
        calls = http(action_error(404, "not_found", "No such tenant."))
        eb.run("get_evidence_package", {"email_id": 1042, REASON: WHY})

        assert calls[0]["headers"][HEADER] == WHY

    def test_get_verdict_sends_it_and_the_tenant(self, eb, get_reply):
        calls = get_reply(200, VERDICT)
        eb.run("get_verdict", {"message_id": "<m@x>", REASON: WHY, TENANT: 7})

        assert calls[0]["headers"][HEADER] == WHY
        assert calls[0]["params"] == {"message_id": "<m@x>", TENANT: 7}
        assert eb.results[-1].summary[TENANT] == 7

    def test_the_uploads_send_it(self, eb, vault, responses):
        vault()
        captured = responses(
            200, {"message": "ok", "risk_score": 1, "risk_level": "low"}
        )
        eb.run("analyze_email", {"vault_id": "vault-id-1", REASON: WHY, TENANT: 7})
        assert captured["headers"][HEADER] == WHY

        captured = responses(200, {"status": "ok", "total": 0, "results": []})
        eb.run("analyze_archive", {"vault_id": "vault-id-1", REASON: WHY, TENANT: 7})
        assert captured["headers"][HEADER] == WHY

    def test_one_actions_reason_does_not_outlive_it(self, eb, http):
        """SOAR hands a run's several parameter sets to one connector instance."""
        calls = http((200, TIMELINE))
        _act(eb, "get_timeline", platform_admin_reason=WHY)
        _act(eb, "get_timeline")

        assert calls[0]["headers"][HEADER] == WHY
        assert HEADER not in calls[1]["headers"]

    def test_whitespace_collapses_as_the_core_collapses_it(self, eb, http):
        calls = http((200, TIMELINE))
        _act(eb, "get_timeline", platform_admin_reason="  Case   4411\n triage\t")

        assert calls[0]["headers"][HEADER] == "Case 4411 triage"


class TestAValueThatCannotTravelIsRefusedFirst:
    @pytest.mark.parametrize(
        "raw",
        [
            "four",
            "   a b  ",
            "x" * 501,
            "Case 4411 — triage",
            "Case\x7f4411",
            "Case\x004411",
        ],
        ids=[
            "too-short",
            "too-short-after-collapse",
            "too-long",
            "not-latin-1",
            "del",
            "nul",
        ],
    )
    def test_refused_before_any_call(self, eb, http, raw):
        calls = http((200, TIMELINE))
        result = _act(eb, "get_timeline", platform_admin_reason=raw)

        assert result.status is APP_ERROR
        assert "platform_admin_reason (action parameter)" in result.message
        assert calls == []

    def test_a_bad_asset_setting_says_it_is_the_asset(self, eb, http):
        _asset(eb, platform_admin_reason="four")
        calls = http((200, TIMELINE))
        result = _act(eb, "get_timeline")

        assert "platform_admin_reason (asset setting)" in result.message
        assert calls == []

    def test_a_bad_asset_setting_stops_the_poll_and_keeps_the_cursor(self, eb, http):
        eb.state = {"cursors": {"7": cursor(3)}}
        _asset(eb, platform_admin_reason="four", target_tenant_id=7)
        calls = http((200, page([], cursor(9))))
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert calls == []
        assert eb.state["cursors"] == {"7": cursor(3)}

    def test_get_job_refuses_it_too(self, eb, http):
        calls = http((200, JOB))
        result = _act(eb, "get_job", platform_admin_reason="four")

        assert result.status is APP_ERROR
        assert calls == []

    @pytest.mark.parametrize(
        "raw", ["x" * 5, "x" * 500, "Café triage"], ids=["min", "max", "latin-1"]
    )
    def test_what_the_core_accepts_goes(self, eb, http, raw):
        """Latin-1 is what the HTTP client encodes a header in, and what the core
        decodes it from, so an accent survives the trip."""
        calls = http((200, TIMELINE))
        _act(eb, "get_timeline", platform_admin_reason=raw)

        assert calls[0]["headers"][HEADER] == raw
        raw.encode("latin-1")


class TestTheWriteIgnoresIt:
    """A reason says why this run reads a customer. It is not part of what is
    written: the body is the same with and without it, and it never turns into
    an Idempotency-Key (none is derived)."""

    @pytest.mark.parametrize("identifier", ["set_verdict", "record_block"])
    def test_the_body_is_the_same_with_and_without(self, eb, http, identifier):
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier)
        _act(eb, identifier, platform_admin_reason=WHY)

        assert calls[0]["json"] == calls[1]["json"]
        assert "Idempotency-Key" not in calls[1]["headers"]
        assert WHY not in json.dumps(calls[1].get("json") or {}), (
            "the reason is a header, never the body"
        )


class TestThe428IsNamed:
    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_on_every_action(self, eb, http, identifier):
        http(_action_428())
        result = (
            _act(eb, identifier, target_tenant_id=7)
            if identifier != "get_job"
            else _act(eb, identifier)
        )

        assert result.status is APP_ERROR
        assert result.summary["refusal"] == "operator_reason_required"
        assert "platform_admin_reason" in result.message
        assert "tenant 7" in result.message
        assert "req-428" in result.message

    def test_a_core_route_shape_on_get_job(self, eb, http):
        """``GET /api/v1/api-upload/jobs/{id}`` is a core route: no ``error`` field."""
        http(FakeHTTPResponse(428, _core_428()))
        result = _act(eb, "get_job")

        assert result.summary["refusal"] == "operator_reason_required"
        assert "tenant 7" in result.message, (
            "the 428's tenant is the only word of it when the call named none"
        )

    def test_a_core_route_shape_on_get_verdict(self, eb, get_reply):
        get_reply(428, _core_428())
        eb.run("get_verdict", {"message_id": "<m@x>"})
        result = eb.results[-1]

        assert result.status is APP_ERROR
        assert result.summary["refusal"] == "operator_reason_required"

    @pytest.mark.parametrize("handler", ["analyze_email", "analyze_archive"])
    def test_a_core_route_shape_on_the_uploads(self, eb, vault, responses, handler):
        vault()
        responses(428, _core_428())
        eb.run(handler, {"vault_id": "vault-id-1", TENANT: 7})
        result = eb.results[-1]

        assert result.status is APP_ERROR
        assert result.summary["refusal"] == "operator_reason_required"
        assert "tenant 7" in result.message

    def test_the_evidence_package_names_it(self, eb, http):
        http(_action_428())
        eb.run("get_evidence_package", {"email_id": 1042, TENANT: 7})

        assert eb.results[-1].summary["refusal"] == "operator_reason_required"

    def test_on_the_poll_it_is_named_and_keeps_the_cursor(self, eb, http):
        eb.state = {"cursors": {"7": cursor(3)}}
        _asset(eb, target_tenant_id=7)
        http(_action_428())
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert "needs a reason, and it read nothing" in result.message
        assert eb.state["cursors"] == {"7": cursor(3)}

    def test_a_refused_reason_says_why(self, eb, http):
        """A reason was sent and the core would not take it, so its words are the news."""
        said = "X-Platform-Admin-Reason: Give a reason of at least 5 characters."
        http(
            action_error(
                428,
                "operator_reason_required",
                {
                    "code": "operator_reason_required",
                    "tenant_id": 7,
                    "header": HEADER,
                    "message": said,
                },
            )
        )
        result = _act(eb, "get_timeline", target_tenant_id=7)

        assert said in result.message

    def test_an_ordinary_error_is_not_mistaken_for_it(self, eb, http):
        http(action_error(428, "precondition_required", "Something else entirely."))
        result = _act(eb, "get_timeline", target_tenant_id=7)

        assert result.status is APP_ERROR
        assert "refusal" not in result.summary

    def test_a_dict_detail_with_another_code_is_not_named(self, eb, http):
        http(
            FakeHTTPResponse(
                403, {"detail": {"code": "api_key_scope_missing", "message": "No."}}
            )
        )
        result = _act(eb, "get_job")

        assert result.status is APP_ERROR
        assert "refusal" not in result.summary


class TestGetVerdictTakesATenant:
    """One campaign leaves one Message-ID in two customers."""

    AMBIGUOUS = "More than one tenant holds an email with that Message-ID. Name the one you mean with target_tenant_id."

    def test_the_asset_tenant_goes(self, eb, get_reply):
        _asset(eb, target_tenant_id=9)
        calls = get_reply(200, VERDICT)
        eb.run("get_verdict", {"message_id": "<m@x>"})

        assert calls[0]["params"] == {"message_id": "<m@x>", TENANT: 9}

    def test_no_tenant_sends_none(self, eb, get_reply):
        calls = get_reply(200, VERDICT)
        eb.run("get_verdict", {"message_id": "<m@x>"})

        assert calls[0]["params"] == {"message_id": "<m@x>"}
        assert eb.results[-1].status is APP_SUCCESS

    def test_a_shared_message_id_is_named(self, eb, get_reply):
        get_reply(409, {"detail": self.AMBIGUOUS})
        eb.run("get_verdict", {"message_id": "<m@x>"})
        result = eb.results[-1]

        assert result.status is APP_ERROR
        assert result.summary["refusal"] == "tenant_ambiguous"
        assert TENANT in result.message

    def test_an_unknown_tenant_is_not_a_missing_email(self, eb, get_reply):
        get_reply(404, {"detail": "No such tenant."})
        eb.run("get_verdict", {"message_id": "<m@x>", TENANT: 999})
        result = eb.results[-1]

        assert result.summary["refusal"] == "tenant_not_found"
        assert "No EmailBadger tenant has id 999" in result.message

    def test_a_bad_tenant_is_refused_before_any_call(self, eb, get_reply):
        calls = get_reply(200, VERDICT)
        eb.run("get_verdict", {"message_id": "<m@x>", TENANT: "acme"})

        assert eb.results[-1].status is APP_ERROR
        assert calls == []


class TestConnectivity:
    def test_a_tenant_with_no_reason_is_warned_about(self, eb, responses):
        """The probe loads no customer row, so it passes either way. The first
        real read is where a missing reason would otherwise show."""
        _asset(eb, target_tenant_id=7)
        responses(422, {"detail": "file required"})
        eb.run("test_connectivity", {})

        assert eb.results[-1].status is APP_SUCCESS
        assert any(REASON in line for line in eb.progress)

    def test_a_tenant_with_a_reason_is_not(self, eb, responses):
        _asset(eb, target_tenant_id=7, platform_admin_reason=WHY)
        captured = responses(422, {"detail": "file required"})
        eb.run("test_connectivity", {})

        assert captured["headers"][HEADER] == WHY
        assert not any(REASON in line for line in eb.progress)

    def test_no_tenant_is_not_warned_about(self, eb, responses):
        responses(422, {"detail": "file required"})
        eb.run("test_connectivity", {})

        assert not any(REASON in line for line in eb.progress)

    def test_a_bad_reason_fails_it(self, eb, responses):
        _asset(eb, platform_admin_reason="four")
        captured = responses(422, {"detail": "file required"})
        eb.run("test_connectivity", {})

        assert eb.results[-1].status is APP_ERROR
        assert "platform_admin_reason (asset setting)" in eb.results[-1].message
        assert captured == {}
