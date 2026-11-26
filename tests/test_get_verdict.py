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
"""`get verdict`: the decisions, not the plumbing.

The action asks EmailBadger again for a verdict that may have moved since
upload. What it has to get right:

- **two different 404s.** "Email not found" is an email this key cannot see. Any
  other 404 is a deployment without the route. Reporting the second as the
  first sends an analyst looking for an email that is there;
- **tier and auth stay distinguishable**, as in every other action;
- **a provisional verdict says so**, because a playbook that closes a case on it
  may be acting before a re-score moves it;
- the Message-ID goes as a **query parameter**, since Message-IDs can contain
  ``/``.
"""

from __future__ import annotations

import json

import pytest
import requests

from .fakes import APP_ERROR, APP_SUCCESS

VERDICT = {
    "email_id": 42,
    "message_id": "<abc/def@example.com>",
    "verdict": "malicious",
    "confidence": 91,
    "confidence_label": "High",
    "risk_score": 87,
    "risk_level": "high",
    "coverage_complete": True,
}


def _run(eb, message_id="<abc/def@example.com>"):
    eb.run("get_verdict", {"message_id": message_id})
    return eb.results[-1]


class TestTheRequest:
    def test_the_message_id_is_a_query_parameter_not_a_path(self, eb, get_reply):
        captured = get_reply(200, VERDICT)
        _run(eb)

        assert captured["url"] == "https://eb.example.test/api/v1/verdicts"
        assert captured["params"] == {"message_id": "<abc/def@example.com>"}
        assert captured["headers"] == {"Authorization": "Bearer eb_test_key"}

    def test_a_blank_message_id_never_reaches_the_server(self, eb, get_reply):
        captured = get_reply(200, VERDICT)
        result = _run(eb, message_id="   ")

        assert result.status is APP_ERROR
        assert "message_id" in result.message
        assert captured == {}


class TestTheAnswer:
    def test_a_verdict_is_returned_and_summarised(self, eb, get_reply):
        get_reply(200, VERDICT)
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.message == "Verdict: malicious"
        assert result.data == [VERDICT]
        assert result.summary["verdict"] == "malicious"
        assert result.summary["coverage_complete"] is True

    def test_a_provisional_verdict_says_so(self, eb, get_reply):
        get_reply(200, {**VERDICT, "coverage_complete": False})
        result = _run(eb)

        assert result.status is APP_SUCCESS
        assert "provisional" in result.message

    @pytest.mark.parametrize("coverage", [True, None])
    def test_only_false_coverage_is_provisional(self, eb, get_reply, coverage):
        """None means coverage was never recorded (older emails), which is not
        the same claim as a provider failing to answer."""
        get_reply(200, {**VERDICT, "coverage_complete": coverage})

        assert "provisional" not in _run(eb).message

    def test_no_verdict_yet_is_not_an_error(self, eb, get_reply):
        get_reply(
            200,
            {**VERDICT, "verdict": None, "risk_level": None, "coverage_complete": None},
        )
        result = _run(eb)

        assert result.status is APP_SUCCESS
        assert "none yet" in result.message


class TestTheTwoKindsOf404:
    def test_an_email_the_key_cannot_see(self, eb, get_reply):
        get_reply(404, {"detail": "Email not found"})
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "<abc/def@example.com>" in result.message
        assert "visible to this API key" in result.message

    @pytest.mark.parametrize(
        "payload", [{"detail": "Not Found"}, json.JSONDecodeError("x", "", 0)]
    )
    def test_a_deployment_without_the_route(self, eb, get_reply, payload):
        get_reply(404, payload)
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "does not serve the verdict route" in result.message
        assert "visible to this API key" not in result.message


class TestTierAndAuthStayDistinct:
    def test_a_bad_key_is_an_auth_failure(self, eb, get_reply):
        get_reply(401, {"detail": "Unauthorized"})

        assert "API key is wrong" in _run(eb).message

    def test_an_unlicensed_deployment_is_a_tier_gate(self, eb, get_reply):
        get_reply(402, {"detail": "licence required"})
        message = _run(eb).message

        assert "Enterprise tier" in message
        assert "API key is wrong" not in message

    def test_a_rejected_message_id_names_the_parameter(self, eb, get_reply):
        get_reply(422, {"detail": [{"loc": ["query", "message_id"]}]})

        assert "Message-ID" in _run(eb).message

    def test_an_unreachable_server(self, eb, get_reply):
        get_reply(200, VERDICT, raises=requests.exceptions.ConnectionError("refused"))
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "Could not reach EmailBadger" in result.message

    def test_a_non_json_success(self, eb, get_reply):
        get_reply(200, json.JSONDecodeError("x", "", 0))
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "non-JSON" in result.message
