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
"""`analyze archive` — the decisions, not the plumbing.

An archive action is mostly about what *partial* means. Forty messages where
two entries are malformed is neither a failure nor a clean success, and both
of those readings lose something an analyst needs: collapsing to APP_ERROR
throws away thirty-eight verdicts, collapsing to a bare success claims two
emails were analysed that were not.

See ``conftest.py`` for how the action runs through the SOAR SDK here.
"""

from __future__ import annotations

import json

import pytest

from .fakes import APP_ERROR, APP_SUCCESS

ZIP_RESULT = {
    "message": "ZIP processed: 2 email(s) analyzed, 1 duplicate(s) skipped",
    "processed": 2,
    "duplicates": 1,
    "errors": 1,
    "results": [
        {
            "message_id": "<a@x>",
            "subject": "one",
            "risk_score": 80,
            "risk_level": "high",
        },
        {
            "message_id": "<b@x>",
            "subject": "two",
            "risk_score": 10,
            "risk_level": "low",
        },
    ],
    "error_details": [{"filename": "broken.eml", "error": "not a valid message"}],
}


def _run(eb, param=None):
    eb.run("analyze_archive", {"vault_id": "vault-id-1", **(param or {})})
    return eb.results[-1]


class TestPartialFailureIsReportedNotHidden:
    def test_a_mixed_archive_succeeds_and_names_the_failures(
        self, eb, vault, responses
    ):
        vault()
        responses(200, ZIP_RESULT)
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert "2 analysed" in result.message
        assert "1 failed" in result.message, (
            "the failed entry vanished from the message"
        )
        assert result.summary["errors"] == 1
        assert result.data[0]["error_details"][0]["filename"] == "broken.eml"

    def test_an_archive_where_nothing_analysed_fails_and_says_why(
        self,
        eb,
        vault,
        responses,
    ):
        """Zero verdicts is a failure — and the first filename is the thing an
        analyst can act on, so it goes in the message rather than only in the
        data."""
        vault()
        responses(
            200,
            {
                "processed": 0,
                "duplicates": 0,
                "errors": 2,
                "results": [],
                "error_details": [
                    {"filename": "one.eml", "error": "entry exceeds size cap"},
                    {"filename": "two.eml", "error": "not a valid message"},
                ],
            },
        )
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "one.eml" in result.message
        assert "entry exceeds size cap" in result.message

    def test_duplicates_alone_are_still_a_success(self, eb, vault, responses):
        """Re-submitting an archive already analysed is what a playbook does
        after a transient timeout. Nothing new was processed, and nothing is
        wrong."""
        vault()
        responses(
            200,
            {
                "processed": 0,
                "duplicates": 3,
                "errors": 0,
                "results": [],
                "error_details": [],
            },
        )
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert "3 duplicate" in result.message


class TestAnEncryptedArchiveNamesItsOwnRemedy:
    def test_password_required_is_not_reported_as_a_generic_http_error(
        self,
        eb,
        vault,
        responses,
    ):
        """422 + password_required is the one 4xx here that tells the analyst
        exactly what to do. Falling through to the status explainer would say
        'unexpected HTTP 422' and send them to check the key or the licence."""
        vault()
        responses(
            422,
            {
                "message": "ZIP is password-protected. Provide the password field.",
                "password_required": True,
            },
        )
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "password" in result.message.lower()
        assert "422" not in result.message

    def test_the_password_is_sent_as_form_data_when_supplied(
        self,
        eb,
        vault,
        responses,
    ):
        vault()
        captured = responses(200, ZIP_RESULT)
        _run(eb, {"password": "hunter2"})  # pragma: allowlist secret
        assert captured["data"]["password"] == "hunter2"  # pragma: allowlist secret

    def test_no_password_field_is_sent_when_none_is_given(
        self,
        eb,
        vault,
        responses,
    ):
        """An empty string is not a password. Sending one turns 'no password'
        into 'the wrong password'."""
        vault()
        captured = responses(200, ZIP_RESULT)
        _run(eb, {"password": ""})
        assert "password" not in captured["data"]


class TestTheRequestItself:
    def test_it_posts_to_the_zip_surface_with_the_bearer_key(
        self,
        eb,
        vault,
        responses,
    ):
        vault()
        captured = responses(200, ZIP_RESULT)
        _run(eb)
        assert captured["url"] == "https://eb.example.test/api/v1/api-upload/zip"
        assert captured["headers"]["Authorization"] == "Bearer eb_test_key"

    def test_skip_ai_analysis_is_sent_as_the_string_the_form_parser_reads(
        self,
        eb,
        vault,
        responses,
    ):
        """`bool` would serialise as "True"/"False"; FastAPI's form coercion
        reads "true"/"false"."""
        vault()
        captured = responses(200, ZIP_RESULT)
        _run(eb, {"skip_ai_analysis": True})
        assert captured["data"]["skip_ai_analysis"] == "true"

    def test_a_missing_vault_id_fails_before_any_request(
        self,
        eb,
        responses,
    ):
        captured = responses(200, ZIP_RESULT)
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "not found" in result.message
        assert captured == {}, "it called EmailBadger with a file it never found"


class TestTheTierGateIsStillDistinguished:
    @pytest.mark.parametrize(
        "code,expected",
        [
            (401, "api key is wrong"),
            (402, "enterprise tier"),
            (404, "enterprise tier"),
            (429, "rate limited"),
        ],
    )
    def test_status_codes_keep_their_analyst_facing_meaning(
        self,
        eb,
        vault,
        responses,
        code,
        expected,
    ):
        """Same explainer the other actions use: reporting a tier gate as an
        auth failure sends someone to rotate a key that is fine."""
        vault()
        responses(code, {})
        result = _run(eb)
        assert result.status is APP_ERROR
        assert expected in result.message.lower(), result.message

    def test_a_non_json_reply_is_named_as_such(self, eb, vault, responses):
        vault()
        responses(200, json.JSONDecodeError("no", "", 0))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "non-JSON" in result.message
