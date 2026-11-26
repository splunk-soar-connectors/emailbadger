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
"""``get job`` — read the job ``reanalyze`` queued, and learn the new email id.

The re-analysed email gets a new id, and the job's ``result`` is the only
place it appears. A job still running is a success with ``settled`` false; a
job that failed, and a re-analysis that left no new record, fail the action so
a playbook branching on success does not carry on with an id that is gone.
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
from .recorded import JOB_NOT_FOUND, REANALYSIS_RESULT, ROUTE_ABSENT, job

PARAM = {"job_id": 77}


def _run(eb, **overrides):
    eb.run("get_job", {**PARAM, **overrides})
    return eb.results[-1]


class TestTheRequest:
    def test_gets_the_jobs_route_with_no_tenant_parameter(self, eb, http):
        """The route takes no ``target_tenant_id``: only the
        key that queued a job can read it, whatever tenant it ran in."""
        calls = http((200, job("queued")))
        _run(eb)

        call = calls[0]
        assert call["method"] == "GET"
        assert call["url"] == "https://eb.example.test/api/v1/api-upload/jobs/77"
        assert not call.get("params"), "the route declares no query parameters"
        assert call["headers"]["Authorization"] == "Bearer eb_test_key"

    @pytest.mark.parametrize("job_id", [0, -3, 7.5])
    def test_bad_job_id_never_reaches_emailbadger(self, eb, http, job_id):
        calls = http((200, job("queued")))
        result = _run(eb, job_id=job_id)
        assert result.status is APP_ERROR
        assert "positive integer" in result.message
        assert calls == []

    @pytest.mark.parametrize("job_id", ["x", "", None])
    def test_a_job_id_that_is_not_a_number_never_reaches_the_action(
        self, eb, http, job_id
    ):
        calls = http((200, job("queued")))
        assert refused_by_validation(_run(eb, job_id=job_id), "job_id")
        assert calls == []


class TestAJobStillRunning:
    @pytest.mark.parametrize("status", ["queued", "running"])
    def test_is_a_success_that_is_not_settled(self, eb, http, status):
        http((200, job(status)))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.summary["status"] == status
        assert result.summary["settled"] is False
        assert result.summary["new_email_id"] is None
        assert "has not settled" in result.message


class TestASettledReanalysis:
    def test_the_new_email_id_is_in_the_summary(self, eb, http):
        """The point of the action: the id later actions must take."""
        http((200, job("succeeded", result=REANALYSIS_RESULT)))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.data == [job("succeeded", result=REANALYSIS_RESULT)]
        assert result.summary == {
            "total_objects": 1,
            "job_id": 77,
            "status": "succeeded",
            "settled": True,
            "new_email_id": 1077,
            "new_verdict": "malicious",
            "new_score": 88,
        }

    def test_the_message_names_the_old_and_new_id_verdict_and_score(self, eb, http):
        http((200, job("succeeded", result=REANALYSIS_RESULT)))
        message = _run(eb).message
        assert "email 1042 is now email 1077" in message
        assert "suspicious -> malicious" in message
        assert "41 -> 88" in message

    def test_one_that_left_no_new_record_is_a_failure(self, eb, http):
        """``new_email_id`` is null when the ingest did not process the source. The
        old analysis is already deleted, so a success here would hand a playbook
        nothing to carry on with and no reason why."""
        http(
            (
                200,
                job(
                    "succeeded",
                    result={
                        **REANALYSIS_RESULT,
                        "status": "error",
                        "new_email_id": None,
                    },
                ),
            )
        )
        result = _run(eb)

        assert result.status is APP_ERROR
        assert "without a new record" in result.message
        assert "ingest status: error" in result.message
        assert "Email 1042 was deleted" in result.message
        assert result.summary["settled"] is True
        assert result.summary["new_email_id"] is None


class TestASettledFailure:
    @pytest.mark.parametrize("status", ["failed", "interrupted"])
    def test_fails_the_action_with_the_jobs_own_reason(self, eb, http, status):
        http(
            (
                200,
                job(
                    status,
                    error="Error re-analysing the email; its source file is still stored",
                ),
            )
        )
        result = _run(eb)

        assert result.status is APP_ERROR
        assert f"Job 77 {status}: Error re-analysing the email" in result.message
        assert "uploaded again" in result.message
        assert result.summary["status"] == status
        assert result.summary["settled"] is True
        assert result.data, (
            "the job is still there to read even though the action failed"
        )


class TestAnUploadJob:
    def test_is_read_the_same_way_and_reports_its_verdict(self, eb, http):
        """``detonate file`` on a deployment that queues uploads answers a job id
        too; its ``result`` is the upload summary, not a re-analysis."""
        summary = {
            "status": "processed",
            "message_id": "<m@x>",
            "risk_score": 70,
            "risk_level": "high",
            "verdict": "malicious",
        }
        http((200, job("succeeded", kind="api_upload", result=summary)))
        result = _run(eb)

        assert result.status is APP_SUCCESS, result.message
        assert result.message == "Job 77 succeeded. Verdict: malicious"
        assert result.summary["new_email_id"] is None


class TestWhenEmailBadgerRefuses:
    def test_no_such_job_and_no_such_route_are_two_messages(self, eb, http):
        """The route's 404 says ``Not found``; FastAPI's own says ``Not Found``.
        Reporting the first as a missing route sends an operator to upgrade a
        deployment that is fine; the second as a missing job hides the upgrade."""
        http(FakeHTTPResponse(404, JOB_NOT_FOUND))
        message = _run(eb).message
        assert "No job 77 is readable by this API key" in message
        assert "only the key that queued a job can read it" in message

        http(FakeHTTPResponse(404, ROUTE_ABSENT))
        message = _run(eb).message
        assert "does not serve /api/v1/api-upload/jobs/{job_id}" in message
        assert "No job" not in message

    def test_the_core_shaped_429_is_a_rate_limit(self, eb, http):
        """The jobs route counts per client address and answers ``{"error": ...}``,
        not the action API's shape."""
        http(FakeHTTPResponse(429, {"error": "Rate limit exceeded: 120 per 1 minute"}))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "Rate limited" in result.message

    @pytest.mark.parametrize(
        "status, payload, expected",
        [
            (401, {"detail": "Invalid API key"}, "wrong, revoked, or disabled"),
            (
                403,
                {"detail": "Read-only users cannot use the API upload"},
                "Read-only users",
            ),
        ],
    )
    def test_each_refusal_has_its_own_message(
        self, eb, http, status, payload, expected
    ):
        http(FakeHTTPResponse(status, payload))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert expected in result.message, result.message

    def test_a_request_id_is_kept_when_one_comes_back(self, eb, http):
        http(action_error(401, "unauthorized", "Invalid API key", request_id="req-9"))
        assert "(request id req-9)" in _run(eb).message

    def test_an_answer_without_a_status_is_a_failure_not_a_silent_success(
        self, eb, http
    ):
        http((200, {"id": 77}))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "job status" in result.message

    def test_unreachable_is_reported(self, eb, http):
        http(requests.exceptions.ConnectionError("refused"))
        result = _run(eb)
        assert result.status is APP_ERROR
        assert "Could not reach EmailBadger" in result.message
