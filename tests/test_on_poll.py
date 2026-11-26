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
"""``on poll`` over the verdict event feed — the decisions, not the plumbing.

The feed replaces webhooks as the certified ingestion path, which makes three
properties load-bearing: a re-poll must not create a second container for an
event already ingested, the cursor must survive between polls, and a cursor
EmailBadger no longer honours must never turn into a *silent* empty poll — an
asset that was off for longer than the feed's retention may have missed events,
and the operator needs to be told so rather than see "0 ingested" forever.

The SDK ends every successful poll with its own "Polling complete" and no
summary, so what the poll has to say goes in its progress log: the count, and
any cursor reset. ``_said`` is that log's last line, the poll's own message.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
import requests

from src.consts import MAX_PAGES_PER_POLL

from .fakes import APP_ERROR, APP_SUCCESS, FakeHTTPResponse, action_error, scope_refusal
from .recorded import bulk_rescored, changed, cursor, page, rendered

TYPES = "verdict.rendered,verdict.changed"


def _poll(eb, param=None, *, poll_now=False):
    eb.poll_now = poll_now
    eb.run("on_poll", dict(param or {}))
    return eb.results[-1]


def _said(eb):
    """What the poll said last: its count, and any reset note after it."""
    return eb.progress[-1]


class TestTheRequest:
    def test_the_first_poll_asks_from_the_oldest_retained_event(self, eb, http):
        calls = http((200, page([], cursor(0))))
        _poll(eb)

        call = calls[0]
        assert call["method"] == "GET"
        assert call["url"] == "https://eb.example.test/api/v1/events"
        assert call["params"] == {"types": TYPES, "limit": 100}, (
            "a new asset sends no since"
        )
        assert call["headers"]["Authorization"] == "Bearer eb_test_key"
        assert call["verify"] is True

    def test_the_next_poll_resumes_from_the_saved_cursor(self, eb, http):
        calls = http((200, page([rendered(1)], cursor(1))))
        _poll(eb)
        assert eb.state["cursors"]["own"] == cursor(1)

        _poll(eb)
        assert calls[1]["params"]["since"] == cursor(1)

    def test_types_and_page_size_come_from_the_asset(self, eb, http):
        eb.config["poll_event_types"] = " verdict.changed, verdicts.bulk_rescored ,"
        eb.config["poll_page_size"] = 5000
        calls = http((200, page([], cursor(0))))
        _poll(eb)

        assert calls[0]["params"]["types"] == "verdict.changed,verdicts.bulk_rescored"
        assert calls[0]["params"]["limit"] == 500, (
            "the feed caps limit at 500; a larger ask is a 422"
        )

    def test_a_blank_types_setting_falls_back_to_the_default(self, eb, http):
        eb.config["poll_event_types"] = " , "
        calls = http((200, page([], cursor(0))))
        _poll(eb)
        assert calls[0]["params"]["types"] == TYPES


class TestContainers:
    def test_one_container_per_event_in_feed_order(self, eb, http):
        events = [
            rendered(1),
            changed(2),
            rendered(3, verdict="benign", risk_level="low"),
        ]
        http((200, page(events, cursor(3))))
        result = _poll(eb)

        assert result.status is APP_SUCCESS, result.message
        assert [c["source_data_identifier"] for c in eb.containers] == [
            e["event_id"] for e in events
        ]
        assert len(eb.containers) == 3
        assert "3 event(s) ingested" in _said(eb)

    def test_a_re_poll_of_the_same_events_adds_no_container(self, eb, http):
        """The dedupe key is EmailBadger's event id, so the same events coming
        back (a restart before the cursor was saved, or an operator resetting
        it) are absorbed by SOAR's own duplicate handling."""
        http((200, page([rendered(1), rendered(2)], cursor(2))))
        _poll(eb)
        eb.state = {}  # lose the cursor, as a reinstalled asset would
        result = _poll(eb)

        assert result.status is APP_SUCCESS
        assert len(eb.containers) == 2

    def test_severity_follows_risk_level_as_get_verdict_reports_it(self, eb, http):
        http(
            (
                200,
                page(
                    [
                        rendered(1, risk_level="critical"),
                        rendered(2, risk_level="high"),
                        rendered(3, risk_level="medium"),
                        rendered(4, risk_level="low"),
                        bulk_rescored(5),
                    ],
                    cursor(5),
                ),
            )
        )
        _poll(eb)

        assert [c["severity"] for c in eb.containers] == [
            "high",
            "high",
            "medium",
            "low",
            "medium",
        ]

    def test_the_container_is_named_for_the_verdict_and_subject(self, eb, http):
        http(
            (
                200,
                page(
                    [rendered(1, subject="Your account"), bulk_rescored(2)], cursor(2)
                ),
            )
        )
        _poll(eb)

        first, second = eb.containers
        assert first["name"] == "EmailBadger malicious: Your account"
        assert (
            second["name"]
            == "EmailBadger verdicts.bulk_rescored: Retro-hunt of feed abuse.ch"
        )
        assert first["data"]["event_id"] == rendered(1)["event_id"], (
            "the whole envelope rides along"
        )

    def test_the_label_comes_from_the_asset_ingest_settings(self, eb, http):
        eb.ingest = {"container_label": "phishing"}
        http((200, page([rendered(1)], cursor(1))))
        _poll(eb)
        assert eb.containers[0]["label"] == "phishing"

    def test_the_event_artifact_carries_the_ids_a_playbook_needs(self, eb, http):
        http((200, page([changed(7)], cursor(7))))
        _poll(eb)

        artifacts = eb.containers[0]["artifacts"]
        event_artifact = artifacts[0]
        cef = event_artifact["cef"]
        assert cef["emailbadgerEmailId"] == 1007
        assert cef["messageId"] == "<msg-7@sender.example>"
        assert cef["verdict"] == "malicious"
        assert cef["previousVerdict"] == "suspicious"
        assert cef["riskLevel"] == "high"
        assert cef["spf"] == "fail"
        assert event_artifact["cef_types"]["emailbadgerEmailId"] == [
            "emailbadger email id"
        ]
        assert event_artifact["cef_types"]["messageId"] == ["emailbadger message id"]

    def test_iocs_land_in_the_cef_field_their_type_calls_for(self, eb, http):
        http((200, page([rendered(1)], cursor(1))))
        _poll(eb)

        _event, url, domain, sha = eb.containers[0]["artifacts"]
        assert url["cef"]["requestURL"] == "https://evil.example/login"
        assert url["cef_types"]["requestURL"] == ["url"]
        assert domain["cef"]["destinationDnsDomain"] == "evil.example"
        assert sha["cef"]["fileHash"] == "a" * 64
        assert sha["cef"]["isMalicious"] is False
        assert [a["severity"] for a in (url, domain, sha)] == ["high", "medium", "low"]

    def test_an_ioc_type_the_app_does_not_know_is_still_kept(self, eb, http):
        http(
            (
                200,
                page(
                    [
                        rendered(
                            1, iocs=[{"type": "bitcoin_address", "value": "bc1q..."}]
                        )
                    ],
                    cursor(1),
                ),
            )
        )
        _poll(eb)
        ioc = eb.containers[0]["artifacts"][1]
        assert ioc["cef"] == {"iocValue": "bc1q...", "iocType": "bitcoin_address"}

    def test_automation_runs_once_per_container_after_the_last_artifact(self, eb, http):
        http((200, page([rendered(1)], cursor(1))))
        _poll(eb)
        flags = [a["run_automation"] for a in eb.containers[0]["artifacts"]]
        assert flags == [False, False, False, True]


class TestTheCursor:
    def test_a_backlog_is_drained_page_by_page_saving_the_cursor_each_time(
        self, eb, http
    ):
        eb.config["poll_page_size"] = 2
        calls = http(
            (200, page([rendered(1), rendered(2)], cursor(2))),
            (200, page([rendered(3)], cursor(3))),
        )
        result = _poll(eb)

        assert len(calls) == 2
        assert "since" not in calls[0]["params"]
        assert calls[1]["params"]["since"] == cursor(2)
        assert eb.state["cursors"]["own"] == cursor(3)
        assert result.status is APP_SUCCESS
        assert "3 event(s) ingested" in _said(eb)

    def test_a_poll_stops_after_a_bounded_number_of_pages(self, eb, http):
        """A feed that outruns the interval is caught up over several polls,
        not in one that never returns. The cursor saved is the last page's,
        so nothing is lost — the next poll carries on from there."""
        eb.config["poll_page_size"] = 1
        calls = http(*[(200, page([rendered(n)], cursor(n))) for n in range(1, 100)])
        _poll(eb)

        assert len(calls) == MAX_PAGES_PER_POLL
        assert len(eb.containers) == MAX_PAGES_PER_POLL
        assert eb.state["cursors"]["own"] == cursor(MAX_PAGES_PER_POLL)

    def test_an_empty_page_is_a_quiet_success_that_still_saves_the_cursor(
        self, eb, http
    ):
        """The feed answers an empty page with a 'now' cursor; keeping it means
        the next poll's cursor is fresh rather than ageing toward the 410."""
        http((200, page([], cursor(0, "2026-10-24T22:30:00Z"))))
        result = _poll(eb)

        assert result.status is APP_SUCCESS
        assert _said(eb) == "0 event(s) ingested"
        assert eb.containers == []
        assert eb.state["cursors"]["own"] == cursor(0, "2026-10-24T22:30:00Z")


AGED_OUT = "any events that aged out before then were not ingested"


def assert_claims_no_loss_it_cannot_know(message):
    """The feed answers the same 410 for a cursor that idled on an empty feed,
    so the reset may say what could have been missed but never that it was.

    The hedged clause has to be there, and with it taken out nothing else may
    speak of a loss, so the old sentence fails however it is rephrased."""
    assert "Resumed from the oldest retained event" in message
    assert AGED_OUT in message
    rest = message.replace(AGED_OUT, "").lower()
    for claim in ("not ingested", "between", "gone", "lost", "missed", "gap"):
        assert claim not in rest, (
            f"an unconditional loss claim ({claim!r}) in: {message}"
        )


class TestACursorEmailBadgerNoLongerHonours:
    def _expired(self, oldest):
        return action_error(
            410,
            "cursor_expired",
            {
                "message": "Cursor is older than the feed's retention",
                "oldest_cursor": oldest,
                "retention_days": 7,
            },
        )

    def test_a_410_resumes_from_the_oldest_cursor_and_says_so(self, eb, http):
        eb.state = {"cursors": {"own": cursor(1, "2026-09-01T00:00:00Z")}}
        calls = http(
            self._expired(cursor(500)),
            (200, page([rendered(501), rendered(502)], cursor(502))),
        )
        result = _poll(eb)

        assert result.status is APP_SUCCESS, result.message
        assert calls[1]["params"]["since"] == cursor(500), (
            "the retry starts from the cursor EmailBadger named"
        )
        assert len(eb.containers) == 2
        assert eb.state["cursors"]["own"] == cursor(502)

        assert "2 event(s) ingested" in _said(eb)
        assert "7-day retention" in _said(eb), "the poll's last word repeats the reset"
        assert_claims_no_loss_it_cannot_know(_said(eb))
        assert any("retention" in line for line in eb.progress[:-1]), (
            "the progress log says it when it happens"
        )
        assert any("retention" in line for line in eb.warnings), (
            "and so does the app log"
        )

    def test_a_410_is_never_a_silent_empty_poll(self, eb, http):
        """Even when the retained feed has nothing new, the reset is in the
        message: '0 ingested' alone would read as a quiet day."""
        eb.state = {"cursors": {"own": cursor(1, "2026-09-01T00:00:00Z")}}
        http(self._expired(cursor(500)), (200, page([], cursor(500))))
        result = _poll(eb)

        assert result.status is APP_SUCCESS
        assert _said(eb).startswith("0 event(s) ingested. ")
        assert_claims_no_loss_it_cannot_know(_said(eb))
        assert eb.state["cursors"]["own"] == cursor(500), (
            "the reset cursor is persisted even when the page after it is empty, "
            "or every later poll would hit the same 410 and log the same reset"
        )

    def test_a_410_naming_no_retention_still_reads_as_a_sentence(self, eb, http):
        eb.state = {"cursors": {"own": cursor(1)}}
        http(
            action_error(410, "cursor_expired", {"oldest_cursor": cursor(500)}),
            (200, page([], cursor(500))),
        )
        result = _poll(eb)

        assert result.status is APP_SUCCESS
        assert "older than the feed's retention." in _said(eb)
        assert_claims_no_loss_it_cannot_know(_said(eb))

    def test_a_second_410_in_the_same_poll_is_a_failure_not_a_loop(self, eb, http):
        eb.state = {"cursors": {"own": cursor(1)}}
        calls = http(self._expired(cursor(500)))
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert len(calls) == 2
        assert "req-0001" in result.message

    def test_a_410_naming_no_oldest_cursor_fails_loudly(self, eb, http):
        eb.state = {"cursors": {"own": cursor(1)}}
        http(
            action_error(
                410,
                "cursor_expired",
                {"message": "Cursor is older than the feed's retention"},
            )
        )
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert "oldest_cursor" in result.message

    def test_a_cursor_from_another_deployment_restarts_from_the_oldest_event(
        self, eb, http
    ):
        """``cursor_invalid`` is a cursor this EmailBadger never issued — the
        asset was repointed, or the deployment restored. Dropping it restarts
        from the oldest retained event; the dedupe key absorbs any overlap."""
        eb.state = {"cursors": {"own": "bm90LW91cnM"}}
        calls = http(
            action_error(
                400, "cursor_invalid", "Cursor was not issued by this deployment"
            ),
            (200, page([rendered(1)], cursor(1))),
        )
        result = _poll(eb)

        assert result.status is APP_SUCCESS, result.message
        assert "since" not in calls[1]["params"]
        assert "not one this EmailBadger issued" in _said(eb)
        assert eb.state["cursors"]["own"] == cursor(1)


class TestPollNow:
    def test_a_manual_poll_honours_container_count(self, eb, http):
        calls = http((200, page([rendered(1), rendered(2)], cursor(2))))
        result = _poll(eb, {"container_count": 2}, poll_now=True)

        assert calls[0]["params"]["limit"] == 2
        assert len(calls) == 1, "the budget is spent; no second page"
        assert result.status is APP_SUCCESS
        assert len(eb.containers) == 2

    def test_container_count_spans_pages_when_the_page_size_is_smaller(self, eb, http):
        eb.config["poll_page_size"] = 2
        calls = http(
            (200, page([rendered(1), rendered(2)], cursor(2))),
            (200, page([rendered(3)], cursor(3))),
        )
        result = _poll(eb, {"container_count": 3}, poll_now=True)

        assert [c["params"]["limit"] for c in calls] == [2, 1]
        assert result.status is APP_SUCCESS
        assert len(eb.containers) == 3

    def test_a_scheduled_poll_ignores_container_count(self, eb, http):
        calls = http((200, page([], cursor(0))))
        _poll(eb, {"container_count": 1}, poll_now=False)
        assert calls[0]["params"]["limit"] == 100


class TestWhenEmailBadgerRefuses:
    @pytest.mark.parametrize(
        "status, code, detail, expected",
        [
            (
                401,
                "unauthorized",
                "Invalid API key",
                "API key is wrong, revoked, or disabled",
            ),
            (
                402,
                "license_required",
                "Enterprise tier required",
                "requires Enterprise tier",
            ),
            (
                403,
                "api_key_scope_missing",
                scope_refusal("events:read"),
                "lacks the scope this action needs. This API key does not carry the 'events:read' scope",
            ),
            (429, "rate_limited", "Too many requests", "retry after 30 seconds"),
        ],
    )
    def test_the_message_names_the_cause_not_a_bad_key(
        self, eb, http, status, code, detail, expected
    ):
        headers = {"Retry-After": "30"} if status == 429 else {}
        http(action_error(status, code, detail, **headers))
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert expected in result.message, result.message
        assert "req-0001" in result.message

    def test_a_deployment_without_the_feed_is_said_so(self, eb, http):
        http(FakeHTTPResponse(404, {"detail": "Not Found"}))
        result = _poll(eb)
        assert result.status is APP_ERROR
        assert "does not serve /api/v1/events" in result.message

    def test_a_network_failure_is_reported(self, eb, http):
        http(requests.exceptions.ConnectionError("refused"))
        result = _poll(eb)
        assert result.status is APP_ERROR
        assert "Could not reach EmailBadger" in result.message

    def test_a_non_json_200_is_a_failure(self, eb, http):
        http(
            FakeHTTPResponse(
                200,
                headers={"Content-Type": "text/html"},
                content=b"<html>login</html>",
            )
        )
        result = _poll(eb)
        assert result.status is APP_ERROR
        assert "non-JSON" in result.message


class TestWhenSoarRefusesAContainer:
    """A container SOAR refuses stops the poll at that page, and the next poll retries the page.

    The traditional app counted a refused container as failed and saved the
    page's cursor anyway, so the event was never offered again. The SDK fails
    the poll on the first refusal and rolls the ingest state back to its last
    commit; the app commits the cursor once per page, after the page's
    containers are in SOAR, so the pages before stay ingested and the refused
    one comes round again. Its containers already saved are absorbed as
    duplicates on the retry, by event id.
    """

    @staticmethod
    def _refuse(event):
        def outcome(container):
            if container["source_data_identifier"] == event["event_id"]:
                return False, "label 'events' does not exist", None
            return True, "saved", 1

        return outcome

    def test_a_refused_container_fails_the_poll_and_names_the_cause(self, eb, http):
        eb.save_container_outcome = self._refuse(rendered(2))
        http((200, page([rendered(1), rendered(2), rendered(3)], cursor(3))))
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert "does not exist" in result.message

    def test_the_refused_page_is_offered_again(self, eb, http):
        eb.state = {"cursors": {"own": cursor(0)}}
        eb.save_container_outcome = self._refuse(rendered(2))
        http((200, page([rendered(1), rendered(2), rendered(3)], cursor(3))))
        _poll(eb)

        assert eb.state["cursors"]["own"] == cursor(0), (
            "the page's cursor is not saved past an event SOAR refused"
        )

    def test_the_pages_before_stay_ingested(self, eb, http):
        eb.config["poll_page_size"] = 2
        eb.save_container_outcome = self._refuse(rendered(3))
        http(
            (200, page([rendered(1), rendered(2)], cursor(2))),
            (200, page([rendered(3), rendered(4)], cursor(4))),
        )
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert eb.state["cursors"]["own"] == cursor(2), (
            "the first page was saved; only the refused one repeats"
        )

    def test_an_sdk_exception_counts_as_a_failed_save(self, eb, http):
        def boom(container):
            raise RuntimeError("severity must be one of high, medium, low")

        eb.save_container_outcome = boom
        http((200, page([rendered(1)], cursor(1))))
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert "severity must be" in result.message


def test_the_query_string_is_what_the_contract_documents(eb, http):
    """Belt and braces: ``requests`` builds the query from ``params``; this
    pins that nothing else sneaks into it."""
    calls = http((200, page([], cursor(0))))
    eb.state = {"cursors": {"own": cursor(9)}}
    _poll(eb)
    sent = calls[0]["params"]
    assert set(sent) == {"since", "types", "limit"}
    assert parse_qs(urlparse(calls[0]["url"]).query) == {}, (
        "nothing hard-coded into the path"
    )
