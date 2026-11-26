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
"""``target_tenant_id`` — acting for a customer tenant.

An MSSP runs one SOAR across many customers. The core lets a Platform Admin's key name
the customer on every call (``?target_tenant_id=``, the SOAR contract's
"Acting for a tenant"), and refuses in
seven distinct ways. Three properties are load-bearing here:

- the tenant goes on **every** route that takes it — the poll and each action —
  and on none when it is not set, so a key bound to one tenant works as before;
- a refusal is **named**, never a generic failure: a customer who turned SOAR
  write-back off and a typo in a tenant id need different people to act, and
  "No such tenant." is a 404 that must not read as the tier gate;
- the feed cursor is bound to its tenant (another tenant's cursor is a 400), so
  the asset keeps one cursor per tenant and never sends one across.
"""

from __future__ import annotations

import pytest

from .fakes import APP_ERROR, APP_SUCCESS, action_error, refused_by_validation
from .recorded import (
    BLOCK_WRITTEN,
    REANALYZE_QUEUED,
    TICKET_PATCHED,
    TICKET_REPORTED,
    TIMELINE,
    VERDICT_SET,
    cursor,
    page,
    rendered,
)

TENANT = "target_tenant_id"

# Each action that takes a tenant, with the smallest parameters it accepts and a
# reply that succeeds. get verdict is deliberately absent: its route takes none.
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
}

# The contract's refusals, exactly as the core sends them, and the name the pack
# gives each in ``summary.refusal``.
REFUSALS = [
    (
        400,
        "bad_request",
        "This install does not separate tenants, so a target tenant cannot be chosen.",
        "tenant_not_separated",
    ),
    (403, "forbidden", "You cannot act in another tenant.", "tenant_not_own"),
    (404, "not_found", "No such tenant.", "tenant_not_found"),
    (
        403,
        "soar_writeback_off",
        "SOAR write-back is turned off for this tenant.",
        "soar_writeback_off",
    ),
    (
        403,
        "analysis_cross_tenant",
        "A re-analysis must run in the email's own tenant.",
        "analysis_cross_tenant",
    ),
]


def _act(eb, identifier, **extra):
    base, _ = ACTIONS[identifier]
    eb.run(identifier, {**base, **extra})
    return eb.results[-1]


def _poll(eb):
    eb.poll_now = False
    eb.run("on_poll", {})
    return eb.results[-1]


def _asset_tenant(eb, value):
    eb.config[TENANT] = value


class TestEveryActionNamesTheTenant:
    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_the_action_parameter_goes_as_target_tenant_id(self, eb, http, identifier):
        calls = http((200, ACTIONS[identifier][1]))
        result = _act(eb, identifier, target_tenant_id=7)

        assert calls[0]["params"][TENANT] == 7
        assert result.summary[TENANT] == 7, (
            "a playbook acting for many customers sees which one"
        )

    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_the_asset_setting_goes_when_the_action_names_none(
        self, eb, http, identifier
    ):
        _asset_tenant(eb, 9)
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier)

        assert calls[0]["params"][TENANT] == 9

    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_the_action_parameter_overrides_the_asset(self, eb, http, identifier):
        _asset_tenant(eb, 9)
        calls = http((200, ACTIONS[identifier][1]))
        _act(eb, identifier, target_tenant_id="12")

        assert calls[0]["params"][TENANT] == 12

    @pytest.mark.parametrize("identifier", ACTIONS)
    def test_no_tenant_sends_no_parameter(self, eb, http, identifier):
        """A key bound to one tenant must behave exactly as before this change."""
        calls = http((200, ACTIONS[identifier][1]))
        result = _act(eb, identifier)

        assert TENANT not in (calls[0].get("params") or {})
        assert TENANT not in result.summary

    def test_the_evidence_package_names_it_too(self, eb, http):
        calls = http(action_error(404, "not_found", "No such tenant."))
        eb.run("get_evidence_package", {"email_id": 1042, TENANT: 7})

        assert calls[0]["params"][TENANT] == 7

    @pytest.mark.parametrize("raw", [0, -3, 5.5])
    def test_a_value_that_is_not_a_tenant_id_is_refused_before_any_call(
        self, eb, http, raw
    ):
        calls = http((200, VERDICT_SET))
        result = _act(eb, "set_verdict", target_tenant_id=raw)

        assert result.status is APP_ERROR
        assert "target_tenant_id (action parameter)" in result.message
        assert calls == [], "a truncated 5.5 would have acted in tenant 5"

    @pytest.mark.parametrize("raw", ["five", "5x", True])
    def test_a_value_that_is_not_a_number_never_reaches_the_action(self, eb, http, raw):
        """``True`` above all: read as a number it is 1, a real tenant."""
        calls = http((200, VERDICT_SET))
        assert refused_by_validation(
            _act(eb, "set_verdict", target_tenant_id=raw), "target_tenant_id"
        )
        assert calls == []

    def test_a_bad_asset_setting_says_it_is_the_asset(self, eb, http):
        _asset_tenant(eb, 5.5)
        http((200, VERDICT_SET))
        result = _act(eb, "set_verdict")

        assert result.status is APP_ERROR
        assert "target_tenant_id (asset setting)" in result.message

    @pytest.mark.parametrize("raw", [5.0, "5", " 5 "])
    def test_soar_and_playbook_spellings_of_a_whole_number_are_accepted(
        self, eb, http, raw
    ):
        calls = http((200, VERDICT_SET))
        _act(eb, "set_verdict", target_tenant_id=raw)

        assert calls[0]["params"][TENANT] == 5

    @pytest.mark.parametrize("raw", [" ", "   "])
    def test_a_blank_that_is_not_empty_is_refused_rather_than_falling_back(
        self, eb, http, raw
    ):
        """A playbook that renders a missing tenant as a space named no tenant on
        purpose: falling back to the asset's would act in one it never named."""
        _asset_tenant(eb, 9)
        calls = http((200, VERDICT_SET))
        assert refused_by_validation(
            _act(eb, "set_verdict", target_tenant_id=raw), "target_tenant_id"
        )
        assert calls == []

    def test_an_empty_action_parameter_means_the_assets_tenant(self, eb, http):
        _asset_tenant(eb, 9)
        calls = http((200, VERDICT_SET))
        _act(eb, "set_verdict", target_tenant_id="")

        assert calls[0]["params"][TENANT] == 9

    @pytest.mark.parametrize("field", ["target_tenant_id", "poll_page_size"])
    def test_a_cleared_numeric_asset_field_means_not_set(self, eb, http, field):
        """SOAR hands a cleared field over as ``""``; refusing it would break every action."""
        eb.config[field] = ""
        calls = http((200, VERDICT_SET))
        result = _act(eb, "set_verdict")

        assert result.status is APP_SUCCESS
        assert TENANT not in (calls[0].get("params") or {})


class TestAPlaybookKeyIsNotTouchedByTheTenant:
    """The Idempotency-Key belongs to the API key, and a repeat naming another
    tenant is a 409. No key is derived any more, so two tenants'
    identical writes cannot collide unless the playbook sends one key for both."""

    @pytest.mark.parametrize(
        "identifier,answer",
        [("record_block", (201, BLOCK_WRITTEN)), ("set_verdict", (200, VERDICT_SET))],
    )
    def test_no_key_goes_out_for_either_tenant(self, eb, http, identifier, answer):
        calls = http(answer)
        _act(eb, identifier, target_tenant_id=7)
        _act(eb, identifier, target_tenant_id=8)

        assert all("Idempotency-Key" not in (c.get("headers") or {}) for c in calls)
        assert [c["params"][TENANT] for c in calls] == [7, 8]

    def test_the_playbooks_key_goes_out_as_given(self, eb, http):
        calls = http((200, VERDICT_SET))
        _act(eb, "set_verdict", target_tenant_id=7, idempotency_key="pb-7")

        assert calls[0]["headers"]["Idempotency-Key"] == "pb-7"


class TestRefusalsAreNamed:
    @pytest.mark.parametrize(
        "status,code,detail,name", REFUSALS, ids=[r[3] for r in REFUSALS]
    )
    def test_each_refusal_is_named_in_the_summary(
        self, eb, http, status, code, detail, name
    ):
        http(action_error(status, code, detail, request_id="req-77"))
        result = _act(eb, "reanalyze", target_tenant_id=7)

        assert result.status is APP_ERROR, "nothing was written"
        assert result.summary["refusal"] == name
        assert "req-77" in result.message

    def test_writeback_off_says_whose_switch_it_is(self, eb, http):
        http(
            action_error(
                403,
                "soar_writeback_off",
                "SOAR write-back is turned off for this tenant.",
            )
        )
        result = _act(eb, "set_verdict", target_tenant_id=7)

        assert "tenant 7" in result.message
        assert "SOAR write-back allowed" in result.message

    def test_an_unknown_tenant_is_not_reported_as_a_missing_email(self, eb, http):
        """Both are 404s on the same route; only one is about the email."""
        http(action_error(404, "not_found", "No such tenant."))
        result = _act(eb, "get_timeline", target_tenant_id=999)

        assert result.summary["refusal"] == "tenant_not_found"
        assert "No EmailBadger tenant has id 999" in result.message

    def test_an_ordinary_403_is_not_mistaken_for_a_tenant_refusal(self, eb, http):
        http(action_error(403, "forbidden", "This API key lacks the soar:write scope."))
        result = _act(eb, "set_verdict", target_tenant_id=7)

        assert result.status is APP_ERROR
        assert "refusal" not in result.summary

    @pytest.mark.parametrize(
        "status,code,detail,name", REFUSALS[:3], ids=[r[3] for r in REFUSALS[:3]]
    )
    def test_the_upload_routes_name_them_too(
        self, eb, vault, responses, status, code, detail, name
    ):
        vault()
        captured = responses(status, {"detail": detail})
        eb.run("analyze_archive", {"vault_id": "vault-id-1", TENANT: 7})
        result = eb.results[-1]

        assert captured["params"] == {TENANT: 7}
        assert result.summary["refusal"] == name

    def test_detonate_file_sends_the_tenant(self, eb, vault, responses):
        vault(name="msg.eml", content=b"From: a@b\r\n\r\nhi")
        captured = responses(
            200, {"message": "ok", "risk_score": 1, "risk_level": "low"}
        )
        eb.run("analyze_email", {"vault_id": "vault-id-1", TENANT: 7})

        assert captured["params"] == {TENANT: 7}


class TestConnectivity:
    def test_the_asset_tenant_is_tested(self, eb, responses):
        _asset_tenant(eb, 7)
        captured = responses(422, {"detail": "file required"})
        eb.run("test_connectivity", {})

        assert captured["params"] == {TENANT: 7}
        assert eb.results[-1].status is APP_SUCCESS

    def test_no_such_tenant_is_not_the_tier_gate(self, eb, responses):
        """A 404 either way. Reporting a typo as unlicensed sends the analyst
        to the licence."""
        _asset_tenant(eb, 999)
        responses(404, {"detail": "No such tenant."})
        eb.run("test_connectivity", {})
        result = eb.results[-1]

        assert result.status is APP_ERROR
        assert "No EmailBadger tenant has id 999" in result.message, (
            "named, not reported as the tier gate"
        )
        assert "Enterprise tier" not in result.message


class TestThePollIsPerTenant:
    def test_the_asset_tenant_goes_on_every_feed_request(self, eb, http):
        _asset_tenant(eb, 7)
        calls = http((200, page([rendered(1)], cursor(1))), (200, page([], cursor(1))))
        _poll(eb)
        _poll(eb)

        assert all(call["params"][TENANT] == 7 for call in calls)

    def test_no_tenant_sends_no_parameter(self, eb, http):
        calls = http((200, page([], cursor(0))))
        _poll(eb)

        assert TENANT not in calls[0]["params"]

    def test_each_tenant_keeps_its_own_cursor(self, eb, http):
        """The core refuses a cursor sent with another tenant (400
        cursor_invalid); re-pointing an asset must not send the old one."""
        _asset_tenant(eb, 7)
        http((200, page([rendered(1)], cursor(1))))
        _poll(eb)

        _asset_tenant(eb, 8)
        calls = http((200, page([], cursor(50))))
        _poll(eb)

        assert calls[-1]["params"][TENANT] == 8
        assert "since" not in calls[-1]["params"], "tenant 7's cursor went to tenant 8"
        assert eb.state["cursors"] == {"7": cursor(1), "8": cursor(50)}

        _asset_tenant(eb, 7)
        calls = http((200, page([], cursor(1))))
        _poll(eb)
        assert calls[-1]["params"]["since"] == cursor(1), (
            "switching back resumes, not restarts"
        )

    def test_the_own_tenants_cursor_is_never_sent_for_another(self, eb, http):
        eb.state = {"cursors": {"own": cursor(4)}}
        _asset_tenant(eb, 7)
        calls = http((200, page([], cursor(60))))
        _poll(eb)

        assert "since" not in calls[0]["params"], (
            "a cursor of the key's own feed is not tenant 7's"
        )
        assert eb.state["cursors"] == {"own": cursor(4), "7": cursor(60)}

    def test_cursor_invalid_resets_only_that_tenants_cursor(self, eb, http):
        eb.state = {"cursors": {"own": cursor(4), "7": "bm90LW91cnM"}}
        _asset_tenant(eb, 7)
        http(
            action_error(
                400, "cursor_invalid", "That cursor was not issued for this feed."
            ),
            (200, page([], cursor(1))),
        )
        _poll(eb)

        assert eb.state["cursors"] == {"own": cursor(4), "7": cursor(1)}

    def test_a_tenant_refusal_on_the_feed_is_named_and_keeps_the_cursor(self, eb, http):
        eb.state = {"cursors": {"7": cursor(3)}}
        _asset_tenant(eb, 7)
        http(action_error(403, "forbidden", "You cannot act in another tenant."))
        result = _poll(eb)

        assert result.status is APP_ERROR
        assert (
            "bound to one tenant and target_tenant_id names another (7)"
            in result.message
        )
        assert eb.state["cursors"] == {"7": cursor(3)}

    def test_the_container_carries_the_envelope_tenant(self, eb, http):
        event = rendered(1)
        event["tenant"] = {"id": 7, "name": "Acme Corp"}
        http((200, page([event], cursor(1))))
        _poll(eb)

        cef = eb.containers[0]["artifacts"][0]["cef"]
        assert cef["emailbadgerTenantId"] == 7
        assert cef["emailbadgerTenantName"] == "Acme Corp"
        assert eb.containers[0]["artifacts"][0]["cef_types"]["emailbadgerTenantId"] == [
            "emailbadger tenant id"
        ]
