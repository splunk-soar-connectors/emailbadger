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
"""The manifest the SDK generates from the app, as SOAR and a playbook author see it.

An SDK app has no hand-written manifest: ``soarapps`` builds it from the
decorators, the parameter classes and the output classes. So the manifest and
the actions can no longer disagree on which actions exist. What can still go
wrong is quieter: an action renamed, a parameter's type or ``contains`` lost,
a summary key a playbook branches on that the manifest does not declare. A
playbook calls an action by its name and chains values by ``contains``, so each
of those breaks a playbook without failing anything else.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from soar_sdk.cli.manifests.processors import ManifestProcessor

from src import api
from src import app as app_module

from . import recorded as r

APP_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def manifest():
    return ManifestProcessor("unused.json", str(APP_DIR)).build().to_json_manifest()


def _action(manifest, identifier):
    return next(a for a in manifest["actions"] if a["identifier"] == identifier)


def _paths(action):
    return {o["data_path"] for o in action["output"]}


#: Every action, by the name a playbook calls it and the identifier SOAR
#: dispatches on, as the traditional app shipped them. ``detonate file``'s
#: identifier is ``analyze_email``; ``soarapps convert`` would have renamed the
#: action after it.
ACTIONS = {
    "test connectivity": "test_connectivity",
    "detonate file": "analyze_email",
    "analyze archive": "analyze_archive",
    "get verdict": "get_verdict",
    "on poll": "on_poll",
    "set verdict": "set_verdict",
    "record block": "record_block",
    "update ticket": "update_ticket",
    "report ticket": "report_ticket",
    "reanalyze": "reanalyze",
    "get job": "get_job",
    "get timeline": "get_timeline",
    "get evidence package": "get_evidence_package",
}


def test_every_action_keeps_its_name_and_identifier(manifest):
    assert {a["action"]: a["identifier"] for a in manifest["actions"]} == ACTIONS


def test_the_app_keeps_its_identity(manifest):
    """A changed ``appid`` or package name installs as a second app beside the first."""
    assert manifest["appid"] == "b8f2e1c4-6a7d-4e9b-9c3f-2d5a8e7b1f04"
    assert manifest["package_name"] == "phantom_emailbadger"
    assert manifest["name"] == "EmailBadger"
    assert manifest["publisher"] == "EmailBadger, LLC"
    assert manifest["main_module"] == "src.app:app"


def test_no_contributors_are_listed(manifest):
    assert not manifest.get("contributors")


def test_test_connectivity_is_present_and_typed(manifest):
    """SOAR requires it, and requires type 'test': an app without it cannot be configured."""
    action = _action(manifest, "test_connectivity")
    assert action["type"] == "test"
    assert action["read_only"] is True


# soar_app_linter.app_validation.REQUIRED_APP_JSON_FIELDS. A manifest missing any
# of them is not recognised as an app at all: the linter reports "no suitable
# app JSON found" and moves on, which reads as a pass.
_LINTER_REQUIRED_FIELDS = (
    "appid",
    "name",
    "description",
    "publisher",
    "package_name",
    "type",
    "main_module",
    "app_version",
    "product_vendor",
    "product_name",
    "product_version_regex",
    "min_phantom_version",
    "logo",
    "configuration",
    "actions",
    "python_version",
)


@pytest.mark.parametrize("field", _LINTER_REQUIRED_FIELDS)
def test_required_manifest_fields_are_present(manifest, field):
    assert manifest.get(field), (
        f"manifest is missing {field!r}, which the SOAR app linter requires"
    )


def test_python_313_is_declared(manifest):
    """SOAR's 2026 platform runs apps on Python 3.13 and fails one that does not declare it."""
    declared = {v.strip() for v in str(manifest["python_version"]).split(",")}
    assert "3.13" in declared


def test_the_api_key_is_declared_as_a_password(manifest):
    """A ``string`` here renders the key in plain text in the asset form and
    stores it unencrypted: the field type IS the protection. ``soarapps
    convert`` dropped it, so it is asserted rather than trusted."""
    assert manifest["configuration"]["api_key"]["data_type"] == "password"


def test_the_archive_password_is_declared_as_a_password(manifest):
    assert (
        _action(manifest, "analyze_archive")["parameters"]["password"]["data_type"]
        == "password"
    )


def test_certificate_verification_defaults_to_on(manifest):
    """An app that ships with verification off makes every deployment insecure by default."""
    assert manifest["configuration"]["verify_server_cert"]["default"] is True


def test_every_logo_the_manifest_references_exists(manifest):
    referenced = {manifest[key] for key in ("logo", "logo_dark") if manifest.get(key)}
    assert referenced, "the manifest declares no logo at all"
    missing = sorted(name for name in referenced if not (APP_DIR / name).is_file())
    assert not missing, f"the manifest references logo(s) that do not exist: {missing}"


def test_the_logo_is_a_parseable_svg_carrying_real_artwork(manifest):
    """The file is a raster in an SVG container; it still has to parse, or the
    catalog shows a broken image and every other check here passes."""
    text = (APP_DIR / manifest["logo"]).read_text()
    root = ET.fromstring(text)
    assert root.tag.endswith("svg"), f"root element is {root.tag!r}, not <svg>"
    assert "base64," in text, (
        "the embedded artwork is gone; the logo would render empty"
    )


def test_the_app_version_moved_with_the_port(manifest):
    major, minor, _patch = (int(part) for part in manifest["app_version"].split("."))
    assert (major, minor) >= (0, 8), (
        "the SDK port changes the app's datapaths; the version moves with it"
    )


class TestTheFeedAndTheActionApi:
    def test_on_poll_is_the_ingest_action(self, manifest):
        on_poll = _action(manifest, "on_poll")
        assert on_poll["action"] == "on poll"
        assert on_poll["type"] == "ingest"
        assert on_poll["read_only"] is True
        assert set(on_poll["parameters"]) == {
            "container_id",
            "start_time",
            "end_time",
            "container_count",
            "artifact_count",
        }, "SOAR passes exactly these to an ingest action"

    def test_the_poll_settings_are_asset_configuration(self, manifest):
        config = manifest["configuration"]
        assert (
            config["poll_event_types"]["default"] == "verdict.rendered,verdict.changed"
        )
        assert config["poll_page_size"]["data_type"] == "numeric"
        assert config["poll_page_size"]["default"] == 100
        assert config["poll_event_types"]["required"] is False
        assert config["poll_page_size"]["required"] is False
        orders = [field["order"] for field in config.values()]
        assert sorted(orders) == list(range(len(orders))), (
            "every setting has its own place in the asset form"
        )

    @pytest.mark.parametrize(
        "identifier",
        [
            "set_verdict",
            "update_ticket",
            "report_ticket",
            "reanalyze",
            "get_timeline",
            "get_evidence_package",
        ],
    )
    def test_every_email_action_takes_the_email_id_get_verdict_and_on_poll_hand_out(
        self, manifest, identifier
    ):
        email_id = _action(manifest, identifier)["parameters"]["email_id"]
        assert email_id["data_type"] == "numeric"
        assert email_id["required"] is True
        assert email_id["contains"] == ["emailbadger email id"]

    def test_get_verdict_hands_out_the_email_id_the_other_actions_take(self, manifest):
        """The SOAR UI chains actions by ``contains``."""
        output = next(
            o
            for o in _action(manifest, "get_verdict")["output"]
            if o["data_path"] == "action_result.data.*.email_id"
        )
        assert output["contains"] == ["emailbadger email id"]

    def test_get_verdict_takes_the_message_id_detonate_file_hands_out(self, manifest):
        get_verdict = _action(manifest, "get_verdict")
        detonate = {
            o["data_path"]: o.get("contains")
            for o in _action(manifest, "analyze_email")["output"]
        }
        assert get_verdict["read_only"] is True
        assert get_verdict["parameters"]["message_id"]["contains"] == [
            "emailbadger message id"
        ]
        assert detonate["action_result.data.*.message_id"] == ["emailbadger message id"]

    def test_set_verdict_offers_only_the_three_verdicts(self, manifest):
        set_verdict = _action(manifest, "set_verdict")
        assert set_verdict["parameters"]["verdict"]["value_list"] == [
            "malicious",
            "suspicious",
            "benign",
        ]
        assert set_verdict["read_only"] is False

    def test_the_writes_mutate_and_the_reads_do_not(self, manifest):
        for identifier in (
            "analyze_email",
            "analyze_archive",
            "set_verdict",
            "record_block",
        ):
            assert _action(manifest, identifier)["read_only"] is False, identifier
        for identifier in ("update_ticket", "report_ticket", "reanalyze"):
            assert _action(manifest, identifier)["read_only"] is False, identifier
        for identifier in (
            "get_verdict",
            "get_job",
            "get_timeline",
            "get_evidence_package",
        ):
            assert _action(manifest, identifier)["read_only"] is True, identifier

    def test_report_ticket_is_the_one_action_that_creates_a_ticket(self, manifest):
        report = _action(manifest, "report_ticket")
        assert report["parameters"]["system"]["required"] is True
        assert report["parameters"]["ticket_id"]["required"] is True
        for optional in ("opened_at", "status", "ticket_url", "idempotency_key"):
            assert report["parameters"][optional]["required"] is False
        # Not on the url right-click menu, as before the SDK port: a ticket link is not an indicator.
        assert "contains" not in report["parameters"]["ticket_url"]
        outputs = {o["data_path"]: o.get("contains") for o in report["output"]}
        assert outputs["action_result.data.*.ticket_url"] == ["url"]
        assert "POST /api/v1/emails/{email_id}/external-tickets" in report["verbose"]
        assert "external_tickets:write" in report["verbose"]
        update = _action(manifest, "update_ticket")["verbose"]
        assert "never creates a ticket" in update
        assert "report ticket" in update

    def test_reanalyze_is_destructive_and_says_so_where_the_analyst_reads(
        self, manifest
    ):
        reanalyze = _action(manifest, "reanalyze")
        assert reanalyze["description"].startswith("DESTRUCTIVE")
        assert "POST /api/v1/emails/{email_id}/reanalyze" in reanalyze["verbose"]
        assert "analysis:write" in reanalyze["verbose"]
        assert "NEW email id" in reanalyze["verbose"]
        assert "deletes the existing analysis" in reanalyze["verbose"]
        assert "run get job with the job id" in reanalyze["verbose"]
        assert {
            "action_result.summary.job_id",
            "action_result.summary.already_running",
            "action_result.data.*.job_id",
        } <= _paths(reanalyze)

    def test_get_job_reads_the_job_reanalyze_hands_out(self, manifest):
        """reanalyze's job id is offered as get job's parameter, and get job's
        new email id is offered to every action that takes an email id."""
        get_job = _action(manifest, "get_job")
        assert get_job["type"] == "investigate"
        assert set(get_job["parameters"]) == {"job_id", "platform_admin_reason"}
        job_id = get_job["parameters"]["job_id"]
        assert job_id["data_type"] == "numeric"
        assert job_id["required"] is True
        handed_out = {
            o["data_path"]: o.get("contains")
            for o in _action(manifest, "reanalyze")["output"]
        }
        assert (
            job_id["contains"]
            == handed_out["action_result.summary.job_id"]
            == ["emailbadger job id"]
        )

        outputs = {o["data_path"]: o.get("contains") for o in get_job["output"]}
        for path in (
            "action_result.summary.new_email_id",
            "action_result.data.*.result.new_email_id",
        ):
            assert outputs[path] == ["emailbadger email id"], (
                f"{path} must chain into the email actions"
            )
        assert "same asset" in get_job["verbose"], (
            "only the key that queued a job can read it"
        )

    def test_record_block_is_a_contain_action_over_the_six_block_types(self, manifest):
        record_block = _action(manifest, "record_block")
        assert record_block["type"] == "contain"
        assert record_block["parameters"]["block_type"]["value_list"] == [
            "sender_address",
            "sender_domain",
            "url",
            "domain",
            "ip",
            "hash",
        ]
        assert record_block["parameters"]["value"]["required"] is True
        assert record_block["parameters"]["never_expires"]["data_type"] == "boolean"
        assert record_block["parameters"]["source_email_id"]["contains"] == [
            "emailbadger email id"
        ]

    def test_record_block_declares_the_three_outcomes_a_playbook_branches_on(
        self, manifest
    ):
        """A guardrail that wants an acknowledgement is a result, not a failure,
        and the manifest has to expose what a playbook branches and re-runs on."""
        record_block = _action(manifest, "record_block")
        assert {
            "action_result.summary.outcome",
            "action_result.summary.written",
            "action_result.summary.acknowledge",
            "action_result.data.*.findings.*.code",
            "action_result.data.*.findings.*.severity",
            "action_result.data.*.badge_state",
            "action_result.data.*.targets.*.status",
        } <= _paths(record_block)
        for outcome in ("written", "acknowledgement_required", "already_blocked"):
            assert outcome in record_block["verbose"], (
                f"the UI help has to name the {outcome} outcome"
            )

    def test_the_timeline_declares_its_entries_and_gaps(self, manifest):
        assert {
            "action_result.data.*.entries.*.at",
            "action_result.data.*.entries.*.kind",
            "action_result.data.*.gaps.*.source",
            "action_result.data.*.gaps.*.reason",
            "action_result.summary.gaps",
        } <= _paths(_action(manifest, "get_timeline"))


#: Each action with the smallest parameters it accepts and a reply that
#: succeeds, to read back the summary it sets.
_SUMMARY_RUNS = {
    "set_verdict": (
        {
            "email_id": 1042,
            "verdict": "malicious",
            "external_actor": "soar",
            "external_reference": "c-1",
        },
        [(200, r.VERDICT_SET)],
    ),
    "record_block": (
        {"block_type": "sender_domain", "value": "sender.example"},
        [(201, r.BLOCK_WRITTEN)],
    ),
    "update_ticket": (
        {
            "email_id": 1042,
            "system": "splunk_soar",
            "ticket_id": "4411",
            "status": "closed",
        },
        [(200, r.TICKET_PATCHED)],
    ),
    "report_ticket": (
        {
            "email_id": 1042,
            "system": "splunk_soar",
            "ticket_id": "4411",
            "opened_at": "2026-10-24T20:00:00Z",
        },
        [(201, r.TICKET_REPORTED)],
    ),
    "reanalyze": ({"email_id": 1042}, [(202, r.REANALYZE_QUEUED)]),
    "get_job": (
        {"job_id": 77},
        [(200, r.job("succeeded", result=r.REANALYSIS_RESULT))],
    ),
    "get_timeline": ({"email_id": 1042}, [(200, r.TIMELINE)]),
}


@pytest.mark.parametrize("identifier", sorted(_SUMMARY_RUNS))
def test_every_summary_key_an_action_sets_is_declared(manifest, eb, http, identifier):
    """A summary key the manifest does not declare is invisible to a playbook author."""
    param, replies = _SUMMARY_RUNS[identifier]
    http(*replies)
    result = eb.run(
        identifier,
        {**param, "target_tenant_id": 7} if identifier != "get_job" else param,
    )
    assert result.status is True, result.message

    declared = {
        o["data_path"].removeprefix("action_result.summary.")
        for o in _action(manifest, identifier)["output"]
        if o["data_path"].startswith("action_result.summary.")
    }
    assert set(result.summary) <= declared, set(result.summary) - declared


#: The routes of these take ``target_tenant_id``; on poll's parameters are fixed
#: by SOAR, so its tenant is the asset's.
TAKES_A_TENANT = {
    "analyze_email",
    "analyze_archive",
    "set_verdict",
    "record_block",
    "update_ticket",
    "report_ticket",
    "reanalyze",
    "get_timeline",
    "get_evidence_package",
    "get_verdict",
}
#: Everything that reaches a customer's records. Not on poll, which uses the asset's.
TAKES_A_REASON = TAKES_A_TENANT | {"get_job"}


class TestTheTenantAndTheReason:
    def test_the_asset_carries_an_optional_numeric_tenant_and_string_reason(
        self, manifest
    ):
        config = manifest["configuration"]
        assert config["target_tenant_id"]["data_type"] == "numeric"
        assert config["target_tenant_id"]["required"] is False
        assert config["platform_admin_reason"]["data_type"] == "string"
        assert config["platform_admin_reason"]["required"] is False

    @pytest.mark.parametrize("identifier", sorted(TAKES_A_TENANT))
    def test_each_action_that_sends_a_tenant_declares_it(self, manifest, identifier):
        action = _action(manifest, identifier)
        param = action["parameters"]["target_tenant_id"]
        assert param["data_type"] == "numeric"
        assert param["required"] is False
        assert param["contains"] == ["emailbadger tenant id"], (
            "a polled container's emailbadgerTenantId is a pick"
        )
        assert {
            "action_result.parameter.target_tenant_id",
            "action_result.summary.target_tenant_id",
            "action_result.summary.refusal",
        } <= _paths(action)

    @pytest.mark.parametrize("identifier", sorted(TAKES_A_REASON))
    def test_each_action_that_reads_a_customer_declares_the_reason_last(
        self, manifest, identifier
    ):
        action = _action(manifest, identifier)
        param = action["parameters"]["platform_admin_reason"]
        assert param["data_type"] == "string"
        assert param["required"] is False
        orders = {name: p["order"] for name, p in action["parameters"].items()}
        assert sorted(orders.values()) == list(range(len(orders)))
        assert orders["platform_admin_reason"] == len(orders) - 1, (
            "the reason comes last in the form"
        )
        assert "action_result.summary.refusal" in _paths(action)

    def test_nothing_else_declares_them(self, manifest):
        tenant = {
            a["identifier"]
            for a in manifest["actions"]
            if "target_tenant_id" in a["parameters"]
        }
        reason = {
            a["identifier"]
            for a in manifest["actions"]
            if "platform_admin_reason" in a["parameters"]
        }
        assert tenant == TAKES_A_TENANT
        assert reason == TAKES_A_REASON

    def test_every_action_settles_them_before_it_calls(self):
        """Each action resolves its tenant (and with it, its reason) through
        ``Run.target_tenant``, or its reason alone through ``Run.settle_reason``."""
        source = Path(app_module.__file__).read_text()
        for identifier in TAKES_A_REASON | {"test_connectivity", "on_poll"}:
            body = source.split(f"\ndef {identifier}(", 1)[1].split("\n@app.", 1)[0]
            assert "run.target_tenant(" in body or "run.settle_reason(" in body, (
                identifier
            )
        assert api.Run.target_tenant.__doc__
