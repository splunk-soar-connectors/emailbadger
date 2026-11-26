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
"""The asset, and each action's parameters, output and summary.

Outputs and summaries are ``PermissiveActionOutput``: the declared fields are
the datapaths a playbook sees, and the data itself is EmailBadger's answer as
it came, so a field EmailBadger adds reaches the playbook without a release of
this app. Every field is optional because EmailBadger sends ``null`` for what
it does not know yet.

Numeric ids are ``float`` parameters, as SOAR's ``numeric`` type arrives, and
are judged as whole numbers inside the action: a ``5.7`` is refused with a
message naming the parameter, where a stricter type would fail before the
action could say which one.
"""

from types import NoneType, UnionType
from typing import Any, Union, get_args, get_origin

from pydantic import model_validator
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.params import Param, Params

from .consts import BLOCK_TYPES, DEFAULT_EVENT_TYPES, DEFAULT_PAGE_SIZE, VERDICTS


class Asset(BaseAsset):
    """The asset's configuration. A cleared numeric field is ``""``, which means "not set"."""

    @model_validator(mode="before")
    @classmethod
    def _blank_means_not_given(cls, values: Any) -> Any:
        return _blank_means_not_given(cls, values)

    base_url: str = AssetField(
        description="EmailBadger base URL (e.g. https://emailbadger.example.com)"
    )
    api_key: str = AssetField(
        description="API key (eb_...). Enterprise tier or above.", sensitive=True
    )
    verify_server_cert: bool | None = AssetField(
        description="Verify server certificate", default=True
    )
    poll_event_types: str | None = AssetField(
        description=(
            "Event types on poll ingests, comma-separated (default verdict.rendered,verdict.changed; "
            "add verdicts.bulk_rescored for re-score runs)"
        ),
        default=DEFAULT_EVENT_TYPES,
        category=FieldCategory.INGEST,
    )
    poll_page_size: float | None = AssetField(
        description="Events fetched per request on poll (1-500)",
        default=DEFAULT_PAGE_SIZE,
        category=FieldCategory.INGEST,
    )
    target_tenant_id: float | None = AssetField(
        description=(
            "Customer tenant this asset acts for (target_tenant_id; a Platform Admin's key only). Leave blank "
            "for the key's own tenant. The action parameter of the same name overrides it."
        ),
    )
    platform_admin_reason: str | None = AssetField(
        description=(
            "Why a Platform Admin's key loads a customer's records, 5 to 500 characters, recorded in the "
            "customer's audit log (X-Platform-Admin-Reason). An installation that separates tenants refuses "
            "those reads without one, on poll included. The action parameter of the same name overrides it."
        ),
    )


# -- shared parameter and output pieces ---------------------------------------

TENANT_DESCRIPTION = (
    "Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). "
    "Overrides the asset's setting; blank means the asset's, or the key's own tenant."
)
REASON_DESCRIPTION = (
    "Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the "
    "customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's "
    "key's call that loads a customer's records is refused without one."
)
EMAIL_ID_DESCRIPTION = (
    "EmailBadger's numeric id of the email (email_id from get verdict, or emailbadgerEmailId on a polled "
    "container's artifact)"
)
KEY_DESCRIPTION = (
    "Idempotency-Key for a replayed answer within 24 hours; not sent when left blank. A key replays the "
    "first answer for every later call that sends it, so use a new one for each intended write"
)


def _base_type(annotation: Any) -> Any:
    """``float`` for ``float | None``, and so on; the annotation itself otherwise."""
    if get_origin(annotation) in (Union, UnionType):
        args = [arg for arg in get_args(annotation) if arg is not NoneType]
        return args[0] if len(args) == 1 else annotation
    return annotation


def _blank_means_not_given(model: Any, values: Any) -> Any:
    """``""`` in a field that is not text means "not given"; ``True`` is never a number.

    SOAR hands a cleared optional field over as ``""``, which pydantic would
    refuse as not a number before the action could run. Only the empty string
    counts: whitespace is refused, as it always was, because a playbook that
    renders a missing tenant as a space must not fall back to another tenant.
    A ``True`` in a numeric field would be read as 1, which for
    ``target_tenant_id`` is a real tenant, so it is refused.
    """
    if not isinstance(values, dict):
        return values
    values = dict(values)
    for name, field in model.model_fields.items():
        key = field.alias or name
        if key not in values:
            continue
        base = _base_type(field.annotation)
        raw = values[key]
        if base is not str and raw == "":
            values[key] = None
        elif base is float and isinstance(raw, bool):
            raise ValueError(f"{key} must be a number, got {raw!r}")
    return values


class EmailBadgerParams(Params):
    """Parameters as SOAR and playbooks hand them over (see ``_blank_means_not_given``)."""

    @model_validator(mode="before")
    @classmethod
    def _blank_means_not_given(cls, values: Any) -> Any:
        return _blank_means_not_given(cls, values)


class Summary(PermissiveActionOutput):
    """What every action's summary may carry."""

    total_objects: int | None = None
    target_tenant_id: int | None = OutputField(cef_types=["emailbadger tenant id"])
    refusal: str | None = OutputField(
        example_values=[
            "tenant_not_separated",
            "tenant_not_own",
            "tenant_not_found",
            "tenant_ambiguous",
            "soar_writeback_off",
            "analysis_cross_tenant",
            "operator_reason_required",
        ]
    )


# -- test connectivity --------------------------------------------------------
# No parameters and no output: the SDK's own test connectivity decorator.


# -- detonate file ------------------------------------------------------------


class DetonateFileParams(EmailBadgerParams):
    vault_id: str = Param(
        description="Vault ID of the .eml file to submit",
        primary=True,
        cef_types=["vault id"],
    )
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class DetonateFileOutput(PermissiveActionOutput):
    status: str | None = OutputField(example_values=["processed", "duplicate"])
    message_id: str | None = OutputField(cef_types=["emailbadger message id"])
    subject: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    verdict: str | None = None
    verdict_confidence: str | None = None


class DetonateFileSummary(Summary):
    risk_level: str | None = None


# -- analyze archive ----------------------------------------------------------


class AnalyzeArchiveParams(EmailBadgerParams):
    vault_id: str = Param(
        description="Vault ID of the .zip archive to submit",
        primary=True,
        cef_types=["vault id"],
    )
    password: str | None = Param(
        description="Password for an encrypted archive", sensitive=True
    )
    skip_ai_analysis: bool | None = Param(
        description="Bypass the LLM analysis pipeline for every email in the archive",
        default=False,
    )
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class ArchiveResult(PermissiveActionOutput):
    message_id: str | None = None
    subject: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None


class ArchiveError(PermissiveActionOutput):
    filename: str | None = None
    error: str | None = None


class AnalyzeArchiveOutput(PermissiveActionOutput):
    processed: int | None = None
    duplicates: int | None = None
    errors: int | None = None
    results: list[ArchiveResult] | None = None
    error_details: list[ArchiveError] | None = None


class AnalyzeArchiveSummary(Summary):
    processed: int | None = None
    duplicates: int | None = None
    errors: int | None = None


# -- get verdict --------------------------------------------------------------


class GetVerdictParams(EmailBadgerParams):
    message_id: str = Param(
        description="Message-ID of the submitted email, angle brackets included, as detonate file returned it",
        primary=True,
        cef_types=["emailbadger message id"],
    )
    target_tenant_id: float | None = Param(
        description=(
            "Customer tenant to read (a Platform Admin's key only; emailbadgerTenantId on a polled container). "
            "Overrides the asset's setting; blank means the asset's, or whichever one tenant holds that Message-ID."
        ),
        cef_types=["emailbadger tenant id"],
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class GetVerdictOutput(PermissiveActionOutput):
    email_id: int | None = OutputField(cef_types=["emailbadger email id"])
    message_id: str | None = OutputField(cef_types=["emailbadger message id"])
    verdict: str | None = None
    confidence: float | None = None
    confidence_label: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    coverage_complete: bool | None = None


class GetVerdictSummary(Summary):
    verdict: str | None = None
    risk_level: str | None = None
    coverage_complete: bool | None = None


# -- set verdict --------------------------------------------------------------


class SetVerdictParams(EmailBadgerParams):
    email_id: float = Param(
        description=EMAIL_ID_DESCRIPTION,
        primary=True,
        cef_types=["emailbadger email id"],
    )
    verdict: str = Param(description="The verdict to set", value_list=list(VERDICTS))
    external_actor: str = Param(
        description="Who decided, as EmailBadger should record it (a playbook or analyst name)"
    )
    external_reference: str = Param(
        description="Where the decision lives in SOAR (container or case id, or a URL)"
    )
    reason: str | None = Param(
        description="Why, up to 500 characters (recorded with the verdict)"
    )
    idempotency_key: str | None = Param(description=KEY_DESCRIPTION)
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class SetVerdictOutput(PermissiveActionOutput):
    changed: bool | None = None
    previous: str | None = None
    current: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    verdict_events: int | None = None
    external_actor: str | None = None
    external_reference: str | None = None


class SetVerdictSummary(Summary):
    changed: bool | None = None
    previous: str | None = None
    current: str | None = None
    risk_level: str | None = None
    replayed: bool | None = None
    idempotency_key: str | None = None


# -- record block -------------------------------------------------------------


class RecordBlockParams(EmailBadgerParams):
    block_type: str = Param(
        description="What kind of indicator value is",
        primary=True,
        value_list=list(BLOCK_TYPES),
    )
    value: str = Param(
        description="The indicator to block (an address, domain, URL, IP or file hash)",
        primary=True,
        cef_types=["email", "domain", "url", "ip", "hash"],
    )
    reason: str | None = Param(
        description="Why, as the next analyst should read it on the block list"
    )
    source_email_id: float | None = Param(
        description=(
            "EmailBadger's numeric id of the email the indicator came from (enables the would-have-caught "
            "and DMARC guardrails)"
        ),
        cef_types=["emailbadger email id"],
    )
    expires_in_days: float | None = Param(
        description="Days until the block expires; the install default (30 unless changed) when blank"
    )
    never_expires: bool | None = Param(
        description="Block permanently (not with expires_in_days)", default=False
    )
    acknowledge: str | None = Param(
        description=(
            "Comma-separated guardrail finding codes this playbook accepts; pass summary.acknowledge from an "
            "acknowledgement_required result"
        )
    )
    idempotency_key: str | None = Param(description=KEY_DESCRIPTION)
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class BlockTarget(PermissiveActionOutput):
    target: str | None = None
    status: str | None = None
    detail: str | None = None


class BlockFinding(PermissiveActionOutput):
    code: str | None = None
    severity: str | None = None
    message: str | None = None


class RecordBlockOutput(PermissiveActionOutput):
    id: int | None = None
    block_type: str | None = None
    value: str | None = None
    reason: str | None = None
    created_by: str | None = None
    created_at: str | None = None
    expires_at: str | None = None
    source_email_id: int | None = OutputField(cef_types=["emailbadger email id"])
    fleet: bool | None = None
    badge_state: str | None = None
    targets: list[BlockTarget] | None = None
    findings: list[BlockFinding] | None = None
    acknowledge: str | None = None


class RecordBlockSummary(Summary):
    outcome: str | None = OutputField(
        example_values=["written", "acknowledgement_required", "already_blocked"]
    )
    written: bool | None = None
    block_id: int | None = None
    badge_state: str | None = None
    expires_at: str | None = None
    targets: int | None = None
    acknowledge: str | None = None
    findings: int | None = None
    replayed: bool | None = None
    idempotency_key: str | None = None


# -- update ticket and report ticket ------------------------------------------


class UpdateTicketParams(EmailBadgerParams):
    email_id: float = Param(
        description=EMAIL_ID_DESCRIPTION,
        primary=True,
        cef_types=["emailbadger email id"],
    )
    system: str = Param(
        description=(
            "Ticketing system the ticket lives in, as EmailBadger knows it (e.g. splunk_soar, jira, servicenow)"
        )
    )
    ticket_id: str = Param(description="The ticket's id in that system")
    status: str | None = Param(description="New status, up to 64 characters")
    ticket_url: str | None = Param(description="Link to the ticket")
    opened_at: str | None = Param(description="When the ticket was opened, RFC 3339")
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class ReportTicketParams(EmailBadgerParams):
    email_id: float = Param(
        description=EMAIL_ID_DESCRIPTION,
        primary=True,
        cef_types=["emailbadger email id"],
    )
    system: str = Param(
        description=(
            "Ticketing system the ticket lives in, up to 64 characters (e.g. splunk_soar, jira, servicenow). "
            "Use the same name each time: it is part of the ticket's identity"
        )
    )
    ticket_id: str = Param(
        description="The ticket's id in that system, up to 255 characters"
    )
    opened_at: str | None = Param(
        description="When the ticket was opened, RFC 3339. Required the first time a ticket is reported"
    )
    ticket_url: str | None = Param(
        description="Link to the ticket, http or https, up to 2048 characters",
    )
    status: str | None = Param(description="The ticket's status, up to 64 characters")
    idempotency_key: str | None = Param(
        description=(
            "Idempotency-Key for a replayed answer within 24 hours; not sent when left blank, because the "
            "route is already idempotent on system and ticket id"
        )
    )
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class TicketOutput(PermissiveActionOutput):
    id: int | None = None
    email_id: int | None = OutputField(cef_types=["emailbadger email id"])
    system: str | None = None
    ticket_id: str | None = None
    ticket_url: str | None = OutputField(cef_types=["url"])
    opened_at: str | None = None
    status: str | None = None
    status_reported_at: str | None = None
    last_reported_at: str | None = None


class UpdateTicketSummary(Summary):
    created: bool | None = None
    status: str | None = None
    ticket_url: str | None = OutputField(cef_types=["url"])


class ReportTicketSummary(UpdateTicketSummary):
    replayed: bool | None = None


# -- reanalyze and get job ----------------------------------------------------


class ReanalyzeParams(EmailBadgerParams):
    email_id: float = Param(
        description=EMAIL_ID_DESCRIPTION,
        primary=True,
        cef_types=["emailbadger email id"],
    )
    idempotency_key: str | None = Param(
        description=(
            "Idempotency-Key for a replayed answer within 24 hours; not sent when left blank. Leave it blank "
            "to re-analyse the same email again after an earlier job has settled"
        )
    )
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class ReanalyzeOutput(PermissiveActionOutput):
    job_id: int | None = OutputField(cef_types=["emailbadger job id"])
    status: str | None = None
    already_running: bool | None = None


class ReanalyzeSummary(Summary):
    job_id: int | None = OutputField(cef_types=["emailbadger job id"])
    status: str | None = None
    already_running: bool | None = None
    replayed: bool | None = None


class GetJobParams(EmailBadgerParams):
    job_id: float = Param(
        description="The job id reanalyze returned (job_id in its result and summary)",
        primary=True,
        cef_types=["emailbadger job id"],
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class JobResult(PermissiveActionOutput):
    status: str | None = None
    message_id: str | None = OutputField(cef_types=["emailbadger message id"])
    old_email_id: int | None = OutputField(cef_types=["emailbadger email id"])
    new_email_id: int | None = OutputField(cef_types=["emailbadger email id"])
    old_score: float | None = None
    new_score: float | None = None
    old_verdict: str | None = None
    new_verdict: str | None = None
    old_risk_level: str | None = None
    new_risk_level: str | None = None


class GetJobOutput(PermissiveActionOutput):
    id: int | None = OutputField(cef_types=["emailbadger job id"])
    kind: str | None = None
    status: str | None = None
    settled: bool | None = None
    error: str | None = None
    created_at: str | None = None
    finished_at: str | None = None
    result: JobResult | None = None


class GetJobSummary(Summary):
    job_id: int | None = OutputField(cef_types=["emailbadger job id"])
    status: str | None = None
    settled: bool | None = None
    new_email_id: int | None = OutputField(cef_types=["emailbadger email id"])
    new_verdict: str | None = None
    new_score: float | None = None


# -- get timeline -------------------------------------------------------------


class EmailIdParams(EmailBadgerParams):
    email_id: float = Param(
        description=EMAIL_ID_DESCRIPTION,
        primary=True,
        cef_types=["emailbadger email id"],
    )
    target_tenant_id: float | None = Param(
        description=TENANT_DESCRIPTION, cef_types=["emailbadger tenant id"]
    )
    platform_admin_reason: str | None = Param(description=REASON_DESCRIPTION)


class TimelineEmail(PermissiveActionOutput):
    id: int | None = OutputField(cef_types=["emailbadger email id"])
    message_id: str | None = OutputField(cef_types=["emailbadger message id"])
    sender: str | None = OutputField(cef_types=["email"])
    recipient: str | None = OutputField(cef_types=["email"])
    subject: str | None = None


class TimelineEntry(PermissiveActionOutput):
    at: str | None = None
    kind: str | None = None
    source: str | None = None
    detail: str | None = None


class TimelineGap(PermissiveActionOutput):
    source: str | None = None
    reason: str | None = None


class GetTimelineOutput(PermissiveActionOutput):
    email: TimelineEmail | None = None
    entries: list[TimelineEntry] | None = None
    gaps: list[TimelineGap] | None = None
    total: int | None = None


class GetTimelineSummary(Summary):
    total: int | None = None
    gaps: int | None = None


# -- get evidence package -----------------------------------------------------


class GetEvidencePackageOutput(PermissiveActionOutput):
    vault_id: str | None = OutputField(cef_types=["vault id"])
    file_name: str | None = OutputField(cef_types=["file name"])
    size: int | None = None
    manifest_sha256: str | None = OutputField(cef_types=["sha256"])
    email_id: int | None = OutputField(cef_types=["emailbadger email id"])


class GetEvidencePackageSummary(Summary):
    vault_id: str | None = OutputField(cef_types=["vault id"])
    size: int | None = None
    manifest_sha256: str | None = OutputField(cef_types=["sha256"])
