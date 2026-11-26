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
"""Splunk SOAR app for EmailBadger.

**Outbound** (SOAR asks EmailBadger): ``test connectivity``, ``detonate file``,
``analyze archive`` and ``get verdict`` ride the programmatic upload surface and
the verdict read (``GET /api/v1/verdicts``). ``set verdict``, ``update ticket``,
``get timeline`` and ``get evidence package`` are the SOAR action API: key-only
routes under ``/api/v1/emails/{email_id}/...``; ``record block`` is its sibling
``POST /api/v1/blocks``; ``report ticket`` is ``POST
/api/v1/emails/{email_id}/external-tickets`` and ``reanalyze`` is ``POST
/api/v1/emails/{email_id}/reanalyze``, whose outcome ``get job`` reads from
``GET /api/v1/api-upload/jobs/{job_id}``.

**Inbound** (EmailBadger tells SOAR): ``on poll`` reads the verdict event feed
and saves one container per event (see ``feed.py``).

How an action talks to EmailBadger, acts for a tenant and fails is in
``api.py``. This module is the actions' decisions.
"""

from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionResult
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams

from . import feed
from .api import (
    NON_JSON,
    Run,
    error_parts,
    explain_status,
    is_blank,
    replayed,
    tenant_refusal,
    whole_number,
)
from .consts import (
    BLOCK_TYPES,
    BLOCKS_PATH,
    EMAIL_NOT_FOUND,
    EMAILS_PATH,
    EVENTS_PATH,
    JOB_NOT_FOUND,
    JOBS_PATH,
    MAX_PAGES_PER_POLL,
    OWN_TENANT_SLOT,
    REANALYZE_JOB_KIND,
    REASON_PARAM,
    TENANT_PARAM,
    TIMEOUT_SECONDS,
    TLS_ADVICE,
    UPLOAD_PATH,
    VERDICT_PATH,
    VERDICTS,
    ZIP_UPLOAD_PATH,
)
from .models import (
    AnalyzeArchiveOutput,
    AnalyzeArchiveParams,
    AnalyzeArchiveSummary,
    Asset,
    DetonateFileOutput,
    DetonateFileParams,
    DetonateFileSummary,
    EmailIdParams,
    GetEvidencePackageOutput,
    GetEvidencePackageSummary,
    GetJobOutput,
    GetJobParams,
    GetJobSummary,
    GetTimelineOutput,
    GetTimelineSummary,
    GetVerdictOutput,
    GetVerdictParams,
    GetVerdictSummary,
    ReanalyzeOutput,
    ReanalyzeParams,
    ReanalyzeSummary,
    RecordBlockOutput,
    RecordBlockParams,
    RecordBlockSummary,
    ReportTicketParams,
    ReportTicketSummary,
    SetVerdictOutput,
    SetVerdictParams,
    SetVerdictSummary,
    TicketOutput,
    UpdateTicketParams,
    UpdateTicketSummary,
)


logger = getLogger()

#: The label a polled container gets when the asset's ingest settings name none.
DEFAULT_CONTAINER_LABEL = "events"

app = App(
    name="EmailBadger",
    app_type="email",
    logo="logo_emailbadger.svg",
    logo_dark="logo_emailbadger.svg",
    product_vendor="EmailBadger",
    product_name="EmailBadger",
    publisher="EmailBadger, LLC",
    appid="b8f2e1c4-6a7d-4e9b-9c3f-2d5a8e7b1f04",
    fips_compliant=True,
    asset_cls=Asset,
)


def _text(value: Any) -> str:
    """A parameter as stripped text, blank for ``None``."""
    return str(value or "").strip()


def _key_header(key: str) -> dict[str, str] | None:
    """The ``Idempotency-Key`` header, only when the playbook supplied a key."""
    return {"Idempotency-Key": key} if key else None


# -- test connectivity --------------------------------------------------------


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the base URL and API key by calling EmailBadger.

    POST with no file: the upload route rejects it, but *how* it rejects
    distinguishes every case that matters: 401 bad key, 402/404 unlicensed, a
    tenant refusal, a 4xx with a body reachable and authenticated. A GET would
    answer 405 for all of them and prove only that a server answered. The
    asset's tenant goes with it: the route judges it before it looks for the
    file, so a tenant the key cannot act in fails here rather than on the first
    real action.
    """
    run = Run(soar, asset)
    tenant, bad = run.target_tenant()
    if bad:
        raise ActionFailure(bad)
    logger.progress(f"Connecting to {run.base_url}")
    if tenant is not None and not run.reason:
        # This probe loads no customer row, so it passes either way. The first
        # real read is where a missing reason would show, so say it now.
        logger.progress(
            f"{TENANT_PARAM} is set and {REASON_PARAM} is not: a Platform Admin's key's reads of this "
            "customer will be refused until a reason is set on the asset or the action."
        )
    try:
        resp = requests.post(
            run.base_url + UPLOAD_PATH,
            headers=run.headers(),
            params=run.tenant_params(tenant),
            verify=run.verify,
            timeout=30,
        )
    except requests.exceptions.SSLError as exc:
        logger.progress("TLS verification failed")
        raise ActionFailure(f"TLS verification failed: {exc}. {TLS_ADVICE}") from None
    except requests.exceptions.RequestException as exc:
        raise ActionFailure(f"Could not reach EmailBadger: {exc}") from None

    # A tenant refusal first: "No such tenant." is a 404, and reporting it as
    # the tier gate would send the analyst to the licence over a typo.
    try:
        payload = resp.json() if resp.status_code >= 400 else None
    except ValueError:
        payload = None
    if tenant_refusal(resp.status_code, payload):
        logger.progress("Test Connectivity Failed")
        raise ActionFailure(run.upload_failed(resp, tenant, payload).get_message())
    if resp.status_code in (401, 402, 404, 429):
        logger.progress("Test Connectivity Failed")
        raise ActionFailure(explain_status(resp.status_code))
    logger.progress("Test Connectivity Passed")


# -- detonate file and analyze archive ----------------------------------------


def _vault_entry(
    soar: SOARClient, vault_id: str, default_name: str
) -> tuple[str, str] | None:
    """The path and filename behind a vault id, or ``None``.

    Shared by both file actions, so the two cannot drift on how a missing
    vault entry reads.
    """
    try:
        attachments = soar.vault.get_attachment(vault_id=vault_id)
    except Exception as exc:
        logger.debug(f"Vault lookup of {vault_id} failed: {exc}")
        return None
    if not attachments:
        return None
    entry = attachments[0]
    return entry.path, entry.name or default_name


@app.action(
    name="detonate file",
    identifier="analyze_email",
    description="Submit an .eml from the vault to EmailBadger and return its verdict",
    action_type="investigate",
    read_only=False,
    verbose=(
        "Uploads the file to /api/v1/api-upload/. EmailBadger de-duplicates by message id: re-submitting an "
        "email it has already analysed returns status 'duplicate' with the existing analysis rather than "
        "re-running it, so this action is safe to retry."
    ),
    summary_type=DetonateFileSummary,
)
def analyze_email(
    params: DetonateFileParams, soar: SOARClient, asset: Asset
) -> DetonateFileOutput:
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    entry = _vault_entry(soar, params.vault_id, "message.eml")
    if entry is None:
        return run.fail(f"Vault id {params.vault_id} not found")
    path, name = entry

    try:
        with open(path, "rb") as handle:
            resp = requests.post(
                run.base_url + UPLOAD_PATH,
                headers=run.headers(),
                params=run.tenant_params(tenant),
                files={"file": (name, handle, "message/rfc822")},
                verify=run.verify,
                timeout=TIMEOUT_SECONDS,
            )
    except requests.exceptions.RequestException as exc:
        return run.fail(f"Upload failed: {exc}")

    if resp.status_code >= 400:
        return run.upload_failed(resp, tenant)
    try:
        payload = resp.json()
    except ValueError:
        return run.fail(NON_JSON)

    # A duplicate is a success, not an error: EmailBadger de-duplicates by
    # message id and returns the prior analysis. Treating it as a failure would
    # make this action unsafe to retry, which is exactly what a playbook does
    # after a transient timeout.
    if payload.get("status") == "duplicate":
        existing = payload.get("existing_analysis", {}) or {}
        payload = {
            "status": "duplicate",
            "message_id": payload.get("message_id"),
            "subject": existing.get("subject"),
            "risk_score": existing.get("risk_score"),
            "risk_level": existing.get("risk_level"),
            "verdict": existing.get("disposition"),
            "verdict_confidence": None,
            "analyzed_at": existing.get("analyzed_at"),
        }

    run.update_summary({"total_objects": 1, "risk_level": payload.get("risk_level")})
    message = (
        f"Verdict: {payload.get('verdict') or payload.get('risk_level') or 'unknown'}"
    )
    return run.succeed(DetonateFileOutput(**payload), message, DetonateFileSummary)


@app.action(
    name="analyze archive",
    description="Submit a .zip of .eml/.msg files from the vault and return a verdict for each",
    action_type="investigate",
    read_only=False,
    verbose=(
        "Uploads the archive to /api/v1/api-upload/zip, which analyses every entry inline and returns one "
        "result per email. Partial failure is normal and is reported rather than hidden: `processed`, "
        "`duplicates` and `errors` are all in the summary, and each failed entry appears in "
        "action_result.data.*.error_details with its filename. The action fails only when nothing was "
        "analysed at all. An encrypted archive answers 422 with password_required: supply the password "
        "parameter rather than treating it as a bad key."
    ),
    summary_type=AnalyzeArchiveSummary,
)
def analyze_archive(
    params: AnalyzeArchiveParams, soar: SOARClient, asset: Asset
) -> AnalyzeArchiveOutput:
    """Submit a .zip and report a verdict per email inside it.

    **Partial failure is the normal case and is reported, not hidden.** An
    archive of forty messages where two entries are malformed is a successful
    run with two named failures. Failing the action would throw away
    thirty-eight verdicts, and a plain success would tell an analyst every
    message was analysed when two were not. The action fails only when nothing
    was analysed at all.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    entry = _vault_entry(soar, params.vault_id, "archive.zip")
    if entry is None:
        return run.fail(f"Vault id {params.vault_id} not found")
    path, name = entry

    data = {}
    if params.password:
        data["password"] = params.password
    # Sent as the string the form parser expects. `bool` would serialise as
    # "True"/"False", and FastAPI's form coercion reads "true"/"false".
    if params.skip_ai_analysis:
        data["skip_ai_analysis"] = "true"

    try:
        with open(path, "rb") as handle:
            resp = requests.post(
                run.base_url + ZIP_UPLOAD_PATH,
                headers=run.headers(),
                params=run.tenant_params(tenant),
                files={"file": (name, handle, "application/zip")},
                data=data,
                verify=run.verify,
                timeout=TIMEOUT_SECONDS,
            )
    except requests.exceptions.RequestException as exc:
        return run.fail(f"Upload failed: {exc}")

    try:
        payload = resp.json()
    except ValueError:
        return run.fail(NON_JSON)

    # An encrypted archive is a 422 carrying `password_required`, and it is the
    # one 4xx here that names its own remedy. Reporting it as "unexpected HTTP
    # 422" would send the analyst looking at the key or the licence instead of
    # the password.
    if resp.status_code == 422 and payload.get("password_required"):
        return run.fail(
            payload.get("message")
            or "The archive is password-protected — supply the password parameter."
        )
    if resp.status_code >= 400:
        return run.upload_failed(resp, tenant, payload)

    processed = payload.get("processed") or 0
    duplicates = payload.get("duplicates") or 0
    errors = payload.get("errors") or 0
    run.update_summary(
        {
            "total_objects": processed + duplicates,
            "processed": processed,
            "duplicates": duplicates,
            "errors": errors,
        }
    )

    if processed == 0 and duplicates == 0 and errors:
        # Nothing was analysed. Naming the first failure gives the analyst
        # something to act on; the rest are in error_details.
        first = (payload.get("error_details") or [{}])[0]
        run.add_data(payload)
        return run.fail(
            f"No emails were analysed ({errors} failed). First failure: "
            f"{first.get('filename', 'unknown')}: {first.get('error', 'unknown error')}"
        )

    message = f"{processed} analysed, {duplicates} duplicate(s)"
    if errors:
        message += f", {errors} failed — see error_details"
    return run.succeed(AnalyzeArchiveOutput(**payload), message, AnalyzeArchiveSummary)


# -- get verdict --------------------------------------------------------------


@app.action(
    name="get verdict",
    description="Read the current verdict on an email already submitted to EmailBadger",
    action_type="investigate",
    read_only=True,
    verbose=(
        "Reads GET /api/v1/verdicts with the Message-ID that detonate file returned. The verdict at upload "
        "can change afterwards (a sandbox run finishes, a re-score fills a provider gap, or an analyst sets "
        "one), so a playbook calls this to ask again. The answer is verdict fields only: the verdict, its "
        "confidence, the risk score and level, and whether coverage is complete. EmailBadger never returns "
        "the email's content here. coverage_complete false means the verdict is provisional. A 404 either "
        "means no email with that Message-ID is visible to the key's user, or that the deployment does not "
        "serve the route; the action says which. Enterprise tier and above. A Platform Admin's key names the "
        "customer with target_tenant_id; with none, the answer is whichever one tenant holds that "
        "Message-ID, and a Message-ID in more than one is refused as tenant_ambiguous."
    ),
    summary_type=GetVerdictSummary,
)
def get_verdict(
    params: GetVerdictParams, soar: SOARClient, asset: Asset
) -> GetVerdictOutput:
    """The current verdict on an email already submitted, by its Message-ID.

    **Two different 404s.** "Email not found" means the key's user can see no
    email with that Message-ID: it was never submitted, or it belongs to
    someone this key cannot see. Any other 404 means the deployment does not
    serve the route at all. Reporting the second as the first would send an
    analyst looking for an email that is there.

    **A tenant goes with it when there is one.** One campaign sent to two
    customers leaves the same Message-ID in both, so a Platform Admin's key
    names the customer it means; naming none is answered when only one tenant
    holds that Message-ID, and refused as ``tenant_ambiguous`` when more than
    one does.
    """
    run = Run(soar, asset, params)
    message_id = _text(params.message_id)
    if not message_id:
        return run.fail("message_id is required")
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)

    try:
        resp = requests.get(
            run.base_url + VERDICT_PATH,
            headers=run.headers(),
            params=run.tenant_params(tenant, {"message_id": message_id}),
            verify=run.verify,
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        return run.fail(f"Could not reach EmailBadger: {exc}")
    try:
        payload = resp.json()
    except ValueError:
        payload = None

    # First: "No such tenant." is a 404, and neither 404 below means that.
    if tenant_refusal(resp.status_code, payload):
        return run.upload_failed(resp, tenant, payload)
    if resp.status_code == 404:
        if isinstance(payload, dict) and payload.get("detail") == EMAIL_NOT_FOUND:
            return run.fail(
                f"No email with Message-ID {message_id} is visible to this API key's user. "
                "It was not submitted, or it belongs to a user this key cannot see."
            )
        return run.fail(
            "This EmailBadger deployment does not serve the verdict route "
            f"({VERDICT_PATH}). It needs a release that includes it, on Enterprise tier "
            "or above."
        )
    if resp.status_code == 422:
        return run.fail(
            "EmailBadger rejected the Message-ID (empty, or longer than 255 characters)."
        )
    if resp.status_code >= 400:
        return run.fail(explain_status(resp.status_code))
    if not isinstance(payload, dict):
        return run.fail(NON_JSON)

    run.update_summary(
        {
            "total_objects": 1,
            "verdict": payload.get("verdict"),
            "risk_level": payload.get("risk_level"),
            "coverage_complete": payload.get("coverage_complete"),
        }
    )
    verdict = payload.get("verdict") or payload.get("risk_level") or "none yet"
    if payload.get("coverage_complete") is False:
        verdict += " (provisional: a provider could not answer, and a re-score may still move it)"
    return run.succeed(
        GetVerdictOutput(**payload), f"Verdict: {verdict}", GetVerdictSummary
    )


# -- on poll ------------------------------------------------------------------


def _container_label() -> str:
    """The container label from the asset's ingest settings."""
    try:
        config = app.actions_manager.get_config() or {}
    except Exception:
        config = {}
    return (config.get("ingest") or {}).get(
        "container_label"
    ) or DEFAULT_CONTAINER_LABEL


class _Cursors:
    """The feed cursors in the asset's ingest state, one per tenant.

    A cursor belongs to the tenant it was issued for, and the feed refuses it
    with any other tenant, or none (``400 cursor_invalid``). So the state keeps
    ``cursors`` keyed by tenant id (``own`` for the key's own tenant), and
    re-pointing an asset at another customer and back resumes each feed where
    it stopped rather than restarting it from the oldest retained event.

    :meth:`save` commits at once. The SDK holds ingest state in a transaction
    for the whole poll and rolls it back on a failure, which would take every
    saved page's cursor with it; committing per page keeps a poll that dies
    mid-backlog resuming from the last page it saved.
    """

    def __init__(self, asset: Asset, slot: str) -> None:
        self.state = asset.ingest_state
        self.slot = slot
        cursors = self.state.get("cursors")
        self.cursors: dict[str, str] = (
            dict(cursors) if isinstance(cursors, dict) else {}
        )

    def get(self) -> str | None:
        return self.cursors.get(self.slot) or None

    def save(self, value: str | None) -> None:
        if value:
            self.cursors[self.slot] = value
        else:
            self.cursors.pop(self.slot, None)
        self.state["cursors"] = dict(self.cursors)
        if self.state.in_transaction:
            self.state.commit()
            self.state.begin_transaction()


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container]:
    """Ingest the verdict event feed: one container per event.

    The cursor EmailBadger returns is saved after every page, once that page's
    containers are in SOAR, so a poll that dies mid-backlog resumes from the
    last page it saved, and the events of the page it was on are re-saved
    harmlessly because each container's ``source_data_identifier`` is the
    event id.

    **A 410 is never a silent empty poll.** A cursor older than the feed's
    retention (the asset was off for longer than that) is answered with the
    oldest cursor still valid; the poll resumes from it and says so in the
    progress log. It claims no loss: a cursor idle on a feed that stayed empty
    gets the same 410 with nothing missed, and the feed cannot tell the two
    apart, so the message says only that any events that aged out were not
    ingested.

    A manual poll (Poll Now) honours ``container_count``; a scheduled poll
    drains up to ``MAX_PAGES_PER_POLL`` pages. The first poll of a new asset
    has no cursor and starts from the oldest retained event.

    ``on poll``'s parameters are fixed by SOAR, so its tenant and its reason
    are the asset's.
    """
    run = Run(soar, asset)
    types = feed.event_types(asset.poll_event_types)
    size = feed.page_size(asset.poll_page_size)
    label = _container_label()

    remaining = None
    if params.is_manual_poll():
        count = whole_number(params.container_count)
        if count:
            remaining = count

    tenant, bad = run.target_tenant(from_action=False)
    if bad:
        raise ActionFailure(bad)
    cursors = _Cursors(asset, str(tenant) if tenant is not None else OWN_TENANT_SLOT)
    cursor = cursors.get()

    seen = pages = 0
    reset_note = None
    while pages < MAX_PAGES_PER_POLL:
        limit = size if remaining is None else min(size, remaining)
        if limit <= 0:
            break
        query: dict[str, Any] = {"types": types, "limit": limit}
        if cursor:
            query["since"] = cursor
        resp, payload, unreachable = run.call(
            "GET", EVENTS_PATH, params=run.tenant_params(tenant, query)
        )
        if unreachable:
            raise ActionFailure(unreachable)

        code, _, _ = error_parts(payload)
        if resp.status_code == 410 and code == "cursor_expired" and reset_note is None:
            detail = (
                payload.get("detail") if isinstance(payload.get("detail"), dict) else {}
            )
            oldest = detail.get("oldest_cursor")
            if not oldest:
                raise ActionFailure(
                    "The saved cursor is older than the feed's retention and EmailBadger named no oldest_cursor "
                    "to resume from."
                )
            retention = detail.get("retention_days")
            window = f"{retention}-day retention" if retention else "retention"
            reset_note = (
                f"EmailBadger refused the saved cursor as older than the feed's {window}. Resumed from "
                "the oldest retained event; any events that aged out before then were not ingested."
            )
            logger.warning(reset_note)
            logger.progress(reset_note)
            cursor = oldest
            cursors.save(cursor)
            continue
        if resp.status_code == 400 and code == "cursor_invalid" and reset_note is None:
            reset_note = (
                "The saved cursor is not one this EmailBadger issued for this tenant's feed (the "
                "deployment was restored, or the asset was pointed at another one). Resumed from the "
                "oldest retained event; re-polled events deduplicate by event id."
            )
            logger.warning(reset_note)
            logger.progress(reset_note)
            cursor = None
            cursors.save(None)
            continue
        if resp.status_code >= 400:
            # Nothing was ingested and the cursor stays put, so a tenant
            # refusal fixed on the asset resumes where the feed left off.
            raise ActionFailure(
                run.action_failed(
                    resp, payload, EVENTS_PATH, tenant=tenant
                ).get_message()
            )
        if not isinstance(payload, dict):
            raise ActionFailure(NON_JSON)

        events = payload.get("events") or []
        for event in events:
            yield Container(**feed.container_for(event, label))
        seen += len(events)
        if remaining is not None:
            remaining -= len(events)

        next_cursor = payload.get("next_cursor")
        if next_cursor and next_cursor != cursor:
            cursor = next_cursor
            cursors.save(cursor)
        pages += 1
        if len(events) < limit:
            break

    message = f"{seen} event(s) ingested"
    if reset_note:
        message += f". {reset_note}"
    logger.progress(message)


# -- set verdict --------------------------------------------------------------


@app.action(
    name="set verdict",
    description="Set the verdict on an email as an analyst's mark would, recorded as this playbook's decision",
    action_type="contain",
    read_only=False,
    verbose=(
        "POST /api/v1/emails/{email_id}/verdict. external_actor and external_reference are stored with the "
        "verdict, the audit row and the verdict.changed event, so a SOAR decision is told apart from an "
        "analyst's. A retry after a timeout is safe without a key: the route is idempotent on email and "
        "external_reference for 24 hours, so the same verdict again replays the stored answer and fires "
        "nothing, and a different verdict under the same reference is applied. An Idempotency-Key goes out "
        "only when you supply one; summary.replayed says when a stored answer came back. 409 "
        "verdict_not_rendered means the analysis has not finished yet. Needs the verdicts:write scope; "
        "Enterprise tier and above."
    ),
    summary_type=SetVerdictSummary,
)
def set_verdict(
    params: SetVerdictParams, soar: SOARClient, asset: Asset
) -> SetVerdictOutput:
    """``POST /api/v1/emails/{email_id}/verdict``: set a verdict as an analyst's mark would.

    **No ``Idempotency-Key`` is derived** The route is already
    idempotent on ``(email, external_reference)`` for 24 hours: a retry with
    the same verdict replays the stored answer and fires nothing, and a
    different verdict under the same reference is applied as the case changing
    its mind. A derived key replayed on top of that, per request body, so
    ``suspicious`` -> ``malicious`` -> ``suspicious`` answered the third call
    with the first one's stored response and wrote nothing.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    email_id = whole_number(params.email_id)
    if email_id is None:
        return run.fail("email_id must be a positive integer")
    verdict = _text(params.verdict).lower()
    if verdict not in VERDICTS:
        return run.fail(f"verdict must be one of {', '.join(VERDICTS)}")
    actor = _text(params.external_actor)
    reference = _text(params.external_reference)
    if not actor or not reference:
        return run.fail("external_actor and external_reference are required")
    body = {
        "verdict": verdict,
        "external_actor": actor,
        "external_reference": reference,
    }
    reason = _text(params.reason)
    if reason:
        body["reason"] = reason
    key = _text(params.idempotency_key)

    path = f"{EMAILS_PATH}/{email_id}/verdict"
    resp, payload, unreachable = run.call(
        "POST",
        path,
        json=body,
        headers=_key_header(key),
        params=run.tenant_params(tenant),
    )
    if unreachable:
        return run.fail(unreachable)
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, path, email_id, tenant)
    if not isinstance(payload, dict):
        return run.fail(NON_JSON)

    was_replayed = replayed(resp)
    run.update_summary(
        {
            "total_objects": 1,
            "changed": payload.get("changed"),
            "previous": payload.get("previous"),
            "current": payload.get("current"),
            "risk_level": payload.get("risk_level"),
            "replayed": was_replayed,
            "idempotency_key": key or None,
        }
    )
    if payload.get("changed"):
        message = f"Verdict on email {email_id} set to {payload.get('current')}"
        if payload.get("previous"):
            message += f" (was {payload['previous']})"
    else:
        message = f"Verdict on email {email_id} already {payload.get('current')}; nothing changed"
    if was_replayed:
        message += ". Replayed from an identical request within the last 24 hours"
    return run.succeed(SetVerdictOutput(**payload), message, SetVerdictSummary)


# -- record block -------------------------------------------------------------


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


@app.action(
    name="record block",
    description=(
        "Block an indicator in EmailBadger through the Block dialog's own guardrails; a guardrail that wants "
        "an acknowledgement is a result, not a failure"
    ),
    action_type="contain",
    read_only=False,
    verbose=(
        "POST /api/v1/blocks. Writes a manual block and offers it to every configured enforcement target; "
        "created_by names the API key. summary.outcome is one of: written (the block exists; badge_state and "
        "the per-target rows say how far it is enforced), acknowledgement_required (EmailBadger's guardrails "
        "want the caller to accept something first, e.g. a safelisted domain or a block that would have "
        "caught clean mail; nothing was written; the findings are in the data and summary.acknowledge is the "
        "exact value to pass back in acknowledge to write it), already_blocked (a live block stands; nothing "
        "written). A finding of severity refuse cannot be acknowledged and fails the action. Expiry is the "
        "install's default (30 days unless changed) when neither expires_in_days nor never_expires is given. "
        "A retry after a timeout is safe without a key: the block it wrote is live, so the repeat answers "
        "already_blocked and writes nothing. An Idempotency-Key goes out only when you supply one. Needs the "
        "blocks:write scope; Enterprise tier and above."
    ),
    summary_type=RecordBlockSummary,
)
def record_block(
    params: RecordBlockParams, soar: SOARClient, asset: Asset
) -> RecordBlockOutput:
    """``POST /api/v1/blocks``: block an indicator through the Block dialog's own guardrails.

    Three answers are results, not failures, because each is a state the
    playbook has to branch on rather than retry: ``written``,
    ``acknowledgement_required`` (nothing was written; ``summary.acknowledge``
    is the exact value to pass back in ``acknowledge``) and
    ``already_blocked``. A finding of severity ``refuse`` cannot be
    acknowledged by anyone, so that one is a failure naming the finding.

    **No ``Idempotency-Key`` is derived** A retry after a timeout is
    safe without one: the block it wrote is live, so the repeat answers
    ``already_blocked`` and writes nothing. A derived key replayed the stored
    ``written`` answer for 24 hours instead, so a block an analyst lifted and
    the playbook then recorded again was never written.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    block_type = _text(params.block_type).lower()
    if block_type not in BLOCK_TYPES:
        return run.fail(f"block_type must be one of {', '.join(BLOCK_TYPES)}")
    value = _text(params.value)
    if not value:
        return run.fail("value is required")

    body: dict[str, Any] = {"block_type": block_type, "value": value}
    reason = _text(params.reason)
    if reason:
        body["reason"] = reason
    source_email_id = whole_number(params.source_email_id)
    if not is_blank(params.source_email_id) and source_email_id is None:
        return run.fail("source_email_id must be a positive integer when given")
    if source_email_id is not None:
        body["source_email_id"] = source_email_id

    never_expires = _truthy(params.never_expires)
    if not is_blank(params.expires_in_days):
        expires_in_days = whole_number(params.expires_in_days)
        if expires_in_days is None:
            return run.fail(
                "expires_in_days must be a whole number of days, at least 1"
            )
        if never_expires:
            return run.fail("Give expires_in_days or never_expires, not both")
        body["expires_in_days"] = expires_in_days
    if never_expires:
        body["never_expires"] = True

    acknowledge = sorted(
        {part.strip() for part in _text(params.acknowledge).split(",") if part.strip()}
    )
    if acknowledge:
        body["acknowledge"] = acknowledge
    key = _text(params.idempotency_key)

    resp, payload, unreachable = run.call(
        "POST",
        BLOCKS_PATH,
        json=body,
        headers=_key_header(key),
        params=run.tenant_params(tenant),
    )
    if unreachable:
        return run.fail(unreachable)

    code, detail, request_id = error_parts(payload)
    suffix = f" (request id {request_id})" if request_id else ""
    label = f"{block_type} {value}"
    if resp.status_code == 409 and code == "already_blocked":
        run.update_summary(
            {
                "total_objects": 0,
                "outcome": "already_blocked",
                "written": False,
                "idempotency_key": key or None,
            }
        )
        return run.succeed_without_data(
            f"{label} is already blocked; nothing was written.{suffix}"
        )
    if resp.status_code == 409 and code == "conflict":
        raw = payload.get("detail") if isinstance(payload, dict) else None
        findings = (
            [f for f in ((raw or {}).get("findings") or []) if isinstance(f, dict)]
            if isinstance(raw, dict)
            else []
        )
        refused = [f for f in findings if f.get("severity") == "refuse"]
        if refused or not findings:
            named = (
                "; ".join(f"{f.get('code')}: {f.get('message')}" for f in refused)
                or detail
            )
            return run.fail(
                f"EmailBadger refuses to block {label}, and no acknowledgement can change that: {named}.{suffix}"
            )
        codes = ",".join(sorted(str(f.get("code")) for f in findings))
        run.update_summary(
            {
                "total_objects": 0,
                "outcome": "acknowledgement_required",
                "written": False,
                "acknowledge": codes,
                "findings": len(findings),
                "idempotency_key": key or None,
            }
        )
        described = "; ".join(f"{f.get('code')} ({f.get('message')})" for f in findings)
        return run.succeed(
            RecordBlockOutput(findings=findings, acknowledge=codes),
            (
                f"Not written: EmailBadger asks the playbook to acknowledge {len(findings)} finding(s) "
                f'before blocking {label}: {described}. Re-run record block with acknowledge="{codes}" '
                f"to write it.{suffix}"
            ),
            RecordBlockSummary,
        )
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, BLOCKS_PATH, source_email_id, tenant)
    if not isinstance(payload, dict):
        return run.fail(NON_JSON)

    was_replayed = replayed(resp)
    targets = payload.get("targets") or []
    counts: dict[str, int] = {}
    for target in targets:
        status = str((target or {}).get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    run.update_summary(
        {
            "total_objects": 1,
            "outcome": "written",
            "written": True,
            "block_id": payload.get("id"),
            "badge_state": payload.get("badge_state"),
            "expires_at": payload.get("expires_at"),
            "targets": len(targets),
            "replayed": was_replayed,
            "idempotency_key": key or None,
        }
    )
    message = (
        f"Blocked {label} (block id {payload.get('id')}, enforcement {payload.get('badge_state')}, "
        f"expires {payload.get('expires_at') or 'never'})"
    )
    if targets:
        message += "; targets: " + ", ".join(
            f"{n} {status}" for status, n in sorted(counts.items())
        )
    else:
        message += (
            "; no enforcement target is configured, so the block is a record only"
        )
    if was_replayed:
        message += ". Replayed from an identical request within the last 24 hours"
    return run.succeed(RecordBlockOutput(**payload), message, RecordBlockSummary)


# -- update ticket and report ticket ------------------------------------------


@app.action(
    name="update ticket",
    description="Write a SOAR ticket's status, URL or opened time back onto the email's case",
    action_type="generic",
    read_only=False,
    verbose=(
        "PATCH /api/v1/emails/{email_id}/external-tickets/{system}/{ticket_id}. Only the fields given are "
        "sent; at least one is required. 404 means either no such email is visible to the key's user or no "
        "such ticket is on it; the action says which when EmailBadger does. This action never creates a "
        "ticket; report ticket does. Needs the external_tickets:write scope; Enterprise tier and above."
    ),
    summary_type=UpdateTicketSummary,
)
def update_ticket(
    params: UpdateTicketParams, soar: SOARClient, asset: Asset
) -> TicketOutput:
    """``PATCH /api/v1/emails/{email_id}/external-tickets/{system}/{ticket_id}``.

    Sends only what the playbook supplied, because the route refuses an empty
    body (422) and a body that renames the ticket; the path is the identity. A
    ticket id may contain ``/`` and is sent as-is.

    **Never creates a ticket**, and never falls back to ``report ticket``: an
    id that is not on the email is a 404, because a typo here must not become
    a record.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    email_id = whole_number(params.email_id)
    if email_id is None:
        return run.fail("email_id must be a positive integer")
    system = _text(params.system)
    ticket_id = _text(params.ticket_id)
    if not system or not ticket_id:
        return run.fail("system and ticket_id are required")

    body = {}
    for field in ("status", "ticket_url", "opened_at"):
        value = _text(getattr(params, field))
        if value:
            body[field] = value
    if not body:
        return run.fail(
            "Nothing to update: supply at least one of status, ticket_url, opened_at"
        )

    path = f"{EMAILS_PATH}/{email_id}/external-tickets/{quote(system, safe='')}/{quote(ticket_id, safe='/')}"
    resp, payload, unreachable = run.call(
        "PATCH", path, json=body, params=run.tenant_params(tenant)
    )
    if unreachable:
        return run.fail(unreachable)
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, path, email_id, tenant)
    if not isinstance(payload, dict):
        return run.fail(NON_JSON)

    ticket = payload.get("ticket") or {}
    run.update_summary(
        {
            "total_objects": 1,
            "created": payload.get("created"),
            "status": ticket.get("status"),
            "ticket_url": ticket.get("ticket_url"),
        }
    )
    return run.succeed(
        TicketOutput(**(ticket or payload)),
        f"Ticket {system}/{ticket_id} on email {email_id} updated: {', '.join(sorted(body))}",
        UpdateTicketSummary,
    )


@app.action(
    name="report ticket",
    description=(
        "Report a ticket this SOAR opened for an email, so the email shows it. Safe to repeat: the same "
        "ticket reported again updates it"
    ),
    action_type="generic",
    read_only=False,
    verbose=(
        "POST /api/v1/emails/{email_id}/external-tickets. The only action that creates a ticket on the "
        "email; update ticket never does (it answers 404 for a ticket not reported yet). Keyed by system and "
        "ticket_id: the first report creates the record (summary.created true) and needs opened_at, a later "
        "one updates only the fields given, and a repeat of an identical report changes nothing but the "
        "report time. An Idempotency-Key goes out only when you supply one; summary.replayed says when the "
        "stored answer was returned. Needs the external_tickets:write scope, and the tenant's 'SOAR "
        "write-back allowed' switch on; Enterprise tier and above."
    ),
    summary_type=ReportTicketSummary,
)
def report_ticket(
    params: ReportTicketParams, soar: SOARClient, asset: Asset
) -> TicketOutput:
    """``POST /api/v1/emails/{email_id}/external-tickets``: report a ticket the SOAR opened.

    The only way a ticket comes to exist on the email. Keyed by (email, system,
    ticket id): the first report is a ``201`` with ``created`` true and needs
    ``opened_at`` (a ``422`` says so otherwise), a later one is a ``200`` that
    updates only the fields sent, so a retry or a second playbook reporting
    the same ticket is harmless.

    **No ``Idempotency-Key`` is derived**: a derived key would replay
    the stored answer for 24 hours, so a status sent again after it changed
    elsewhere would be answered from the cache and never written.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    email_id = whole_number(params.email_id)
    if email_id is None:
        return run.fail("email_id must be a positive integer")
    system = _text(params.system)
    ticket_id = _text(params.ticket_id)
    if not system or not ticket_id:
        return run.fail("system and ticket_id are required")

    body = {"system": system, "ticket_id": ticket_id}
    for field in ("status", "ticket_url", "opened_at"):
        value = _text(getattr(params, field))
        if value:
            body[field] = value
    key = _text(params.idempotency_key)

    path = f"{EMAILS_PATH}/{email_id}/external-tickets"
    resp, payload, unreachable = run.call(
        "POST",
        path,
        json=body,
        headers=_key_header(key),
        params=run.tenant_params(tenant),
    )
    if unreachable:
        return run.fail(unreachable)
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, path, email_id, tenant)
    if not isinstance(payload, dict):
        return run.fail(NON_JSON)

    was_replayed = replayed(resp)
    ticket = payload.get("ticket") or {}
    created = bool(payload.get("created"))
    run.update_summary(
        {
            "total_objects": 1,
            "created": created,
            "status": ticket.get("status"),
            "ticket_url": ticket.get("ticket_url"),
            "replayed": was_replayed,
        }
    )
    if created:
        message = f"Ticket {system}/{ticket_id} reported on email {email_id}"
    else:
        updated = (
            ", ".join(sorted(set(body) - {"system", "ticket_id"}))
            or "nothing but the report time"
        )
        message = f"Ticket {system}/{ticket_id} was already reported on email {email_id}; updated: {updated}"
    if was_replayed:
        message += ". Replayed from an identical request within the last 24 hours"
    return run.succeed(
        TicketOutput(**(ticket or payload)), message, ReportTicketSummary
    )


# -- reanalyze and get job ----------------------------------------------------


@app.action(
    name="reanalyze",
    description=(
        "DESTRUCTIVE: re-run the analysis of an email from its stored source. Deletes the existing analysis "
        "and returns the id of the job that replaces it"
    ),
    action_type="generic",
    read_only=False,
    verbose=(
        "POST /api/v1/emails/{email_id}/reanalyze. The job deletes the existing analysis (its verdict, cases, "
        "hunts, blocks, tickets and timeline go with it) and re-ingests the stored source, so the new analysis "
        "has a NEW email id and the old id answers 404 afterwards. This action returns the job id as soon as "
        "the job is queued and does not wait; the job settles with the old and new score, verdict and email "
        "id in its result: run get job with the job id, on this same asset, to read it. A repeat while the job "
        "is queued or running returns the same job id with summary.already_running true and queues nothing, "
        "which is a success. Once it has settled, a new call starts a new job. 410 source_unavailable means "
        "retention removed the stored source: nothing is queued; upload the email again instead. An "
        "Idempotency-Key goes out only when you supply one. Needs the analysis:write scope, and the tenant's "
        "'SOAR write-back allowed' switch on; Enterprise tier and above."
    ),
    summary_type=ReanalyzeSummary,
)
def reanalyze(
    params: ReanalyzeParams, soar: SOARClient, asset: Asset
) -> ReanalyzeOutput:
    """``POST /api/v1/emails/{email_id}/reanalyze``: queue a fresh analysis, return the job id.

    **A repeat joins the running job**: while a re-analysis of the same email
    is queued or running, the route answers the same ``job_id`` with
    ``already_running`` true and writes no second audit row. That is a success.
    No ``Idempotency-Key`` is derived, because one would replay the
    stored answer for 24 hours and a genuine second re-analysis, after the
    first has settled, would never start.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    email_id = whole_number(params.email_id)
    if email_id is None:
        return run.fail("email_id must be a positive integer")
    key = _text(params.idempotency_key)

    path = f"{EMAILS_PATH}/{email_id}/reanalyze"
    resp, payload, unreachable = run.call(
        "POST", path, headers=_key_header(key), params=run.tenant_params(tenant)
    )
    if unreachable:
        return run.fail(unreachable)
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, path, email_id, tenant)
    if not isinstance(payload, dict) or payload.get("job_id") is None:
        return run.fail("EmailBadger did not return a job id for the re-analysis")

    was_replayed = replayed(resp)
    already_running = bool(payload.get("already_running"))
    run.update_summary(
        {
            "total_objects": 1,
            "job_id": payload.get("job_id"),
            "status": payload.get("status"),
            "already_running": already_running,
            "replayed": was_replayed,
        }
    )
    if already_running:
        message = (
            f"A re-analysis of email {email_id} is already running as job {payload['job_id']}; this call "
            "joined it and queued nothing new"
        )
    else:
        message = (
            f"Re-analysis of email {email_id} queued as job {payload['job_id']}. The existing "
            "analysis is deleted and the new one gets a new email id, found in the job's result"
        )
    if was_replayed:
        message += ". Replayed from an identical request within the last 24 hours"
    return run.succeed(ReanalyzeOutput(**payload), message, ReanalyzeSummary)


@app.action(
    name="get job",
    description=(
        "Read a job this asset queued, such as a re-analysis: its status and, once settled, the old and new "
        "email id, score and verdict"
    ),
    action_type="investigate",
    read_only=True,
    verbose=(
        "GET /api/v1/api-upload/jobs/{job_id}. The job id comes from reanalyze (or from detonate file on a "
        "deployment that queues uploads). Only the API key that queued a job can read it, so run this on the "
        "same asset; any other key, a job that does not exist and one that is too old all answer the same "
        "not-found. Read until summary.settled is true, with a pause between reads: the limit is 120 a minute "
        "per client address. A queued or running job is a success with settled false. A re-analysis that "
        "succeeded puts the NEW email id in summary.new_email_id, beside the new verdict and score; the old "
        "email id answers 404 from then on, so later actions take the new one. A job that failed or was "
        "interrupted, and a re-analysis that settled without a new record, fail this action with the reason, "
        "though the job's data is still in the result. A read: safe to repeat, no scope needed, no tier gate. "
        "A Platform Admin's key reading a job in a customer's tenant needs platform_admin_reason."
    ),
    summary_type=GetJobSummary,
)
def get_job(params: GetJobParams, soar: SOARClient, asset: Asset) -> GetJobOutput:
    """``GET /api/v1/api-upload/jobs/{job_id}``: the state of a job this key queued.

    The way a playbook learns what ``reanalyze`` did: the re-analysed email has
    a *new* id, and the job's ``result`` is the only place it appears.

    **Only the key that queued the job can read it.** Another key, account or
    tenant gets the same 404 as a job that does not exist or has aged out, so
    the message names all of them.

    **A job that failed is a failed action.** Reading it worked, but a playbook
    that branches on success would otherwise carry on as though the
    re-analysis happened. So is a re-analysis that settled with no new record.
    Queued and running are successes with ``settled`` false.
    """
    run = Run(soar, asset, params)
    job_id = whole_number(params.job_id)
    if job_id is None:
        return run.fail("job_id must be a positive integer")
    # The route names no tenant, but the rule follows the row: a job a
    # Platform Admin's key queued in a customer's tenant needs a reason to read.
    bad = run.settle_reason()
    if bad:
        return run.fail(bad)

    path = f"{JOBS_PATH}/{job_id}"
    resp, payload, unreachable = run.call("GET", path)
    if unreachable:
        return run.fail(unreachable)
    if resp.status_code == 404:
        if isinstance(payload, dict) and payload.get("detail") == JOB_NOT_FOUND:
            return run.fail(
                f"No job {job_id} is readable by this API key. It does not exist, it is too old, or "
                "it was queued by another key, account or tenant: only the key that queued a job "
                "can read it, so run this on the asset that queued it."
            )
        return run.fail(
            f"This EmailBadger deployment does not serve {JOBS_PATH}/{{job_id}}. It needs a release that includes it."
        )
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, path)
    if not isinstance(payload, dict) or not payload.get("status"):
        return run.fail("EmailBadger did not return a job status")

    status = payload["status"]
    settled = bool(payload.get("settled"))
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    reanalysis = payload.get("kind") == REANALYZE_JOB_KIND
    run.update_summary(
        {
            "total_objects": 1,
            "job_id": job_id,
            "status": status,
            "settled": settled,
            "new_email_id": result.get("new_email_id"),
            "new_verdict": result.get("new_verdict"),
            "new_score": result.get("new_score"),
        }
    )

    def done(message: str) -> GetJobOutput:
        return run.succeed(GetJobOutput(**payload), message, GetJobSummary)

    def failed(message: str) -> ActionResult:
        run.add_data(payload)
        return run.fail(message)

    if not settled:
        return done(
            f"Job {job_id} is {status} and has not settled; read it again shortly"
        )
    if status != "succeeded":
        message = f"Job {job_id} {status}: {payload.get('error') or 'no reason given'}"
        if reanalysis:
            message += (
                ". If it stopped after the old analysis was deleted, no record remains; the source "
                "file is still stored, so the email can be uploaded again"
            )
        return failed(message)
    if not reanalysis:
        verdict = (
            result.get("verdict")
            or result.get("risk_level")
            or result.get("status")
            or "unknown"
        )
        return done(f"Job {job_id} succeeded. Verdict: {verdict}")
    if result.get("new_email_id") is None:
        return failed(
            f"Re-analysis job {job_id} settled without a new record (ingest status: "
            f"{result.get('status') or 'unknown'}). Email {result.get('old_email_id')} was deleted; "
            "the source file is still stored, so the email can be uploaded again"
        )
    return done(
        f"Re-analysis settled: email {result.get('old_email_id')} is now email {result['new_email_id']}. "
        f"Verdict {result.get('old_verdict')} -> {result.get('new_verdict')}, score "
        f"{result.get('old_score')} -> {result.get('new_score')}"
    )


# -- get timeline -------------------------------------------------------------


@app.action(
    name="get timeline",
    description="Read the forensic timeline of an email",
    action_type="investigate",
    read_only=True,
    verbose=(
        "GET /api/v1/emails/{email_id}/timeline: what happened to the email and when, across EmailBadger's "
        "own records and the mail systems it could search. gaps lists where it could not look; the action "
        "message counts them so a playbook does not take the timeline as complete when it is not. Needs the "
        "evidence:read scope; Enterprise tier and above."
    ),
    summary_type=GetTimelineSummary,
)
def get_timeline(
    params: EmailIdParams, soar: SOARClient, asset: Asset
) -> GetTimelineOutput:
    """``GET /api/v1/emails/{email_id}/timeline``: the forensic timeline as JSON.

    ``gaps`` are where EmailBadger could not look (a mailbox not searched, a
    provider that did not answer); the message counts them so a playbook that
    treats the timeline as complete sees that it is not.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    email_id = whole_number(params.email_id)
    if email_id is None:
        return run.fail("email_id must be a positive integer")

    path = f"{EMAILS_PATH}/{email_id}/timeline"
    resp, payload, unreachable = run.call("GET", path, params=run.tenant_params(tenant))
    if unreachable:
        return run.fail(unreachable)
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, path, email_id, tenant)
    if not isinstance(payload, dict):
        return run.fail(NON_JSON)

    entries = payload.get("entries") or []
    gaps = payload.get("gaps") or []
    total = payload.get("total", len(entries))
    run.update_summary({"total_objects": 1, "total": total, "gaps": len(gaps)})
    message = (
        f"{total} timeline entr{'y' if total == 1 else 'ies'} for email {email_id}"
    )
    if gaps:
        message += f", {len(gaps)} gap(s) where EmailBadger could not look"
    return run.succeed(GetTimelineOutput(**payload), message, GetTimelineSummary)


# -- get evidence package -----------------------------------------------------


@app.action(
    name="get evidence package",
    description="Download the sealed evidence package of an email into the vault",
    action_type="investigate",
    read_only=True,
    verbose=(
        "GET /api/v1/emails/{email_id}/evidence-package: the ZIP EmailBadger's Evidence Package export "
        "produces, saved to the vault of the current container with its X-Manifest-SHA256 kept alongside. "
        "The API key's user must be a Tenant Admin or Platform Admin (403 otherwise; the action says so). The "
        "route is rate limited per address; a 429 reports the Retry-After. Needs the evidence:read scope; "
        "Enterprise tier and above."
    ),
    summary_type=GetEvidencePackageSummary,
)
def get_evidence_package(
    params: EmailIdParams, soar: SOARClient, asset: Asset
) -> GetEvidencePackageOutput:
    """``GET /api/v1/emails/{email_id}/evidence-package``: the sealed ZIP, into the vault.

    The key's user must be a Tenant Admin or Platform Admin (403 otherwise, and
    the message says so rather than "forbidden"). The ZIP's
    ``X-Manifest-SHA256`` is kept with the vault entry so the package in
    someone's hands can be matched to the export that produced it.
    """
    run = Run(soar, asset, params)
    tenant, bad = run.target_tenant()
    if bad:
        return run.fail(bad)
    email_id = whole_number(params.email_id)
    if email_id is None:
        return run.fail("email_id must be a positive integer")

    path = f"{EMAILS_PATH}/{email_id}/evidence-package"
    resp, payload, unreachable = run.call(
        "GET", path, timeout=TIMEOUT_SECONDS, params=run.tenant_params(tenant)
    )
    if unreachable:
        return run.fail(unreachable)
    if resp.status_code == 403:
        _, detail, request_id = error_parts(payload)
        # "Admin" matches the core's "Administrator access required" and any admin-role wording after it.
        if detail and "Admin" in detail:
            message = (
                "The evidence package is an admin's export; this API key's user is neither a Tenant Admin "
                "nor a Platform Admin. Mint the key under a Tenant Admin or Platform Admin account."
            )
            if request_id:
                message += f" (request id {request_id})"
            return run.fail(message)
    if resp.status_code >= 400:
        return run.action_failed(resp, payload, path, email_id, tenant)
    content_type = (resp.headers.get("Content-Type") or "").lower()
    if "zip" not in content_type:
        return run.fail(
            f"EmailBadger answered with {content_type or 'no content type'}, not a ZIP"
        )

    file_name = f"emailbadger-evidence-{email_id}.zip"
    manifest_sha256 = resp.headers.get("X-Manifest-SHA256")
    try:
        vault_id = soar.vault.create_attachment(
            soar.get_executing_container_id(),
            resp.content,
            file_name,
            metadata={"manifest_sha256": manifest_sha256} if manifest_sha256 else None,
        )
    except Exception as exc:
        return run.fail(f"Could not add the package to the vault: {exc}")

    record = {
        "vault_id": vault_id,
        "file_name": file_name,
        "size": len(resp.content),
        "manifest_sha256": manifest_sha256,
        "email_id": email_id,
    }
    run.update_summary(
        {
            "total_objects": 1,
            "vault_id": vault_id,
            "size": record["size"],
            "manifest_sha256": manifest_sha256,
        }
    )
    return run.succeed(
        GetEvidencePackageOutput(**record),
        f"Evidence package for email {email_id} saved to the vault ({record['size']} bytes)",
        GetEvidencePackageSummary,
    )


if __name__ == "__main__":
    app.cli()
