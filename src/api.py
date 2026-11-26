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
"""One action's conversation with EmailBadger.

Every action runs over the API-key surface (``Authorization: Bearer eb_...``,
Enterprise tier and above). A licensed-down deployment answers 402 or 404
rather than 401, and every action says so rather than reporting a bad key.

The action API answers every error in one shape, ``{"error": <code>, "detail":
<text>, "request_id": <id>}``. The ``error`` code is what this module branches
on, and the request id goes into every failure message so a support thread can
find the audit row.

**For a tenant**: an MSSP Platform Admin's key names the customer with
``target_tenant_id``. It is set on the asset, or on the action, which wins. A
tenant refusal is named in ``summary.refusal``.

**A reason**: on an install that separates tenants, a Platform Admin's key's
call that loads a customer's records carries ``X-Platform-Admin-Reason``, or it
reads nothing and answers 428. ``platform_admin_reason`` is set on the asset,
or on the action, which wins, and goes on every call when set. The rule follows
the rows a call loads rather than ``target_tenant_id``, so a call naming no
tenant can need one too.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import requests
from soar_sdk.action_results import ActionResult
from soar_sdk.logging import getLogger

from .consts import (
    CALL_TIMEOUT_SECONDS,
    EMAIL_NOT_FOUND,
    REASON_HEADER,
    REASON_MAX_CHARS,
    REASON_MIN_CHARS,
    REASON_PARAM,
    REASON_REQUIRED,
    TENANT_PARAM,
    TENANT_REFUSALS_BY_CODE,
    TENANT_REFUSALS_BY_DETAIL,
    TLS_ADVICE,
)


if TYPE_CHECKING:
    from soar_sdk.abstract import SOARClient
    from soar_sdk.action_results import ActionOutput
    from soar_sdk.asset import BaseAsset
    from soar_sdk.params import Params


logger = getLogger()

NON_JSON = "EmailBadger returned a non-JSON response"


def whole_number(raw: Any) -> int | None:
    """``raw`` as a positive whole number, or ``None``.

    SOAR hands a numeric field over as an int or a float (``5.0``), a playbook
    as a string. Anything that is not a whole number is ``None``, because a
    truncated ``5.7`` would act on record 5.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        number = raw
    elif isinstance(raw, float):
        if not raw.is_integer():
            return None
        number = int(raw)
    else:
        text = str(raw if raw is not None else "").strip()
        if text.isdigit():
            number = int(text)
        else:
            try:
                value = float(text)
            except ValueError:
                return None
            if not value.is_integer():
                return None
            number = int(value)
    return number if number > 0 else None


def is_blank(value: Any) -> bool:
    return value is None or value == ""


def error_parts(payload: Any) -> tuple[Any, Any, Any]:
    """``(code, detail, request_id)`` from an action-API error body.

    ``detail`` is flattened to text: the feed's 410 carries a dict, a
    request-validation failure a list, everything else a string.
    """
    if not isinstance(payload, dict):
        return None, None, None
    detail = payload.get("detail")
    if isinstance(detail, dict):
        detail = detail.get("message") or json.dumps(detail, sort_keys=True)
    elif isinstance(detail, list):
        detail = "; ".join(
            str(item.get("msg", item)) if isinstance(item, dict) else str(item)
            for item in detail
        )
    return payload.get("error"), detail, payload.get("request_id")


def tenant_refusal(status: int, payload: Any) -> str | None:
    """The app's name for a tenant refusal, or ``None`` if this is not one.

    Matched on the contract's code where it has one of its own, else on its
    exact ``detail``. The upload routes answer some refusals with ``message``
    rather than ``detail``, so both are read. An action-API route puts the code
    in ``error``; a core route's 428 has only ``detail.code``.
    """
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail")
    nested = detail.get("code") if isinstance(detail, dict) else None
    named = TENANT_REFUSALS_BY_CODE.get((status, payload.get("error") or nested))
    if named:
        return named
    for field in ("detail", "message"):
        text = payload.get(field)
        if isinstance(text, str):
            named = TENANT_REFUSALS_BY_DETAIL.get((status, text.strip()))
            if named:
                return named
    return None


def explain_tenant_refusal(refusal: str, tenant: Any) -> str | None:
    """What to do about a tenant refusal, for the analyst reading the action."""
    named = f"tenant {tenant}" if tenant is not None else "the API key's own tenant"
    if refusal == "tenant_not_separated":
        return (
            f"This EmailBadger install does not separate tenants, so target_tenant_id {tenant} cannot "
            "be chosen. Clear target_tenant_id on the action and the asset."
        )
    if refusal == "tenant_not_own":
        return (
            f"This API key's owner is bound to one tenant and target_tenant_id names another ({tenant}). "
            "Use a key minted in that tenant, or a Platform Admin's key."
        )
    if refusal == "tenant_not_found":
        return f"No EmailBadger tenant has id {tenant}. Check target_tenant_id on the action and the asset."
    if refusal == "soar_writeback_off":
        return (
            f"SOAR write-back is off in {named}, so nothing was written. A Tenant Admin of that tenant "
            "turns on 'SOAR write-back allowed' (API Keys page); for a Platform Admin's key it is the "
            "customer's switch that decides, not the Platform Admin's."
        )
    if refusal == "analysis_cross_tenant":
        return (
            f"A re-analysis cannot run across tenants: it would spend {named}'s analysis quota on a "
            "Platform Admin's key, so nothing was queued. Run it from an asset whose key was minted in that tenant."
        )
    if refusal == "tenant_ambiguous":
        return (
            "More than one tenant holds an email with that Message-ID, so neither was returned. Set "
            "target_tenant_id on the action, or on the asset, to the customer you mean."
        )
    if refusal == REASON_REQUIRED:
        customer = f"tenant {tenant}" if tenant is not None else "a customer tenant"
        return (
            f"This call loads records of {customer} with a Platform Admin's key, so it needs a reason, and "
            f"it read nothing. Set {REASON_PARAM} on the action, or on the asset, to {REASON_MIN_CHARS} to "
            f"{REASON_MAX_CHARS} characters; it is recorded in the customer's audit log under Operator Access."
        )
    return None


def explain_status(status_code: int) -> str:
    """Turn an upload route's HTTP status into something an analyst can act on.

    The tier gate is the reason this exists: a 402/404 on a *valid* key means
    the deployment is not licensed for this surface, and reporting that as an
    auth failure sends the analyst to rotate a key that is fine.
    """
    if status_code == 401:
        return "Authentication failed — the API key is wrong, revoked, or disabled."
    if status_code in (402, 404):
        return (
            "EmailBadger accepted the request but the programmatic upload surface is "
            "unavailable. It requires Enterprise tier or above; check the deployment's licence."
        )
    if status_code == 429:
        return "Rate limited by EmailBadger. Retry with backoff."
    return f"Unexpected HTTP {status_code} from EmailBadger."


def explain_action_error(
    resp: Any, payload: Any, path: str, email_id: Any = None
) -> str:
    """Turn an action-API refusal into something an analyst can act on.

    The tier gate and the scope gate are the reason this exists: a 402 on a
    valid key is a licence problem, a 403 ``api_key_scope_missing`` is a key
    minted without the scope, and a 404 is either an email this key cannot
    see or a deployment without the route. Reporting any of them as "bad
    key" sends the analyst to rotate a key that is fine.
    """
    code, detail, request_id = error_parts(payload)
    status = resp.status_code
    if status == 401:
        message = "Authentication failed — the API key is wrong, revoked, or disabled."
    elif status == 402:
        message = "EmailBadger accepted the key but this surface requires Enterprise tier or above; check the deployment's licence."
    elif status == 403 and code == "api_key_scope_missing":
        message = f"The API key lacks the scope this action needs. {detail}"
    elif status == 403:
        message = f"EmailBadger refused the request: {detail or 'forbidden'}."
    elif status == 404 and (code == "not_found" or detail == EMAIL_NOT_FOUND):
        if detail == EMAIL_NOT_FOUND:
            message = (
                f"No email with id {email_id} is visible to this API key's user. It was not "
                "submitted, it was re-analysed under a new id, or it belongs to a user this key "
                "cannot see."
            )
        else:
            message = (
                f"{detail or 'Not found'}: nothing this API key's user can see matches."
            )
    elif status == 404:
        message = f"This EmailBadger deployment does not serve {path}. It needs a release that includes it, on Enterprise tier or above."
    elif status == 409 and code == "verdict_not_rendered":
        message = f"Email {email_id} has no verdict or risk score yet (its analysis has not finished). Retry once get verdict answers."
    elif status == 409 and code == "idempotency_in_progress":
        message = "An identical request is still being processed. Retry shortly."
    elif status == 409 and code == "idempotency_conflict":
        message = "The Idempotency-Key was used within the last 24 hours for a different request. Use a new key for a new request."
    elif status == 409:
        message = f"EmailBadger reports a conflict: {detail or code}."
    elif status == 410 and code == "source_unavailable":
        message = (
            f"Email {email_id}'s stored source file is gone (retention removed it, or it was "
            "never kept), so there is nothing to re-analyse and nothing was queued. Upload the "
            "email again instead."
        )
    elif status == 410:
        message = f"EmailBadger reports the request is stale ({code}): {detail}."
    elif status == 422:
        message = f"EmailBadger rejected the request: {detail or 'validation error'}."
    elif status == 429:
        retry_after = resp.headers.get("Retry-After")
        message = "Rate limited by EmailBadger"
        message += (
            f"; retry after {retry_after} seconds."
            if retry_after
            else ". Retry with backoff."
        )
    elif status == 400:
        message = (
            f"EmailBadger rejected the request ({code or 'bad_request'}): {detail}."
        )
    else:
        message = f"Unexpected HTTP {status} from EmailBadger"
        message += f": {detail}." if detail else "."
    if request_id:
        message += f" (request id {request_id})"
    return message


def replayed(resp: Any) -> bool:
    """Whether EmailBadger answered from its idempotency store."""
    return (resp.headers.get("Idempotent-Replay") or "").lower() == "true"


class Run:
    """One action run: the asset's connection, the action's tenant and reason, and its result.

    An action ends with :meth:`succeed` or :meth:`fail`. A success is the
    action's typed output, with the summary and message set on the SOAR client.
    A failure is an ``ActionResult`` rather than an ``ActionFailure``, because a
    failed action still carries a summary a playbook branches on
    (``summary.refusal``, ``summary.target_tenant_id``), and an exception
    carries only a message.
    """

    def __init__(
        self, soar: SOARClient, asset: BaseAsset, params: Params | None = None
    ) -> None:
        self.soar = soar
        self.asset = asset
        self.params = params
        self.param: dict[str, Any] = params.model_dump() if params is not None else {}
        self.summary: dict[str, Any] = {}
        self.data: list[dict[str, Any]] = []
        # rstrip: an operator pasting a URL with a trailing slash would
        # otherwise produce //api/v1/... , which some proxies 404 rather than
        # normalise, a confusing failure to debug from a SOAR action result.
        self.base_url: str = str(asset.base_url).rstrip("/")
        verify = asset.verify_server_cert
        self.verify: bool = True if verify is None else bool(verify)
        self.reason: str | None = None

    # -- the result ------------------------------------------------------

    def update_summary(self, values: dict[str, Any]) -> None:
        self.summary.update(values)

    def add_data(self, item: dict[str, Any]) -> None:
        self.data.append(item)

    def succeed(
        self, output: ActionOutput, message: str, summary_cls: type[ActionOutput]
    ) -> ActionOutput:
        self.soar.set_summary(summary_cls(**self.summary))
        self.soar.set_message(message)
        return output

    def succeed_without_data(self, message: str) -> ActionResult:
        """A success with a summary and no data item: nothing was read or written."""
        result = ActionResult(True, message, param=self.param)
        result.set_summary(dict(self.summary))
        return result

    def fail(self, message: str) -> ActionResult:
        result = ActionResult(False, message, param=self.param)
        for item in self.data:
            result.add_data(item)
        if self.summary:
            result.set_summary(dict(self.summary))
        return result

    # -- acting for a tenant ---------------------------------------------

    def settle_reason(self) -> str | None:
        """Settle this action's reason for :meth:`headers`; an error message, or ``None``.

        The action's own ``platform_admin_reason`` wins; otherwise the asset's.
        Refused here rather than sent, because a header is the one place a
        playbook's text can break the request: a control character or one
        outside Latin-1 raises inside the HTTP client instead of answering.
        Whitespace, newlines included, is collapsed as the core collapses it,
        so the length judged is the length it will judge.
        """
        self.reason = None
        raw = self.param.get(REASON_PARAM)
        source = "action parameter"
        if is_blank(raw):
            raw = getattr(self.asset, REASON_PARAM, None)
            source = "asset setting"
        if is_blank(raw):
            return None
        text = " ".join(str(raw).split())
        if not REASON_MIN_CHARS <= len(text) <= REASON_MAX_CHARS:
            return f"{REASON_PARAM} ({source}) must be {REASON_MIN_CHARS} to {REASON_MAX_CHARS} characters, got {len(text)}"
        try:
            text.encode("latin-1")
        except UnicodeEncodeError:
            return f"{REASON_PARAM} ({source}) must be Latin-1 text, because it travels in a request header"
        if not text.isprintable():
            return f"{REASON_PARAM} ({source}) must not contain control characters"
        self.reason = text
        return None

    def target_tenant(
        self, *, from_action: bool = True
    ) -> tuple[int | None, str | None]:
        """``(tenant id or None, error message or None)`` for this action.

        The action's own ``target_tenant_id`` wins; otherwise the asset's. An
        asset per customer sets it once on the asset; one shared asset leaves
        it empty and a playbook passes the container's ``emailbadgerTenantId``
        on each action. ``None`` sends no parameter, so a key bound to one
        tenant works exactly as before. The id goes into the summary, so a
        playbook routing many customers through one asset sees which it acted in.

        The reason is settled here too, so every action that names a tenant
        carries one and a bad value stops the action the same way.
        ``on poll``'s parameters are fixed by SOAR, so it reads the asset's only.
        """
        bad_reason = (
            self.settle_reason() if from_action else self._settle_asset_reason()
        )
        if bad_reason:
            return None, bad_reason
        raw = self.param.get(TENANT_PARAM) if from_action else None
        source = "action parameter"
        if is_blank(raw):
            raw = getattr(self.asset, TENANT_PARAM, None)
            source = "asset setting"
        if is_blank(raw):
            return None, None
        tenant = whole_number(raw)
        if tenant is None:
            if isinstance(raw, float) and raw.is_integer():
                raw = int(raw)
            return (
                None,
                f"target_tenant_id ({source}) must be a positive whole number, got {raw!r}",
            )
        self.update_summary({TENANT_PARAM: tenant})
        return tenant, None

    def _settle_asset_reason(self) -> str | None:
        saved, self.param = self.param, {}
        try:
            return self.settle_reason()
        finally:
            self.param = saved

    @staticmethod
    def tenant_params(
        tenant: int | None, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """``params`` with ``target_tenant_id`` added when there is a tenant to name."""
        merged = dict(params or {})
        if tenant is not None:
            merged[TENANT_PARAM] = tenant
        return merged

    def headers(self) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.asset.api_key}"}
        if self.reason:
            headers[REASON_HEADER] = self.reason
        return headers

    # -- failing as a refusal --------------------------------------------

    def refuse_for_tenant(
        self,
        refusal: str,
        tenant: Any,
        request_id: Any = None,
        payload: Any = None,
    ) -> ActionResult:
        """Fail the action as a named tenant refusal: ``summary.refusal`` carries the name."""
        detail = payload.get("detail") if isinstance(payload, dict) else None
        if refusal == REASON_REQUIRED and isinstance(detail, dict):
            # The 428 names the tenant whose rows it reached, which is the only
            # word of it when the call named none, and says why a reason that
            # was sent did not count.
            if tenant is None:
                tenant = detail.get("tenant_id")
            why = detail.get("message")
            message = explain_tenant_refusal(refusal, tenant) or ""
            if why:
                message += f" EmailBadger said: {why}"
        else:
            message = explain_tenant_refusal(refusal, tenant) or ""
        if request_id:
            message += f" (request id {request_id})"
        self.update_summary({"refusal": refusal})
        return self.fail(message)

    def action_failed(
        self,
        resp: Any,
        payload: Any,
        path: str,
        email_id: Any = None,
        tenant: Any = None,
    ) -> ActionResult:
        """Fail with an action-API refusal, naming a tenant refusal when it is one."""
        refusal = tenant_refusal(resp.status_code, payload)
        if refusal:
            _, _, request_id = error_parts(payload)
            return self.refuse_for_tenant(refusal, tenant, request_id, payload)
        return self.fail(explain_action_error(resp, payload, path, email_id))

    def upload_failed(
        self, resp: Any, tenant: Any, payload: Any = None
    ) -> ActionResult:
        """Fail an upload: a tenant refusal by name, anything else through ``explain_status``."""
        if payload is None:
            try:
                payload = resp.json()
            except ValueError:
                payload = None
        refusal = tenant_refusal(resp.status_code, payload)
        if refusal:
            return self.refuse_for_tenant(refusal, tenant, payload=payload)
        return self.fail(explain_status(resp.status_code))

    # -- talking to EmailBadger ------------------------------------------

    def call(
        self, method: str, path: str, **kwargs: Any
    ) -> tuple[Any, Any, str | None]:
        """One request to EmailBadger: ``(response, payload, unreachable)``.

        ``payload`` is the decoded JSON body when there is one (every error,
        and every success that is not a file), else ``None``. ``unreachable``
        is the message to fail with when no response came back at all.
        """
        headers = dict(self.headers())
        headers.update(kwargs.pop("headers", None) or {})
        timeout = kwargs.pop("timeout", CALL_TIMEOUT_SECONDS)
        try:
            resp = requests.request(
                method,
                self.base_url + path,
                headers=headers,
                verify=self.verify,
                timeout=timeout,
                **kwargs,
            )
        except requests.exceptions.SSLError as exc:
            return None, None, f"TLS verification failed: {exc}. {TLS_ADVICE}"
        except requests.exceptions.RequestException as exc:
            return None, None, f"Could not reach EmailBadger: {exc}"

        payload = None
        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "json" in content_type or resp.status_code >= 400:
            try:
                payload = resp.json()
            except ValueError:
                payload = None
        return resp, payload, None
