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
"""The routes, limits and names the app shares with EmailBadger."""

UPLOAD_PATH = "/api/v1/api-upload/"
ZIP_UPLOAD_PATH = "/api/v1/api-upload/zip"
VERDICT_PATH = "/api/v1/verdicts"
#: The 404 detail the verdict route gives for "no email this key can see has
#: that Message-ID". Any other 404 means the deployment does not serve the
#: route at all, which is a version or licence problem, not a missing email.
EMAIL_NOT_FOUND = "Email not found"
TIMEOUT_SECONDS = 120
#: Every call that is not an upload or a package download.
CALL_TIMEOUT_SECONDS = 30

#: The SOAR action API and the event feed.
EVENTS_PATH = "/api/v1/events"
EMAILS_PATH = "/api/v1/emails"
DEFAULT_EVENT_TYPES = "verdict.rendered,verdict.changed"
DEFAULT_PAGE_SIZE = 100
#: The feed's own ceiling on ``limit``; a larger ask is a 422.
MAX_PAGE_SIZE = 500
#: A scheduled poll drains a backlog page by page. This bounds one poll's work
#: so a feed that outruns the interval is caught up over several polls rather
#: than in one that never returns.
MAX_PAGES_PER_POLL = 20
VERDICTS = ("malicious", "suspicious", "benign")
#: The job read. Not an action-API route: its errors are the core's
#: ``{"detail": ...}``, so its "no such job" 404 is told apart from a missing
#: route by the text alone (FastAPI's own 404 says ``Not Found``).
JOBS_PATH = "/api/v1/api-upload/jobs"
JOB_NOT_FOUND = "Not found"
REANALYZE_JOB_KIND = "api_reanalyze"
BLOCKS_PATH = "/api/v1/blocks"
BLOCK_TYPES = ("sender_address", "sender_domain", "url", "domain", "ip", "hash")
#: Container severity from the envelope's ``verdict.risk_level``, the same
#: field ``get verdict`` surfaces, mapped onto SOAR's three stock severities.
#: An event without a risk level (``verdicts.bulk_rescored``) is ``medium``.
SEVERITY_BY_RISK_LEVEL = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}
DEFAULT_SEVERITY = "medium"
#: The CEF field an IOC of each type lands in, so stock SOAR playbooks and
#: reputation apps find it. Anything else goes under ``iocValue``.
IOC_CEF_FIELDS = {
    "url": "requestURL",
    "domain": "destinationDnsDomain",
    "hostname": "destinationDnsDomain",
    "ip": "destinationAddress",
    "ipv4": "destinationAddress",
    "ipv6": "destinationAddress",
    "hash": "fileHash",
    "md5": "fileHash",
    "sha1": "fileHash",
    "sha256": "fileHash",
    "email": "fromEmail",
}
CEF_TYPES = {
    "messageId": ["emailbadger message id"],
    "emailbadgerEmailId": ["emailbadger email id"],
    "emailbadgerTenantId": ["emailbadger tenant id"],
    "fromEmail": ["email"],
    "toEmail": ["email"],
    "requestURL": ["url"],
    "destinationDnsDomain": ["domain"],
    "destinationAddress": ["ip"],
    "fileHash": ["hash"],
}

#: Acting for a tenant. A Platform Admin's key names the customer tenant with
#: this query parameter on every route that takes it; a key bound to one tenant
#: needs none and may only name its own.
TENANT_PARAM = "target_tenant_id"
#: The ``on poll`` cursor slot for the key's own tenant (no ``target_tenant_id``).
#: A feed cursor belongs to the tenant it was issued for, and the feed refuses
#: it with any other (``400 cursor_invalid``), so the state keeps one per tenant.
OWN_TENANT_SLOT = "own"
#: A Platform Admin's key's reason for loading a customer's records. Given per call:
#: a reason from the console does not stand in, and a call without one reads
#: nothing and answers 428. The core recognises it only from a Platform Admin, so a
#: key bound to one tenant may send it and nothing changes.
REASON_PARAM = "platform_admin_reason"
REASON_HEADER = "X-Platform-Admin-Reason"
REASON_MIN_CHARS = 5
REASON_MAX_CHARS = 500
#: The 428 code keeps its pre-rename spelling: it is the core's value, not ours.
REASON_REQUIRED = "operator_reason_required"
#: The tenant refusals, each a distinct result a playbook branches on through
#: ``summary.refusal``. The first three carry the generic codes (``bad_request``,
#: ``forbidden``, ``not_found``) and are told apart by the contract's exact
#: ``detail``; the last two carry codes of their own. Keyed by
#: ``(status, error code or detail)``; the value is the name the app reports.
#: A core route has no ``error`` field, so its 428 carries the code under
#: ``detail``, as a dict; ``tenant_refusal`` reads both.
TENANT_REFUSALS_BY_DETAIL = {
    (
        400,
        "This install does not separate tenants, so a target tenant cannot be chosen.",
    ): "tenant_not_separated",
    (403, "You cannot act in another tenant."): "tenant_not_own",
    (404, "No such tenant."): "tenant_not_found",
    (
        409,
        "More than one tenant holds an email with that Message-ID. Name the one you mean with target_tenant_id.",
    ): "tenant_ambiguous",
}
TENANT_REFUSALS_BY_CODE = {
    (403, "soar_writeback_off"): "soar_writeback_off",
    (403, "analysis_cross_tenant"): "analysis_cross_tenant",
    (428, REASON_REQUIRED): REASON_REQUIRED,
}

TLS_ADVICE = "If this deployment uses a private CA, install it on the SOAR host rather than disabling verification."
