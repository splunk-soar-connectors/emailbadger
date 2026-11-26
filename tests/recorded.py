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
"""Recorded answers from the SOAR action API and the event feed.

Shapes come from EmailBadger's published SOAR contract and the routes behind
it, not from memory: every error is ``{"error", "detail", "request_id"}``, the feed page is
``{"events", "next_cursor"}``, and the envelopes are the webhook's, unchanged.
"""

from __future__ import annotations

import base64


def cursor(seq, issued="2026-10-24T22:00:00Z"):
    """A feed cursor as EmailBadger mints it: opaque base64 of ``seq:issued``."""
    return base64.urlsafe_b64encode(f"{seq}:{issued}".encode()).decode().rstrip("=")


def rendered(
    seq,
    *,
    email_id=None,
    verdict="malicious",
    risk_level="high",
    subject=None,
    iocs=None,
):
    """A ``verdict.rendered`` envelope; ``seq`` makes the id and the email unique."""
    email_id = email_id or 1000 + seq
    return {
        "event_type": "verdict.rendered",
        "event_id": f"{seq:032x}",
        "timestamp": f"2026-10-24T21:{seq % 60:02d}:00Z",
        "source": "https://eb.example.test",
        "tenant": {"id": 1, "name": "Default"},
        "email": {
            "id": email_id,
            "message_id": f"<msg-{seq}@sender.example>",
            "sender": "attacker@sender.example",
            "recipient": "victim@example.test",
            "subject": subject or f"Invoice {seq} overdue",
            "datetime_received": "2026-10-24T20:59:00Z",
        },
        "verdict": {
            "verdict": verdict,
            "confidence": 0.93,
            "confidence_label": "high",
            "contributing_factors": ["Sender domain registered 3 days ago"],
            "risk_score": 87 if risk_level == "high" else 12,
            "risk_level": risk_level,
        },
        "authentication": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        "iocs": iocs
        if iocs is not None
        else [
            {
                "type": "url",
                "value": "https://evil.example/login",
                "severity": "high",
                "confidence": 0.9,
                "is_malicious": True,
                "tlp": "amber",
                "pap": "amber",
            },
            {
                "type": "domain",
                "value": "evil.example",
                "severity": "medium",
                "confidence": 0.7,
                "is_malicious": True,
                "tlp": "amber",
                "pap": "amber",
            },
            {
                "type": "sha256",
                "value": "a" * 64,
                "severity": "low",
                "confidence": 0.5,
                "is_malicious": False,
                "tlp": "green",
                "pap": "green",
            },
        ],
        "iocs_truncated": False,
        "links": {
            "analysis": f"https://eb.example.test/#/emails/{email_id}",
            "iocs": f"https://eb.example.test/api/v1/emails/{email_id}/iocs",
            "activity": f"https://eb.example.test/api/v1/emails/{email_id}/activity",
            "eml": f"https://eb.example.test/api/v1/emails/{email_id}/eml",
        },
    }


def changed(seq, **kwargs):
    event = rendered(seq, **kwargs)
    event["event_type"] = "verdict.changed"
    event["previous_verdict"] = {"verdict": "suspicious", "confidence": 0.61}
    return event


def bulk_rescored(seq):
    return {
        "event_type": "verdicts.bulk_rescored",
        "event_id": f"{seq:032x}",
        "timestamp": "2026-10-24T21:30:00Z",
        "source": "https://eb.example.test",
        "tenant": {"id": 1, "name": "Default"},
        "run": {
            "id": 44,
            "kind": "retro_hunt",
            "detail": "Retro-hunt of feed abuse.ch",
        },
        "changed": 2,
        "counts_by_verdict": {"malicious": 2},
        "emails": [{"id": 1042, "previous": "suspicious", "current": "malicious"}],
        "emails_truncated": False,
        "links": {"affected": "https://eb.example.test/api/v1/emails?rescored_by=44"},
    }


def page(events, next_cursor):
    return {"events": events, "next_cursor": next_cursor}


# -- the action routes --------------------------------------------------------

VERDICT_SET = {
    "changed": True,
    "previous": "suspicious",
    "current": "malicious",
    "risk_score": 95,
    "risk_level": "critical",
    "verdict_events": 2,
    "external_actor": "soar-playbook:phish-triage",
    "external_reference": "container 4411",
}

VERDICT_UNCHANGED = {
    **VERDICT_SET,
    "changed": False,
    "previous": "malicious",
    "verdict_events": 1,
}

TICKET_PATCHED = {
    "created": False,
    "ticket": {
        "id": 9,
        "email_id": 1042,
        "system": "splunk_soar",
        "ticket_id": "4411",
        "ticket_url": "https://soar.example.test/mission/4411",
        "opened_at": "2026-10-24T20:00:00Z",
        "status": "closed",
        "reported_by": "api-key:soar",
        "first_reported_at": "2026-10-24T20:00:05Z",
        "last_reported_at": "2026-10-24T22:10:00Z",
        "last_reported_by": "api-key:soar",
        "status_reported_at": "2026-10-24T22:10:00Z",
    },
}

TICKET_REPORTED = {
    "created": True,
    "ticket": {
        **TICKET_PATCHED["ticket"],
        "status": "open",
        "status_reported_at": "2026-10-24T20:00:05Z",
        "last_reported_at": "2026-10-24T20:00:05Z",
    },
}

# POST /api/v1/emails/{email_id}/reanalyze: a 202 either way. A repeat while the
# job is queued or running answers the same job id with ``already_running``.
REANALYZE_QUEUED = {"job_id": 77, "status": "queued", "already_running": False}
REANALYZE_JOINED = {"job_id": 77, "status": "running", "already_running": True}


# GET /api/v1/api-upload/jobs/{job_id}: a background job as the route answers it.
# ``result`` is set only on ``succeeded`` and ``error`` only on ``failed`` and
# ``interrupted``. A re-analysis's ``result`` is ``run_reanalyze``'s outcome.
def job(status, *, kind="api_reanalyze", result=None, error=None):
    settled = status in ("succeeded", "failed", "interrupted")
    return {
        "id": 77,
        "kind": kind,
        "subject": "key:9:reanalyze:1042",
        "status": status,
        "settled": settled,
        "result": result if status == "succeeded" else None,
        "error": error if status in ("failed", "interrupted") else None,
        "created_at": "2026-10-25T13:00:00",
        "started_at": None if status == "queued" else "2026-10-25T13:00:01",
        "finished_at": "2026-10-25T13:00:40" if settled else None,
    }


REANALYSIS_RESULT = {
    "status": "processed",
    "old_email_id": 1042,
    "new_email_id": 1077,
    "message_id": "<msg-42@sender.example>",
    "old_score": 41,
    "new_score": 88,
    "old_verdict": "suspicious",
    "new_verdict": "malicious",
    "old_risk_level": "medium",
    "new_risk_level": "high",
    "vector_removed": True,
}
JOB_NOT_FOUND = {
    "detail": "Not found"
}  # the route's own 404: core shape, no ``error`` key

TIMELINE = {
    "email": {
        "id": 1042,
        "message_id": "<msg-42@sender.example>",
        "sender": "attacker@sender.example",
        "recipient": "victim@example.test",
        "subject": "Invoice 42 overdue",
    },
    "entries": [
        {
            "at": "2026-10-24T20:59:00Z",
            "kind": "received",
            "source": "gateway",
            "detail": "Delivered to inbox",
        },
        {
            "at": "2026-10-24T21:00:02Z",
            "kind": "analysed",
            "source": "emailbadger",
            "detail": "Verdict malicious",
        },
        {
            "at": "2026-10-24T21:04:00Z",
            "kind": "clicked",
            "source": "proxy",
            "detail": "https://evil.example/login",
        },
    ],
    "gaps": [{"source": "m365_audit", "reason": "No audit log provider is configured"}],
    "total": 3,
}

NOT_FOUND = ("not_found", "Email not found")
ROUTE_ABSENT = {
    "detail": "Not Found"
}  # FastAPI's own 404: no ``error`` key, no request id


# -- POST /api/v1/blocks ------------------------------------------------------

BLOCK_WRITTEN = {
    "id": 31,
    "block_type": "sender_domain",
    "value": "sender.example",
    "reason": "Credential-harvest campaign, container 4411",
    "created_by": "soar@example.test (API key eb_test)",
    "created_at": "2026-10-24T22:12:00Z",
    "expires_at": "2026-11-23T22:12:00Z",
    "source_email_id": 1042,
    "fleet": False,
    "review": None,
    "targets": [
        {
            "target": "m365_tenant_allow_block",
            "status": "applied",
            "detail": "Tenant Allow/Block List entry created",
        },
        {
            "target": "proofpoint_blocked_senders",
            "status": "pending",
            "detail": "Queued for the next sync",
        },
    ],
    "badge_state": "partly_blocked",
}

BLOCK_WRITTEN_PERMANENT = {
    **BLOCK_WRITTEN,
    "id": 32,
    "expires_at": None,
    "targets": [],
    "badge_state": "pending",
}

# The Block dialog's guardrails, as the route reports them. ``acknowledge`` ones
# can be accepted by re-sending with their codes; a ``refuse`` one cannot.
FINDING_WOULD_HAVE_CAUGHT = {
    "code": "would_have_caught",
    "severity": "acknowledge",
    "message": "This block would have caught 3 emails that were judged clean in the last 30 days.",
    "detail": {"clean_matches": 3, "window_days": 30},
}
FINDING_SAFELISTED = {
    "code": "safelisted",
    "severity": "acknowledge",
    "message": "sender.example is on the safelist.",
    "detail": {"safelist_entry_id": 7},
}
FINDING_PUBLIC_SUFFIX = {
    "code": "wrong_layer_public_suffix",
    "severity": "refuse",
    "message": "gmail.com is a public mail provider; block the sender address, not the domain.",
    "detail": {"suggest": "sender_address"},
}


def block_conflict(*findings):
    """The 409 ``conflict`` detail: nothing written, these findings stand."""
    return {
        "message": "This block was not written. See findings.",
        "findings": list(findings),
    }


ALREADY_BLOCKED = ("already_blocked", "sender.example is already blocked.")
BLOCKS_SCOPE_MISSING = (
    "api_key_scope_missing",
    (
        "This API key does not carry the 'blocks:write' scope. Mint a key with it ticked; scopes cannot be "
        "added to an existing key."
    ),
)
