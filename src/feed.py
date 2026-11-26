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
"""EmailBadger's event feed as SOAR containers.

``on poll`` reads ``GET /api/v1/events?since=<cursor>&types=<csv>&limit=<n>``
and saves one container per event. The feed is the app's ingestion path: it
needs no inbound port on SOAR, it is replayable, and a re-poll is harmless
because every container's ``source_data_identifier`` is the event id
EmailBadger assigned. The app registers no webhook handler.
"""

from __future__ import annotations

from typing import Any

from .consts import (
    CEF_TYPES,
    DEFAULT_EVENT_TYPES,
    DEFAULT_PAGE_SIZE,
    DEFAULT_SEVERITY,
    IOC_CEF_FIELDS,
    MAX_PAGE_SIZE,
    SEVERITY_BY_RISK_LEVEL,
)


def event_types(configured: Any) -> str:
    """The asset's ``poll_event_types`` as the feed's ``types``, blanks dropped."""
    parts = (part.strip() for part in str(configured or DEFAULT_EVENT_TYPES).split(","))
    return ",".join(part for part in parts if part) or DEFAULT_EVENT_TYPES


def page_size(configured: Any) -> int:
    """The asset's ``poll_page_size``, held to the feed's own 1 to 500."""
    try:
        size = int(configured or DEFAULT_PAGE_SIZE)
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE
    return max(1, min(size, MAX_PAGE_SIZE))


def container_for(event: dict[str, Any], label: str) -> dict[str, Any]:
    """The container, with its artifacts, for one event of the feed.

    The envelope is the webhook's, unchanged, so a deployment that moves from
    webhooks to the feed keeps its playbooks. The whole envelope rides in
    ``data``; the fields a playbook branches on are CEF so the stock apps find
    them, the envelope's ``tenant`` block among them.
    """
    event_type = event.get("event_type") or "event"
    email = event.get("email") or {}
    verdict = event.get("verdict") or {}
    links = event.get("links") or {}
    event_id = (
        event.get("event_id")
        or f"{event_type}:{email.get('id')}:{event.get('timestamp')}"
    )

    subject = (
        email.get("subject")
        or email.get("message_id")
        or (f"email {email['id']}" if email.get("id") else None)
    )
    if verdict:
        name = f"EmailBadger {verdict.get('verdict') or verdict.get('risk_level') or event_type}"
        if subject:
            name += f": {subject}"
    else:
        run = event.get("run") or {}
        name = f"EmailBadger {event_type}"
        if run.get("detail"):
            name += f": {run['detail']}"
    severity = SEVERITY_BY_RISK_LEVEL.get(
        str(verdict.get("risk_level") or "").lower(), DEFAULT_SEVERITY
    )

    tenant = event.get("tenant") or {}
    cef = {
        "emailbadgerEventType": event_type,
        "emailbadgerEmailId": email.get("id"),
        # The envelope's tenant block, so a playbook routes per customer and
        # passes emailbadgerTenantId straight into an action's target_tenant_id.
        "emailbadgerTenantId": tenant.get("id"),
        "emailbadgerTenantName": tenant.get("name"),
        "messageId": email.get("message_id"),
        "fromEmail": email.get("sender"),
        "toEmail": email.get("recipient"),
        "emailSubject": email.get("subject"),
        "verdict": verdict.get("verdict"),
        "confidence": verdict.get("confidence"),
        "riskScore": verdict.get("risk_score"),
        "riskLevel": verdict.get("risk_level"),
        "previousVerdict": (event.get("previous_verdict") or {}).get("verdict"),
        "analysisUrl": links.get("analysis"),
    }
    authentication = event.get("authentication") or {}
    for check in ("spf", "dkim", "dmarc"):
        cef[check] = authentication.get(check)
    cef = {key: value for key, value in cef.items() if value is not None}

    artifacts = [
        {
            "name": event_type,
            "label": "event",
            "source_data_identifier": f"{event_id}:event",
            "severity": severity,
            "cef": cef,
            "cef_types": {key: types for key, types in CEF_TYPES.items() if key in cef},
            "data": event,
            "run_automation": False,
        }
    ]
    for index, ioc in enumerate(event.get("iocs") or []):
        ioc_type = str(ioc.get("type") or "").lower()
        field = IOC_CEF_FIELDS.get(ioc_type, "iocValue")
        ioc_cef = {
            field: ioc.get("value"),
            "iocType": ioc_type or None,
            "isMalicious": ioc.get("is_malicious"),
            "iocSeverity": ioc.get("severity"),
            "iocConfidence": ioc.get("confidence"),
            "tlp": ioc.get("tlp"),
            "pap": ioc.get("pap"),
        }
        artifacts.append(
            {
                "name": f"{ioc_type or 'ioc'} IOC",
                "label": "ioc",
                "source_data_identifier": f"{event_id}:ioc:{index}",
                "severity": SEVERITY_BY_RISK_LEVEL.get(
                    str(ioc.get("severity") or "").lower(), DEFAULT_SEVERITY
                ),
                "cef": {
                    key: value for key, value in ioc_cef.items() if value is not None
                },
                "cef_types": {
                    key: types for key, types in CEF_TYPES.items() if key in ioc_cef
                },
                "run_automation": False,
            }
        )
    # One automation run per container, once every artifact is in place.
    artifacts[-1]["run_automation"] = True

    description = f"{event_type} from {event.get('source') or 'EmailBadger'} at {event.get('timestamp')}"
    if event.get("iocs_truncated"):
        description += "; the IOC list is truncated, see links.iocs"
    return {
        "name": name[:255],
        "label": label,
        "source_data_identifier": str(event_id),
        "severity": severity,
        "description": description,
        "data": event,
        "artifacts": artifacts,
    }
