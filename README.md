# EmailBadger

Publisher: EmailBadger, LLC <br>
Connector Version: 0.8.0 <br>
Product Vendor: EmailBadger <br>
Product Name: EmailBadger <br>
Minimum Product Version: 7.0.0

Submit suspicious email to EmailBadger for analysis and read back its verdict.

## Before you start

The app reaches EmailBadger's API with an API key (`eb_...`), on the Enterprise tier or above. A
deployment on a lower licence answers 402, and the app reports a licence problem rather than a bad
key.

### API key scopes

Mint the key with the scopes for the actions you will run. Scopes cannot be added to an existing
key, and an action whose scope is missing fails with `api_key_scope_missing`, naming the scope.

| Action | Scope |
|--------|-------|
| on poll | `events:read` |
| get timeline, get evidence package | `evidence:read` |
| set verdict | `verdicts:write` |
| reanalyze | `analysis:write` |
| report ticket, update ticket | `external_tickets:write` |
| record block | `blocks:write` |
| test connectivity, detonate file, analyze archive, get verdict, get job | none |

### Ingesting events

`on poll` reads EmailBadger's event feed and saves one container per event. It needs no inbound port
on SOAR. A re-poll is harmless, because each container's source data identifier is the event id
EmailBadger assigned. The app registers no webhook handler.

### Several customer tenants

On an install that separates tenants, a Platform Admin's key names the customer with `target_tenant_id`,
set on the asset or on the action, and the action's value wins. A call that loads a customer's
records also needs `platform_admin_reason`, 5 to 500 characters, set the same way. Without one the call
reads nothing and answers 428. `on poll` uses the asset's reason.

### TLS

The app verifies EmailBadger's certificate unless `verify_server_cert` is off. For a deployment
behind a private CA, add the CA to SOAR's trust store rather than turning verification off.

## Port Information

The app uses HTTP/HTTPS to reach EmailBadger.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

### Configuration variables

This table lists the configuration variables required to operate EmailBadger. These variables are specified when configuring a EmailBadger asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | EmailBadger base URL (e.g. https://emailbadger.example.com) |
**api_key** | required | password | API key (eb\_...). Enterprise tier or above. |
**verify_server_cert** | optional | boolean | Verify server certificate |
**poll_event_types** | optional | string | Event types on poll ingests, comma-separated (default verdict.rendered,verdict.changed; add verdicts.bulk_rescored for re-score runs) |
**poll_page_size** | optional | numeric | Events fetched per request on poll (1-500) |
**target_tenant_id** | optional | numeric | Customer tenant this asset acts for (target_tenant_id; a Platform Admin's key only). Leave blank for the key's own tenant. The action parameter of the same name overrides it. |
**platform_admin_reason** | optional | string | Why a Platform Admin's key loads a customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). An installation that separates tenants refuses those reads without one, on poll included. The action parameter of the same name overrides it. |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the base URL and API key by calling EmailBadger.

POST with no file: the upload route rejects it, but \*how\* it rejects
distinguishes every case that matters: 401 bad key, 402/404 unlicensed, a
tenant refusal, a 4xx with a body reachable and authenticated. A GET would
answer 405 for all of them and prove only that a server answered. The
asset's tenant goes with it: the route judges it before it looks for the
file, so a tenant the key cannot act in fails here rather than on the first
real action. <br>
[detonate file](#action-detonate-file) - Submit an .eml from the vault to EmailBadger and return its verdict <br>
[analyze archive](#action-analyze-archive) - Submit a .zip of .eml/.msg files from the vault and return a verdict for each <br>
[get verdict](#action-get-verdict) - Read the current verdict on an email already submitted to EmailBadger <br>
[on poll](#action-on-poll) - Ingest the verdict event feed: one container per event.

The cursor EmailBadger returns is saved after every page, once that page's
containers are in SOAR, so a poll that dies mid-backlog resumes from the
last page it saved, and the events of the page it was on are re-saved
harmlessly because each container's `source_data_identifier` is the
event id.

\*\*A 410 is never a silent empty poll.\*\* A cursor older than the feed's
retention (the asset was off for longer than that) is answered with the
oldest cursor still valid; the poll resumes from it and says so in the
progress log. It claims no loss: a cursor idle on a feed that stayed empty
gets the same 410 with nothing missed, and the feed cannot tell the two
apart, so the message says only that any events that aged out were not
ingested.

A manual poll (Poll Now) honours `container_count`; a scheduled poll
drains up to `MAX_PAGES_PER_POLL` pages. The first poll of a new asset
has no cursor and starts from the oldest retained event.

`on poll`'s parameters are fixed by SOAR, so its tenant and its reason
are the asset's. <br>
[set verdict](#action-set-verdict) - Set the verdict on an email as an analyst's mark would, recorded as this playbook's decision <br>
[record block](#action-record-block) - Block an indicator in EmailBadger through the Block dialog's own guardrails; a guardrail that wants an acknowledgement is a result, not a failure <br>
[update ticket](#action-update-ticket) - Write a SOAR ticket's status, URL or opened time back onto the email's case <br>
[report ticket](#action-report-ticket) - Report a ticket this SOAR opened for an email, so the email shows it. Safe to repeat: the same ticket reported again updates it <br>
[reanalyze](#action-reanalyze) - DESTRUCTIVE: re-run the analysis of an email from its stored source. Deletes the existing analysis and returns the id of the job that replaces it <br>
[get job](#action-get-job) - Read a job this asset queued, such as a re-analysis: its status and, once settled, the old and new email id, score and verdict <br>
[get timeline](#action-get-timeline) - Read the forensic timeline of an email <br>
[get evidence package](#action-get-evidence-package) - Download the sealed evidence package of an email into the vault

## action: 'test connectivity'

Validate the base URL and API key by calling EmailBadger.

POST with no file: the upload route rejects it, but \*how\* it rejects
distinguishes every case that matters: 401 bad key, 402/404 unlicensed, a
tenant refusal, a 4xx with a body reachable and authenticated. A GET would
answer 405 for all of them and prove only that a server answered. The
asset's tenant goes with it: the route judges it before it looks for the
file, so a tenant the key cannot act in fails here rather than on the first
real action.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'detonate file'

Submit an .eml from the vault to EmailBadger and return its verdict

Type: **investigate** <br>
Read only: **False**

Uploads the file to /api/v1/api-upload/. EmailBadger de-duplicates by message id: re-submitting an email it has already analysed returns status 'duplicate' with the existing analysis rather than re-running it, so this action is safe to retry.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of the .eml file to submit | string | `vault id` |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.status | string | | processed duplicate |
action_result.data.\*.message_id | string | `emailbadger message id` | |
action_result.data.\*.subject | string | | |
action_result.data.\*.risk_score | numeric | | |
action_result.data.\*.risk_level | string | | |
action_result.data.\*.verdict | string | | |
action_result.data.\*.verdict_confidence | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.risk_level | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'analyze archive'

Submit a .zip of .eml/.msg files from the vault and return a verdict for each

Type: **investigate** <br>
Read only: **False**

Uploads the archive to /api/v1/api-upload/zip, which analyses every entry inline and returns one result per email. Partial failure is normal and is reported rather than hidden: `processed`, `duplicates` and `errors` are all in the summary, and each failed entry appears in action_result.data.\*.error_details with its filename. The action fails only when nothing was analysed at all. An encrypted archive answers 422 with password_required: supply the password parameter rather than treating it as a bad key.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of the .zip archive to submit | string | `vault id` |
**password** | optional | Password for an encrypted archive | password | |
**skip_ai_analysis** | optional | Bypass the LLM analysis pipeline for every email in the archive | boolean | |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.password | string | | |
action_result.parameter.skip_ai_analysis | boolean | | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.processed | numeric | | |
action_result.data.\*.duplicates | numeric | | |
action_result.data.\*.errors | numeric | | |
action_result.data.\*.results.\*.message_id | string | | |
action_result.data.\*.results.\*.subject | string | | |
action_result.data.\*.results.\*.risk_score | numeric | | |
action_result.data.\*.results.\*.risk_level | string | | |
action_result.data.\*.error_details.\*.filename | string | | |
action_result.data.\*.error_details.\*.error | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.processed | numeric | | |
action_result.summary.duplicates | numeric | | |
action_result.summary.errors | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get verdict'

Read the current verdict on an email already submitted to EmailBadger

Type: **investigate** <br>
Read only: **True**

Reads GET /api/v1/verdicts with the Message-ID that detonate file returned. The verdict at upload can change afterwards (a sandbox run finishes, a re-score fills a provider gap, or an analyst sets one), so a playbook calls this to ask again. The answer is verdict fields only: the verdict, its confidence, the risk score and level, and whether coverage is complete. EmailBadger never returns the email's content here. coverage_complete false means the verdict is provisional. A 404 either means no email with that Message-ID is visible to the key's user, or that the deployment does not serve the route; the action says which. Enterprise tier and above. A Platform Admin's key names the customer with target_tenant_id; with none, the answer is whichever one tenant holds that Message-ID, and a Message-ID in more than one is refused as tenant_ambiguous.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**message_id** | required | Message-ID of the submitted email, angle brackets included, as detonate file returned it | string | `emailbadger message id` |
**target_tenant_id** | optional | Customer tenant to read (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or whichever one tenant holds that Message-ID. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.message_id | string | `emailbadger message id` | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.email_id | numeric | `emailbadger email id` | |
action_result.data.\*.message_id | string | `emailbadger message id` | |
action_result.data.\*.verdict | string | | |
action_result.data.\*.confidence | numeric | | |
action_result.data.\*.confidence_label | string | | |
action_result.data.\*.risk_score | numeric | | |
action_result.data.\*.risk_level | string | | |
action_result.data.\*.coverage_complete | boolean | | True False |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.verdict | string | | |
action_result.summary.risk_level | string | | |
action_result.summary.coverage_complete | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

Ingest the verdict event feed: one container per event.

The cursor EmailBadger returns is saved after every page, once that page's
containers are in SOAR, so a poll that dies mid-backlog resumes from the
last page it saved, and the events of the page it was on are re-saved
harmlessly because each container's `source_data_identifier` is the
event id.

\*\*A 410 is never a silent empty poll.\*\* A cursor older than the feed's
retention (the asset was off for longer than that) is answered with the
oldest cursor still valid; the poll resumes from it and says so in the
progress log. It claims no loss: a cursor idle on a feed that stayed empty
gets the same 410 with nothing missed, and the feed cannot tell the two
apart, so the message says only that any events that aged out were not
ingested.

A manual poll (Poll Now) honours `container_count`; a scheduled poll
drains up to `MAX_PAGES_PER_POLL` pages. The first poll of a new asset
has no cursor and starts from the oldest retained event.

`on poll`'s parameters are fixed by SOAR, so its tenant and its reason
are the asset's.

Type: **ingest** <br>
Read only: **True**

Callback action for the on_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of container records to query for. | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for. | numeric | |
**container_id** | optional | Comma-separated list of container IDs to limit the ingestion to. | string | |

#### Action Output

No Output

## action: 'set verdict'

Set the verdict on an email as an analyst's mark would, recorded as this playbook's decision

Type: **contain** <br>
Read only: **False**

POST /api/v1/emails/{email_id}/verdict. external_actor and external_reference are stored with the verdict, the audit row and the verdict.changed event, so a SOAR decision is told apart from an analyst's. A retry after a timeout is safe without a key: the route is idempotent on email and external_reference for 24 hours, so the same verdict again replays the stored answer and fires nothing, and a different verdict under the same reference is applied. An Idempotency-Key goes out only when you supply one; summary.replayed says when a stored answer came back. 409 verdict_not_rendered means the analysis has not finished yet. Needs the verdicts:write scope; Enterprise tier and above.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_id** | required | EmailBadger's numeric id of the email (email_id from get verdict, or emailbadgerEmailId on a polled container's artifact) | numeric | `emailbadger email id` |
**verdict** | required | The verdict to set | string | |
**external_actor** | required | Who decided, as EmailBadger should record it (a playbook or analyst name) | string | |
**external_reference** | required | Where the decision lives in SOAR (container or case id, or a URL) | string | |
**reason** | optional | Why, up to 500 characters (recorded with the verdict) | string | |
**idempotency_key** | optional | Idempotency-Key for a replayed answer within 24 hours; not sent when left blank. A key replays the first answer for every later call that sends it, so use a new one for each intended write | string | |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_id | numeric | `emailbadger email id` | |
action_result.parameter.verdict | string | | |
action_result.parameter.external_actor | string | | |
action_result.parameter.external_reference | string | | |
action_result.parameter.reason | string | | |
action_result.parameter.idempotency_key | string | | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.changed | boolean | | True False |
action_result.data.\*.previous | string | | |
action_result.data.\*.current | string | | |
action_result.data.\*.risk_score | numeric | | |
action_result.data.\*.risk_level | string | | |
action_result.data.\*.verdict_events | numeric | | |
action_result.data.\*.external_actor | string | | |
action_result.data.\*.external_reference | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.changed | boolean | | True False |
action_result.summary.previous | string | | |
action_result.summary.current | string | | |
action_result.summary.risk_level | string | | |
action_result.summary.replayed | boolean | | True False |
action_result.summary.idempotency_key | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'record block'

Block an indicator in EmailBadger through the Block dialog's own guardrails; a guardrail that wants an acknowledgement is a result, not a failure

Type: **contain** <br>
Read only: **False**

POST /api/v1/blocks. Writes a manual block and offers it to every configured enforcement target; created_by names the API key. summary.outcome is one of: written (the block exists; badge_state and the per-target rows say how far it is enforced), acknowledgement_required (EmailBadger's guardrails want the caller to accept something first, e.g. a safelisted domain or a block that would have caught clean mail; nothing was written; the findings are in the data and summary.acknowledge is the exact value to pass back in acknowledge to write it), already_blocked (a live block stands; nothing written). A finding of severity refuse cannot be acknowledged and fails the action. Expiry is the install's default (30 days unless changed) when neither expires_in_days nor never_expires is given. A retry after a timeout is safe without a key: the block it wrote is live, so the repeat answers already_blocked and writes nothing. An Idempotency-Key goes out only when you supply one. Needs the blocks:write scope; Enterprise tier and above.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**block_type** | required | What kind of indicator value is | string | |
**value** | required | The indicator to block (an address, domain, URL, IP or file hash) | string | `email` `domain` `url` `ip` `hash` |
**reason** | optional | Why, as the next analyst should read it on the block list | string | |
**source_email_id** | optional | EmailBadger's numeric id of the email the indicator came from (enables the would-have-caught and DMARC guardrails) | numeric | `emailbadger email id` |
**expires_in_days** | optional | Days until the block expires; the install default (30 unless changed) when blank | numeric | |
**never_expires** | optional | Block permanently (not with expires_in_days) | boolean | |
**acknowledge** | optional | Comma-separated guardrail finding codes this playbook accepts; pass summary.acknowledge from an acknowledgement_required result | string | |
**idempotency_key** | optional | Idempotency-Key for a replayed answer within 24 hours; not sent when left blank. A key replays the first answer for every later call that sends it, so use a new one for each intended write | string | |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.block_type | string | | |
action_result.parameter.value | string | `email` `domain` `url` `ip` `hash` | |
action_result.parameter.reason | string | | |
action_result.parameter.source_email_id | numeric | `emailbadger email id` | |
action_result.parameter.expires_in_days | numeric | | |
action_result.parameter.never_expires | boolean | | |
action_result.parameter.acknowledge | string | | |
action_result.parameter.idempotency_key | string | | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.block_type | string | | |
action_result.data.\*.value | string | | |
action_result.data.\*.reason | string | | |
action_result.data.\*.created_by | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.expires_at | string | | |
action_result.data.\*.source_email_id | numeric | `emailbadger email id` | |
action_result.data.\*.fleet | boolean | | True False |
action_result.data.\*.badge_state | string | | |
action_result.data.\*.targets.\*.target | string | | |
action_result.data.\*.targets.\*.status | string | | |
action_result.data.\*.targets.\*.detail | string | | |
action_result.data.\*.findings.\*.code | string | | |
action_result.data.\*.findings.\*.severity | string | | |
action_result.data.\*.findings.\*.message | string | | |
action_result.data.\*.acknowledge | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.outcome | string | | written acknowledgement_required already_blocked |
action_result.summary.written | boolean | | True False |
action_result.summary.block_id | numeric | | |
action_result.summary.badge_state | string | | |
action_result.summary.expires_at | string | | |
action_result.summary.targets | numeric | | |
action_result.summary.acknowledge | string | | |
action_result.summary.findings | numeric | | |
action_result.summary.replayed | boolean | | True False |
action_result.summary.idempotency_key | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update ticket'

Write a SOAR ticket's status, URL or opened time back onto the email's case

Type: **generic** <br>
Read only: **False**

PATCH /api/v1/emails/{email_id}/external-tickets/{system}/{ticket_id}. Only the fields given are sent; at least one is required. 404 means either no such email is visible to the key's user or no such ticket is on it; the action says which when EmailBadger does. This action never creates a ticket; report ticket does. Needs the external_tickets:write scope; Enterprise tier and above.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_id** | required | EmailBadger's numeric id of the email (email_id from get verdict, or emailbadgerEmailId on a polled container's artifact) | numeric | `emailbadger email id` |
**system** | required | Ticketing system the ticket lives in, as EmailBadger knows it (e.g. splunk_soar, jira, servicenow) | string | |
**ticket_id** | required | The ticket's id in that system | string | |
**status** | optional | New status, up to 64 characters | string | |
**ticket_url** | optional | Link to the ticket | string | |
**opened_at** | optional | When the ticket was opened, RFC 3339 | string | |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_id | numeric | `emailbadger email id` | |
action_result.parameter.system | string | | |
action_result.parameter.ticket_id | string | | |
action_result.parameter.status | string | | |
action_result.parameter.ticket_url | string | | |
action_result.parameter.opened_at | string | | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.email_id | numeric | `emailbadger email id` | |
action_result.data.\*.system | string | | |
action_result.data.\*.ticket_id | string | | |
action_result.data.\*.ticket_url | string | `url` | |
action_result.data.\*.opened_at | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.status_reported_at | string | | |
action_result.data.\*.last_reported_at | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.created | boolean | | True False |
action_result.summary.status | string | | |
action_result.summary.ticket_url | string | `url` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'report ticket'

Report a ticket this SOAR opened for an email, so the email shows it. Safe to repeat: the same ticket reported again updates it

Type: **generic** <br>
Read only: **False**

POST /api/v1/emails/{email_id}/external-tickets. The only action that creates a ticket on the email; update ticket never does (it answers 404 for a ticket not reported yet). Keyed by system and ticket_id: the first report creates the record (summary.created true) and needs opened_at, a later one updates only the fields given, and a repeat of an identical report changes nothing but the report time. An Idempotency-Key goes out only when you supply one; summary.replayed says when the stored answer was returned. Needs the external_tickets:write scope, and the tenant's 'SOAR write-back allowed' switch on; Enterprise tier and above.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_id** | required | EmailBadger's numeric id of the email (email_id from get verdict, or emailbadgerEmailId on a polled container's artifact) | numeric | `emailbadger email id` |
**system** | required | Ticketing system the ticket lives in, up to 64 characters (e.g. splunk_soar, jira, servicenow). Use the same name each time: it is part of the ticket's identity | string | |
**ticket_id** | required | The ticket's id in that system, up to 255 characters | string | |
**opened_at** | optional | When the ticket was opened, RFC 3339. Required the first time a ticket is reported | string | |
**ticket_url** | optional | Link to the ticket, http or https, up to 2048 characters | string | |
**status** | optional | The ticket's status, up to 64 characters | string | |
**idempotency_key** | optional | Idempotency-Key for a replayed answer within 24 hours; not sent when left blank, because the route is already idempotent on system and ticket id | string | |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_id | numeric | `emailbadger email id` | |
action_result.parameter.system | string | | |
action_result.parameter.ticket_id | string | | |
action_result.parameter.opened_at | string | | |
action_result.parameter.ticket_url | string | | |
action_result.parameter.status | string | | |
action_result.parameter.idempotency_key | string | | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.email_id | numeric | `emailbadger email id` | |
action_result.data.\*.system | string | | |
action_result.data.\*.ticket_id | string | | |
action_result.data.\*.ticket_url | string | `url` | |
action_result.data.\*.opened_at | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.status_reported_at | string | | |
action_result.data.\*.last_reported_at | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.created | boolean | | True False |
action_result.summary.status | string | | |
action_result.summary.ticket_url | string | `url` | |
action_result.summary.replayed | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'reanalyze'

DESTRUCTIVE: re-run the analysis of an email from its stored source. Deletes the existing analysis and returns the id of the job that replaces it

Type: **generic** <br>
Read only: **False**

POST /api/v1/emails/{email_id}/reanalyze. The job deletes the existing analysis (its verdict, cases, hunts, blocks, tickets and timeline go with it) and re-ingests the stored source, so the new analysis has a NEW email id and the old id answers 404 afterwards. This action returns the job id as soon as the job is queued and does not wait; the job settles with the old and new score, verdict and email id in its result: run get job with the job id, on this same asset, to read it. A repeat while the job is queued or running returns the same job id with summary.already_running true and queues nothing, which is a success. Once it has settled, a new call starts a new job. 410 source_unavailable means retention removed the stored source: nothing is queued; upload the email again instead. An Idempotency-Key goes out only when you supply one. Needs the analysis:write scope, and the tenant's 'SOAR write-back allowed' switch on; Enterprise tier and above.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_id** | required | EmailBadger's numeric id of the email (email_id from get verdict, or emailbadgerEmailId on a polled container's artifact) | numeric | `emailbadger email id` |
**idempotency_key** | optional | Idempotency-Key for a replayed answer within 24 hours; not sent when left blank. Leave it blank to re-analyse the same email again after an earlier job has settled | string | |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_id | numeric | `emailbadger email id` | |
action_result.parameter.idempotency_key | string | | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.job_id | numeric | `emailbadger job id` | |
action_result.data.\*.status | string | | |
action_result.data.\*.already_running | boolean | | True False |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.job_id | numeric | `emailbadger job id` | |
action_result.summary.status | string | | |
action_result.summary.already_running | boolean | | True False |
action_result.summary.replayed | boolean | | True False |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get job'

Read a job this asset queued, such as a re-analysis: its status and, once settled, the old and new email id, score and verdict

Type: **investigate** <br>
Read only: **True**

GET /api/v1/api-upload/jobs/{job_id}. The job id comes from reanalyze (or from detonate file on a deployment that queues uploads). Only the API key that queued a job can read it, so run this on the same asset; any other key, a job that does not exist and one that is too old all answer the same not-found. Read until summary.settled is true, with a pause between reads: the limit is 120 a minute per client address. A queued or running job is a success with settled false. A re-analysis that succeeded puts the NEW email id in summary.new_email_id, beside the new verdict and score; the old email id answers 404 from then on, so later actions take the new one. A job that failed or was interrupted, and a re-analysis that settled without a new record, fail this action with the reason, though the job's data is still in the result. A read: safe to repeat, no scope needed, no tier gate. A Platform Admin's key reading a job in a customer's tenant needs platform_admin_reason.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**job_id** | required | The job id reanalyze returned (job_id in its result and summary) | numeric | `emailbadger job id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.job_id | numeric | `emailbadger job id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.id | numeric | `emailbadger job id` | |
action_result.data.\*.kind | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.settled | boolean | | True False |
action_result.data.\*.error | string | | |
action_result.data.\*.created_at | string | | |
action_result.data.\*.finished_at | string | | |
action_result.data.\*.result.status | string | | |
action_result.data.\*.result.message_id | string | `emailbadger message id` | |
action_result.data.\*.result.old_email_id | numeric | `emailbadger email id` | |
action_result.data.\*.result.new_email_id | numeric | `emailbadger email id` | |
action_result.data.\*.result.old_score | numeric | | |
action_result.data.\*.result.new_score | numeric | | |
action_result.data.\*.result.old_verdict | string | | |
action_result.data.\*.result.new_verdict | string | | |
action_result.data.\*.result.old_risk_level | string | | |
action_result.data.\*.result.new_risk_level | string | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.job_id | numeric | `emailbadger job id` | |
action_result.summary.status | string | | |
action_result.summary.settled | boolean | | True False |
action_result.summary.new_email_id | numeric | `emailbadger email id` | |
action_result.summary.new_verdict | string | | |
action_result.summary.new_score | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get timeline'

Read the forensic timeline of an email

Type: **investigate** <br>
Read only: **True**

GET /api/v1/emails/{email_id}/timeline: what happened to the email and when, across EmailBadger's own records and the mail systems it could search. gaps lists where it could not look; the action message counts them so a playbook does not take the timeline as complete when it is not. Needs the evidence:read scope; Enterprise tier and above.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_id** | required | EmailBadger's numeric id of the email (email_id from get verdict, or emailbadgerEmailId on a polled container's artifact) | numeric | `emailbadger email id` |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_id | numeric | `emailbadger email id` | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.email.id | numeric | `emailbadger email id` | |
action_result.data.\*.email.message_id | string | `emailbadger message id` | |
action_result.data.\*.email.sender | string | `email` | |
action_result.data.\*.email.recipient | string | `email` | |
action_result.data.\*.email.subject | string | | |
action_result.data.\*.entries.\*.at | string | | |
action_result.data.\*.entries.\*.kind | string | | |
action_result.data.\*.entries.\*.source | string | | |
action_result.data.\*.entries.\*.detail | string | | |
action_result.data.\*.gaps.\*.source | string | | |
action_result.data.\*.gaps.\*.reason | string | | |
action_result.data.\*.total | numeric | | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.total | numeric | | |
action_result.summary.gaps | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get evidence package'

Download the sealed evidence package of an email into the vault

Type: **investigate** <br>
Read only: **True**

GET /api/v1/emails/{email_id}/evidence-package: the ZIP EmailBadger's Evidence Package export produces, saved to the vault of the current container with its X-Manifest-SHA256 kept alongside. The API key's user must be a Tenant Admin or Platform Admin (403 otherwise; the action says so). The route is rate limited per address; a 429 reports the Retry-After. Needs the evidence:read scope; Enterprise tier and above.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_id** | required | EmailBadger's numeric id of the email (email_id from get verdict, or emailbadgerEmailId on a polled container's artifact) | numeric | `emailbadger email id` |
**target_tenant_id** | optional | Customer tenant to act in (a Platform Admin's key only; emailbadgerTenantId on a polled container). Overrides the asset's setting; blank means the asset's, or the key's own tenant. | numeric | `emailbadger tenant id` |
**platform_admin_reason** | optional | Why this Platform Admin is loading this customer's records, 5 to 500 characters, recorded in the customer's audit log (X-Platform-Admin-Reason). Overrides the asset's setting; a Platform Admin's key's call that loads a customer's records is refused without one. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email_id | numeric | `emailbadger email id` | |
action_result.parameter.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.parameter.platform_admin_reason | string | | |
action_result.data.\*.vault_id | string | `vault id` | |
action_result.data.\*.file_name | string | `file name` | |
action_result.data.\*.size | numeric | | |
action_result.data.\*.manifest_sha256 | string | `sha256` | |
action_result.data.\*.email_id | numeric | `emailbadger email id` | |
action_result.summary.total_objects | numeric | | |
action_result.summary.target_tenant_id | numeric | `emailbadger tenant id` | |
action_result.summary.refusal | string | | tenant_not_separated tenant_not_own tenant_not_found tenant_ambiguous soar_writeback_off analysis_cross_tenant operator_reason_required |
action_result.summary.vault_id | string | `vault id` | |
action_result.summary.size | numeric | | |
action_result.summary.manifest_sha256 | string | `sha256` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
