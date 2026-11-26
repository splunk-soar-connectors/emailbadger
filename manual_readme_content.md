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
