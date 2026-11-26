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
"""What the tests stand in for: EmailBadger's HTTP answers, and SOAR's vault."""

import json
from types import SimpleNamespace

APP_SUCCESS = True
APP_ERROR = False


class FakeHTTPResponse:
    """What ``requests`` hands back: status, headers, body."""

    def __init__(self, status_code, payload=None, *, headers=None, content=None):
        self.status_code = status_code
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        self._payload = payload
        if content is not None:
            self.content = content
        elif payload is None or isinstance(payload, Exception):
            self.content = b""
        else:
            self.content = json.dumps(payload).encode("utf-8")

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        if self._payload is None:
            raise json.JSONDecodeError("no body", "", 0)
        return self._payload


class FakeVault:
    """The vault surface the app uses: look a file up, add a file.

    ``put`` writes a real file, so the upload actions open and stream it as
    they would on SOAR. ``added`` records every attachment created.
    """

    def __init__(self, tmp_path):
        self._tmp_path = tmp_path
        self._entries = {}
        self.added = []
        self.refuse_with = None

    def put(self, name="archive.zip", content=b"PK\x03\x04stub", vault_id="vault-id-1"):
        path = self._tmp_path / name
        path.write_bytes(content)
        self._entries[vault_id] = SimpleNamespace(path=str(path), name=name)
        return vault_id

    def get_attachment(self, vault_id=None, file_name=None, container_id=None):
        entry = self._entries.get(vault_id)
        return [entry] if entry else []

    def create_attachment(self, container_id, file_content, file_name, metadata=None):
        if self.refuse_with:
            raise RuntimeError(self.refuse_with)
        self.added.append(
            {
                "container_id": container_id,
                "content": file_content,
                "file_name": file_name,
                "metadata": metadata,
            }
        )
        return "vault-id-evidence"


def refused_by_validation(result, parameter):
    """Whether the SDK refused the action's parameters, naming ``parameter``."""
    return (
        result.status is APP_ERROR
        and result.message.startswith("Validation Error")
        and parameter in result.message
    )


def scope_refusal(scope):
    """The sentence a route answers with, recorded from a live 403."""
    return (
        f"This API key does not carry the '{scope}' scope. Mint a key with it ticked; scopes cannot be added to "
        "an existing key."
    )


def action_error(status, code, detail, request_id="req-0001", **headers):
    """An action-API refusal in the one shape every route answers with."""
    return FakeHTTPResponse(
        status,
        {"error": code, "detail": detail, "request_id": request_id},
        headers={"X-Request-ID": request_id, **headers},
    )
