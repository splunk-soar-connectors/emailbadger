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
"""Run the app's actions through the SOAR SDK, with EmailBadger and the vault faked.

Every action runs through its real SDK wrapper: the parameters are validated
into the action's ``Params`` class, the output is adapted into the action
result SOAR stores, and ``on poll``'s containers go through the SDK's own
save loop and ingest-state transaction. What is faked is everything outside
the app: EmailBadger's HTTP answers (``requests``), SOAR's vault, and SOAR's
container store.

The assertions are about the app's own decisions: which URL, which fields,
which analyst-facing message, which summary. A passing suite says nothing
about whether the app runs on a SOAR instance; only a live run does.
"""

import itertools
from dataclasses import dataclass, field
from typing import Any

import pytest
import requests
from pydantic import ValidationError
from soar_sdk.app_client import AppClient
from soar_sdk.asset_state import AssetState
from soar_sdk.params import MAX_COUNT_VALUE, OnPollParams

from src import app as app_module
from src.models import Asset

from .fakes import FakeHTTPResponse, FakeVault

ASSET_ID = "101"
CONTAINER_ID = 7
BASE_CONFIG = {
    "base_url": "https://eb.example.test/",
    "api_key": "eb_test_key",  # pragma: allowlist secret
    "verify_server_cert": True,
}


@dataclass
class Result:
    """One action result, as SOAR stores it."""

    status: bool
    message: str
    summary: dict
    data: list
    param: dict = field(default_factory=dict)


class _Soar(AppClient):
    """The SOAR client an action receives, with the vault and the container faked."""

    def __init__(self, vault):
        super().__init__()
        self._vault_api = vault

    def get_executing_container_id(self):
        return CONTAINER_ID

    def get_asset_id(self):
        return ASSET_ID


class Harness:
    """The app as SOAR runs it, one action at a time.

    ``config`` is the asset's configuration. ``run(identifier, param)`` runs
    one action and returns its ``Result``; ``results`` keeps every one.
    ``containers`` is every container ``on poll`` saved; a container whose
    ``source_data_identifier`` was saved before is answered as SOAR answers a
    duplicate. ``state`` is the asset's ingest state, read and planted as a
    dict. ``progress`` is every progress line the app logged.
    """

    def __init__(self, monkeypatch, tmp_path):
        self.config = dict(BASE_CONFIG)
        self.ingest = {"container_label": "events"}
        self.vault = FakeVault(tmp_path)
        self.results: list[Result] = []
        self.containers: list[dict] = []
        self.progress: list[str] = []
        self.warnings: list[str] = []
        self.poll_now = False
        self.save_container_outcome = None
        self._planted_state: dict | None = None
        self._ids = itertools.count(1000)
        manager = app_module.app.actions_manager
        self._manager = manager
        monkeypatch.setattr(manager, "save_container", self._save_container)
        monkeypatch.setattr(
            manager, "get_config", lambda: {**self.config, "ingest": self.ingest}
        )
        monkeypatch.setattr(
            app_module.logger,
            "progress",
            lambda message, *a, **k: self.progress.append(message),
        )
        monkeypatch.setattr(
            app_module.logger,
            "warning",
            lambda message, *a, **k: self.warnings.append(message),
        )
        # One state store for the asset, kept across runs as SOAR keeps it.
        manager.save_state({})
        self._asset: Asset | None = None

    # -- the asset and its ingest state ----------------------------------

    def _build_asset(self) -> Asset:
        asset = Asset.model_validate(self.config)
        asset._ingest_state = AssetState(
            self._manager,
            "ingest",
            ASSET_ID,
            app_id=app_module.app.app_meta_info["appid"],
        )
        if self._planted_state is not None:
            asset._ingest_state.put_all(self._planted_state)
            self._planted_state = None
        return asset

    @property
    def state(self) -> dict:
        if self._planted_state is not None:
            return dict(self._planted_state)
        return self._build_asset().ingest_state.get_all()

    @state.setter
    def state(self, value: dict) -> None:
        self._planted_state = dict(value)

    # -- SOAR's container store ------------------------------------------

    def _save_container(self, container, fail_on_duplicate=False):
        if self.save_container_outcome is not None:
            return self.save_container_outcome(container)
        for index, existing in enumerate(self.containers):
            if (
                existing["source_data_identifier"]
                == container["source_data_identifier"]
            ):
                return True, "Duplicate container found", 1000 + index
        self.containers.append(container)
        return True, "Container saved", 1000 + len(self.containers) - 1

    # -- running an action -----------------------------------------------

    def run(self, identifier: str, param: dict | None = None) -> Result:
        action = self._manager.get_action(identifier)
        assert action is not None, f"no action {identifier!r}"
        asset = self._build_asset()
        app_module.app._asset = asset
        soar = _Soar(self.vault)
        before = len(self._manager.get_action_results())
        if identifier == "test_connectivity":
            action(None, soar=soar)
        elif identifier == "on_poll":
            values = dict(param or {})
            if not self.poll_now:
                values["container_count"] = MAX_COUNT_VALUE
            action(OnPollParams.model_validate(values), soar=soar)
        else:
            try:
                params = action.params_class.model_validate(param or {})
            except ValidationError as exc:
                # What the SDK does with parameters that do not validate: it
                # reports them and never runs the action.
                result = Result(
                    False,
                    f"Validation Error - the params data for action could not be parsed: {exc!s}",
                    {},
                    [],
                )
                self.results.append(result)
                return result
            action(params, soar=soar, asset=asset)
        new = self._manager.get_action_results()[before:]
        assert len(new) == 1, f"{identifier} produced {len(new)} action results"
        raw = new[0]
        result = Result(
            status=raw.get_status(),
            message=raw.get_message(),
            summary=dict(raw.get_summary() or {}),
            data=list(raw.get_data() or []),
            param=dict(raw.get_param() or {}),
        )
        self.results.append(result)
        return result


@pytest.fixture
def eb(monkeypatch, tmp_path):
    """The app, configured against a fake EmailBadger at ``https://eb.example.test``."""
    return Harness(monkeypatch, tmp_path)


@pytest.fixture
def vault(eb):
    """Put a file in the vault and hand back its id."""
    return eb.vault.put


@pytest.fixture
def responses(monkeypatch):
    """Capture the outbound upload POST and dictate the reply."""
    captured: dict[str, Any] = {}

    def _set(status_code, payload, raises=None):
        def fake_post(url, **kwargs):
            captured["url"] = url
            captured["data"] = kwargs.get("data")
            captured["headers"] = kwargs.get("headers")
            captured["files"] = kwargs.get("files")
            captured["params"] = kwargs.get("params")
            captured["verify"] = kwargs.get("verify")
            if raises:
                raise raises
            return FakeHTTPResponse(status_code, payload)

        monkeypatch.setattr(requests, "post", fake_post)
        return captured

    return _set


@pytest.fixture
def get_reply(monkeypatch):
    """Capture the outbound GET of the verdict read and dictate the reply."""
    captured: dict[str, Any] = {}

    def _set(status_code, payload, raises=None):
        def fake_get(url, **kwargs):
            captured["url"] = url
            captured["params"] = kwargs.get("params")
            captured["headers"] = kwargs.get("headers")
            if raises:
                raise raises
            return FakeHTTPResponse(status_code, payload)

        monkeypatch.setattr(requests, "get", fake_get)
        return captured

    return _set


@pytest.fixture
def http(monkeypatch):
    """Script ``requests.request`` for the action API and the feed.

    ``http(reply, reply, ...)`` answers successive calls in order (the last
    one repeats); ``http.calls`` is every request made, as
    ``{"method", "url", "params", "json", "headers", "timeout", "verify"}``.
    A reply may be a ``FakeHTTPResponse``, a ``(status, payload)`` tuple, or
    an exception to raise instead of answering.
    """
    calls: list[dict[str, Any]] = []
    replies: list[Any] = []

    def fake_request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        reply = replies[min(len(calls) - 1, len(replies) - 1)]
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, tuple):
            reply = FakeHTTPResponse(*reply)
        return reply

    def _set(*scripted):
        replies[:] = list(scripted)
        monkeypatch.setattr(requests, "request", fake_request)
        return calls

    _set.calls = calls
    return _set
