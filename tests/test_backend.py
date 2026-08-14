from __future__ import annotations

from typing import Any

import pytest

from codex_controller._backend import OfficialBackend


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, Any]] = []

    def request(self, method: str, params: Any, *, response_model: Any) -> Any:
        self.calls.append((method, params, response_model))
        return response_model()


def test_goal_model_uses_thread_settings_update_protocol() -> None:
    client = RecordingClient()

    OfficialBackend._set_model(client, "thread-1", "selected-model")

    assert client.calls[0][0] == "thread/settings/update"
    assert client.calls[0][1] == {
        "threadId": "thread-1",
        "model": "selected-model",
    }


def test_empty_goal_model_is_rejected() -> None:
    with pytest.raises(ValueError):
        OfficialBackend._set_model(RecordingClient(), "thread-1", "  ")

