from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timezone
from typing import Any, TextIO

from .config import OutputMode
from .models import model_to_data


class EventRenderer:
    """Render app-server notifications in quiet, human, or JSONL debug form."""

    def __init__(
        self,
        mode: OutputMode | str,
        output: TextIO | None = None,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.mode = OutputMode.parse(mode)
        self.output = output or sys.stdout
        self._lock = threading.Lock()
        self._sequence = 0
        self._open_channel: tuple[str, str] | None = None
        self._seen_agent_deltas: set[str] = set()
        self._context = dict(context or {})

    def wrapper_event(self, name: str, **data: Any) -> None:
        if self.mode is OutputMode.QUIET:
            return
        with self._lock:
            if self.mode is OutputMode.DEBUG:
                self._debug_write("wrapper", name, data)
                return
            self._finish_open_channel()
            if name == "thread.started":
                self._line(f"codex  thread {data.get('thread_id')}")
            elif name == "thread.resumed":
                self._line(f"codex  resumed thread {data.get('thread_id')}")
            elif name == "goal.started":
                model = f" [{data.get('model')}]" if data.get("model") else ""
                self._line(f"goal{model}   {data.get('objective', '')}")
            elif name == "goal.resumed":
                model = f" with {data.get('model')}" if data.get("model") else ""
                self._line(
                    f"↻      resumed Goal{model} (attempt {data.get('attempt')})"
                )
            elif name == "goal.retry":
                delay = float(data.get("delay_seconds", 0.0))
                reason = str(data.get("reason", "transient interruption"))
                self._line(f"↻      {reason}; resuming in {delay:.1f}s")
            elif name == "goal.stopped":
                self._line(f"goal   stopped: {data.get('status')}")
            elif name == "goal.completed":
                self._line(
                    "goal   complete "
                    f"({data.get('tokens_used', 0)} tokens, {data.get('resume_count', 0)} resumes)"
                )
            elif name == "runtime.reconnecting":
                self._line("↻      Codex runtime disconnected; reconnecting")
            elif name == "warning":
                self._line(f"!      {data.get('message', '')}")

    def notification(self, notification: Any) -> None:
        if self.mode is OutputMode.QUIET:
            return
        method = str(getattr(notification, "method", "unknown"))
        payload = model_to_data(getattr(notification, "payload", notification))
        with self._lock:
            if self.mode is OutputMode.DEBUG:
                self._debug_write("codex", method, payload)
                return
            self._human_notification(method, payload)

    def exception(self, exc: BaseException, *, context: str) -> None:
        if self.mode is OutputMode.QUIET:
            return
        with self._lock:
            if self.mode is OutputMode.DEBUG:
                self._debug_write(
                    "wrapper",
                    "exception",
                    {
                        "context": context,
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "repr": repr(exc),
                    },
                )
                return
            self._finish_open_channel()
            self._line(f"!      {context}: {exc}")

    def close(self) -> None:
        if self.mode is OutputMode.QUIET:
            return
        with self._lock:
            self._finish_open_channel()
            self.output.flush()

    def _human_notification(self, method: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return

        if method == "item/agentMessage/delta":
            item_id = str(payload.get("itemId", ""))
            self._stream_delta("agent", item_id, str(payload.get("delta", "")), "codex\n")
            self._seen_agent_deltas.add(item_id)
            return

        if method == "item/reasoning/summaryTextDelta":
            item_id = str(payload.get("itemId", ""))
            self._stream_delta("reasoning", item_id, str(payload.get("delta", "")), "• ")
            return

        if method in {"item/started", "item/completed"}:
            self._finish_open_channel()
            item = payload.get("item", {})
            if isinstance(item, dict):
                self._human_item(method, item)
            return

        if method == "turn/plan/updated":
            self._finish_open_channel()
            plan = payload.get("plan")
            if isinstance(plan, list):
                self._line("plan")
                for step in plan:
                    if isinstance(step, dict):
                        status = str(step.get("status", "pending"))
                        marker = "✓" if status == "completed" else "→" if status == "inProgress" else "·"
                        self._line(f"  {marker} {step.get('step', '')}")
            return

        if method == "error":
            self._finish_open_channel()
            error = payload.get("error", {})
            message = error.get("message") if isinstance(error, dict) else error
            suffix = " (Codex will retry)" if payload.get("willRetry") else ""
            self._line(f"!      {message}{suffix}")
            return

        if method == "turn/completed":
            self._finish_open_channel()
            turn = payload.get("turn", {})
            if isinstance(turn, dict):
                status = turn.get("status", "unknown")
                duration = turn.get("durationMs")
                duration_text = f" in {float(duration) / 1000:.1f}s" if isinstance(duration, (int, float)) else ""
                self._line(f"—      turn {status}{duration_text}")

    def _human_item(self, method: str, item: dict[str, Any]) -> None:
        item_type = item.get("type")
        started = method == "item/started"

        if item_type == "commandExecution":
            if started:
                self._line(f"• Run {self._compact(str(item.get('command', '')), 180)}")
            else:
                exit_code = item.get("exitCode")
                duration = item.get("durationMs")
                parts = []
                if exit_code is not None:
                    parts.append(f"exit {exit_code}")
                if isinstance(duration, (int, float)):
                    parts.append(f"{float(duration) / 1000:.1f}s")
                if parts:
                    self._line(f"  └ {' · '.join(parts)}")
            return

        if item_type in {"mcpToolCall", "dynamicToolCall"} and started:
            server = f"{item.get('server')}." if item.get("server") else ""
            self._line(f"• Call {server}{item.get('tool', '')}")
            return

        if item_type == "fileChange" and not started:
            changes = item.get("changes")
            count = len(changes) if isinstance(changes, list) else 0
            self._line(f"• Applied file changes{f' ({count})' if count else ''}")
            return

        if item_type == "agentMessage" and not started:
            item_id = str(item.get("id", ""))
            if item_id not in self._seen_agent_deltas and item.get("text"):
                self._line("codex")
                self._line(str(item["text"]))
            return

        if item_type == "subAgentActivity" and started:
            self._line(f"• Subagent {item.get('kind', '')}: {item.get('agentPath', '')}")

    def _stream_delta(self, kind: str, item_id: str, delta: str, prefix: str) -> None:
        channel = (kind, item_id)
        if self._open_channel != channel:
            self._finish_open_channel()
            self.output.write(prefix)
            self._open_channel = channel
        self.output.write(delta)
        self.output.flush()

    def _finish_open_channel(self) -> None:
        if self._open_channel is not None:
            self.output.write("\n")
            self.output.flush()
            self._open_channel = None

    def _line(self, text: str) -> None:
        self.output.write(text + "\n")
        self.output.flush()

    def _debug_write(self, source: str, event: str, data: Any) -> None:
        self._sequence += 1
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": self._sequence,
            "source": source,
            "event": event,
            "data": model_to_data(data),
        }
        if self._context:
            record["context"] = model_to_data(self._context)
        self.output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.output.flush()

    @staticmethod
    def _compact(value: str, limit: int) -> str:
        single_line = " ".join(value.split())
        if len(single_line) <= limit:
            return single_line
        return single_line[: limit - 1] + "…"
