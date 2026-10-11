"""Shared fixtures for the log_compliance_auditor tests.

The log is built to the awkward cases the tool exists for: the timestamp at
the end of the record, the program name first, custom event codes, a second
shape with a different timestamp format, JSON lines mixed in, stack-trace
continuation lines and a little junk that belongs to no record shape.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PLUGIN_DIR = Path(__file__).resolve().parent.parent
PROFILE_EXAMPLE = (
    PLUGIN_DIR.parent
    / "logging_standard_profiler"
    / "examples"
    / "profile.example.json"
)

COUNT_A, COUNT_B, COUNT_C, COUNT_JUNK = 600, 315, 80, 5
TOTAL = COUNT_A + COUNT_B + COUNT_C + COUNT_JUNK
CONTINUATION_LINES = 6


def load_tool():
    name = "log_compliance_auditor_tool"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "tool.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def build_log(path: Path) -> Path:
    users = ["alice", "bob", "carol", "dave"]
    lines: list[str] = []
    for i in range(COUNT_A):
        second = i % 60
        minute = (i // 60) % 60
        lines.append(
            f"authsvc[{400 + i % 7}] INFO code=AU{100 + i % 5} user={users[i % 4]} "
            f"result={'OK' if i % 3 else 'FAIL'} src=10.0.{i % 4}.{1 + i % 200} "
            f"session opened for request {i} @2026-03-01T10:{minute:02d}:{second:02d}.{i % 1000:03d}+00:00"
        )
        if i < 3:
            lines.append("    at com.example.auth.Session.open(Session.java:42)")
            lines.append("    at com.example.auth.Handler.handle(Handler.java:17)")
    for i in range(COUNT_B):
        lines.append(
            f"billing WARN XQ-{70 + i % 9} actor:{users[i % 4]} "
            f"outcome:{'DENIED' if i % 2 else 'ALLOWED'} from 192.168.1.{1 + i % 250} "
            f"| 01/Mar/2026:11:{(i // 60) % 60:02d}:{i % 60:02d} +0000"
        )
    for i in range(COUNT_C):
        lines.append(
            json.dumps(
                {
                    "time": 1772359200123 + i * 1000,
                    "svc": "api",
                    "evt": f"GET /items/{i % 3}",
                    "user": {"name": users[i % 4]},
                    "status": "ok" if i % 4 else "error",
                }
            )
        )
    for i in range(COUNT_JUNK):
        lines.append(f"--- log rotated, segment {i} ---")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


PATTERN_A = {
    "pattern_id": "auth",
    "kind": "regex",
    "describes": "auth service record, timestamp last",
    "regex": (
        r"^(?P<program>[\w.-]+)\[(?P<pid>\d+)\] (?P<level>[A-Z]+) code=(?P<code>[A-Z]{2}\d{3}) "
        r"user=(?P<user>\S+) result=(?P<result>\S+) src=(?P<src>\S+) (?P<message>.*) @(?P<ts>\S+)$"
    ),
    "fields": {
        "program": {"element": "source_component"},
        "pid": {"element": "process_id"},
        "level": {"element": "severity"},
        "code": {"element": "event_type"},
        "user": {"element": "actor_identity"},
        "result": {"element": "outcome"},
        "src": {"element": "source_address"},
        "message": {"element": "message"},
        "ts": {"element": "timestamp", "format": "iso8601"},
    },
}
PATTERN_A_WRONG_FORMAT = json.loads(json.dumps(PATTERN_A))
PATTERN_A_WRONG_FORMAT["fields"]["ts"]["format"] = "%Y-%m-%d %H:%M:%S"

PATTERN_B = {
    "pattern_id": "billing",
    "kind": "regex",
    "describes": "billing record",
    "regex": (
        r"^(?P<program>\w+) (?P<level>[A-Z]+) (?P<code>[A-Z]{2}-\d+) actor:(?P<user>\S+) "
        r"outcome:(?P<result>\S+) from (?P<src>\S+) \| (?P<ts>.+)$"
    ),
    "fields": {
        "program": {"element": "source_component"},
        "level": {"element": "severity"},
        "code": {"element": "event_type"},
        "user": {"element": "actor_identity"},
        "result": {"element": "outcome"},
        "src": {"element": "source_address"},
        "ts": {"element": "timestamp", "format": "%d/%b/%Y:%H:%M:%S %z"},
    },
}
PATTERN_C = {
    "pattern_id": "api_json",
    "kind": "json",
    "describes": "JSON api record",
    "fields": {
        "time": {"element": "timestamp", "format": "epoch_ms"},
        "svc": {"element": "source_component"},
        "evt": {"element": "event_type"},
        "user.name": {"element": "actor_identity"},
        "status": {"element": "outcome"},
    },
}


def reply(*patterns: dict[str, Any]) -> str:
    return json.dumps({"patterns": list(patterns)})


@dataclass
class FakeResponse:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    truncated: bool = False
    provider_id: str = "fake_provider"
    vendor: str = "fake"
    model_used: str = "fake-model"
    model_version: str = "fake-model-001"
    token_usage: dict[str, int] | None = None
    transport_path: str | None = None


class FakeLLM:
    """Replays scripted replies and keeps every prompt it was sent."""

    def __init__(self, replies: list[Any]) -> None:
        self.replies = list(replies)
        self.prompts: list[str] = []

    def query_text(
        self,
        prompt,
        system_context=None,
        max_tokens=4096,
        grounding_data=None,
        hints=None,
    ):
        self.prompts.append(prompt)
        if not self.replies:
            return FakeResponse(ok=False, error="script exhausted")
        item = self.replies.pop(0)
        if isinstance(item, FakeResponse):
            return item
        return FakeResponse(text=item)


@dataclass
class FakeArtifact:
    artifact_id: str
    artifact_type: str
    file_path: str
    metadata: dict[str, Any] = field(default_factory=dict)


class FakeContext:
    def __init__(
        self, llm: Any = None, artifacts: list[FakeArtifact] | None = None
    ) -> None:
        self.llm_query = llm
        self.artifacts = artifacts or []
        self.registered: list[FakeArtifact] = []

    def register_artifact(self, artifact_type, file_path, source_tool, metadata):
        artifact = FakeArtifact(
            f"art_{len(self.artifacts) + len(self.registered) + 1:04d}",
            artifact_type,
            str(file_path),
            dict(metadata or {}),
        )
        self.registered.append(artifact)
        self.artifacts.append(artifact)
        return artifact
