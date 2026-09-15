"""The chunked text path must not discard the fact that a reply was cut off.

The native path already read both truncation signals; the text path called the
flag-discarding `_parse_llm_json` wrapper and ignored `LLMResponse.truncated`
entirely, so a chunk that assessed half its candidates was merged and reported
exactly like one that assessed all of them.
"""

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_intel_ingester_tool_truncation"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()
_SOURCE = (PLUGIN_DIR / "tool.py").read_text(encoding="utf-8")


@pytest.fixture
def tool_instance():
    return _tool_mod.ThreatIntelIngester()


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
    model_used: str | None = "mock-light"
    transport_path: str | None = "text"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class MockArtifactRef:
    artifact_id: str
    artifact_type: str
    file_path: str
    source_tool: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class MockReferenceDataView:
    _data: dict = field(default_factory=dict)

    def get(self, key: str, default=None):
        return self._data.get(key, default)


@dataclass
class MockExecutionContext:
    session_id: str = "test_session_trunc"
    selected_pillar: str = "log_analysis"
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)
    logger: Any = None
    reference_data: MockReferenceDataView = field(
        default_factory=MockReferenceDataView
    )
    llm_enabled: bool = False
    llm_query: Any = None
    register_artifact: Callable | None = None
    limits: dict = field(default_factory=dict)


_GOOD_REPLY = json.dumps({
    "refined_iocs": [
        {"value": "198.51.100.7", "ioc_type": "ip", "confidence": "high",
         "priority": "medium", "context": "c2", "related_mitre": [],
         "is_false_positive": False},
    ],
    "additional_mitre_techniques": [],
    "report_metadata": {"title": "Report"},
    "attack_graph": {"paths": [], "convergence_points": [], "branch_points": []},
})


class _TextLLM:
    """Answers the chunked text path, optionally cut off at the output cap."""

    def __init__(self, truncated: bool = False, body: str | None = None):
        self.truncated = truncated
        self.body = body if body is not None else _GOOD_REPLY
        self.text_calls: list[str] = []

    def supports_native_document(self, mime_type: str) -> bool:
        return False

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.text_calls.append(prompt)
        return _Resp(
            text=self.body,
            finish_reason="MAX_TOKENS" if self.truncated else "STOP",
            truncated=self.truncated,
        )


@pytest.fixture
def text_run(tmp_path, monkeypatch):
    # Without this the ingester writes its artifact under the default
    # workspace, outside the test's tmp_path — the same reason the batched
    # native fixture in test_contract.py sets it.
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    report = tmp_path / "report.txt"
    report.write_text(
        "Observed beaconing to 198.51.100.7 and 203.0.113.9 over 443.\n",
        encoding="utf-8",
    )
    artifact = MockArtifactRef(
        artifact_id="art_txt", artifact_type="text", file_path=str(report),
    )

    def register(artifact_type, file_path, source_tool, metadata):
        return MockArtifactRef(
            artifact_id="art_out", artifact_type=artifact_type, file_path=file_path,
        )

    def make_context(llm):
        return MockExecutionContext(
            artifacts=[artifact], llm_enabled=True, llm_query=llm,
            register_artifact=register,
        )

    return make_context


class TestTextPathReadsTruncation:
    def test_a_clean_run_reports_no_truncation(self, tool_instance, text_run):
        llm = _TextLLM(truncated=False)
        result = tool_instance.execute({"artifact_id": "art_txt"}, text_run(llm))
        assert result.ok, result.message
        summary = result.result["summary"]
        assert summary["truncated"] is False
        assert summary["truncated_chunks"] == []

    def test_a_cut_off_chunk_is_recorded_with_its_index(
        self, tool_instance, text_run,
    ):
        llm = _TextLLM(truncated=True)
        result = tool_instance.execute({"artifact_id": "art_txt"}, text_run(llm))
        assert result.ok, result.message
        summary = result.result["summary"]
        assert summary["truncated"] is True
        assert summary["truncated_chunks"] == [1], (
            "the affected chunk index must be recorded, not just a boolean"
        )

    def test_truncated_content_is_kept_not_discarded(self, tool_instance, text_run):
        """A partial answer beats none. The defect is the silence, not the text."""
        llm = _TextLLM(truncated=True)
        result = tool_instance.execute({"artifact_id": "art_txt"}, text_run(llm))
        assert result.ok
        assert result.result["summary"]["ingestion_mode"] == "llm", (
            "a truncated reply must not be downgraded to the regex baseline"
        )
        assert result.result["iocs"], "the IOCs the model did return must survive"

    def test_bracket_repair_alone_counts_as_truncation(
        self, tool_instance, text_run,
    ):
        """The transport reports STOP, but the reply only parsed after unmatched
        brackets were closed. Neither signal subsumes the other."""
        cut = _GOOD_REPLY[: len(_GOOD_REPLY) // 2]
        llm = _TextLLM(truncated=False, body=cut)
        result = tool_instance.execute({"artifact_id": "art_txt"}, text_run(llm))
        assert result.ok, result.message
        assert result.result["summary"]["truncated_chunks"] == [1], (
            "a reply repaired by closing brackets was truncated even though "
            "the provider's finish reason did not say so"
        )


class TestTruncationReachesTheLLMSummary:
    """summarize_for_llm is what downstream reasoning actually sees."""

    def test_truncation_is_stated(self, tool_instance, text_run):
        llm = _TextLLM(truncated=True)
        result = tool_instance.execute({"artifact_id": "art_txt"}, text_run(llm))
        text = tool_instance.summarize_for_llm(result)
        assert "TRUNCATED OUTPUT" in text
        assert "chunk 1" in text

    def test_a_clean_run_says_nothing_about_truncation(
        self, tool_instance, text_run,
    ):
        llm = _TextLLM(truncated=False)
        result = tool_instance.execute({"artifact_id": "art_txt"}, text_run(llm))
        assert "TRUNCATED" not in tool_instance.summarize_for_llm(result)


class TestTheFlagDiscardingWrapperIsNotUsed:
    """`_parse_llm_json` drops the repair flag `_parse_llm_json_result`
    returns. It is kept because a test exercises the repair logging through it,
    but no production call site may use it again."""

    def test_no_call_site_calls_the_wrapper(self):
        body = _SOURCE.split("def _parse_llm_json_result", 1)[1]
        assert "_parse_llm_json(" not in body, (
            "a call to _parse_llm_json discards the bracket-repair flag, which "
            "is the defect fixed in Stage 1.2 — call _parse_llm_json_result"
        )
