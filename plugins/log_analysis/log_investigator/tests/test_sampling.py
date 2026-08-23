"""Sampling and match-counting tests for log_investigator.

Covers the budget that decides how much of a large log the model actually sees.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "log_investigator_tool"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()
LogInvestigator = _tool_mod.LogInvestigator


class RecordingLLM:
    """Captures the prompt so tests can assert what the model was shown."""

    def __init__(self):
        self.prompts = []
        self.max_tokens = []

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        self.prompts.append(prompt)
        self.max_tokens.append(max_tokens)
        return type("R", (), {"ok": True, "text": "analysis"})()


class Ctx:
    def __init__(self, llm=None):
        self.llm_query = llm
        self.llm_enabled = llm is not None
        self.artifacts = []


@pytest.fixture
def plugin():
    return LogInvestigator()


def _write_log(tmp_path, total_lines, match_every, needle="Failed password"):
    p = tmp_path / "auth.log"
    lines = []
    for i in range(total_lines):
        if i % match_every == 0:
            lines.append(
                f"Jan  1 00:00:00 host sshd[{i}]: {needle} for root "
                f"from 10.0.0.{i % 255}"
            )
        else:
            lines.append(f"Jan  1 00:00:00 host systemd[{i}]: routine message")
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


class TestMatchCounting:
    """Counts must reflect the whole file, not where the buffer filled."""

    def test_counts_are_complete_when_matches_exceed_retention(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=10_000, match_every=3)
        result = plugin.execute(
            {"mode": "investigate", "file_path": str(log),
             "search_term": "Failed password", "context_lines": 100},
            Ctx(),
        )
        assert result.ok
        data = result.result
        # The whole file is scanned even though only 100 matches are retained.
        assert data["lines_scanned"] == 10_000
        assert data["total_matches"] == pytest.approx(3334, abs=2)
        assert len(data["sample_matches"]) == 20

    def test_full_log_flag_does_not_change_counts(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=5_000, match_every=5)
        base = {"mode": "investigate", "file_path": str(log),
                "search_term": "Failed password", "context_lines": 50}
        a = plugin.execute({**base, "full_log": False}, Ctx()).result
        b = plugin.execute({**base, "full_log": True}, Ctx()).result
        assert a["lines_scanned"] == b["lines_scanned"] == 5_000
        assert a["total_matches"] == b["total_matches"]


class TestSampleSelection:
    def test_returns_everything_when_under_budget(self):
        lines = [f"line {i}" for i in range(300)]
        sel, strategy, truncated = LogInvestigator._select_sample(lines, 300)
        assert sel == lines
        assert truncated is None
        assert "300" in strategy

    def test_flags_line_count_truncation(self):
        lines = [f"line {i}" for i in range(100)]
        sel, strategy, truncated = LogInvestigator._select_sample(lines, 3412)
        assert len(sel) == 100
        assert truncated == "line_count"
        assert "3412" in strategy

    def test_char_budget_binds_on_wide_lines(self):
        wide = [("X" * 1000) + f" evt{i}" for i in range(5000)]
        sel, _, truncated = LogInvestigator._select_sample(wide, 5000)
        assert truncated == "char_budget"
        assert sum(len(line) + 1 for line in sel) <= _tool_mod.MAX_SAMPLE_CHARS
        assert len(sel) < len(wide)

    def test_preserves_late_file_activity(self):
        """First-N sampling would miss an attack that starts late."""
        lines = [f"early{i} " + "Y" * 400 for i in range(4000)]
        lines += [f"ATTACK{i} " + "Y" * 400 for i in range(1000)]
        sel, _, _ = LogInvestigator._select_sample(lines, 5000)
        assert sum(1 for line in sel if line.startswith("ATTACK")) > 0
        # The behaviour this replaces captured none of them.
        assert sum(1 for line in lines[:50] if line.startswith("ATTACK")) == 0

    def test_keeps_both_ends(self):
        lines = [f"L{i:05d} " + "Z" * 500 for i in range(5000)]
        sel, _, truncated = LogInvestigator._select_sample(lines, 5000)
        assert truncated == "char_budget"
        assert sel[0] == lines[0]
        assert sel[-1] == lines[-1]

    def test_empty_input(self):
        assert LogInvestigator._select_sample([], 0) == ([], "none", None)


class TestPromptSample:
    def test_default_retention_is_500_not_50(self, plugin, tmp_path):
        """Guards the [:50] regression — context_lines must actually apply."""
        log = _write_log(tmp_path, total_lines=10_000, match_every=2)
        llm = RecordingLLM()
        result = plugin.execute(
            {"mode": "investigate", "file_path": str(log),
             "search_term": "Failed password"},
            Ctx(llm),
        )
        assert result.result["sampling"]["sampled"] == _tool_mod.DEFAULT_CONTEXT_LINES
        # Count sample rows between the header and the analysis section.
        body = llm.prompts[0].split("SAMPLE LOG ENTRIES", 1)[1]
        body = body.split("ANALYSIS REQUIRED", 1)[0]
        assert body.count("Failed password") == _tool_mod.DEFAULT_CONTEXT_LINES

    def test_prompt_discloses_partial_coverage(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=10_000, match_every=2)
        llm = RecordingLLM()
        plugin.execute(
            {"mode": "investigate", "file_path": str(log),
             "search_term": "Failed password", "context_lines": 100},
            Ctx(llm),
        )
        assert "showing 100 of" in llm.prompts[0]

    def test_no_disclosure_when_sample_is_complete(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=200, match_every=100)
        llm = RecordingLLM()
        plugin.execute(
            {"mode": "investigate", "file_path": str(log),
             "search_term": "Failed password"},
            Ctx(llm),
        )
        header = llm.prompts[0].split("ANALYSIS REQUIRED")[0]
        assert "showing" not in header

    def test_output_tokens_are_explicit(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=100, match_every=10)
        llm = RecordingLLM()
        plugin.execute(
            {"mode": "investigate", "file_path": str(log),
             "search_term": "Failed password"},
            Ctx(llm),
        )
        assert llm.max_tokens == [4096]

    def test_long_lines_are_truncated(self, plugin, tmp_path):
        log = tmp_path / "wide.log"
        log.write_text(
            "\n".join("NEEDLE " + "Q" * 9000 for _ in range(10)), encoding="utf-8",
        )
        result = plugin.execute(
            {"mode": "investigate", "file_path": str(log), "search_term": "NEEDLE"},
            Ctx(),
        )
        assert all(len(line) <= _tool_mod.MAX_LINE_CHARS
                   for line in result.result["sample_matches"])


class TestSamplingMetadata:
    def test_sampling_block_reports_coverage(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=10_000, match_every=2)
        result = plugin.execute(
            {"mode": "investigate", "file_path": str(log),
             "search_term": "Failed password", "context_lines": 200},
            Ctx(),
        )
        sampling = result.result["sampling"]
        assert sampling["sampled"] == 200
        assert sampling["total_matches"] == 5000
        assert sampling["truncated_by"] == "line_count"

    def test_summary_states_partial_coverage(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=10_000, match_every=2)
        result = plugin.execute(
            {"mode": "investigate", "file_path": str(log),
             "search_term": "Failed password", "context_lines": 200},
            Ctx(RecordingLLM()),
        )
        summary = plugin.summarize_for_llm(result)
        assert "200 of 5000" in summary
        assert len(summary) <= 2000

    def test_no_matches_reports_empty_sampling(self, plugin, tmp_path):
        log = _write_log(tmp_path, total_lines=100, match_every=1000)
        result = plugin.execute(
            {"mode": "investigate", "file_path": str(log), "search_term": "zzz-absent"},
            Ctx(),
        )
        assert result.ok
        assert result.result["sampling"]["sampled"] == 0
        assert result.result["ai_analysis"] is None
