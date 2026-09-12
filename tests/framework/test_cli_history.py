"""
Tests for the history CLI commands.

'history' was defined twice in shell.py, so the tool-execution listing was
silently replaced by the LLM-conversation listing. The two streams are now
separate commands ('tool_history', 'llm_history') with a merged 'history'
timeline over both, and the duplicate-name guard below keeps the shadowing
from coming back.
"""

import ast
import io
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell
from framework.session.models import Pillar, ToolExecutionStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EventMillShell:
    """A shell with an active session and no cloud environment."""
    monkeypatch.delenv("K_SERVICE", raising=False)

    sh = EventMillShell(workspace_path=tmp_path)
    sh.session_manager.new_session("test")
    sh.session_manager.set_pillar(Pillar.LOG_ANALYSIS)
    return sh


def _seed_execution(
    shell: EventMillShell,
    tool_name: str,
    status: ToolExecutionStatus = ToolExecutionStatus.COMPLETED,
    summary: str = "",
    output_artifact_id: str | None = None,
) -> str:
    """Record one finished tool execution and return its id."""
    execution = shell.session_manager.start_execution(tool_name)
    if status is ToolExecutionStatus.RUNNING:
        return execution.execution_id
    shell.session_manager.complete_execution(
        execution,
        status=status,
        output_artifact_id=output_artifact_id,
        summary=summary,
    )
    return execution.execution_id


def _seed_turn(shell: EventMillShell, question: str, answer: str, when: datetime) -> None:
    """Append one LLM turn in the shape do_ask records."""
    shell._conversation_history.append({
        "question": question,
        "answer": answer,
        "timestamp": when.isoformat(timespec="seconds"),
    })


# ---------------------------------------------------------------------------
# The shadowing regression itself
# ---------------------------------------------------------------------------


class TestCommandNamesAreUnique:
    """A second def of the same do_* name silently replaces the first."""

    def test_no_duplicate_command_definitions(self):
        source = io.open(
            Path("framework/cli/shell.py"), encoding="utf-8"
        ).read()
        tree = ast.parse(source)
        shell_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "EventMillShell"
        )
        names = [
            node.name
            for node in shell_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("do_")
        ]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        assert duplicates == []

    def test_all_three_commands_exist(self, shell):
        assert callable(shell.do_history)
        assert callable(shell.do_tool_history)
        assert callable(shell.do_llm_history)


# ---------------------------------------------------------------------------
# tool_history
# ---------------------------------------------------------------------------


class TestToolHistory:
    """Tests for the tool execution listing."""

    def test_lists_executions_with_duration(self, shell, capsys):
        _seed_execution(shell, "pdf_profiler")
        shell.onecmd("tool_history")
        out = capsys.readouterr().out
        assert "pdf_profiler" in out
        assert "completed" in out
        assert "Duration" in out

    def test_running_execution_has_no_duration(self, shell, capsys):
        _seed_execution(shell, "zeek_runner", status=ToolExecutionStatus.RUNNING)
        shell.onecmd("tool_history")
        out = capsys.readouterr().out
        assert "running" in out

    def test_empty(self, shell, capsys):
        shell.onecmd("tool_history")
        assert "No tool executions yet" in capsys.readouterr().out

    def test_requires_session(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("K_SERVICE", raising=False)
        sh = EventMillShell(workspace_path=tmp_path)
        capsys.readouterr()
        sh.onecmd("tool_history")
        assert "No active session" in capsys.readouterr().out

    def test_filter_by_tool(self, shell, capsys):
        _seed_execution(shell, "pdf_profiler")
        _seed_execution(shell, "threat_report_analyzer")
        shell.onecmd("tool_history --tool pdf_profiler")
        out = capsys.readouterr().out
        assert "pdf_profiler" in out
        assert "threat_report_analyzer" not in out

    def test_filter_by_status(self, shell, capsys):
        _seed_execution(shell, "pdf_profiler")
        _seed_execution(shell, "threat_report_analyzer", status=ToolExecutionStatus.FAILED)
        shell.onecmd("tool_history --status failed")
        out = capsys.readouterr().out
        assert "threat_report_analyzer" in out
        assert "pdf_profiler" not in out

    def test_filter_with_no_match_says_so(self, shell, capsys):
        _seed_execution(shell, "pdf_profiler")
        shell.onecmd("tool_history --tool nope")
        assert "No tool executions match" in capsys.readouterr().out

    def test_limit_keeps_most_recent(self, shell, capsys):
        _seed_execution(shell, "first_tool")
        _seed_execution(shell, "second_tool")
        shell.onecmd("tool_history --limit 1")
        out = capsys.readouterr().out
        assert "second_tool" in out
        assert "first_tool" not in out
        assert "1 of 2 executions shown" in out

    def test_detail_shows_summary_and_artifacts(self, shell, capsys):
        _seed_execution(
            shell,
            "pdf_profiler",
            summary="42 candidate pages",
            output_artifact_id="art_123",
        )
        shell.onecmd("tool_history --detail")
        out = capsys.readouterr().out
        assert "42 candidate pages" in out
        assert "art_123" in out

    def test_execution_id_shows_one_execution(self, shell, capsys):
        exec_id = _seed_execution(shell, "pdf_profiler", summary="42 candidate pages")
        _seed_execution(shell, "threat_report_analyzer", summary="other summary")
        shell.onecmd(f"tool_history {exec_id}")
        out = capsys.readouterr().out
        assert "42 candidate pages" in out
        assert "other summary" not in out

    def test_unknown_execution_id(self, shell, capsys):
        shell.onecmd("tool_history exec_nope")
        assert "Execution not found" in capsys.readouterr().out

    def test_unknown_flag(self, shell, capsys):
        shell.onecmd("tool_history --nope 1")
        assert "Unknown flag --nope" in capsys.readouterr().out

    def test_unknown_status(self, shell, capsys):
        shell.onecmd("tool_history --status sideways")
        assert "Unknown --status" in capsys.readouterr().out

    def test_negative_limit(self, shell, capsys):
        shell.onecmd("tool_history --limit -1")
        assert "cannot be negative" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# llm_history
# ---------------------------------------------------------------------------


class TestLLMHistory:
    """Tests for the LLM conversation listing."""

    def test_lists_turns_with_timestamp(self, shell, capsys):
        _seed_turn(shell, "which users were targeted?", "root and admin", datetime(2026, 9, 5, 10, 30))
        shell.onecmd("llm_history")
        out = capsys.readouterr().out
        assert "which users were targeted?" in out
        assert "root and admin" in out
        assert "10:30:00" in out

    def test_empty(self, shell, capsys):
        shell.onecmd("llm_history")
        assert "No conversation history" in capsys.readouterr().out

    def test_answer_is_truncated_by_default(self, shell, capsys):
        _seed_turn(shell, "q", "x" * 400, datetime(2026, 9, 5, 10, 30))
        shell.onecmd("llm_history")
        out = capsys.readouterr().out
        assert "..." in out
        assert "x" * 400 not in out

    def test_full_shows_whole_answer(self, shell, capsys):
        _seed_turn(shell, "q", "line one\nline two", datetime(2026, 9, 5, 10, 30))
        shell.onecmd("llm_history --full")
        out = capsys.readouterr().out
        assert "line one" in out
        assert "line two" in out

    def test_last_keeps_most_recent(self, shell, capsys):
        _seed_turn(shell, "first question", "a", datetime(2026, 9, 5, 10, 30))
        _seed_turn(shell, "second question", "b", datetime(2026, 9, 5, 10, 31))
        shell.onecmd("llm_history --last 1")
        out = capsys.readouterr().out
        assert "second question" in out
        assert "first question" not in out
        assert "1 of 2 turns shown" in out

    def test_clear(self, shell, capsys):
        _seed_turn(shell, "q", "a", datetime(2026, 9, 5, 10, 30))
        shell.onecmd("llm_history clear")
        assert "cleared" in capsys.readouterr().out
        assert shell._conversation_history == []

    def test_unknown_flag(self, shell, capsys):
        shell.onecmd("llm_history --nope")
        assert "Unknown flag --nope" in capsys.readouterr().out

    def test_turn_without_timestamp_still_lists(self, shell, capsys):
        shell._conversation_history.append({"question": "q", "answer": "a"})
        shell.onecmd("llm_history")
        assert "q" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# merged history
# ---------------------------------------------------------------------------


class TestMergedHistory:
    """Tests for the timeline over both streams."""

    def test_shows_both_streams(self, shell, capsys):
        _seed_execution(shell, "pdf_profiler")
        _seed_turn(shell, "which users were targeted?", "root", datetime.now())
        shell.onecmd("history")
        out = capsys.readouterr().out
        assert "pdf_profiler" in out
        assert "which users were targeted?" in out
        assert "1 tool, 1 llm" in out

    def test_ordered_oldest_first(self, shell, capsys):
        _seed_turn(shell, "older question", "a", datetime.now() - timedelta(hours=1))
        _seed_execution(shell, "later_tool")
        shell.onecmd("history")
        out = capsys.readouterr().out
        assert out.index("older question") < out.index("later_tool")

    def test_empty(self, shell, capsys):
        shell.onecmd("history")
        assert "No history yet" in capsys.readouterr().out

    def test_limit_keeps_most_recent(self, shell, capsys):
        _seed_execution(shell, "first_tool")
        _seed_execution(shell, "second_tool")
        shell.onecmd("history --limit 1")
        out = capsys.readouterr().out
        assert "second_tool" in out
        assert "first_tool" not in out
        assert "1 of 2 events shown" in out

    def test_clear_only_touches_llm_turns(self, shell, capsys):
        _seed_execution(shell, "pdf_profiler")
        _seed_turn(shell, "q", "a", datetime.now())
        shell.onecmd("history clear")
        assert shell._conversation_history == []
        assert shell.session_manager.list_executions()

    def test_unknown_flag(self, shell, capsys):
        shell.onecmd("history --nope 1")
        assert "Unknown flag --nope" in capsys.readouterr().out

    def test_turn_without_timestamp_sorts_last(self, shell, capsys):
        shell._conversation_history.append({"question": "untimed question", "answer": "a"})
        _seed_execution(shell, "pdf_profiler")
        shell.onecmd("history")
        out = capsys.readouterr().out
        assert out.index("pdf_profiler") < out.index("untimed question")


# ---------------------------------------------------------------------------
# session scoping
# ---------------------------------------------------------------------------


class TestConversationScoping:
    """In-memory LLM turns belong to the session they were asked in."""

    def test_new_session_clears_turns(self, shell):
        _seed_turn(shell, "q", "a", datetime.now())
        shell.onecmd("new second investigation")
        assert shell._conversation_history == []

    def test_load_session_clears_turns(self, shell):
        first = shell.session_manager.get_current_session().session_id
        shell.onecmd("new second investigation")
        _seed_turn(shell, "q", "a", datetime.now())
        shell.onecmd(f"load_session {first}")
        assert shell._conversation_history == []
