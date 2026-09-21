"""A mistyped flag is named, not silently accepted.

Found 2026-09-16 on a live run. The operator typed `--ignore_cap` for
`--ignore_caps`, and the run reported success having done the opposite of what
was asked: the extraction caps applied, seven key findings were cut, and
nothing in the output said the flag had not been understood.

Three things had to line up for that to be silent. The shell reads
`input.schema.json` only to *type* flag values, never to validate them
(`_plugin_input_schema` returns the `properties` block alone). Undeclared keys
are passed through deliberately, "for the plugin's own validate_inputs() to
judge". And no plugin's `validate_inputs` rejects unknown keys.

The fix names the arguments the tool does accept and blocks the run rather
than continuing with an incomplete guess at what the operator meant. Naming
the right path is the job; inferring intent, and running the tool anyway once
the operator's real request could not, is not.
"""

from pathlib import Path

import pytest

from framework.cli.shell import EventMillShell


class _FakeManifest:
    def __init__(self, tool_name: str, plugin_dir: Path):
        self.tool_name = tool_name
        self.plugin_dir = plugin_dir


class _FakePlugin:
    def __init__(self, tool_name: str, plugin_dir: Path):
        self.tool_name = tool_name
        self.manifest = _FakeManifest(tool_name, plugin_dir)


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EventMillShell:
    monkeypatch.delenv("K_SERVICE", raising=False)
    return EventMillShell(workspace_path=tmp_path)


@pytest.fixture
def plugin(tmp_path: Path) -> _FakePlugin:
    """A plugin whose schema declares the flags the analyzer really has."""
    schemas = tmp_path / "fake_plugin" / "schemas"
    schemas.mkdir(parents=True, exist_ok=True)
    (schemas / "input.schema.json").write_text(
        '{"type": "object", "properties": {'
        '"action": {"type": "string"},'
        '"report_path": {"type": "string"},'
        '"max_word_count": {"type": "integer"},'
        '"ignore_caps": {"type": "boolean"}'
        "}}",
        encoding="utf-8",
    )
    return _FakePlugin("threat_report_analyzer", tmp_path / "fake_plugin")


class TestAnUnknownFlagIsNamed:
    def test_the_live_typo_is_reported(self, shell, plugin, capsys):
        """`--ignore_cap` for `--ignore_caps`, exactly as it was typed."""
        shell._parse_flag_payload(
            "--action summarize --report_path r.pdf --ignore_cap", plugin,
        )
        out = capsys.readouterr().out
        (line,) = [ln for ln in out.splitlines() if "is not an argument" in ln]
        assert "--ignore_cap" in line
        # The warning line names the tool itself, not only the list that
        # follows it: a session runs several tools, and "not an argument"
        # without saying of what is half a message.
        assert "threat_report_analyzer" in line

    def test_the_arguments_that_do_exist_are_listed(self, shell, plugin, capsys):
        """Naming the right path is the teaching. The operator reads the list
        and picks; nothing is chosen for them."""
        shell._parse_flag_payload("--ignore_cap", plugin)
        out = capsys.readouterr().out
        assert "--ignore_caps" in out
        assert "--report_path" in out
        assert "--max_word_count" in out

    def test_nothing_is_corrected_or_substituted(self, shell, plugin, capsys):
        """The message must not become a guess. `ignore_caps` is never inferred
        from `ignore_cap` - the run is blocked instead of silently retargeted."""
        payload = shell._parse_flag_payload("--ignore_cap", plugin)
        assert payload is None

    def test_it_blocks_rather_than_running_with_a_guess(self, shell, plugin, capsys):
        """An unknown flag aborts the whole run - even alongside otherwise-valid
        flags - rather than running the tool on a partial, unintended payload."""
        payload = shell._parse_flag_payload(
            "--action summarize --ignore_cap", plugin,
        )
        assert payload is None

    def test_a_correct_flag_says_nothing(self, shell, plugin, capsys):
        payload = shell._parse_flag_payload(
            "--action summarize --ignore_caps", plugin,
        )
        assert payload == {"action": "summarize", "ignore_caps": True}
        assert capsys.readouterr().out == ""

    def test_each_unknown_flag_is_named_once(self, shell, plugin, capsys):
        shell._parse_flag_payload("--nope 1 --nope 2 --alsono 3", plugin)
        out = capsys.readouterr().out
        assert out.count("--nope is not an argument") == 1
        assert "--alsono is not an argument" in out

    def test_a_plugin_with_no_readable_schema_warns_about_nothing(
        self, shell, tmp_path, capsys,
    ):
        """Without a schema every flag would look unknown, and warning about
        all of them would be noise that teaches nothing."""
        empty = tmp_path / "no_schema"
        empty.mkdir(parents=True, exist_ok=True)
        payload = shell._parse_flag_payload(
            "--whatever 1", _FakePlugin("mystery_tool", empty),
        )
        assert payload == {"whatever": "1"}
        assert capsys.readouterr().out == ""
