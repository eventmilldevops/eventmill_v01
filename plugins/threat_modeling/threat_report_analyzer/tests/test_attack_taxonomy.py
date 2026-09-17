"""Both report tools must answer to one ATT&CK taxonomy.

The analyzer extracted `T\\d{4}` ids from model prose and published them
unchecked. It passed no grounding and no reference data to any LLM call - the
only `reference_data` in the file scanned the directory for *report files* -
and its prompts asked for "MITRE ATT&CK technique IDs" with no version anchor.

So the model answered from its training data, which for every current model
predates v19. The 154-page live run on 2026-09-16 produced a table headed
**Defense Evasion | T1027**, a tactic ATT&CK removed in v19 and split into
Stealth and Defense Impairment, and cited "MITRE ATT&CK Framework (v14+)" as a
source. `v14` appears nowhere in this repository - it was the model's own.

The ingester reconciled the identical retired tactic correctly on the same
document the same day, which is the whole problem: one report, two tools, two
taxonomies, and the analyzer's export is the one an analyst opens.

Two halves, because one cannot do the job alone:

- **Grounding** fixes the prose. Narrative text cannot be safely rewritten
  afterwards, so the only way the summary stops saying "Defense Evasion" is for
  the model to be told which release it is answering against.
- **Reconciliation** fixes the structured field, and gives the export one
  technique table that was actually checked - because a model writes the
  taxonomy it was trained on however well the prompt is grounded.
"""

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool_taxonomy"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()

from framework.reference_data import mitre_attack  # noqa: E402


# ---------------------------------------------------------------------------
# The shared helpers
# ---------------------------------------------------------------------------


class TestTheSharedReconciler:
    def test_a_technique_carries_its_v19_tactic(self):
        """T1027's only tactic in v19.2 is Stealth. The live run called it
        Defense Evasion, which no longer exists."""
        (entry,) = mitre_attack.reconcile_technique_ids(["T1027"])
        assert entry["technique_name"] == "Obfuscated Files or Information"
        assert entry["tactics"] == ["Stealth"]
        assert entry["mitre_validated"] is True

    def test_defense_evasion_is_not_a_tactic_anywhere(self):
        """The assertion behind the whole change: it is gone, not renamed in
        place, so anything still emitting it is answering from a stale
        release."""
        assert "Defense Evasion" not in mitre_attack.TACTIC_ORDER
        assert "Defense Evasion" in mitre_attack.LEGACY_TACTIC_ALIASES

    def test_an_unknown_id_is_reported_not_dropped(self):
        (entry,) = mitre_attack.reconcile_technique_ids(["T9999"])
        assert entry["mitre_validated"] is False
        assert entry["technique_id"] == "T9999"

    def test_order_is_first_appearance_and_deduplicated(self):
        ids = [e["technique_id"] for e in
               mitre_attack.reconcile_technique_ids(
                   ["T1566", "T1027", "T1566"])]
        assert ids == ["T1566", "T1027"]

    def test_blank_ids_are_skipped(self):
        assert mitre_attack.reconcile_technique_ids(["", "  ", None]) == []


class TestTheGroundingBlock:
    def test_it_names_the_release(self):
        text = mitre_attack.attack_grounding()
        assert mitre_attack.attack_version() in text
        assert "19" in text

    def test_it_names_the_retired_tactic_and_its_successors(self):
        """Naming the successors is the point - "do not use Defense Evasion"
        without saying what replaced it leaves the model to guess."""
        text = mitre_attack.attack_grounding()
        assert "Defense Evasion" in text
        assert "Stealth" in text
        assert "Defense Impairment" in text

    def test_it_lists_the_enterprise_tactics(self):
        text = mitre_attack.attack_grounding()
        for tactic in ("Initial Access", "Execution", "Exfiltration", "Impact"):
            assert tactic in text

    def test_ics_only_tactics_are_left_out(self):
        """These are real v19 tactics but not enterprise ones, and listing
        them in a prompt about an enterprise threat report invites their use."""
        text = mitre_attack.attack_grounding()
        assert "Inhibit Response Function" not in text
        assert "Impair Process Control" not in text

    def test_no_lookup_means_no_claim(self, monkeypatch):
        """Claiming a version we cannot check is worse than saying nothing."""
        monkeypatch.setattr(mitre_attack, "get_mitre_db", lambda: {})
        assert mitre_attack.attack_grounding() == ""


# ---------------------------------------------------------------------------
# The analyzer uses them
# ---------------------------------------------------------------------------


class TestThePromptsAreGrounded:
    @pytest.mark.parametrize("template", [
        "SUMMARIZATION_PROMPT_TEMPLATE",
        "CHUNK_SUMMARIZATION_PROMPT_TEMPLATE",
        "SYNTHESIS_PROMPT_TEMPLATE",
    ])
    def test_every_template_has_a_grounding_slot(self, template):
        assert "{attack_grounding}" in getattr(_tool_mod, template)


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    model_used: str = "fake-model"
    transport_path: str = "inline_bytes"
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


@dataclass
class _LLM:
    body: str = "Summary body."
    prompts: list = field(default_factory=list)

    def supports_native_document(self, mime_type: str) -> bool:
        return False

    def query_with_document(self, prompt, artifact, **kwargs):
        self.prompts.append(prompt)
        return _Resp(text=self.body)

    def query_text(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return _Resp(text=self.body)


@dataclass
class _Context:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)


@pytest.fixture
def run_report(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    vault = tmp_path / "vault"
    vault.mkdir(parents=True, exist_ok=True)

    def go(body, tool=None, export_to=None, chunk_tokens=None,
           report_text="A threat report."):
        report = vault / "report.txt"
        report.write_text(report_text, encoding="utf-8")
        tool = tool or _tool_mod.ThreatReportAnalyzer()
        if chunk_tokens:
            tool.MAX_TOKENS_PER_CHUNK = chunk_tokens
        # A relative report_path, resolved to the real file: the export name is
        # built from the path as given, so an absolute one lands outside the
        # generated directory and the write is refused.
        monkeypatch.setattr(tool, "_resolve_report_path", lambda *a, **k: report)
        if export_to is not None:
            export_to.mkdir(parents=True, exist_ok=True)
            monkeypatch.setattr(
                tool, "_get_generated_path", lambda ctx: export_to,
            )
            monkeypatch.setattr(
                tool, "_get_common_bucket_path", lambda ctx: export_to,
            )
        llm = _LLM(body=body)
        result = tool._summarize_report(
            {"report_path": "vendor/report.txt"}, _Context(llm_query=llm),
        )
        assert result.ok, result.message
        return tool, result, llm

    return go


# The shape the live run produced: a tactic table using a retired tactic name.
LIVE_BODY = """Summary of the intrusion.

| Tactic | Technique ID | Technique Name |
| --- | --- | --- |
| Initial Access | T1566 | Phishing |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage |

## Sources and References
* MITRE ATT&CK Framework (v14+).
"""


class TestTheRunReconcilesItsTechniques:
    def test_the_grounding_reaches_the_prompt(self, run_report):
        _, _, llm = run_report(LIVE_BODY)
        assert llm.prompts
        assert all("Defense Evasion" in p for p in llm.prompts), (
            "the prompt must name the retired tactic to rule it out"
        )
        assert all(mitre_attack.attack_version() in p for p in llm.prompts)

    def test_the_native_document_path_is_grounded(self, tmp_path, monkeypatch):
        """The chunked path is not the one a real report takes. The 154-page
        live run went native as a whole document, so grounding that misses
        query_with_document misses the case that matters."""
        monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
        pdf = tmp_path / "r.pdf"
        pdf.write_bytes(b"%PDF-fake")
        tool = _tool_mod.ThreatReportAnalyzer()
        monkeypatch.setattr(tool, "_resolve_report_path", lambda *a, **k: pdf)
        monkeypatch.setattr(tool, "_pdf_page_count", lambda p: 3)

        class _NativeLLM(_LLM):
            def supports_native_document(self, mime_type: str) -> bool:
                return mime_type == "application/pdf"

        llm = _NativeLLM(body=LIVE_BODY)
        result = tool._summarize_report(
            {"report_path": "vendor/r.pdf"}, _Context(llm_query=llm),
        )
        assert result.ok, result.message
        assert llm.prompts, "the native path must have been taken"
        assert all(
            mitre_attack.attack_version() in p for p in llm.prompts
        ), "the native document prompt went out ungrounded"

    def test_every_call_in_a_multi_section_run_is_grounded(self, run_report):
        """A single-section report takes the whole-report prompt and never
        reaches the section or synthesis templates. Those are the calls a long
        report actually makes - the 154-page run made sixteen of them - so a
        fixture that only ever produces one chunk leaves both ungrounded and
        the suite green."""
        long_report = "\n\n".join(
            f"Section {i}. " + ("narrative " * 200) for i in range(6)
        )
        _, result, llm = run_report(
            LIVE_BODY, report_text=long_report, chunk_tokens=200,
        )
        assert result.result["summaries"][0]["chunk_count"] > 1, (
            "the fixture must actually produce several sections"
        )
        assert len(llm.prompts) > 2, "sections plus a synthesis"
        version = mitre_attack.attack_version()
        for prompt in llm.prompts:
            assert version in prompt, (
                "a call went out with no ATT&CK release"
            )
            assert "Defense Evasion" in prompt

    def test_the_result_carries_reconciled_entries(self, run_report):
        _, result, _ = run_report(LIVE_BODY)
        summary = result.result["summaries"][0]
        by_id = {e["technique_id"]: e for e in summary["attack_techniques"]}
        assert by_id["T1027"]["tactics"] == ["Stealth"], (
            "the structured field must carry the v19 tactic even though the "
            "prose above it says Defense Evasion"
        )
        assert by_id["T1027"]["technique_name"] == (
            "Obfuscated Files or Information"
        )

    def test_the_result_states_which_release(self, run_report):
        _, result, _ = run_report(LIVE_BODY)
        assert result.result["summaries"][0]["attack_version"] == (
            mitre_attack.attack_version()
        )

    def test_relevant_techniques_still_holds_plain_ids(self, run_report):
        """Downstream consumers read this as a list of strings; reconciliation
        must not change its shape."""
        _, result, _ = run_report(LIVE_BODY)
        techniques = result.result["summaries"][0]["relevant_techniques"]
        assert all(isinstance(t, str) for t in techniques)
        assert "T1027" in techniques

    def test_the_reconciled_block_resets_between_runs(self, run_report):
        tool, _, _ = run_report(LIVE_BODY)
        assert tool._reconciled
        _, result, _ = run_report("Summary with no techniques.", tool=tool)
        assert result.result["summaries"][0]["attack_techniques"] == []

    def test_a_run_that_fails_early_does_not_keep_the_last_one_s_techniques(
        self, tmp_path, monkeypatch,
    ):
        """Run state, like _dropped and _truncations. One tool object
        summarises many reports, and a run that returns before reconciliation
        must not leave the previous report's technique table standing where
        the export path can still reach it."""
        monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
        tool = _tool_mod.ThreatReportAnalyzer()
        tool._reconciled = mitre_attack.reconcile_technique_ids(["T1027"])
        assert tool._attack_block(), "stale state to be cleared"

        monkeypatch.setattr(tool, "_resolve_report_path", lambda *a, **k: None)
        result = tool._summarize_report(
            {"report_path": "vendor/missing.pdf"}, _Context(llm_query=_LLM()),
        )
        assert not result.ok, "this run must return before reconciliation"
        assert tool._attack_block() == "", (
            "the previous report's techniques are still standing"
        )


class TestTheExportCarriesACheckedTable:
    def test_the_block_names_the_release_and_the_tactics(self, run_report):
        tool, _, _ = run_report(LIVE_BODY)
        block = tool._attack_block()
        assert f"v{mitre_attack.attack_version()}" in block
        assert "Stealth" in block, (
            "the file an analyst opens must carry at least one technique "
            "table that was actually checked"
        )

    def test_an_unknown_id_is_marked_rather_than_listed_as_fact(
        self, run_report,
    ):
        """On its own row, not only in the footnote. A reader scanning the
        table sees the row; a blank name column reads as "we did not look up
        the name", which is a different claim from "ATT&CK does not have this".
        """
        tool, _, _ = run_report("Techniques: T1566 and T9999.")
        rows = {
            line.split("|")[1].strip(): line
            for line in tool._attack_block().splitlines()
            if line.startswith("| T")
        }
        assert "T9999" in rows
        assert "not in ATT&CK" in rows["T9999"]
        assert "Phishing" in rows["T1566"], "a known id still reads normally"

    def test_no_techniques_means_no_block(self, run_report):
        """An empty table would imply the report named no techniques."""
        tool, _, _ = run_report("A summary naming no techniques at all.")
        assert tool._attack_block() == ""

    def test_the_block_is_written_into_the_summary_file(
        self, run_report, tmp_path,
    ):
        export_dir = tmp_path / "gen"
        run_report(LIVE_BODY, export_to=export_dir)
        # summary_path on the result is only populated when a bucket mirror
        # exists; the file itself is written regardless, and the file is what
        # an analyst opens.
        written = list(export_dir.rglob("*.summary.md"))
        assert written, "the run must have written a summary file"
        text = written[0].read_text(encoding="utf-8")
        assert "ATT&CK techniques (reconciled against v" in text
        assert text.index("Event Mill threat_report_analyzer") < text.index(
            "ATT&CK techniques (reconciled"
        ), "provenance header first, then the checked table, then the prose"
