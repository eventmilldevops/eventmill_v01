"""Contract tests for the Threat Report Analyzer plugin.

Covers the PDF-handling behaviour this plugin owns: that it does not restate
provider limits, that a provider's refusal is surfaced rather than worked
around, that partial page coverage is reported, and that two runs over one
report do not overwrite each other.
"""

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    _name = "threat_report_analyzer_tool"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()


# ---------------------------------------------------------------------------
# Fixtures and stand-ins
# ---------------------------------------------------------------------------


@pytest.fixture
def manifest() -> dict:
    with open(PLUGIN_DIR / "manifest.json", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def tool_instance():
    cls = getattr(_tool_mod, "ThreatReportAnalyzer", None)
    if cls is None:  # pragma: no cover - guards a manifest/class rename
        pytest.skip("ThreatReportAnalyzer not found in tool module")
    return cls()


@dataclass
class _Resp:
    """Stand-in for LLMResponse."""

    ok: bool = True
    text: str = ""
    error: str | None = None
    model_used: str = "fake-model"
    transport_path: str = "inline_bytes"
    fallback_reason: str | None = None


@dataclass
class _LLM:
    """LLM stand-in that answers query_with_document with a canned response."""

    doc_response: _Resp = field(default_factory=_Resp)
    text_response: _Resp = field(default_factory=lambda: _Resp(text="chunk text"))
    doc_calls: list = field(default_factory=list)
    text_calls: list = field(default_factory=list)

    def supports_native_document(self, mime_type: str) -> bool:
        return mime_type == "application/pdf"

    def query_with_document(self, prompt, artifact, **kwargs):
        self.doc_calls.append({"artifact": artifact, "prompt": prompt})
        return self.doc_response

    def query_text(self, prompt, **kwargs):
        self.text_calls.append({"prompt": prompt})
        return self.text_response


@dataclass
class _Context:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Provider limits must not be restated in the plugin
# ---------------------------------------------------------------------------


class TestNoProviderLimitsInPluginCode:
    """Provider caps belong to framework/llm/providers/<id>.json.

    The plugin used to carry MAX_PDF_SIZE_BYTES = 50 MB and
    MAX_PDF_PAGES = 1000 — Gemini's numbers, wrong for Anthropic and OpenAI
    (100 pages / 32 MB) and applied whichever provider was routed to.
    """

    def test_the_old_provider_shaped_constants_are_gone(self, tool_instance):
        for gone in ("MAX_PDF_SIZE_BYTES", "MAX_PDF_PAGES"):
            assert not hasattr(tool_instance, gone), (
                f"{gone} restates a provider limit; the dispatcher's PDF "
                f"guard owns that against the provider actually routed to"
            )

    def test_local_ceilings_exist_and_are_not_a_vendor_figure(self, tool_instance):
        """They bound what this process reads off disk, nothing else."""
        assert tool_instance.MAX_LOCAL_PDF_BYTES > 50 * 1024 * 1024, (
            "a local read ceiling at exactly a vendor's limit would read as "
            "a provider check again"
        )
        assert tool_instance.MAX_LOCAL_PDF_PAGES > 1000

    def test_provider_limits_are_read_from_the_manifests(self):
        """The numbers the plugin no longer hardcodes live here, per vendor."""
        from framework.llm.providers import pdf_handling

        assert pdf_handling("gcp_gemini")["max_pages"] == 1000
        assert pdf_handling("anthropic")["max_pages"] == 100
        assert pdf_handling("anthropic")["max_size_mb"] == 32


# ---------------------------------------------------------------------------
# A provider refusal is a decision, not a condition to route around
# ---------------------------------------------------------------------------


class TestProviderRefusalIsSurfaced:
    """This tool reads PDFs natively. If the provider will not take the
    document, falling back to pypdf text returns a summary that looks like
    any other while being built from markedly worse input."""

    def test_page_limit_refusal_is_classified_as_policy(self, tool_instance):
        assert (
            "pdf_exceeds_provider_page_limit"
            in tool_instance.PROVIDER_LIMIT_REFUSALS
        )
        assert (
            "pdf_exceeds_provider_size_limit"
            in tool_instance.PROVIDER_LIMIT_REFUSALS
        )

    def test_a_transport_failure_is_not_classified_as_policy(self, tool_instance):
        """Those still degrade to the text path, which is the right call."""
        for transient in ("model_unavailable", "timeout", None):
            assert transient not in tool_instance.PROVIDER_LIMIT_REFUSALS

    def test_refusal_blocks_and_names_both_ways_out(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        pdf = tmp_path / "big.pdf"
        pdf.write_bytes(b"%PDF-fake")
        monkeypatch.setattr(
            tool_instance, "_resolve_report_path", lambda *a, **k: pdf,
        )
        llm = _LLM(doc_response=_Resp(
            ok=False,
            error="PDF has 150 pages, above anthropic's limit of 100 pages.",
            fallback_reason="pdf_exceeds_provider_page_limit",
        ))
        result = tool_instance.execute(
            {"action": "summarize", "report_path": "vendor/big.pdf"},
            _Context(llm_query=llm),
        )
        assert result.ok is False
        assert result.error_code == "ARTIFACT_TOO_LARGE"
        assert "150 pages" in result.message
        assert "gcp_gemini" in result.message, "must name the provider that can"
        assert "split" in result.message.lower(), "must offer the other way"
        assert llm.text_calls == [], "must not silently analyse worse input"


# ---------------------------------------------------------------------------
# Page coverage
# ---------------------------------------------------------------------------


class TestPageCoverageIsReported:
    def test_no_coverage_claimed_when_nothing_measured_it(self, tool_instance):
        """Native ingestion reads the whole document, so there is no page
        count to report — inventing one would be worse than silence."""
        tool_instance._last_pdf_pages = None
        assert tool_instance._coverage_fields() == {}

    def test_full_read_reports_nothing_dropped(self, tool_instance):
        tool_instance._last_pdf_pages = (154, 154)
        assert tool_instance._coverage_fields() == {
            "pages_total": 154, "pages_read": 154, "pages_dropped": 0,
        }

    def test_truncated_read_reports_the_gap(self, tool_instance):
        tool_instance._last_pdf_pages = (2500, 2000)
        assert tool_instance._coverage_fields() == {
            "pages_total": 2500, "pages_read": 2000, "pages_dropped": 500,
        }

    def test_truncation_is_stated_in_the_llm_summary(self, tool_instance):
        result = type("R", (), {
            "ok": True,
            "result": {
                "action": "summarize",
                "summaries": [{
                    "report_path": "vendor/big.pdf",
                    "summary_path": "gs://b/x.md",
                    "word_count": 1676,
                    "chunk_count": 20,
                    "pages_total": 2500,
                    "pages_read": 2000,
                    "pages_dropped": 500,
                }],
            },
        })()
        text = tool_instance.summarize_for_llm(result)
        assert "INCOMPLETE COVERAGE" in text
        assert "2000 of 2500" in text

    def test_full_coverage_says_nothing_about_coverage(self, tool_instance):
        result = type("R", (), {
            "ok": True,
            "result": {
                "action": "summarize",
                "summaries": [{
                    "report_path": "vendor/ok.pdf",
                    "summary_path": "gs://b/x.md",
                    "word_count": 1676,
                    "chunk_count": 1,
                    "pages_total": 154,
                    "pages_read": 154,
                    "pages_dropped": 0,
                }],
            },
        })()
        assert "INCOMPLETE COVERAGE" not in tool_instance.summarize_for_llm(result)


# ---------------------------------------------------------------------------
# Exports are stamped, so re-runs accumulate rather than overwrite
# ---------------------------------------------------------------------------


class TestStampedExports:
    def test_stamp_is_sortable_utc(self, tool_instance):
        stamp = tool_instance._run_stamp()
        assert len(stamp) == 16 and stamp.endswith("Z") and "T" in stamp
        assert stamp[:8].isdigit()

    def test_stamp_sorts_chronologically_as_a_string(self, tool_instance):
        """A bucket listing sorts lexicographically; the two must agree."""
        assert "20260914T235959Z" < "20260915T000000Z"

    def test_summary_keeps_the_summary_md_suffix(self, tool_instance):
        name = tool_instance._export_name(
            "vendor/report.pdf", "20260915T031500Z", "summary.md",
        )
        assert name == "vendor/report.pdf.20260915T031500Z.summary.md"
        assert name.endswith(".summary.md"), (
            "the stamp goes before the suffix so a *.summary.md glob still "
            "matches"
        )

    def test_two_runs_do_not_collide(self, tool_instance):
        a = tool_instance._export_name("r.pdf", "20260915T031500Z", "summary.md")
        b = tool_instance._export_name("r.pdf", "20260915T031501Z", "summary.md")
        assert a != b

    def test_chunk_exports_share_the_runs_stamp(self, tool_instance):
        stamp = "20260915T031500Z"
        summary = tool_instance._export_name("r.pdf", stamp, "summary.md")
        chunk = tool_instance._export_name("r.pdf", stamp, "chunk_003.summary.md")
        assert stamp in summary and stamp in chunk, (
            "one run's files must group together in the bucket"
        )

    def test_discovery_finds_the_newest_stamped_summary(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        generated = tmp_path / "generated" / "threat_report_analyzer"
        generated.mkdir(parents=True)
        for stamp in ("20260914T120000Z", "20260915T031500Z"):
            (generated / f"r.pdf.{stamp}.summary.md").write_text("x")
        # A chunk summary shares the prefix and must not be mistaken for it.
        (generated / "r.pdf.20260915T031500Z.chunk_001.summary.md").write_text("x")
        monkeypatch.setattr(
            tool_instance, "_get_generated_path", lambda ctx: generated,
        )
        found = tool_instance._summary_output_path("r.pdf", None)
        assert found.name == "r.pdf.20260915T031500Z.summary.md"

    def test_discovery_still_finds_a_pre_stamp_summary(
        self, tool_instance, tmp_path, monkeypatch,
    ):
        """Summaries written before stamping must not become invisible."""
        generated = tmp_path / "generated" / "threat_report_analyzer"
        generated.mkdir(parents=True)
        legacy = generated / "r.pdf.summary.md"
        legacy.write_text("x")
        monkeypatch.setattr(
            tool_instance, "_get_generated_path", lambda ctx: generated,
        )
        found = tool_instance._summary_output_path("r.pdf", None)
        assert found == legacy and found.exists()
