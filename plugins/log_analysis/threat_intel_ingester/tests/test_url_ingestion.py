"""threat_intel_ingester --url: fetch, convert, and read a page in one pass.

The fetch itself is covered in tests/framework/test_url_fetch.py; here it is
replaced, so these tests are about what the ingester does with what came back.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

pytest.importorskip("bs4")
pytest.importorskip("markdownify")

from framework.documents.url_fetch import FetchedDocument, UrlFetchError  # noqa: E402

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load_tool_module():
    name = "threat_intel_ingester_tool_url"
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_tool_mod = _load_tool_module()

URL = "https://vendor.example/blog/storm-0000/?utm=x"


@dataclass
class _Artifact:
    artifact_id: str
    artifact_type: str
    file_path: str
    source_tool: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class _Context:
    session_id: str = "s"
    selected_pillar: str = "log_analysis"
    artifacts: list = field(default_factory=list)
    config: dict = field(default_factory=dict)
    logger: Any = None
    reference_data: Any = None
    llm_enabled: bool = True
    llm_query: Any = None
    register_artifact: Callable | None = None
    limits: dict = field(default_factory=dict)


@dataclass
class _Resp:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    token_usage: dict | None = None
    model_used: str | None = "mock-light"
    transport_path: str | None = None
    fallback_reason: str | None = None
    finish_reason: str | None = "STOP"
    truncated: bool = False


class _TextLLM:
    """Answers every candidate it is shown, and records each call."""

    def __init__(self, fail_first: int = 0, truncate_over: int | None = None):
        self.text_calls: list[dict] = []
        self.doc_calls: list[dict] = []
        self.fail_first = fail_first
        self.truncate_over = truncate_over

    def supports_native_document(self, mime_type: str) -> bool:
        return mime_type == "application/pdf"

    @staticmethod
    def _ips(prompt: str) -> list[str]:
        return [
            line.split("- [ip] ", 1)[1].split(" |", 1)[0]
            for line in prompt.splitlines() if line.startswith("- [ip] ")
        ]

    @staticmethod
    def _reply(ips: list[str]) -> str:
        return json.dumps({
            "refined_iocs": [
                {"value": v, "ioc_type": "ip", "confidence": "high", "priority": "high",
                 "context": "seen", "related_mitre": [], "is_false_positive": False}
                for v in ips
            ],
            "additional_mitre_techniques": [],
            "report_metadata": {"title": "Storm-0000 campaign",
                                "attributed_actor": "Storm-0000",
                                "attribution_confidence": "high"},
            "attack_graph": {"paths": [], "convergence_points": [], "branch_points": []},
        })

    def query_text(self, prompt, system_context=None, max_tokens=4096,
                   grounding_data=None, hints=None):
        ips = self._ips(prompt)
        self.text_calls.append({
            "prompt": prompt, "max_tokens": max_tokens, "hints": hints, "ips": ips,
        })
        if len(self.text_calls) <= self.fail_first:
            return _Resp(ok=False, error="503 UNAVAILABLE")
        body = self._reply(ips)
        if self.truncate_over is not None and len(ips) > self.truncate_over:
            return _Resp(text=body[: len(body) // 2], finish_reason="MAX_TOKENS",
                         truncated=True)
        return _Resp(text=body)

    def query_with_document(self, prompt, artifact, system_context=None,
                            max_tokens=8192, grounding_data=None, hints=None):
        ips = self._ips(prompt)
        self.doc_calls.append({"artifact": artifact, "ips": ips})
        return _Resp(text=self._reply(ips))


PAGE = """<!doctype html><html><head><title>Storm-0000 campaign | Vendor</title>
<script>var cdn = "198.51.100.77";</script></head><body>
<nav><a href="https://vendor.example/products">Products</a></nav>
<main>
<h1>Storm-0000 campaign</h1>
<p>Storm-0000, a state-aligned actor, abused a trusted application.</p>
<p>""" + "The intrusion is described here in narrative detail. " * 30 + """</p>
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td><b>144.172.64[.]128</b></td><td>IP</td><td>Sign-ins</td></tr>
<tr><td><b>144.172.64[.]99</b></td><td>IP</td><td></td></tr>
<tr><td>evil_domain[.]com</td><td>Domain</td><td>C2</td></tr></table>
<h2>Hunting</h2>
<pre><code>let IPs = dynamic(["144.172.64.60"]);</code></pre>
<article><h3>Related: Storm-9999 phishing</h3><p>Teaser.</p></article>
</main><footer>Copyright</footer></body></html>"""


def _doc(body: bytes, kind: str = "html", content_type: str = "text/html; charset=utf-8"):
    return FetchedDocument(
        requested_url=URL,
        final_url="https://vendor.example/blog/storm-0000/",
        kind=kind,
        content_type=content_type,
        charset="utf-8" if kind != "pdf" else None,
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        fetched_at="2026-10-26T16:00:00+00:00",
        peer_address="93.184.216.34",
        redirects=[URL],
    )


@pytest.fixture
def run(tmp_path, monkeypatch):
    """Execute the ingester on a fetched document; returns a runner."""
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path))
    registered: list[dict] = []

    def register(artifact_type, file_path, source_tool, metadata):
        art_id = f"art_{len(registered):04d}"
        registered.append({
            "artifact_id": art_id, "artifact_type": artifact_type,
            "file_path": file_path, "source_tool": source_tool, "metadata": metadata,
        })
        return _Artifact(art_id, artifact_type, file_path, source_tool, metadata)

    def runner(fetched, llm=None, payload=None, artifacts=None):
        def fake_fetch(url, **_kw):
            if isinstance(fetched, Exception):
                raise fetched
            return fetched
        monkeypatch.setattr(_tool_mod, "fetch_url", fake_fetch)
        ctx = _Context(
            artifacts=list(artifacts or []),
            llm_enabled=llm is not None, llm_query=llm, register_artifact=register,
        )
        return _tool_mod.ThreatIntelIngester().execute(payload or {"url": URL}, ctx)

    runner.registered = registered
    runner.tmp = tmp_path
    return runner


class TestOnePass:
    def test_a_blog_post_is_read_whole_in_one_call(self, run):
        llm = _TextLLM()
        result = run(_doc(PAGE.encode("utf-8")), llm)
        assert result.ok, result.message
        summary = result.result["summary"]
        assert summary["ingestion_plan"]["strategy"] == "text_whole"
        assert len(llm.text_calls) == 1
        assert llm.doc_calls == []
        assert summary["chunks_attempted"] == 0
        assert summary["analysis_status"] == "complete"

        call = llm.text_calls[0]
        prompt = call["prompt"]
        assert "[The complete report text follows; nothing has been omitted.]" in prompt
        # Verbatim table row, attribution and code, in one prompt.
        assert "144.172.64[.]128" in prompt and "Storm-0000, a state-aligned" in prompt
        assert 'dynamic(["144.172.64.60"])' in prompt
        assert "[Fetched from https://vendor.example/blog/storm-0000/]" in prompt
        # Page furniture never reaches the model.
        for noise in ("198.51.100.77", "Products", "Copyright", "Storm-9999"):
            assert noise not in prompt
        # The regex baseline saw the defanged values.
        assert {"144.172.64.128", "144.172.64.99", "144.172.64.60"} <= set(call["ips"])

    def test_the_call_is_sized_like_a_native_one(self, run):
        llm = _TextLLM()
        run(_doc(PAGE.encode("utf-8")), llm)
        call = llm.text_calls[0]
        assert call["max_tokens"] == _tool_mod._native_max_output_tokens()
        assert call["hints"].thinking_level == _tool_mod._NATIVE_THINKING_LEVEL
        assert call["hints"].tier is None

    def test_coverage_and_provenance_are_in_sections(self, run):
        result = run(_doc(PAGE.encode("utf-8")), _TextLLM())
        summary = result.result["summary"]
        meta = result.result["report_metadata"]
        assert summary["coverage_unit"] == "sections"
        assert meta["page_count"] == meta["pages_total"] >= 3
        occ = result.result["iocs"][0]["occurrences"][0]
        assert occ["batch_label"] == f"s1-{meta['page_count']}"

    def test_the_source_travels_with_the_result(self, run):
        body = PAGE.encode("utf-8")
        result = run(_doc(body), _TextLLM())
        source = result.result["report_metadata"]["source"]
        assert source["final_url"] == "https://vendor.example/blog/storm-0000/"
        assert source["requested_url"] == URL
        assert source["content_sha256"] == hashlib.sha256(body).hexdigest()
        assert len(source["markdown_sha256"]) == 64
        assert source["fetched_kind"] == "html"
        assert "raw_file_path" not in source
        assert "fetch_s" in result.result["summary"]["timings"]
        assert "text_s" in result.result["summary"]["timings"]

        persisted_path = result.output_artifacts[0]["file_path"]
        persisted = json.loads(Path(persisted_path).read_text(encoding="utf-8"))
        assert persisted["source"]["content_sha256"] == source["content_sha256"]
        assert persisted["coverage"]["unit"] == "sections"

    def test_the_summary_names_the_unit_and_the_source(self, run):
        result = run(_doc(PAGE.encode("utf-8")), _TextLLM())
        text = _tool_mod.ThreatIntelIngester().summarize_for_llm(result)
        n = result.result["report_metadata"]["page_count"]
        assert f"Ingested text ({n} sections) fetched from https://vendor.example/" in text

    def test_the_fetched_page_is_registered_as_this_runs_input(self, run):
        run(_doc(PAGE.encode("utf-8")), _TextLLM())
        source, output = run.registered
        assert source["artifact_type"] == "text"
        assert source["source_tool"] == "threat_intel_ingester"
        assert source["metadata"]["ingest_as"] == _tool_mod._SECTIONED_TEXT
        md = Path(source["file_path"]).read_text(encoding="utf-8")
        assert "144.172.64[.]128" in md
        # The original HTML is kept beside the Markdown that was read.
        assert Path(source["metadata"]["raw_file_path"]).read_bytes() == PAGE.encode("utf-8")
        assert output["artifact_type"] == "json_events"
        assert output["metadata"]["source_artifact"] == source["artifact_id"]
        assert output["metadata"]["source_url"] == "https://vendor.example/blog/storm-0000/"


def _dense_page(sections: int, per_section: int) -> bytes:
    parts = ["<html><body><main><h1>IOC dump</h1>"]
    for s in range(sections):
        rows = "".join(
            f"<li>45.{s}.{i // 250}.{i % 250}</li>" for i in range(per_section)
        )
        parts.append(f"<h2>Cluster {s + 1}</h2><ul>{rows}</ul>")
    parts.append("</main></body></html>")
    return "".join(parts).encode("utf-8")


class TestLargePages:
    def test_too_much_for_one_call_is_split_at_headings(self, run):
        llm = _TextLLM()
        result = run(_doc(_dense_page(12, 120)), llm)
        assert result.ok, result.message
        plan = result.result["summary"]["ingestion_plan"]
        assert plan["strategy"] == "text_batched"
        assert len(llm.text_calls) == plan["batch_count"] > 1
        n = result.result["report_metadata"]["page_count"]
        covered = [s for b in plan["batches"] for s in range(b["start"], b["end"] + 1)]
        assert covered == list(range(1, n + 1))
        for call, batch in zip(llm.text_calls, plan["batches"]):
            assert f"[Report sections {batch['start']}-{batch['end']} of {n}]" in call["prompt"]
            assert f"sections {batch['start']}-{batch['end']} of {n}; other sections" in call["prompt"]
            assert len(call["ips"]) == batch["candidates"]
        assert result.result["summary"]["analysis_status"] == "complete"

    def test_a_cut_off_reply_is_halved_and_rerun(self, run):
        # 120 candidates fit one call by estimate; the model disagrees.
        llm = _TextLLM(truncate_over=100)
        result = run(_doc(_dense_page(4, 30)), llm)
        assert result.ok, result.message
        summary = result.result["summary"]
        assert summary["ingestion_plan"]["strategy"] == "text_whole"
        assert len(llm.text_calls) == 3  # whole, then two halves
        assert len(llm.text_calls[0]["ips"]) == 120
        assert all(len(c["ips"]) <= 100 for c in llm.text_calls[1:])
        assert summary["chunks_attempted"] == 0
        assert {i["value"] for i in result.result["iocs"]} == {
            f"45.{s}.0.{i}" for s in range(4) for i in range(30)
        }

    def test_a_failed_call_falls_back_to_chunks_for_its_sections(self, run):
        llm = _TextLLM(fail_first=1)
        result = run(_doc(PAGE.encode("utf-8")), llm)
        assert result.ok, result.message
        summary = result.result["summary"]
        assert summary["chunks_attempted"] >= 1
        # The fallback is the ordinary chunked path, at its own small budget.
        assert all(c["max_tokens"] == 4096 for c in llm.text_calls[1:])
        assert {i["value"] for i in result.result["iocs"]} >= {"144.172.64.128"}


class TestPdfLinks:
    def test_a_linked_pdf_is_read_as_a_pdf(self, run, monkeypatch):
        monkeypatch.setattr(
            _tool_mod, "extract_pdf_page_texts",
            lambda path, max_pages=None: ["Storm-0000 used 203.0.113[.]5", "page two"],
        )
        llm = _TextLLM()
        result = run(_doc(b"%PDF-1.7 fake", kind="pdf", content_type="application/pdf"), llm)
        assert result.ok, result.message
        source = run.registered[0]
        assert source["artifact_type"] == "pdf_report"
        assert source["file_path"].endswith(".pdf")
        assert source["metadata"]["mime_type"] == "application/pdf"
        assert "ingest_as" not in source["metadata"]
        assert result.result["summary"]["ingestion_plan"]["strategy"] == "native"
        assert len(llm.doc_calls) == 1
        assert llm.doc_calls[0]["artifact"].file_path == source["file_path"]
        assert result.result["summary"]["coverage_unit"] == "pages"
        assert result.result["report_metadata"]["source"]["fetched_kind"] == "pdf"


class TestRefusals:
    @pytest.mark.parametrize("reason, code", [
        ("invalid", "INPUT_VALIDATION_FAILED"),
        ("blocked", "INPUT_VALIDATION_FAILED"),
        ("failed", "ARTIFACT_UNREADABLE"),
        ("too_large", "ARTIFACT_UNREADABLE"),
        ("unsupported", "ARTIFACT_UNREADABLE"),
    ])
    def test_fetch_failures_keep_their_cause(self, run, reason, code):
        result = run(UrlFetchError(reason, "the real cause"), _TextLLM())
        assert not result.ok
        assert result.error_code == code
        assert "the real cause" in result.message
        assert run.registered == []

    def test_an_empty_shell_page_names_javascript(self, run):
        shell = b"<html><head><title>App</title></head><body><div id='root'></div><script>x()</script></body></html>"
        result = run(_doc(shell), _TextLLM())
        assert not result.ok
        assert result.error_code == "ARTIFACT_UNREADABLE"
        assert "JavaScript" in result.message

    def test_both_sources_are_refused(self, run):
        result = run(_doc(PAGE.encode()), _TextLLM(),
                     payload={"url": URL, "artifact_id": "art_x"})
        assert not result.ok and result.error_code == "INPUT_VALIDATION_FAILED"


class TestRerunAndRegression:
    def test_rerun_by_artifact_id_reads_the_saved_copy_the_same_way(self, run):
        run(_doc(PAGE.encode("utf-8")), _TextLLM())
        saved = run.registered[0]
        art = _Artifact(saved["artifact_id"], "text", saved["file_path"],
                        "threat_intel_ingester", saved["metadata"])
        llm = _TextLLM()
        result = run(UrlFetchError("failed", "must not fetch"), llm,
                     payload={"artifact_id": saved["artifact_id"]}, artifacts=[art])
        assert result.ok, result.message
        assert result.result["summary"]["ingestion_plan"]["strategy"] == "text_whole"
        assert len(llm.text_calls) == 1
        assert result.result["report_metadata"]["source"]["final_url"].startswith(
            "https://vendor.example/"
        )

    def test_a_loaded_markdown_file_is_still_read_in_chunks(self, run):
        md = run.tmp / "notes.md"
        md.write_text("## IOCs\n\n" + "\n".join(
            f"45.1.{i // 250}.{i % 250}" for i in range(20)), encoding="utf-8")
        art = _Artifact("art_md", "text", str(md))
        llm = _TextLLM()
        result = run(UrlFetchError("failed", "unused"), llm,
                     payload={"artifact_id": "art_md"}, artifacts=[art])
        assert result.ok, result.message
        summary = result.result["summary"]
        assert summary["ingestion_plan"]["strategy"] == "chunked_text"
        assert summary["coverage_unit"] == "lines"
        assert "source" not in result.result["report_metadata"]
        assert all(c["max_tokens"] == 4096 for c in llm.text_calls)
