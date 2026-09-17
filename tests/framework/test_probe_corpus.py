"""Stage 0 of the multi-provider plan — the model-interchange probe corpus.

Plan: ``docs/specs/multi_provider_llm_clients.md``.

``scripts/make_probe_pdf.py`` is the only instrument that can answer whether a
model or provider swap changed what the platform actually finds. The version
used for the Gemini 3.8 Flash comparison on 2026-09-12 was never committed —
only its output survived, in the change log — so these tests pin the corpus to
the numbers that comparison reported: **94 unique indicators, 82 of them
non-technique**, across three pages.

They are cheap and they guard three different failure modes:

- the inventory drifting, which would silently invalidate every recall figure
  ever compared against the 09-12 baseline;
- an indicator being written off the bottom of a page, where it would be scored
  as a model miss rather than a fixture bug;
- the generator becoming non-deterministic, which would make two runs differ by
  something other than the model.

Extraction here uses ``pypdf`` rather than ``pdfplumber``: pypdf is a base
dependency, so this test runs without the log-analysis extra installed.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "scripts" / "make_probe_pdf.py"

# The inventory reported in docs/change_log/2026-09-12-light-tier-gemini-3-8-flash.md.
BASELINE_COUNTS = {
    "ipv4": 24, "domain": 20, "sha256": 16, "url": 12, "cve": 10, "technique": 12,
}
BASELINE_TOTAL = 94
BASELINE_NON_TECHNIQUE = 82
BASELINE_PAGES = 3


@pytest.fixture(scope="module")
def probe():
    spec = importlib.util.spec_from_file_location("make_probe_pdf", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generated(probe, tmp_path_factory) -> tuple[Path, dict]:
    out = tmp_path_factory.mktemp("probe") / "probe"
    probe.main(["--out", str(out)])
    truth = json.loads(
        out.with_name("probe.ground_truth.json").read_text(encoding="utf-8"),
    )
    return out.with_suffix(".pdf"), truth


class TestInventoryMatchesTheBaseline:
    def test_counts_are_the_09_12_counts(self, generated):
        _, truth = generated
        assert truth["counts"] == BASELINE_COUNTS
        assert truth["total_unique_indicators"] == BASELINE_TOTAL
        assert truth["non_technique_indicators"] == BASELINE_NON_TECHNIQUE

    def test_every_indicator_is_unique_within_its_type(self, generated):
        _, truth = generated
        for kind, values in truth["indicators"].items():
            assert len(set(values)) == len(values), f"duplicate {kind}"

    def test_url_hostnames_are_not_themselves_indicators(self, generated):
        """The 12 extra regex candidates that give refinement something to do.

        If these leaked into the domain set they would stop being derived
        hostnames and the extractor would score an easy 94.
        """
        _, truth = generated
        hosts = set(truth["derived_hostnames"])
        assert len(hosts) == 12
        assert not (hosts & set(truth["indicators"]["domain"]))
        for url, host in zip(truth["indicators"]["url"], truth["derived_hostnames"]):
            assert host in url

    def test_techniques_resolve_against_the_repo_lookup(self, generated):
        """A fabricated id would be reported as an extraction failure, not a miss."""
        _, truth = generated
        lookup = json.loads(
            (REPO_ROOT / "framework" / "reference_data"
             / "mitre_techniques.json").read_text(encoding="utf-8"),
        )
        table = lookup.get("techniques", lookup)
        for entry in truth["techniques"]:
            assert entry["id"] in table
            assert entry["name"] == table[entry["id"]]["name"]
            assert entry["tactics"], f"{entry['id']} carries no tactic"

    def test_t1078_is_present(self, generated):
        """The 09-12 comparison turned on this one.

        A wrong tactic on T1078 was first read as a model difference and later
        shown to be a thinking-level effect. Any re-run of that argument needs
        the technique to still be in the corpus.
        """
        _, truth = generated
        assert "T1078" in [e["id"] for e in truth["techniques"]]


class TestTheDocumentActuallyCarriesThem:
    def test_three_pages(self, generated):
        from pypdf import PdfReader
        pdf_path, truth = generated
        assert len(PdfReader(str(pdf_path)).pages) == BASELINE_PAGES == truth["pages"]

    def test_every_indicator_survives_text_extraction(self, generated):
        """Nothing written off the bottom of a page, nothing mangled by encoding.

        A missing indicator here would be scored as a model miss in every
        subsequent comparison.
        """
        from pypdf import PdfReader
        pdf_path, truth = generated
        text = "\n".join(
            page.extract_text() or "" for page in PdfReader(str(pdf_path)).pages
        )
        missing = [
            (kind, value)
            for kind, values in truth["indicators"].items()
            for value in values
            if value not in text
        ]
        assert not missing, f"{len(missing)} indicators not extractable: {missing[:5]}"

    def test_the_corpus_is_ioc_dense(self, generated):
        """Profiles as ioc_dense, which is the batching path the 09-12 run took.

        94 candidates over 3 pages is ~31 per page against a threshold of 8.
        """
        from framework.documents.profile import IOC_DENSE_PER_PAGE
        _, truth = generated
        assert truth["total_unique_indicators"] / truth["pages"] >= IOC_DENSE_PER_PAGE


class TestTheGeneratorIsDeterministic:
    def test_two_runs_are_byte_identical(self, probe, tmp_path):
        """Two probe runs must differ by the model and nothing else."""
        first, second = tmp_path / "a", tmp_path / "b"
        probe.main(["--out", str(first)])
        probe.main(["--out", str(second)])
        assert first.with_suffix(".pdf").read_bytes() == \
            second.with_suffix(".pdf").read_bytes()
        assert first.with_name("a.ground_truth.json").read_text(encoding="utf-8") == \
            second.with_name("b.ground_truth.json").read_text(encoding="utf-8")

    def test_check_mode_writes_nothing(self, probe, tmp_path, capsys):
        assert probe.main(["--check", "--out", str(tmp_path / "unused")]) == 0
        assert not list(tmp_path.iterdir())
        assert "94 unique indicators" in capsys.readouterr().out
