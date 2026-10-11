"""Contract and behaviour tests for logging_standard_profiler.

Model replies are scripted. They prove the handling around the model: quote
checking, shape coercion, salvage of a cut-off reply. They say nothing about
how well a real model reads a real standard; that is what the live run in the
change log is for.
"""

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
EXAMPLE_PROFILE = PLUGIN_DIR / "examples" / "profile.example.json"


def _load_tool():
    name = "logging_standard_profiler_tool"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "tool.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()
ps, ex, cl = tool.ps, tool.ex, tool.cl

STANDARD_TEXT = """Example Corp Application Logging Standard v2.1

1 Purpose
This standard exists so that applications produce logs that support
investigation. It applies to all teams.

4.2 Record content
Each log entry shall include a timestamp in UTC with at least millisecond
resolution. Authentication events shall record the user identity and the
outcome of the attempt.

6 Retention
Log data shall be retained for a minimum of twelve months.
"""

GOOD_REPLY = {
    "standard": {
        "title": "Example Corp Application Logging Standard",
        "version": "v2.1",
    },
    "requirements": [
        {
            "requirement_id": "4.2-a",
            "section": "4.2 Record content",
            "page": 1,
            "obligation": "must",
            "assessable_from": "record_content",
            "summary": "Records carry a UTC millisecond timestamp.",
            "quote": "Each log entry shall include a timestamp in UTC with at least millisecond resolution.",
            "elements": [
                {
                    "element": "timestamp",
                    "constraints": {
                        "timezone_required": True,
                        "min_precision": "millisecond",
                    },
                }
            ],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "4.2-b",
            "section": "4.2 Record content",
            "page": 1,
            "obligation": "must",
            "assessable_from": "record_content",
            "summary": "Authentication events identify the user and the outcome.",
            "quote": "Authentication events must log who the user was and what happened.",
            "elements": [{"element": "actor_identity"}, {"element": "outcome"}],
            "unmapped_reason": None,
        },
        {
            "requirement_id": "6",
            "section": "6 Retention",
            "page": 1,
            "obligation": "must",
            "assessable_from": "not_assessable_from_sample",
            "summary": "Logs are kept twelve months.",
            "quote": "Log data shall be retained for a minimum of twelve months.",
            "elements": [],
            "unmapped_reason": None,
        },
    ],
}


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
    transport_path: str | None = None
    token_usage: dict[str, int] | None = None


class FakeLLM:
    def __init__(self, replies: list[Any]) -> None:
        self.replies = list(replies)
        self.prompts: list[str] = []

    def supports_native_document(self, mime_type: str) -> bool:
        return False

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
            return FakeResponse(ok=False, error="no scripted reply left")
        item = self.replies.pop(0)
        return item if isinstance(item, FakeResponse) else FakeResponse(text=item)


@dataclass
class FakeArtifact:
    artifact_id: str
    artifact_type: str
    file_path: str
    metadata: dict[str, Any] = field(default_factory=dict)


class FakeContext:
    def __init__(self, llm: Any = None) -> None:
        self.llm_query = llm
        self.artifacts: list[FakeArtifact] = []
        self.registered: list[FakeArtifact] = []

    def register_artifact(self, artifact_type, file_path, source_tool, metadata):
        artifact = FakeArtifact(
            f"art_{len(self.registered) + 1:04d}",
            artifact_type,
            str(file_path),
            dict(metadata or {}),
        )
        self.registered.append(artifact)
        return artifact


@pytest.fixture
def plugin():
    return tool.LoggingStandardProfiler()


@pytest.fixture
def standard(tmp_path):
    path = tmp_path / "standard.txt"
    path.write_text(STANDARD_TEXT, encoding="utf-8")
    return path


def extract(plugin, standard, replies):
    context = FakeContext(FakeLLM(replies))
    result = plugin.execute(
        {"action": "extract_profile", "file_path": str(standard)}, context
    )
    return result, context


class TestManifest:
    @pytest.fixture
    def manifest(self):
        return json.loads((PLUGIN_DIR / "manifest.json").read_text(encoding="utf-8"))

    def test_identity(self, manifest):
        assert manifest["tool_name"] == "logging_standard_profiler"
        assert manifest["pillar"] == PLUGIN_DIR.parent.name
        assert manifest["safe_for_auto_invoke"] is False
        assert manifest["model_tier"] == "heavy"

    def test_manifest_validates_against_schema(self, manifest):
        import jsonschema

        schema_path = PLUGIN_DIR.parents[2] / "docs" / "specs" / "manifest_schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(manifest)

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()


class TestProfileContract:
    def test_example_profile_is_valid(self):
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        report = ps.validate_profile(profile)
        assert report["errors"] == []

    def test_example_carries_the_current_catalogue(self):
        # The auditor reads the catalogue from the profile, so a stale copy in
        # the example would teach readers the wrong element names.
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        assert profile["catalogue"] == ps.load_catalogue()

    def test_unreviewed_draft_is_a_warning_not_an_error(self):
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        profile["review_status"] = "draft_unreviewed"
        report = ps.validate_profile(profile)
        assert report["errors"] == []
        assert any("draft_unreviewed" in w for w in report["warnings"])

    def test_unknown_element_is_an_error(self):
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        profile["requirements"][0]["elements"] = [{"element": "mood"}]
        assert any("'mood'" in e for e in ps.validate_profile(profile)["errors"])

    def test_a_group_of_alternatives_is_valid(self):
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        profile["requirements"][0]["elements"] = [
            {"any_of": [{"element": "host"}, {"element": "source_component"}]}
        ]
        assert ps.validate_profile(profile)["errors"] == []
        profile["requirements"][0]["elements"] = [
            {"any_of": [{"element": "host"}, {"element": "mood"}]},
            {"any_of": [{"element": "host"}]},
        ]
        errors = ps.validate_profile(profile)["errors"]
        assert any("'mood'" in e for e in errors)
        assert any("at least two" in e for e in errors)

    def test_clarity_grades_each_category(self):
        catalogue = ps.load_catalogue()
        def requirement(rid, obligation, kind, elements, quote="Records shall carry it."):
            return {
                "requirement_id": rid,
                "obligation": obligation,
                "assessable_from": "record_content",
                "kind": kind,
                "quote": quote,
                "elements": elements,
            }

        one = lambda name: [{"element": name}]  # noqa: E731
        profile = {
            "catalogue": catalogue,
            "requirements": [
                requirement("A", "must", "presence", one("timestamp")),
                requirement(
                    "B",
                    "must",
                    "presence",
                    one("actor_identity"),
                    "Where applicable, records shall identify the user.",
                ),
                requirement("C", "should", "presence", one("session_id")),
                requirement(
                    "D",
                    "must",
                    "presence",
                    [{"any_of": [{"element": "target_object"}, {"element": "message"}]}],
                ),
                requirement("E", "must", "quality", one("outcome")),
                requirement(
                    "F",
                    "must",
                    "presence",
                    [{"any_of": [{"element": "host"}, {"element": "source_address"}]}],
                ),
                {
                    "requirement_id": "G",
                    "obligation": "must",
                    "assessable_from": "not_assessable_from_sample",
                    "kind": None,
                    "elements": one("event_type"),
                },
            ],
        }
        clarity = cl.grade(profile)
        got = {c["category"]: c for c in clarity["categories"]}
        assert [c["category"] for c in clarity["categories"]] == [
            "when", "what", "who", "outcome", "where", "link", "target",
        ]
        assert {k: v["bin"] for k, v in got.items()} == {
            "when": 5,
            "what": 1,
            "who": 4,
            "outcome": 1,
            "where": 5,
            "link": 3,
            "target": 3,
        }
        assert got["when"]["gaps"] == []
        assert got["what"]["gaps"] == [cl.NOT_ADDRESSED] and not got["what"]["addressed"]
        assert got["who"]["gaps"] == [cl.MISSING["unconditional"]]
        assert got["outcome"]["addressed"] and got["outcome"]["value_rules"] == 1
        assert got["outcome"]["gaps"][0] == cl.MISSING["countable"]
        assert got["link"]["gaps"] == [
            cl.MISSING["mandatory"],
            cl.MISSING["unconditional"],
        ]
        assert got["target"]["gaps"][0] == cl.MISSING["specific"]
        assert got["who"]["clauses"] == ["B"]
        assert clarity["requirements_sha256"] == cl.requirements_digest(
            profile["requirements"]
        )
        assert "who 4" in cl.summary_line(clarity)
        assert cl.grade({"catalogue": {"elements": {}}, "requirements": []}) is None

    def test_example_profile_carries_a_current_grade(self):
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        assert profile["standard_clarity"] == cl.grade(profile)
        assert ps.validate_profile(profile)["errors"] == []
        profile["standard_clarity"] = "good"
        assert any(
            "standard_clarity" in e for e in ps.validate_profile(profile)["errors"]
        )

    def test_validate_profile_refreshes_a_missing_or_stale_grade(
        self, plugin, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("EVENTMILL_WORKSPACE", str(tmp_path / "ws"))
        current = plugin.execute(
            {"action": "validate_profile", "file_path": str(EXAMPLE_PROFILE)}, None
        )
        assert current.ok and current.result["refreshed_profile"] is None
        assert current.result["standard_clarity"]["categories"]

        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        del profile["standard_clarity"]
        del profile["catalogue"]["investigation_categories"]
        old = tmp_path / "old.json"
        old.write_text(json.dumps(profile), encoding="utf-8")
        result = plugin.execute(
            {"action": "validate_profile", "file_path": str(old)}, None
        )
        assert result.ok and result.result["valid"]
        written = json.loads(
            Path(result.result["refreshed_profile"]["file"]).read_text(encoding="utf-8")
        )
        assert written["standard_clarity"] == current.result["standard_clarity"]
        assert written["catalogue"]["investigation_categories"]
        assert "missing or out of date" in plugin.summarize_for_llm(result)
        assert "Clarity of the standard" in plugin.summarize_for_llm(result)

    def test_kind_is_optional_and_checked(self):
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        for requirement in profile["requirements"]:
            requirement.pop("kind", None)
        assert ps.validate_profile(profile)["errors"] == []
        profile["requirements"][0]["kind"] = "vibes"
        assert any("kind must be one of" in e for e in ps.validate_profile(profile)["errors"])

    def test_duplicate_ids_are_an_error(self):
        profile = json.loads(EXAMPLE_PROFILE.read_text(encoding="utf-8"))
        profile["requirements"][1]["requirement_id"] = profile["requirements"][0][
            "requirement_id"
        ]
        assert any("duplicate" in e for e in ps.validate_profile(profile)["errors"])

    @pytest.mark.parametrize("bad", [None, [], "x", {"requirements": "none"}, {}])
    def test_garbage_never_raises(self, bad):
        assert ps.validate_profile(bad)["errors"]

    def test_validate_action(self, plugin):
        result = plugin.execute(
            {"action": "validate_profile", "file_path": str(EXAMPLE_PROFILE)}, None
        )
        assert result.ok and result.result["valid"] is True
        assert result.result["counts"]["testable_against_records"] == 4
        assert "valid" in plugin.summarize_for_llm(result)


class TestUntrustedRequirementShape:
    @pytest.fixture
    def catalogue(self):
        return ps.load_catalogue()

    @pytest.mark.parametrize("raw", [None, "text", 3, [], {}, {"summary": ""}])
    def test_unusable_records_are_dropped_with_a_note(self, raw, catalogue):
        requirement, notes = ps.normalise_requirement(raw, catalogue, 1)
        assert requirement is None and notes

    def test_wrong_types_are_coerced(self, catalogue):
        requirement, notes = ps.normalise_requirement(
            {
                "requirement_id": 4.2,
                "summary": "s",
                "obligation": "SHALL",
                "assessable_from": "maybe",
                "elements": "timestamp",
                "page": "7",
                "quote": ["not", "a", "string"],
            },
            catalogue,
            1,
        )
        assert requirement["requirement_id"] == "4.2"
        assert requirement["obligation"] == "should"
        assert requirement["assessable_from"] == "not_assessable_from_sample"
        assert requirement["elements"] == []
        assert requirement["page"] == 7
        assert notes

    def test_invented_element_is_never_kept(self, catalogue):
        requirement, _ = ps.normalise_requirement(
            {
                "summary": "s",
                "obligation": "must",
                "assessable_from": "record_content",
                "elements": [{"element": "geo_location"}, "timestamp"],
            },
            catalogue,
            1,
        )
        assert [e["element"] for e in requirement["elements"]] == ["timestamp"]
        assert "geo_location" in requirement["unmapped_reason"]

    def test_alternatives_are_kept_as_a_group(self, catalogue):
        requirement, _ = ps.normalise_requirement(
            {
                "summary": "s",
                "obligation": "must",
                "assessable_from": "record_content",
                "elements": [
                    "timestamp",
                    {
                        "any_of": ["host", {"element": "source_component"}, "host"],
                        "label": "origin",
                    },
                ],
            },
            catalogue,
            1,
        )
        assert requirement["elements"] == [
            {"element": "timestamp"},
            {
                "any_of": [{"element": "host"}, {"element": "source_component"}],
                "label": "origin",
            },
        ]

    def test_a_group_left_with_one_element_becomes_a_required_element(self, catalogue):
        requirement, notes = ps.normalise_requirement(
            {
                "summary": "s",
                "obligation": "must",
                "assessable_from": "record_content",
                "elements": [{"any_of": ["host", "tenant"]}, {"any_of": "host"}],
            },
            catalogue,
            1,
        )
        assert requirement["elements"] == [{"element": "host"}]
        assert "tenant" in requirement["unmapped_reason"]
        assert any("one usable element" in n for n in notes)

    @pytest.mark.parametrize(
        "raw_kind,quote,assessable,expected",
        [
            (None, "Each entry shall include the user.", "record_content", "presence"),
            ("QUALITY", "Values shall be valid.", "record_content", "quality"),
            ("mood", "Each entry shall include the user.", "record_set", "presence"),
            (
                "presence",
                "Identifiers shall be stable and shall not expose secrets.",
                "record_content",
                "prohibition",
            ),
            ("presence", "Records must never hold tokens.", "record_content", "prohibition"),
            ("permission", "Time may be split across fields.", "record_content", "permission"),
            ("presence", "Logs shall be kept a year.", "not_assessable_from_sample", None),
        ],
    )
    def test_kind(self, catalogue, raw_kind, quote, assessable, expected):
        requirement, _ = ps.normalise_requirement(
            {
                "summary": "s",
                "quote": quote,
                "obligation": "must",
                "assessable_from": assessable,
                "kind": raw_kind,
                "elements": ["actor_identity"],
            },
            catalogue,
            1,
        )
        assert requirement["kind"] == expected

    def test_timestamp_constraints_only_on_timestamps(self, catalogue):
        requirement, notes = ps.normalise_requirement(
            {
                "summary": "s",
                "obligation": "must",
                "assessable_from": "record_content",
                "elements": [
                    {"element": "outcome", "constraints": {"timezone_required": True}}
                ],
            },
            catalogue,
            1,
        )
        assert "constraints" not in requirement["elements"][0]
        assert any("only applies to a timestamp" in n for n in notes)


class TestReplyParsing:
    def test_fenced_json(self):
        _, requirements, _ = ex.parse_reply(
            "```json\n" + json.dumps(GOOD_REPLY) + "\n```"
        )
        assert len(requirements) == 3

    def test_truncated_reply_keeps_whole_requirements(self):
        text = json.dumps(GOOD_REPLY)
        cut = text[: text.index('"requirement_id": "6"') + 30]
        _, requirements, notes = ex.parse_reply(cut)
        assert [r["requirement_id"] for r in requirements] == ["4.2-a", "4.2-b"]
        assert any("salvaged 2" in n for n in notes)

    @pytest.mark.parametrize(
        "text", [None, "", "I cannot read this.", "[", '"x"', "42"]
    )
    def test_never_raises(self, text):
        standard, requirements, notes = ex.parse_reply(text)
        assert requirements == [] and notes


class TestQuoteCheck:
    def test_survives_line_breaks_case_and_typographic_quotes(self):
        pages = [
            "Each log entry shall include a time-\nstamp in UTC.\n“Quoted” text here."
        ]
        requirements = [
            {"quote": "each log entry shall include a timestamp in UTC."},
            {"quote": '"Quoted" text here.'},
            {"quote": "This sentence is not in the document."},
            {"quote": ""},
        ]
        counts = ex.check_quotes(requirements, pages)
        assert [r["quote_status"] for r in requirements] == [
            "found",
            "found",
            "quote_not_found",
            "not_checked",
        ]
        assert counts == {"found": 2, "quote_not_found": 1, "not_checked": 1}

    def test_page_is_taken_from_where_the_quote_was_found(self):
        requirements = [{"quote": "retained for twelve months", "page": 9}]
        ex.check_quotes(requirements, ["intro", "Logs are retained for twelve months."])
        assert requirements[0]["page"] == 2

    def test_no_text_layer_means_not_checked(self):
        requirements = [{"quote": "anything"}]
        ex.check_quotes(requirements, ["", ""])
        assert requirements[0]["quote_status"] == "not_checked"


class TestExtractProfile:
    def test_writes_a_draft_profile_and_registers_it(self, plugin, standard):
        result, context = extract(plugin, standard, [json.dumps(GOOD_REPLY)])
        assert result.ok, result.message
        assert len(context.registered) == 1
        profile = json.loads(
            open(context.registered[0].file_path, encoding="utf-8").read()
        )
        assert profile["review_status"] == "draft_unreviewed"
        assert profile["catalogue"] == ps.load_catalogue()
        assert profile["provenance"]["model_version"] == "fake-model-001"
        assert len(profile["standard"]["document_sha256"]) == 64
        assert ps.validate_profile(profile)["errors"] == []

    def test_paraphrased_quote_is_flagged_not_dropped(self, plugin, standard):
        result, context = extract(plugin, standard, [json.dumps(GOOD_REPLY)])
        assert result.result["quote_check"] == {
            "found": 2,
            "quote_not_found": 1,
            "not_checked": 0,
        }
        profile = json.loads(
            open(context.registered[0].file_path, encoding="utf-8").read()
        )
        flagged = [
            r for r in profile["requirements"] if r["quote_status"] == "quote_not_found"
        ]
        assert [r["requirement_id"] for r in flagged] == ["4.2-b"]
        assert any("4.2-b" in w for w in result.result["validation"]["warnings"])

    def test_boilerplate_is_separated_from_testable(self, plugin, standard):
        result, _ = extract(plugin, standard, [json.dumps(GOOD_REPLY)])
        counts = result.result["counts"]
        assert counts["testable_against_records"] == 2
        assert counts["by_assessable_from"]["not_assessable_from_sample"] == 1

    def test_prompt_shows_shapes_and_the_catalogue(self, plugin, standard):
        _, context = extract(plugin, standard, [json.dumps(GOOD_REPLY)])
        prompt = context.llm_query.prompts[0]
        assert '"assessable_from": "not_assessable_from_sample"' in prompt
        assert "actor_identity (identity)" in prompt
        assert "Each log entry shall include a timestamp" in prompt
        assert '"any_of"' in prompt and "only one member of a group" in prompt
        assert '"event_selection" - ' in prompt and '"kind": "prohibition"' in prompt

    def test_only_presence_rules_count_as_testable(self, plugin, standard):
        reply = json.loads(json.dumps(GOOD_REPLY))
        reply["requirements"][1]["kind"] = "event_selection"
        result, _ = extract(plugin, standard, [json.dumps(reply)])
        counts = result.result["counts"]
        assert counts["testable_against_records"] == 1
        assert counts["by_kind"]["event_selection"] == 1
        assert "not countable: 1 event_selection" in plugin.summarize_for_llm(result)

    def test_duplicate_ids_are_made_unique(self, plugin, standard):
        reply = json.loads(json.dumps(GOOD_REPLY))
        reply["requirements"][1]["requirement_id"] = "4.2-a"
        result, context = extract(plugin, standard, [json.dumps(reply)])
        profile = json.loads(
            open(context.registered[0].file_path, encoding="utf-8").read()
        )
        assert [r["requirement_id"] for r in profile["requirements"]][:2] == [
            "4.2-a",
            "4.2-a#2",
        ]
        assert result.result["validation"]["errors"] == []

    def test_unusable_reply_fails_with_what_came_back(self, plugin, standard):
        result, context = extract(
            plugin, standard, ["I am unable to open the document."]
        )
        assert not result.ok
        assert result.error_code == "EXTRACTION_EMPTY"
        assert "unable to open" in result.message
        assert context.registered == []

    def test_model_failure_is_reported_as_such(self, plugin, standard):
        result, _ = extract(
            plugin, standard, [FakeResponse(ok=False, error="504 deadline")]
        )
        assert not result.ok
        assert result.error_code == "LLM_QUERY_FAILED"
        assert "504" in result.message

    def test_no_model(self, plugin, standard):
        result = plugin.execute(
            {"action": "extract_profile", "file_path": str(standard)}, FakeContext(None)
        )
        assert result.error_code == "LLM_UNAVAILABLE"

    def test_summary_leads_with_review_status(self, plugin, standard):
        result, _ = extract(plugin, standard, [json.dumps(GOOD_REPLY)])
        summary = plugin.summarize_for_llm(result)
        assert "draft_unreviewed" in summary.splitlines()[0]
        assert "art_0001" in summary
        assert len(summary) < 4000

    def test_long_document_is_read_in_parts(self):
        pages = ["x" * 50_000 for _ in range(5)]
        parts = ex.text_parts(pages, max_chars=120_000)
        assert [(p["first_page"], p["last_page"]) for p in parts] == [
            (1, 2),
            (3, 4),
            (5, 5),
        ]


class NativeLLM(FakeLLM):
    def __init__(self, replies):
        super().__init__(replies)
        self.documents: list[Any] = []

    def supports_native_document(self, mime_type: str) -> bool:
        return mime_type == "application/pdf"

    def query_with_document(
        self,
        prompt,
        artifact,
        system_context=None,
        max_tokens=8192,
        grounding_data=None,
        hints=None,
    ):
        self.prompts.append(prompt)
        self.documents.append(artifact)
        item = self.replies.pop(0)
        if isinstance(item, FakeResponse):
            return item
        return FakeResponse(text=item, transport_path="inline_bytes")


class TestNativeDocument:
    @pytest.fixture
    def scanned_pdf(self, tmp_path):
        # Not a parseable PDF, which is what a scan with no text layer amounts
        # to for the local quote check.
        path = tmp_path / "standard.pdf"
        path.write_bytes(b"%PDF-1.4 not really a pdf")
        return path

    def test_native_read_without_local_text_leaves_quotes_unchecked(
        self, plugin, scanned_pdf
    ):
        llm = NativeLLM([json.dumps(GOOD_REPLY)])
        context = FakeContext(llm)
        result = plugin.execute(
            {"action": "extract_profile", "file_path": str(scanned_pdf)}, context
        )
        assert result.ok, result.message
        assert llm.documents[0].file_path == str(scanned_pdf)
        assert "The standard is attached as a document" in llm.prompts[0]
        assert result.result["quote_check"]["not_checked"] == 3
        assert any("PDF text" in n for n in result.result["notes"])
        profile = json.loads(
            open(context.registered[0].file_path, encoding="utf-8").read()
        )
        assert profile["provenance"]["transport"] == "inline_bytes"

    def test_native_failure_with_no_text_says_why(self, plugin, scanned_pdf):
        llm = NativeLLM([FakeResponse(ok=False, error="document exceeds page limit")])
        result = plugin.execute(
            {"action": "extract_profile", "file_path": str(scanned_pdf)},
            FakeContext(llm),
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_UNREADABLE"
        assert "page limit" in result.message


class TestValidateInputs:
    def test_needs_a_document(self, plugin):
        assert not plugin.validate_inputs({"action": "extract_profile"}).ok

    def test_unknown_action(self, plugin):
        assert not plugin.validate_inputs({"action": "certify", "file_path": "x"}).ok

    def test_default_action(self, plugin):
        assert plugin.validate_inputs({"artifact_id": "art_0001"}).ok


SWEEP_STANDARD = """Example Corp Application Logging Standard v2.1

1 Purpose
The word shall states a mandatory requirement in this standard.

4.2 Record content
Each log entry shall include a timestamp in UTC with at least millisecond
resolution. Authentication events shall record the user identity and the
outcome of the attempt. Records should name the host that produced them.

6 Retention
Log data shall be retained for a minimum of twelve months. Archives must be
encrypted at rest.
"""

SWEEP_REPLY = {
    "sentences": [
        {"n": 1, "requirement": False, "why": "defines a term"},
        {
            "n": 4,
            "requirement": True,
            "obligation": "should",
            "assessable_from": "record_content",
            "summary": "Records name their host.",
            "elements": [{"element": "host"}, {"element": "made_up"}],
            "unmapped_reason": None,
        },
    ]
}


class TestSentenceSweep:
    """The first read is selective; the sweep classifies what it left."""

    @pytest.fixture
    def swept(self, plugin, tmp_path):
        path = tmp_path / "standard.txt"
        path.write_text(SWEEP_STANDARD, encoding="utf-8")
        result, context = extract(
            plugin, path, [json.dumps(GOOD_REPLY), json.dumps(SWEEP_REPLY)]
        )
        profile = json.loads(
            open(context.registered[0].file_path, encoding="utf-8").read()
        )
        return result, context, profile

    def test_obligation_sentences_carry_their_heading(self):
        found = ex.obligation_sentences([SWEEP_STANDARD])
        assert [s["section_number"] for s in found] == [
            "1",
            "4.2",
            "4.2",
            "4.2",
            "6",
            "6",
        ]
        assert found[3]["text"] == "Records should name the host that produced them."
        assert found[1]["section"] == "4.2 Record content"

    def test_only_unquoted_sentences_are_sent(self, swept):
        _, context, _ = swept
        prompt = context.llm_query.prompts[1]
        assert "Records should name the host" in prompt
        assert "Archives must be encrypted at rest." in prompt
        listing = prompt.split("SENTENCES:")[1]
        assert "Log data shall be retained" not in listing

    def test_swept_requirement_quotes_the_document_not_the_model(self, swept):
        _, _, profile = swept
        host = [
            r for r in profile["requirements"] if r["extracted_by"] == "sentence_sweep"
        ]
        assert len(host) == 1
        assert host[0]["quote"] == "Records should name the host that produced them."
        assert host[0]["quote_status"] == "found"
        assert host[0]["requirement_id"] == "4.2"
        assert [e["element"] for e in host[0]["elements"]] == ["host"]

    def test_requirements_are_in_document_order(self, swept):
        _, _, profile = swept
        quotes = [r["quote"][:12] for r in profile["requirements"]]
        assert quotes.index("Records shou") < quotes.index("Log data sha")

    def test_coverage_accounts_for_every_sentence(self, plugin, swept):
        result, _, profile = swept
        coverage = profile["statement_coverage"]
        assert coverage["obligation_sentences"] == 6
        assert coverage["quoted_by_document_read"] == 2
        assert coverage["swept_requirements"] == 1
        assert coverage["swept_not_a_requirement"] == 1
        assert coverage["not_classified"] == 2
        assert coverage["not_classified_sentences"][1]["text"].startswith("Archives")
        assert coverage["not_a_requirement_sentences"][0]["why"] == "defines a term"
        assert result.result["statement_coverage"]["obligation_sentences"] == 6
        assert "6 sentences" in plugin.summarize_for_llm(result)

    def test_failed_sweep_keeps_the_first_read(self, plugin, tmp_path):
        path = tmp_path / "standard.txt"
        path.write_text(SWEEP_STANDARD, encoding="utf-8")
        result, context = extract(plugin, path, [json.dumps(GOOD_REPLY)])
        assert result.ok
        assert result.result["statement_coverage"]["sweep"] == "failed"
        assert result.result["statement_coverage"]["not_classified"] == 4
        assert any("sweep call failed" in n for n in result.result["notes"])

    def test_skip_sweep_makes_one_call(self, plugin, tmp_path):
        path = tmp_path / "standard.txt"
        path.write_text(SWEEP_STANDARD, encoding="utf-8")
        context = FakeContext(FakeLLM([json.dumps(GOOD_REPLY)]))
        result = plugin.execute(
            {"action": "extract_profile", "file_path": str(path), "skip_sweep": True},
            context,
        )
        assert len(context.llm_query.prompts) == 1
        assert result.result["statement_coverage"]["sweep"] == "skipped_on_request"
