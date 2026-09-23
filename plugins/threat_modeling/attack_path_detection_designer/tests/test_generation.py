"""Stage G1b: drafting detections, against scripted provider replies.

No live call is made here. The designer plan's own guidance is to test
generation with scripted responses first; a live run verifies integration and
draft quality, never detection effectiveness.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
FIXTURES = PLUGIN_DIR / "tests" / "fixtures"


def _load(filename: str, alias: str):
    spec = importlib.util.spec_from_file_location(alias, PLUGIN_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


gen = _load("generation.py", "attack_path_detection_designer_generation")
_tool_mod = _load("tool.py", "attack_path_detection_designer_tool")

GRAPH = str(FIXTURES / "path_graph_20260917_022646.json")
SEED = str(FIXTURES / "scenario_seed_20260917_022646.json")
MAP = str(FIXTURES / "flow_maps" / "telemetry_saas_flow_map.json")


@dataclass
class FakeResponse:
    ok: bool = True
    text: str | None = None
    error: str | None = None
    model_used: str = "gemini-3.1-pro-preview"
    truncated: bool = False
    finish_reason: str = "STOP"
    token_usage: dict | None = None
    error_kind: str | None = None


@dataclass
class FakeLLM:
    """Scripted provider. Records every prompt so the contract can be asserted."""

    responder: Any
    prompts: list[str] = field(default_factory=list)

    def query_text(self, prompt, system_context=None, max_tokens=None, hints=None, **kw):
        self.prompts.append(prompt)
        return self.responder(prompt, len(self.prompts))


@dataclass
class FakeContext:
    llm_query: Any = None
    artifacts: list = field(default_factory=list)


@pytest.fixture
def tool():
    return _tool_mod.AttackPathDetectionDesigner()


@pytest.fixture
def nodes(tool):
    """The real pack for the 9-node Fox Kitten pair, bound to the estate."""
    result = tool.execute(
        {"sources": [GRAPH, SEED], "flow_map_path": MAP}, context=None
    )
    return result.result["nodes"]


def _draft_for(node: dict[str, Any], **overrides) -> dict[str, Any]:
    """A draft that satisfies the contract, so a test can break one thing."""
    candidates = node.get("telemetry_candidates") or []
    source_id = candidates[0]["source_id"] if candidates else None
    draft = {
        "title": f"{node['technique_id']} - {node.get('asset_name')} - drafted",
        "status": "experimental",
        "description": "Detects the modelled behaviour at this step of the path.",
        "logsource": {"definition": "Collection described rather than product named."},
        "falsepositives": ["Legitimate administrative use"],
        "level": "medium",
        "x_eventmill": {
            "format_version": "1.0",
            "draft_id": node["draft_id"],
            "node": {
                "path_id": node["path_id"],
                "node_index": node["node_index"],
                "technique_id": node["technique_id"],
            },
            "telemetry": (
                [{"source_id": source_id, "necessity": "required"}] if source_id else []
            ),
            "detection_logic": {
                "kind": "single_event",
                "pseudocode": "match events where principal is unexpected",
                "missing_data_behaviour": "insufficient_telemetry",
            },
            "assessment": node.get("assessment") or {"version": "1.0", "tuple": {}},
            "catalogue_status": "new_unchecked",
            "validation_status": "draft_unvalidated",
        },
    }
    for key, value in overrides.items():
        draft[key] = value
    return draft


def _responder(nodes: list[dict], mutate=None):
    """Reply to each batch with one valid draft per step it was given."""

    def respond(prompt: str, call_index: int) -> FakeResponse:
        payload = json.loads(prompt[prompt.find("{") :])
        wanted = [s["draft_id"] for s in payload["steps_to_draft"]]
        drafts = [_draft_for(n) for n in nodes if n["draft_id"] in wanted]
        if mutate:
            drafts = mutate(drafts, call_index)
        return FakeResponse(text=json.dumps({"drafts": drafts}))

    return respond


# ---------------------------------------------------------------------------
# The prompt contract
# ---------------------------------------------------------------------------

def test_batches_are_per_path_and_carry_the_whole_path_outline(nodes):
    batched = gen.batches(nodes, max_nodes=6)
    assert len(batched) == 2  # the pair has two paths, 4 and 5 nodes
    for batch in batched:
        assert len({n["path_id"] for n in batch}) == 1

    outline = gen.path_outline(nodes, batched[0][0]["path_id"])
    assert len(outline) == len([n for n in nodes if n["path_id"] == batched[0][0]["path_id"]])


def test_a_long_path_splits_without_losing_predecessor_context(nodes):
    batched = gen.batches(nodes, max_nodes=2)
    assert len(batched) > 2
    outline = gen.path_outline(nodes, batched[0][0]["path_id"])
    assert len(outline) > len(batched[0])  # the outline exceeds the batch


def test_the_prompt_offers_telemetry_and_withholds_the_audit_trail(nodes):
    prompt = gen.build_prompt(nodes[:2], {"actor_label": "Fox Kitten"}, [])
    assert "telemetry_candidates" in prompt
    assert "mitigation_focus" in prompt
    # Section 1.4b: generation never sees the full uncovered list.
    assert "uncovered_mitigations" not in prompt
    assert "provenance_by_field" not in prompt


def test_the_system_context_forbids_inventing_sources_and_ids():
    assert "DS####" in gen.SYSTEM_CONTEXT
    assert "ONLY the telemetry sources listed" in gen.SYSTEM_CONTEXT
    assert "actor evidence is false" in gen.SYSTEM_CONTEXT


# ---------------------------------------------------------------------------
# A complete run
# ---------------------------------------------------------------------------

def test_a_scripted_run_produces_one_draft_per_node(tool, nodes):
    llm = FakeLLM(_responder(nodes))
    result = tool.execute(
        {
            "action": "generate_detections",
            "sources": [GRAPH, SEED],
            "flow_map_path": MAP,
        },
        FakeContext(llm_query=llm),
    )
    assert result.ok is True
    ledger = result.result["coverage"]
    assert ledger["generation_status"] == "complete"
    assert ledger["generated_drafts"] == ledger["expected_nodes"] == 9
    assert result.result["rejected"] == []
    assert len(llm.prompts) == 2  # one call per path

    summary = tool.summarize_for_llm(result)
    assert "Generation complete" in summary
    assert "draft_unvalidated" in summary
    assert len(summary) < 4000


def test_without_a_provider_it_says_so_rather_than_inventing(tool):
    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED]}, FakeContext()
    )
    assert result.ok is False
    assert result.error_code == "LLM_UNAVAILABLE"


# ---------------------------------------------------------------------------
# What may not pass as a detection
# ---------------------------------------------------------------------------

def test_a_missing_node_makes_the_run_incomplete(tool, nodes):
    llm = FakeLLM(_responder(nodes, mutate=lambda drafts, i: drafts[:-1]))
    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=llm),
    )
    assert result.ok is False
    assert result.error_code == "GENERATION_INCOMPLETE"
    ledger = result.result["coverage"]
    assert ledger["generation_status"] == "partial"
    assert len(ledger["missing_draft_ids"]) == 2  # one per path
    # The partial output is still returned rather than discarded.
    assert result.result["drafts"]


def test_a_duplicate_draft_cannot_pass_as_coverage(tool, nodes):
    def duplicate(drafts, call_index):
        return drafts[:-1] + [drafts[0]]

    llm = FakeLLM(_responder(nodes, mutate=duplicate))
    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=llm),
    )
    assert result.ok is False
    ledger = result.result["coverage"]
    assert ledger["duplicate_draft_ids"]
    assert ledger["missing_draft_ids"]


def test_a_truncated_reply_is_rejected_even_when_transport_says_ok(tool, nodes):
    def respond(prompt, call_index):
        return FakeResponse(text='{"drafts": [{"title": "T1190 - half a', truncated=True)

    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=FakeLLM(respond)),
    )
    assert result.ok is False
    assert result.result["coverage"]["generation_status"] == "failed"
    assert any("output cap" in str(p) for p in result.result["rejected"])


def test_a_source_that_was_not_offered_is_refused(nodes):
    node = next(n for n in nodes if n.get("telemetry_candidates"))
    draft = _draft_for(node)
    draft["x_eventmill"]["telemetry"] = [
        {"source_id": "splunk.everything", "necessity": "required"}
    ]
    problems = gen.validate_draft(draft, node)
    assert any("was not offered" in p for p in problems)


def test_a_data_component_identifier_is_refused(nodes):
    node = nodes[0]
    draft = _draft_for(node)
    draft["x_eventmill"]["detection_logic"]["pseudocode"] = "see DS0029 network traffic"
    assert any("DS####" in p for p in gen.validate_draft(draft, node))


def test_missing_data_may_not_evaluate_as_benign(nodes):
    node = nodes[0]
    draft = _draft_for(node)
    draft["x_eventmill"]["detection_logic"]["missing_data_behaviour"] = "no_match"
    assert any("insufficient_telemetry" in p for p in gen.validate_draft(draft, node))


def test_a_product_may_not_be_named_below_component_bound(nodes):
    node = copy.deepcopy(nodes[0])
    node["context_completeness"] = "asset_named"
    draft = _draft_for(node, logsource={"product": "postgres"})
    assert any("only component_bound" in p for p in gen.validate_logsource(draft, node))


def test_a_changed_technique_id_is_refused(nodes):
    node = nodes[0]
    draft = _draft_for(node)
    draft["x_eventmill"]["node"]["technique_id"] = "T1003"
    assert any("changed from the source node" in p for p in gen.validate_draft(draft, node))


def test_a_draft_for_an_unknown_node_is_refused(tool, nodes):
    def respond(prompt, call_index):
        stranger = _draft_for(nodes[0])
        stranger["x_eventmill"]["draft_id"] = "drf_0000000000000000"
        return FakeResponse(text=json.dumps({"drafts": [stranger]}))

    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=FakeLLM(respond)),
    )
    assert result.ok is False
    assert any("does not match any node" in str(p) for p in result.result["rejected"])


# ---------------------------------------------------------------------------
# The operator's rule: weak evidence is recorded, never a filter
# ---------------------------------------------------------------------------

def test_a_node_with_false_actor_evidence_still_gets_drafted(tool, nodes):
    """Attackers change tactics; an unevidenced step is still a step."""
    weakened = copy.deepcopy(nodes)
    for node in weakened[:2]:
        node["assessment"]["tuple"]["actor_evidence"] = {
            "value": False,
            "reason_codes": ["not_established_in_local_sources"],
            "basis": "synthetic for this test",
            "warning": True,
        }

    llm = FakeLLM(_responder(weakened))
    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=llm),
    )
    assert result.ok is True
    assert result.result["coverage"]["generated_drafts"] == 9


def test_a_node_with_no_telemetry_still_gets_drafted(tool, nodes):
    """none_declared is a stated gap, not a reason to skip the node."""
    bare = [n for n in nodes if not n.get("telemetry_candidates")]
    llm = FakeLLM(_responder(nodes))
    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=llm),
    )
    assert result.ok is True
    produced = {(d["x_eventmill"]["draft_id"]) for d in result.result["drafts"]}
    for node in bare:
        assert node["draft_id"] in produced


def test_thinking_level_is_stated_not_left_to_the_client():
    """An unset level resolves to 'high', and thinking time is the deadline risk."""
    hints = _tool_mod.nz_hints()
    assert hints.thinking_level == _tool_mod.DEFAULT_THINKING_LEVEL == "medium"
    assert hints.tier == "heavy"
    assert not hasattr(hints, "provider")  # vendor choice belongs to `use`


def test_the_operator_can_raise_thinking_level(tool, nodes):
    seen: list[Any] = []

    def respond(prompt, call_index):
        return FakeResponse(text=json.dumps({"drafts": []}))

    llm = FakeLLM(respond)

    class Recording(FakeLLM):
        def query_text(self, prompt, system_context=None, max_tokens=None, hints=None, **kw):
            seen.append(hints.thinking_level)
            return respond(prompt, 1)

    tool.execute(
        {
            "action": "generate_detections",
            "sources": [GRAPH, SEED],
            "flow_map_path": MAP,
            "thinking_level": "high",
        },
        FakeContext(llm_query=Recording(respond)),
    )
    assert set(seen) == {"high"}


# ---------------------------------------------------------------------------
# A reply is untrusted shape, not only untrusted content
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "mangle",
    [
        pytest.param(lambda d: d.update(x_eventmill="see below"), id="extension_is_a_string"),
        pytest.param(lambda d: d.update(logsource="windows security log"), id="logsource_is_a_string"),
        pytest.param(
            lambda d: d["x_eventmill"].update(telemetry=["pgaudit.object_access"]),
            id="telemetry_is_a_list_of_strings",
        ),
        pytest.param(
            lambda d: d["x_eventmill"].update(node="scm-ci-vault step 0"),
            id="node_is_a_string",
        ),
        pytest.param(
            lambda d: d["x_eventmill"].update(detection_logic="pseudocode only"),
            id="logic_is_a_string",
        ),
        pytest.param(
            lambda d: d["x_eventmill"].update(events_of_interest={"event": "4624"}),
            id="events_is_an_object",
        ),
    ],
)
def test_a_malformed_draft_is_rejected_rather_than_crashing(tool, nodes, mangle):
    """The live run died on `'str' object has no attribute 'get'`."""

    def respond(prompt, call_index):
        payload = json.loads(prompt[prompt.find("{") :])
        wanted = [s["draft_id"] for s in payload["steps_to_draft"]]
        drafts = [_draft_for(n) for n in nodes if n["draft_id"] in wanted]
        mangle(drafts[0])
        return FakeResponse(text=json.dumps({"drafts": drafts}))

    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=FakeLLM(respond)),
    )
    assert result.ok is False
    assert result.error_code == "GENERATION_INCOMPLETE"
    assert result.result["rejected"]
    # The other nodes in the batch still produced drafts.
    assert result.result["drafts"]


def test_a_reply_of_strings_instead_of_objects_is_rejected(tool, nodes):
    def respond(prompt, call_index):
        return FakeResponse(text=json.dumps({"drafts": ["a draft", "another draft"]}))

    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=FakeLLM(respond)),
    )
    assert result.ok is False
    assert result.result["coverage"]["generation_status"] == "failed"


def test_shape_helpers_never_raise():
    for value in ("text", 3, None, [], {"a": 1}):
        assert isinstance(gen.as_dict(value), dict)
        assert isinstance(gen.as_dicts(value), list)
    assert gen.draft_id_of("not a draft") is None
    assert gen.draft_id_of({"x_eventmill": "string"}) is None
    assert gen.draft_id_of({"x_eventmill": {"draft_id": "drf_x"}}) == "drf_x"


def test_a_failed_run_says_why_in_its_message(tool, nodes):
    """A failed run prints its message and little else."""

    def respond(prompt, call_index):
        return FakeResponse(text="I cannot help with that request.")

    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=FakeLLM(respond)),
    )
    assert result.ok is False
    assert "0 of 9" in result.message
    assert "no JSON object" in result.message
    assert "reply began" in result.message
    assert "ok=True" in result.message  # the call itself succeeded


def test_an_empty_reply_is_distinguishable_from_a_refusal(tool, nodes):
    """Empty text with tokens spent is thinking starvation, not a refusal."""

    def respond(prompt, call_index):
        return FakeResponse(text="", token_usage={"output_tokens": 0, "thinking_tokens": 31000})

    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=FakeLLM(respond)),
    )
    assert result.ok is False
    assert "empty response" in result.message
    call = result.result["calls"][0]
    assert call["reply_chars"] == 0
    assert call["token_usage"]["thinking_tokens"] == 31000


def test_the_prompt_shows_the_shape_rather_than_naming_the_keys(nodes):
    """The first live run returned `node` as a string and `telemetry` as an
    object, because the contract listed key names and never their shapes."""
    prompt = gen.build_prompt(nodes[:1], {"actor_label": "x"}, [])
    payload = json.loads(prompt[prompt.find("{") :])
    example = payload["draft_example"]["x_eventmill"]
    assert isinstance(example["node"], dict)
    assert isinstance(example["telemetry"], list)
    assert isinstance(example["telemetry"][0], dict)
    assert example["detection_logic"]["missing_data_behaviour"] == "insufficient_telemetry"
    assert payload["draft_contract"]["field_types"]["x_eventmill.node"] == "object"
    assert "never a string" in gen.SYSTEM_CONTEXT


def test_one_wrong_shape_reports_one_problem_not_four(nodes):
    """A `node` that arrived as a string buried its own cause in symptoms."""
    node = nodes[0]
    draft = _draft_for(node)
    draft["x_eventmill"]["node"] = "scm-to-vault step 0"
    problems = gen.validate_draft(draft, node)
    assert problems == ["x_eventmill.node is str, not an object"]


def test_a_wrong_logic_shape_does_not_also_report_its_contents(nodes):
    node = nodes[0]
    draft = _draft_for(node)
    draft["x_eventmill"]["detection_logic"] = "just pseudocode"
    problems = gen.validate_draft(draft, node)
    assert problems == ["x_eventmill.detection_logic is str, not an object"]


def test_a_source_id_may_not_masquerade_as_a_sigma_product(nodes):
    """The first successful live run filled logsource.product with our own
    source_id, which names a product to nobody outside this repository."""
    node = next(
        n for n in nodes
        if n["context_completeness"] == "component_bound" and n.get("telemetry_candidates")
    )
    source_id = node["telemetry_candidates"][0]["source_id"]
    draft = _draft_for(node, logsource={"product": source_id})
    problems = gen.validate_logsource(draft, node)
    assert any("is a telemetry source_id, not a product" in p for p in problems)


def test_a_real_product_name_passes(nodes):
    node = next(n for n in nodes if n["context_completeness"] == "component_bound")
    draft = _draft_for(node, logsource={"product": "postgresql"})
    assert gen.validate_logsource(draft, node) == []


def test_the_prompt_says_product_is_never_a_source_id():
    assert "NEVER a source_id" in gen.SYSTEM_CONTEXT or "NEVER a source_id" in json.dumps(
        gen.DRAFT_EXAMPLE
    )
    assert "belong in x_eventmill.telemetry" in gen.SYSTEM_CONTEXT


# ---------------------------------------------------------------------------
# Annotation: what the record can state for itself
# ---------------------------------------------------------------------------

# A fixture library rather than the real one, so these tests describe the check
# and not the seed library's current field lists.
ANNOTATION_LIBRARY = {
    "postgres.session": {
        "source_id": "postgres.session",
        # `username` is deliberately a bare word and `db_user` deliberately
        # distinctive: the library checks only report names that could not be
        # ordinary English, because the contract allows prose pseudocode.
        "fields": {"native": ["client_ip", "username", "db_user"], "derived": []},
    },
    "container.file_access": {
        "source_id": "container.file_access",
        "fields": {"native": ["process_name", "file_path", "action"], "derived": []},
    },
}


def _logic_draft(**logic) -> dict[str, Any]:
    base = {
        "kind": "single_event",
        "normalized_fields": [],
        "join_keys": [],
        "window": None,
        "thresholds": {},
        "pseudocode": "SELECT * FROM postgres.session",
        "missing_data_behaviour": "insufficient_telemetry",
    }
    base.update(logic)
    return {
        "x_eventmill": {
            "telemetry": [
                {"source_id": "postgres.session", "required_fields": ["client_ip"]}
            ],
            "detection_logic": base,
            "review_flags": [],
        }
    }


def _codes(flags) -> list[str]:
    return [f["code"] for f in flags]


@pytest.mark.parametrize(
    "raw,expected",
    [
        (60, "60_sec"),
        ("60", "60_sec"),
        ("10 minutes", "10_min"),
        ("5m", "5_min"),
        ("24 hours", "24_hour"),
        ("7 days", "7_day"),
        ("10_min", "10_min"),
        (None, None),
        ("", None),
    ],
)
def test_a_window_is_canonical_value_timeunit(raw, expected):
    """One live run produced both 60 and "10 minutes" for the same field."""
    value, problem = gen.normalize_window(raw)
    assert value == expected
    assert problem is None


@pytest.mark.parametrize("raw", ["whenever the build runs", "10 fortnights", True])
def test_an_unreadable_window_is_kept_and_flagged(raw):
    """Discarding a parameter an engineer proposed is worse than carrying one
    that needs a human to read it."""
    value, problem = gen.normalize_window(raw)
    assert value == raw
    assert problem


def test_kind_follows_the_shape_not_the_skeleton():
    """`single_event` is the prompt example's placeholder, so a model that
    reasons about the logic still returns it while filling in a window."""
    draft = _logic_draft(window=60, thresholds={"directory_access_count": 100})
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    logic = draft["x_eventmill"]["detection_logic"]
    assert logic["kind"] == "threshold"
    assert logic["window"] == "60_sec"
    assert "LOGIC_KIND_CORRECTED" in _codes(flags)


def test_join_keys_make_it_a_correlation():
    draft = _logic_draft(join_keys=["session_id"])
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "correlation"


def test_a_single_event_with_no_window_is_left_alone():
    draft = _logic_draft()
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "single_event"
    assert "LOGIC_KIND_CORRECTED" not in _codes(flags)


def test_a_declared_method_is_not_overwritten():
    """`baseline_deviation` is a claim about method that no structural rule
    can infer, so a draft that makes it keeps it."""
    draft = _logic_draft(kind="baseline_deviation", window="10_min")
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "baseline_deviation"
    assert "LOGIC_KIND_CORRECTED" not in _codes(flags)


def test_a_collected_field_the_logic_never_reads_is_flagged():
    """The T1210 draft collected `username` and then filtered on source address
    alone, so the field separating the app from its stolen credentials went
    unused. The flag asks the question; it does not answer it."""
    draft = _logic_draft(pseudocode="SELECT * FROM postgres.session WHERE client_ip NOT IN known_ips")
    draft["x_eventmill"]["telemetry"][0]["required_fields"] = ["client_ip", "username"]
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert "FIELD_DECLARED_UNUSED" in _codes(flags)
    assert "username" in flags[0]["message"]


def test_a_field_read_but_never_declared_is_flagged():
    """required_fields is what a collection engineer onboards against."""
    draft = _logic_draft(pseudocode="WHERE client_ip IS set AND db_user IS unexpected")
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert "FIELD_UNDECLARED_IN_LOGIC" in _codes(flags)


def test_a_field_belonging_to_an_uncited_source_says_so():
    """The credential-file draft read `file_path` from an application log that
    has no such field. Either the source list or the logic is wrong."""
    draft = _logic_draft(pseudocode="WHERE client_ip IS set AND file_path MATCHES creds")
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert "FIELD_FROM_UNCITED_SOURCE" in _codes(flags)
    assert "container.file_access" in flags[-1]["message"]


def test_quoted_values_are_not_field_references():
    """Pseudocode reading `type IS 'username'` names a value, not a field."""
    draft = _logic_draft(pseudocode="WHERE client_ip IS set AND type IS 'username'")
    assert _codes(gen.annotate(draft, ANNOTATION_LIBRARY)) == []


def test_placeholders_and_keywords_never_become_findings():
    """The library is what keeps the check quiet: only names it knows to be
    fields of some source are reported."""
    draft = _logic_draft(
        pseudocode="SELECT * FROM postgres.session WHERE client_ip IN anomalous_set"
    )
    assert _codes(gen.annotate(draft, ANNOTATION_LIBRARY)) == []


def test_without_a_library_only_the_unused_direction_runs():
    """Generation takes the library as an argument and works without it."""
    draft = _logic_draft(pseudocode="WHERE username IS unexpected")
    codes = _codes(gen.annotate(draft, None))
    assert codes == ["FIELD_DECLARED_UNUSED"]


def test_annotation_appends_rather_than_replacing():
    draft = _logic_draft(window=60)
    draft["x_eventmill"]["review_flags"] = [{"code": "EXISTING", "message": "kept"}]
    gen.annotate(draft, ANNOTATION_LIBRARY)
    codes = _codes(draft["x_eventmill"]["review_flags"])
    assert codes[0] == "EXISTING"
    assert "LOGIC_KIND_CORRECTED" in codes


def test_every_flag_code_is_registered():
    """An unregistered code is a typo that reads as a finding."""
    with pytest.raises(KeyError):
        gen._review_flag("NOT_A_REAL_CODE", "message")


def test_the_prompt_asks_for_a_canonical_window():
    assert "60_sec" in gen.SYSTEM_CONTEXT
    assert "single_event | threshold | correlation" in json.dumps(gen.DRAFT_EXAMPLE)


def test_the_summary_says_which_questions_the_drafts_carry():
    """A flag that only exists in the artifact is a flag nobody acts on."""
    drafts = [
        {"x_eventmill": {"review_flags": [
            {"code": "FIELD_DECLARED_UNUSED", "message": "m"},
            {"code": "LOGIC_KIND_CORRECTED", "message": "m"},
        ]}},
        {"x_eventmill": {"review_flags": [{"code": "FIELD_DECLARED_UNUSED", "message": "m"}]}},
        {"x_eventmill": {"review_flags": []}},
    ]
    line = _tool_mod._review_flag_line(drafts)
    assert "3 across 2 of 3 draft(s)" in line
    assert "FIELD_DECLARED_UNUSED 2" in line
    assert line.index("FIELD_DECLARED_UNUSED") < line.index("LOGIC_KIND_CORRECTED")


def test_the_summary_carries_codes_and_never_the_messages():
    """The messages name fields and sources; nine drafts' worth would push
    everything after this line past the budget."""
    drafts = [
        {"x_eventmill": {"review_flags": [
            {"code": "FIELD_FROM_UNCITED_SOURCE", "message": "'file_path' belongs to x"}
        ]}}
    ]
    line = _tool_mod._review_flag_line(drafts)
    assert "file_path" not in line


def test_no_flags_is_stated_rather_than_left_silent():
    assert "none across 2 draft(s)" in _tool_mod._review_flag_line(
        [{"x_eventmill": {"review_flags": []}}, {"x_eventmill": {}}]
    )


def test_the_flag_line_survives_a_malformed_draft():
    drafts = [{"x_eventmill": "not an object"}, {"x_eventmill": {"review_flags": "no"}}]
    assert "none across 2 draft(s)" in _tool_mod._review_flag_line(drafts)


def test_the_generation_summary_reports_flags_above_the_closing_caveat(tool, nodes):
    """summarize_for_llm truncates from the end, so the flags go above the
    line a reader needs least."""
    llm = FakeLLM(_responder(nodes))
    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=llm),
    )
    summary = tool.summarize_for_llm(result)
    assert "Review flags:" in summary
    assert summary.index("Review flags:") < summary.index("a person still judges")


# ---------------------------------------------------------------------------
# Fields are offered, not invented
# ---------------------------------------------------------------------------

def _node_offering(source_id: str, native: list[str], derived: list[str] | None = None):
    return {
        "telemetry_candidates": [
            {"source_id": source_id, "fields": {"native": native, "derived": derived or []}}
        ]
    }


def _cites(source_id: str, required_fields: list[str]) -> dict[str, Any]:
    return {"telemetry": [{"source_id": source_id, "required_fields": required_fields}]}


def test_a_field_the_source_does_not_have_is_refused():
    """The first live run on the annotated build invented all 14 of its field
    names - `http_method` for `method`, `head_branch` for `ref` - because the
    candidate carried prerequisites and withheld the field list."""
    node = _node_offering("application.runtime_log", ["method", "route", "request_id"])
    problems = gen._validate_telemetry(_cites("application.runtime_log", ["http_method"]), node)
    assert any("'http_method' are not fields of" in p for p in problems)


def test_the_refusal_names_what_the_source_does_offer():
    """A rejection a model cannot act on costs the draft and teaches nothing."""
    node = _node_offering("application.runtime_log", ["method", "route"])
    problems = gen._validate_telemetry(_cites("application.runtime_log", ["http_method"]), node)
    assert "method, route" in problems[0]


def test_offered_native_and_derived_fields_both_pass():
    node = _node_offering(
        "pgaudit.object_access", ["statement", "object_name"], ["rows_touched_estimate"]
    )
    extension = _cites("pgaudit.object_access", ["statement", "rows_touched_estimate"])
    assert gen._validate_telemetry(extension, node) == []


def test_a_candidate_with_no_field_list_is_not_second_guessed():
    """Inventing a complaint is worse than having nothing to check against."""
    node = {"telemetry_candidates": [{"source_id": "legacy.source"}]}
    assert gen._validate_telemetry(_cites("legacy.source", ["anything"]), node) == []


def test_an_unoffered_source_is_still_refused_before_its_fields():
    """One problem, not two: the source is the cause and the fields the symptom."""
    node = _node_offering("a.source", ["x"])
    problems = gen._validate_telemetry(_cites("b.source", ["y"]), node)
    assert len(problems) == 1
    assert "was not offered" in problems[0]


def test_the_prompt_offers_the_field_names(nodes):
    """Withholding them while passing absent_without_enrichment told a model
    what each source lacks and never what it has."""
    node = next(n for n in nodes if n.get("telemetry_candidates"))
    candidate = node["telemetry_candidates"][0]
    assert "native" in candidate["fields"]
    assert "derived" in candidate["fields"]
    prompt = gen.build_prompt([node], {}, gen.path_outline(nodes, node["path_id"]))
    assert "fields.native" in gen.SYSTEM_CONTEXT
    assert candidate["fields"]["native"][0] in prompt


def test_the_prompt_says_a_field_is_never_substituted():
    assert "never write \"http_method\"" in gen.SYSTEM_CONTEXT
    assert "fields.derived" in gen.SYSTEM_CONTEXT


# ---------------------------------------------------------------------------
# Two defects the same live run found in the annotation itself
# ---------------------------------------------------------------------------

def test_a_drafts_own_alias_is_not_read_as_a_foreign_field():
    """A draft mapping `connection.remote_address` to `source_ip` and then
    filtering on `source_ip` reads its own alias, not another source's field
    of the same name. The first version reported it as foreign."""
    draft = _logic_draft(
        normalized_fields=[{"name": "username", "from": "client_ip"}],
        pseudocode="WHERE username IS unexpected",
    )
    assert _codes(gen.annotate(draft, ANNOTATION_LIBRARY)) == []


def test_the_native_field_behind_an_alias_still_counts_as_read():
    """Subtracting aliases must not make the field they map from look unused."""
    draft = _logic_draft(
        normalized_fields=[{"name": "src", "from": "client_ip"}],
        pseudocode="WHERE src IN known",
    )
    assert "FIELD_DECLARED_UNUSED" not in _codes(gen.annotate(draft, ANNOTATION_LIBRARY))


def test_a_grouped_threshold_keeps_the_kind_it_declared():
    """A live draft counting statements BY user_name over ten minutes declared
    itself a threshold and was correct; reading its grouping key as a join
    rewrote the one kind the model had reasoned its way to."""
    draft = _logic_draft(
        kind="threshold", join_keys=["user_name"], window="10_min",
        thresholds={"query_count": 100},
    )
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "threshold"
    assert "LOGIC_KIND_CORRECTED" not in _codes(flags)


def test_join_keys_without_thresholds_are_still_a_correlation():
    draft = _logic_draft(join_keys=["session_id"])
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "correlation"


def test_thresholds_outrank_join_keys_when_the_kind_is_the_placeholder():
    draft = _logic_draft(join_keys=["session_id"], thresholds={"n": 10})
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "threshold"


# ---------------------------------------------------------------------------
# An absence is not a signal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "pseudocode",
    [
        "WHERE operation = 'read' AND auth_identity IS NULL",
        "WHERE principal = NULL",
        "WHERE principal == NULL",
        "WHERE tenant IS EMPTY",
        "WHERE tenant IS MISSING",
        "WHERE token IS UNSET",
        "WHERE token NOT SET",
    ],
)
def test_an_absence_used_as_the_signal_is_flagged(pseudocode):
    """A live draft alerted on `auth_identity IS NULL` to mean unauthenticated.
    If that field is not collected, every record satisfies the condition."""
    draft = _logic_draft(pseudocode=pseudocode)
    assert "LOGIC_NULL_AS_MATCH" in _codes(gen.annotate(draft, ANNOTATION_LIBRARY))


@pytest.mark.parametrize(
    "pseudocode",
    [
        "WHERE principal IS NOT NULL AND status = 500",
        "WHERE principal != NULL",
        "WHERE principal <> NULL",
        "WHERE client_ip IN known_ips",
    ],
)
def test_requiring_a_value_to_be_present_is_not_the_defect(pseudocode):
    """`IS NOT NULL` requires presence - the opposite failure, and a
    legitimate condition."""
    draft = _logic_draft(pseudocode=pseudocode)
    assert "LOGIC_NULL_AS_MATCH" not in _codes(gen.annotate(draft, ANNOTATION_LIBRARY))


def test_a_null_test_that_declares_insufficiency_is_the_handling_asked_for():
    draft = _logic_draft(
        pseudocode="IF principal IS NULL THEN insufficient_telemetry ELSE compare"
    )
    assert "LOGIC_NULL_AS_MATCH" not in _codes(gen.annotate(draft, ANNOTATION_LIBRARY))


def test_a_quoted_null_is_a_value_not_a_condition():
    draft = _logic_draft(pseudocode="WHERE message CONTAINS 'IS NULL'")
    assert "LOGIC_NULL_AS_MATCH" not in _codes(gen.annotate(draft, ANNOTATION_LIBRARY))


def test_null_as_match_never_rejects_a_draft(nodes):
    """It is read out of prose, so it states the concern and leaves the
    judgement; the rejections are checkable facts about the record."""
    node = next(n for n in nodes if n.get("telemetry_candidates"))
    draft = _draft_for(node)
    draft["x_eventmill"]["detection_logic"]["pseudocode"] = "WHERE principal IS NULL"
    assert gen.validate_draft(draft, node) == []


def test_the_prompt_says_an_absence_may_not_be_the_signal():
    assert "Never make an absence the thing that fires" in gen.SYSTEM_CONTEXT


# ---------------------------------------------------------------------------
# Prose pseudocode, the model's own caveats, and who made what
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "pseudocode",
    [
        "Alert when process_args show an interpreter executing command patterns",
        "suppress established monitoring request patterns",
        "Flag a successful request whose route is in the maintained set",
        "when the response has a health, status, or service endpoint",
    ],
)
def test_an_english_word_in_prose_is_not_a_field_reference(pseudocode):
    """The contract allows pseudocode as prose. One live draft produced four
    findings this way: `command`, `request` and `status` are ordinary words
    that are also fields of some library source."""
    draft = _logic_draft(pseudocode=pseudocode)
    codes = _codes(gen.annotate(draft, ANNOTATION_LIBRARY))
    assert "FIELD_FROM_UNCITED_SOURCE" not in codes
    assert "FIELD_UNDECLARED_IN_LOGIC" not in codes


def test_a_distinctive_name_in_prose_is_still_caught():
    """Every true positive so far has been distinctive."""
    draft = _logic_draft(pseudocode="Alert when file_path matches a credential file")
    assert "FIELD_FROM_UNCITED_SOURCE" in _codes(gen.annotate(draft, ANNOTATION_LIBRARY))


def test_the_models_own_flags_move_to_caveats_rather_than_being_discarded():
    """A live run filled review_flags with bare strings. The content is
    exactly what a tester wants; the field was the wrong one."""
    draft = _logic_draft()
    draft["x_eventmill"]["review_flags"] = [
        "collection_status_unknown",
        "authentication_not_directly_observed",
    ]
    gen.annotate(draft, ANNOTATION_LIBRARY)
    extension = draft["x_eventmill"]
    assert extension["caveats"] == [
        "collection_status_unknown",
        "authentication_not_directly_observed",
    ]
    assert all(isinstance(f, dict) for f in extension["review_flags"])


def test_relocated_caveats_join_the_ones_already_there_without_duplicates():
    draft = _logic_draft()
    draft["x_eventmill"]["caveats"] = ["attempt_only_not_code_execution"]
    draft["x_eventmill"]["review_flags"] = [
        "attempt_only_not_code_execution",
        "no_file_or_process_visibility",
    ]
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["caveats"] == [
        "attempt_only_not_code_execution",
        "no_file_or_process_visibility",
    ]


def test_a_well_formed_flag_the_model_supplied_is_kept_in_place():
    draft = _logic_draft()
    draft["x_eventmill"]["review_flags"] = [{"code": "EXISTING", "message": "kept"}]
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["review_flags"][0]["code"] == "EXISTING"
    assert "caveats" not in draft["x_eventmill"]


def test_review_flags_stay_machine_derived_so_the_summary_stays_coded():
    draft = _logic_draft(window=60)
    draft["x_eventmill"]["review_flags"] = ["collection_status_unknown"]
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert "UNCODED" not in _tool_mod._review_flag_line([draft])


def test_the_prompt_asks_for_caveats_and_reserves_review_flags():
    assert "caveats" in gen.SYSTEM_CONTEXT
    assert "Leave\n  review_flags empty" in gen.SYSTEM_CONTEXT


def test_the_projection_model_is_named_as_the_projections(nodes, tool):
    """One export carries the model that projected the path and the model that
    drafted the detections; a single `model_attribution` let a reader take the
    first for the second."""
    result = tool.execute({"sources": [GRAPH, SEED], "flow_map_path": MAP}, context=None)
    engagement = result.result["engagement"]
    assert engagement["projection_model"]["vendor"]
    assert engagement["projection_model_present"] is True
    assert "Projection model:" in tool.summarize_for_llm(result)


def test_a_run_reports_the_model_that_drafted_it(tool, nodes):
    llm = FakeLLM(_responder(nodes))
    result = tool.execute(
        {"action": "generate_detections", "sources": [GRAPH, SEED], "flow_map_path": MAP},
        FakeContext(llm_query=llm),
    )
    assert result.result["generation_model"] == ["gemini-3.1-pro-preview"]
    summary = tool.summarize_for_llm(result)
    assert "Generation model: gemini-3.1-pro-preview" in summary
    assert "projected by" in summary


def test_an_identity_mapping_counts_the_field_as_read():
    """Two live runs mapped `actor` to `actor` and `process_path` to itself.
    Subtracting the alias took the native reference with it, so the field read
    most plainly of all was the one reported unused."""
    draft = _logic_draft(
        normalized_fields=[{"name": "client_ip", "from": "client_ip"}],
        pseudocode="IF token_seen IS TRUE THEN alert",
    )
    assert "FIELD_DECLARED_UNUSED" not in _codes(gen.annotate(draft, ANNOTATION_LIBRARY))


def test_a_genuine_alias_is_still_subtracted():
    draft = _logic_draft(
        normalized_fields=[{"name": "db_user", "from": "client_ip"}],
        pseudocode="WHERE db_user IS unexpected",
    )
    codes = _codes(gen.annotate(draft, ANNOTATION_LIBRARY))
    assert "FIELD_FROM_UNCITED_SOURCE" not in codes
    assert "FIELD_UNDECLARED_IN_LOGIC" not in codes


# ---------------------------------------------------------------------------
# Parameters stay parameters
# ---------------------------------------------------------------------------

def test_a_threshold_written_as_prose_moves_to_threshold_notes():
    """`thresholds` is where a model puts the parameter and, given the chance,
    the reasoning behind it. Nothing is discarded: the note keeps the
    parameter's name."""
    draft = _logic_draft(
        thresholds={
            "rows": 1000,
            "runs_per_principal": "proposed starting point: alert on the first event",
        }
    )
    gen.annotate(draft, ANNOTATION_LIBRARY)
    logic = draft["x_eventmill"]["detection_logic"]
    assert logic["thresholds"] == {"rows": 1000}
    assert logic["threshold_notes"]["runs_per_principal"].startswith("proposed")


def test_a_numeric_string_is_read_as_the_number_it_is():
    draft = _logic_draft(thresholds={"rows": "1000", "ratio": "2.5"})
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["thresholds"] == {
        "rows": 1000,
        "ratio": 2.5,
    }


def test_prose_in_thresholds_can_no_longer_rewrite_the_kind():
    """The one wrong correction in the Opus run: the only threshold entry read
    'alert on the first event', which made the mapping non-empty and turned a
    correct single_event into a threshold."""
    draft = _logic_draft(
        kind="single_event",
        thresholds={"runs": "proposed starting point: alert on the first event"},
        pseudocode="WHERE workflow_changed_and_run_by_same_actor = true",
    )
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "single_event"
    assert "LOGIC_KIND_CORRECTED" not in _codes(flags)


def test_a_real_threshold_still_corrects_the_placeholder():
    draft = _logic_draft(kind="single_event", thresholds={"rows": 1000})
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "threshold"
    assert "LOGIC_KIND_CORRECTED" in _codes(flags)


def test_a_join_key_that_is_a_sentence_moves_to_join_notes():
    """One draft set join_keys to 'approximate temporal join only; no shared
    identifier exists...' - true, useful, and not a key."""
    draft = _logic_draft(
        join_keys=[
            "session_id",
            "approximate temporal join only; no shared identifier exists",
        ]
    )
    gen.annotate(draft, ANNOTATION_LIBRARY)
    logic = draft["x_eventmill"]["detection_logic"]
    assert logic["join_keys"] == ["session_id"]
    assert logic["join_notes"] == [
        "approximate temporal join only; no shared identifier exists"
    ]


def test_a_logic_whose_only_join_key_was_prose_is_not_a_correlation():
    draft = _logic_draft(kind="single_event", join_keys=["no shared identifier exists"])
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "single_event"


def test_the_ambiguity_flag_is_retired_but_the_declared_kind_is_still_kept():
    """It fired on eight of nine drafts in one run. A flag at that rate tells
    a reader nothing, and all it reported was the default behaviour."""
    assert "LOGIC_KIND_AMBIGUOUS" not in gen.REVIEW_FLAG_CODES
    draft = _logic_draft(
        kind="correlation", join_keys=["session_id"], thresholds={"rows": 1000}
    )
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "correlation"
    assert not [f for f in flags if f["code"].startswith("LOGIC_KIND")]


def test_the_prompt_asks_for_numbers_and_field_names():
    assert "never a sentence" in gen.SYSTEM_CONTEXT
    assert "join_keys are field names only" in gen.SYSTEM_CONTEXT
    assert "threshold_notes" in json.dumps(gen.DRAFT_EXAMPLE)
    assert "join_notes" in json.dumps(gen.DRAFT_EXAMPLE)


def _multi_source_draft(**logic) -> dict[str, Any]:
    draft = _logic_draft(**logic)
    draft["x_eventmill"]["telemetry"].append(
        {"source_id": "container.file_access", "required_fields": ["process_path"]}
    )
    return draft


def test_two_sources_over_a_window_stay_a_correlation_without_a_join_key():
    """A draft joining CI records to runner process events said in prose that
    the two share no identifier. Once that moved to join_notes the remaining
    shape read as a threshold - relocating the explanation must not change
    what the record claims."""
    draft = _multi_source_draft(
        kind="correlation",
        join_keys=["no shared identifier exists between the two sources"],
        window="10_min",
    )
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    logic = draft["x_eventmill"]["detection_logic"]
    assert logic["kind"] == "correlation"
    assert logic["join_keys"] == []
    assert logic["join_notes"]
    assert "LOGIC_KIND_CORRECTED" not in _codes(flags)


def test_one_source_over_a_window_is_still_a_threshold():
    draft = _logic_draft(kind="single_event", window="10_min")
    gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "threshold"


def test_multiple_sources_with_a_real_threshold_keep_the_declared_kind():
    draft = _multi_source_draft(
        kind="threshold", join_keys=["session_id"], window="30_min",
        thresholds={"rows": 500000},
    )
    flags = gen.annotate(draft, ANNOTATION_LIBRARY)
    assert draft["x_eventmill"]["detection_logic"]["kind"] == "threshold"
    assert "LOGIC_KIND_CORRECTED" not in _codes(flags)
