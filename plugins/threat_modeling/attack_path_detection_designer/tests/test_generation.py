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
