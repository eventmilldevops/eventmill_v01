"""Contract compliance tests for log_compliance_auditor."""

import json

import pytest

from .helpers import (
    CONTINUATION_LINES,
    COUNT_A,
    PLUGIN_DIR,
    PROFILE_EXAMPLE,
    TOTAL,
    FakeContext,
    build_log,
    load_tool,
)

tool = load_tool()


@pytest.fixture
def manifest():
    with open(PLUGIN_DIR / "manifest.json") as f:
        return json.load(f)


@pytest.fixture
def plugin():
    return tool.LogComplianceAuditor()


@pytest.fixture
def log_file(tmp_path):
    return build_log(tmp_path / "app.log")


class TestManifest:
    def test_identity(self, manifest):
        assert manifest["tool_name"] == "log_compliance_auditor"
        assert manifest["pillar"] == PLUGIN_DIR.parent.name
        assert manifest["class_name"] == "LogComplianceAuditor"

    def test_not_auto_invocable(self, manifest):
        # It sends raw log lines to a vendor and costs heavy-tier calls.
        assert manifest["safe_for_auto_invoke"] is False
        assert manifest["model_tier"] == "heavy"
        assert manifest["stability"] == "experimental"

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()

    def test_manifest_validates_against_schema(self, manifest):
        import jsonschema

        schema_path = PLUGIN_DIR.parents[2] / "docs" / "specs" / "manifest_schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(manifest)


class TestValidateInputs:
    def test_metadata(self, plugin):
        assert plugin.metadata()["tool_name"] == "log_compliance_auditor"

    def test_survey_needs_only_a_log(self, plugin):
        assert plugin.validate_inputs({"action": "survey", "file_path": "x.log"}).ok

    def test_audit_needs_a_profile(self, plugin):
        result = plugin.validate_inputs({"action": "audit", "file_path": "x.log"})
        assert not result.ok
        assert any("profile" in e for e in result.errors)

    def test_resume_needs_a_previous_run(self, plugin):
        result = plugin.validate_inputs(
            {"action": "resume", "file_path": "x.log", "profile_path": "p.json"}
        )
        assert not result.ok
        assert any("state_artifact_id" in e for e in result.errors)

    def test_unknown_action(self, plugin):
        assert not plugin.validate_inputs({"action": "certify", "file_path": "x"}).ok

    def test_sample_lines_capped_at_200(self, plugin):
        result = plugin.validate_inputs(
            {"file_path": "x.log", "profile_path": "p.json", "sample_lines": 500}
        )
        assert not result.ok

    def test_bool_is_not_an_integer(self, plugin):
        result = plugin.validate_inputs(
            {"file_path": "x.log", "profile_path": "p.json", "max_rounds": True}
        )
        assert not result.ok


class TestSurvey:
    def test_counts_and_container(self, plugin, log_file):
        result = plugin.execute({"action": "survey", "file_path": str(log_file)}, None)
        assert result.ok
        survey = result.result["survey"]
        assert survey["records"] == TOTAL
        assert survey["continuation_lines"] == CONTINUATION_LINES
        # 600 of 1000 records carry three or more key=value tokens.
        assert survey["container"] == "key_value"
        assert survey["container_shares"] == {"json": 0.08, "key_value": 0.6}
        assert survey["clusters"][0]["count"] == COUNT_A

    def test_few_shapes_from_many_lines(self, plugin, log_file):
        result = plugin.execute({"action": "survey", "file_path": str(log_file)}, None)
        # Four shapes were written; the clusterer must not explode them.
        assert result.result["survey"]["cluster_count"] <= 8

    def test_result_does_not_carry_the_log(self, plugin, log_file):
        result = plugin.execute({"action": "survey", "file_path": str(log_file)}, None)
        for cluster in result.result["survey"]["clusters"]:
            assert len(cluster["samples"]) <= 3

    def test_missing_file(self, plugin):
        result = plugin.execute({"action": "survey", "file_path": "/no/such.log"}, None)
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"

    def test_empty_file(self, plugin, tmp_path):
        empty = tmp_path / "empty.log"
        empty.write_text("\n\n", encoding="utf-8")
        result = plugin.execute({"action": "survey", "file_path": str(empty)}, None)
        assert not result.ok
        assert result.error_code == "ARTIFACT_UNREADABLE"

    def test_summary_is_bounded(self, plugin, log_file):
        result = plugin.execute({"action": "survey", "file_path": str(log_file)}, None)
        summary = plugin.summarize_for_llm(result)
        assert summary.startswith("Survey of app.log")
        assert len(summary) < 4000


class TestGuards:
    def test_audit_without_model(self, plugin, log_file):
        result = plugin.execute(
            {
                "action": "audit",
                "file_path": str(log_file),
                "profile_path": str(PROFILE_EXAMPLE),
            },
            FakeContext(llm=None),
        )
        assert not result.ok
        assert result.error_code == "LLM_UNAVAILABLE"

    def test_unusable_profile_names_the_problem(self, plugin, log_file, tmp_path):
        bad = tmp_path / "profile.json"
        bad.write_text(json.dumps({"requirements": []}), encoding="utf-8")
        result = plugin.execute(
            {"action": "audit", "file_path": str(log_file), "profile_path": str(bad)},
            FakeContext(llm=object()),
        )
        assert not result.ok
        assert result.error_code == "INPUT_VALIDATION_FAILED"
        assert "catalogue" in result.message

    def test_failure_summary(self, plugin):
        failed = tool.ToolResult(ok=False, error_code="X", message="File missing")
        assert "failed" in plugin.summarize_for_llm(failed)
