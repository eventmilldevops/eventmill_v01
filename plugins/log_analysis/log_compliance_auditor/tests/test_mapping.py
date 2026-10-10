"""The mapping loop, value checks, assessment and renderings.

The model replies here are scripted, which proves the loop's mechanics and
nothing about what a real model returns. The hostile-shape tests exist because
a reply is untrusted shape; the live runs recorded in the change log are what
test the prompts.
"""

import json
import time

import pytest

from .helpers import (
    COUNT_A,
    COUNT_B,
    COUNT_C,
    COUNT_JUNK,
    PATTERN_A,
    PATTERN_A_WRONG_FORMAT,
    PATTERN_B,
    PATTERN_C,
    PROFILE_EXAMPLE,
    TOTAL,
    FakeContext,
    FakeLLM,
    FakeResponse,
    build_log,
    load_tool,
    reply,
)

tool = load_tool()
ml, vd, sv, az, rn = tool.ml, tool.vd, tool.sv, tool.az, tool.rn


@pytest.fixture
def plugin():
    return tool.LogComplianceAuditor()


@pytest.fixture
def log_file(tmp_path):
    return build_log(tmp_path / "app.log")


@pytest.fixture
def catalogue():
    return json.loads(PROFILE_EXAMPLE.read_text(encoding="utf-8"))["catalogue"]


def audit(plugin, log_file, replies, **extra):
    llm = FakeLLM(replies)
    context = FakeContext(llm=llm)
    payload = {
        "action": "audit",
        "file_path": str(log_file),
        "profile_path": str(PROFILE_EXAMPLE),
        **extra,
    }
    return plugin.execute(payload, context), llm, context


def findings(result):
    return {f["requirement_id"]: f for f in result.result["assessment"]["findings"]}


class TestValidators:
    @pytest.mark.parametrize(
        "value,fmt,has_tz,digits",
        [
            ("2026-03-01T10:00:00.123+00:00", "iso8601", True, 3),
            ("2026-03-01 10:00:00", "%Y-%m-%d %H:%M:%S", False, 0),
            ("01/Mar/2026:11:00:01 +0000", "%d/%b/%Y:%H:%M:%S %z", True, 0),
            ("1772359200123", "epoch_ms", True, 3),
            ("2026-03-01T10:00:00.123456789Z", "iso8601", True, 9),
        ],
    )
    def test_timestamp_formats(self, value, fmt, has_tz, digits):
        parsed = vd.parse_timestamp(value, fmt)
        assert parsed is not None
        assert parsed["has_tz"] is has_tz
        assert parsed["digits"] == digits

    def test_wrong_format_does_not_parse(self):
        assert (
            vd.parse_timestamp("2026-03-01T10:00:00.123+00:00", "%Y-%m-%d %H:%M:%S")
            is None
        )

    def test_yearless_syslog_time_is_flagged_not_failed(self):
        stats = vd.FieldStats("timestamp", "%b %d %H:%M:%S")
        stats.add("Mar  1 10:00:00")
        summary = stats.summary()
        assert summary["valid"] == 1
        assert "year_absent" in summary["flags"]
        assert "no_timezone" in summary["flags"]

    def test_implausible_year_fails(self):
        stats = vd.FieldStats("timestamp", "%Y-%m-%d %H:%M:%S")
        stats.add("1970-01-01 00:00:00")
        assert stats.summary()["valid"] == 0

    def test_format_suggestion_on_failure(self):
        stats = vd.FieldStats("timestamp", "%Y-%m-%d %H:%M:%S")
        stats.add("2026-03-01T10:00:00.123+00:00")
        assert stats.summary()["format_suggestion"] == "iso8601"

    def test_address(self):
        assert vd.is_address("10.0.0.5") == (True, True)
        assert vd.is_address("db-1.internal") == (True, False)
        assert vd.is_address("10.0.0.5:443")[0] is False
        assert vd.is_address("999.1.1")[0] is False

    def test_placeholders_are_empty_not_invalid(self):
        stats = vd.FieldStats("identity")
        for value in ("-", "", "null", "alice"):
            stats.add(value)
        summary = stats.summary()
        assert summary["records"] == 4
        assert summary["filled"] == 1
        assert summary["pass_rate"] == 1.0

    def test_constant_identity_is_a_flag(self):
        stats = vd.FieldStats("identity")
        for _ in range(60):
            stats.add("svc-account")
        summary = stats.summary()
        assert summary["pass_rate"] == 1.0
        assert "constant_value" in summary["flags"]


class TestUntrustedPatternShape:
    def test_lookahead_is_refused_with_a_reason(self, catalogue):
        pattern, notes = ml.normalise_pattern(
            {"regex": r"^(?=x)(?P<a>.*)$", "fields": {}}, catalogue, "p1"
        )
        assert pattern is None
        assert "RE2" in notes[0]

    def test_backreference_is_refused(self, catalogue):
        pattern, _ = ml.normalise_pattern(
            {"regex": r"^(?P<a>\w+) \1$", "fields": {}}, catalogue, "p1"
        )
        assert pattern is None

    def test_unnamed_group_is_refused(self, catalogue):
        pattern, notes = ml.normalise_pattern(
            {"regex": r"^(\d+) (?P<a>.*)$", "fields": {}}, catalogue, "p1"
        )
        assert pattern is None
        assert "unnamed" in notes[0]

    def test_angle_bracket_groups_are_accepted(self, catalogue):
        pattern, _ = ml.normalise_pattern(
            {"regex": r"^(?<user>\w+)$", "fields": {"user": "actor_identity"}},
            catalogue,
            "p1",
        )
        assert pattern["regex"] == r"^(?P<user>\w+)$"
        assert pattern["fields"]["user"]["element"] == "actor_identity"

    def test_invented_element_becomes_unclassified(self, catalogue):
        pattern, notes = ml.normalise_pattern(
            {"regex": r"^(?P<x>\w+)$", "fields": {"x": {"element": "mood"}}},
            catalogue,
            "p1",
        )
        assert pattern["fields"]["x"]["element"] is None
        assert any("not in the catalogue" in n for n in notes)

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "regex",
            7,
            [],
            {"regex": 12},
            {"regex": ""},
            {"kind": "json", "fields": []},
            {"regex": r"^(?P<a>.*)$", "fields": "nope"},
        ],
    )
    def test_wrong_types_never_raise(self, raw, catalogue):
        pattern, notes = ml.normalise_pattern(raw, catalogue, "p1")
        assert pattern is None or pattern["fields"]
        assert isinstance(notes, list)

    @pytest.mark.parametrize(
        "text",
        [
            None,
            "",
            "sorry, I cannot",
            "[1, 2",
            '{"patterns": "none"}',
            '"just a string"',
            '```json\n{"patterns": [{"regex": "^(?P<a>.*)$"}]}\n```',
        ],
    )
    def test_reply_parsing_never_raises(self, text):
        patterns, notes = ml.parse_reply(text)
        assert isinstance(patterns, list) and isinstance(notes, list)

    def test_catastrophic_pattern_is_bounded(self, tmp_path, catalogue):
        # Exponential under a backtracking engine; RE2 runs it in linear time.
        log = tmp_path / "evil.log"
        log.write_text(("x" * 3000 + "z\n") * 2000, encoding="utf-8")
        pattern, _ = ml.normalise_pattern(
            {"regex": r"^(?P<a>(?:x+x+)+)y$", "fields": {}}, catalogue, "p1"
        )
        started = time.monotonic()
        test = ml.run_patterns(log, [pattern], sv, vd)
        assert time.monotonic() - started < 20
        assert test["matched"] == 0 and test["records"] == 2000


class TestLoop:
    def test_converges_in_two_rounds(self, plugin, log_file):
        result, llm, _ = audit(
            plugin,
            log_file,
            [reply(PATTERN_A_WRONG_FORMAT, PATTERN_C), reply(PATTERN_A, PATTERN_B)],
        )
        assert result.ok, result.message
        data = result.result
        assert data["status"] == "converged"
        assert data["rounds_run"] == 2
        assert data["assessment"]["records_mapped"] == TOTAL - COUNT_JUNK
        # Round two was told what failed, with the value and a format that fits.
        assert "FIELDS WHOSE VALUES FAILED" in llm.prompts[1]
        assert "iso8601" in llm.prompts[1]
        assert "LINES NO PATTERN MATCHED" in llm.prompts[1]

    def test_only_a_sample_leaves_the_container(self, plugin, log_file):
        result, llm, _ = audit(
            plugin, log_file, [reply(PATTERN_A, PATTERN_B, PATTERN_C)]
        )
        sent = result.result["sent_to_model"]
        assert sent["calls"] == 1
        assert sent["lines"] <= 200
        assert sent["lines"] < TOTAL / 10
        assert len(llm.prompts[0]) < 80_000

    def test_junk_stays_unmatched_and_is_reported(self, plugin, log_file):
        result, _, _ = audit(plugin, log_file, [reply(PATTERN_A, PATTERN_B, PATTERN_C)])
        assert result.result["assessment"]["records_unmapped"] == COUNT_JUNK
        assert "rotated" in result.result["unmatched_groups"][0]["samples"][0]

    def test_round_limit_reports_incomplete(self, plugin, log_file):
        result, _, _ = audit(plugin, log_file, [reply(PATTERN_A)], max_rounds=1)
        assert result.ok
        assert result.result["status"] == "stopped_round_limit"
        summary = plugin.summarize_for_llm(result)
        assert summary.startswith("MAPPING INCOMPLETE")
        assert "resume" in summary

    def test_no_progress_stops(self, plugin, log_file):
        result, llm, _ = audit(
            plugin,
            log_file,
            [reply(PATTERN_A), reply(PATTERN_A), reply(PATTERN_A), reply(PATTERN_A)],
        )
        assert result.result["status"] == "stopped_no_progress"
        assert len(llm.prompts) == 3

    def test_worse_revision_is_not_adopted(self, plugin, log_file):
        broken = dict(PATTERN_A, regex=r"^(?P<program>nothing)$", fields={})
        result, _, _ = audit(
            plugin,
            log_file,
            [reply(PATTERN_A, PATTERN_B, PATTERN_C), reply(broken)],
            target_coverage=1.0,
            max_rounds=2,
        )
        types = {
            t["pattern_id"]: t for t in result.result["extraction_spec"]["record_types"]
        }
        assert types["auth"]["records"] == COUNT_A
        assert result.result["mapping_state"]["history"][1]["accepted"] is False

    def test_unusable_replies_fail_with_a_diagnosis(self, plugin, log_file):
        result, llm, context = audit(
            plugin,
            log_file,
            ["I could not parse that.", '{"patterns": [{"regex": "(?=a)"}]}'],
        )
        assert not result.ok
        assert result.error_code == "MAPPING_FAILED"
        assert "State saved at" in result.message
        assert "YOUR PREVIOUS REPLY COULD NOT BE USED" in llm.prompts[1]
        assert context.registered == []

    def test_model_failure_keeps_what_was_mapped(self, plugin, log_file):
        result, _, _ = audit(
            plugin,
            log_file,
            [reply(PATTERN_A), FakeResponse(ok=False, error="504 deadline exceeded")],
        )
        assert result.ok
        assert result.result["status"] == "stopped_llm_failure"
        assert "504" in result.result["stop_reason"]
        assert result.result["assessment"]["records_mapped"] == COUNT_A

    def test_time_budget_stops_before_a_call_it_cannot_afford(
        self, log_file, catalogue
    ):
        survey = sv.survey_file(log_file)
        state = ml.new_state({"file": "app.log"}, dict(ml.DEFAULTS))
        now = [0.0]
        calls = []

        def ask(prompt):
            calls.append(prompt)
            now[0] += 200.0
            return {"ok": True, "text": reply(PATTERN_A)}

        ml.run_loop(
            log_file,
            survey,
            catalogue,
            ["timestamp"],
            state,
            ask,
            sv,
            vd,
            deadline=300.0,
            clock=lambda: now[0],
        )
        assert len(calls) == 1
        assert state["status"] == "stopped_time_budget"
        assert state["patterns"]

    def test_resume_continues_from_a_result(self, plugin, log_file):
        first, _, context = audit(
            plugin, log_file, [reply(PATTERN_A, PATTERN_C)], max_rounds=1
        )
        result_artifact = next(
            a for a in context.registered if a.metadata["kind"] == "audit_result"
        )
        llm = FakeLLM([reply(PATTERN_B)])
        context.llm_query = llm
        second = plugin.execute(
            {
                "action": "resume",
                "file_path": str(log_file),
                "profile_path": str(PROFILE_EXAMPLE),
                "state_artifact_id": result_artifact.artifact_id,
            },
            context,
        )
        assert second.ok, second.message
        assert second.result["status"] == "converged"
        assert second.result["rounds_run"] == 2
        assert second.result["sent_to_model"]["calls"] == 2
        # The resumed round is feedback on held patterns, not a fresh start.
        assert "CURRENT PATTERNS" in llm.prompts[0]


class TestAssessment:
    @pytest.fixture
    def result(self, plugin, log_file):
        result, _, _ = audit(plugin, log_file, [reply(PATTERN_A, PATTERN_B, PATTERN_C)])
        assert result.ok, result.message
        return result

    def test_states(self, result):
        f = findings(result)
        assert f["4.2.2"]["state"] == "observed"
        assert f["4.2.3"]["state"] == "observed"
        assert f["4.2.1"]["state"] == "partially_observed"
        assert f["4.2.4"]["state"] == "partially_observed"
        assert f["4.3.1"]["state"] == "not_evaluated"
        assert f["6.1"]["state"] == "not_assessable_from_sample"
        assert f["6.3"]["state"] == "not_assessable_from_sample"

    def test_exact_record_counts(self, result):
        f = findings(result)
        # Billing timestamps have a zone but only whole seconds.
        assert f["4.2.1"]["records_with_all_elements"] == COUNT_A + COUNT_C
        assert f["4.2.3"]["records_with_all_elements"] == TOTAL - COUNT_JUNK
        # The JSON records carry no source address.
        assert f["4.2.4"]["records_with_all_elements"] == COUNT_A + COUNT_B
        billing = next(
            t for t in f["4.2.1"]["by_record_type"] if t["pattern_id"] == "billing"
        )
        assert billing["state"] == "not_observed"
        assert any(
            "coarser than millisecond" in n for n in billing["elements"][0]["notes"]
        )

    def test_out_of_reach_is_not_counted_as_assessed(self, result):
        assessment = result.result["assessment"]
        assert assessment["requirements"] == 7
        assert assessment["requirements_assessed"] == 4
        assert assessment["counts"]["not_assessable_from_sample"] == 2

    def test_missing_element_is_not_observed(self, plugin, log_file):
        no_user = json.loads(json.dumps(PATTERN_A))
        no_user["fields"]["user"] = {"element": None}
        result, _, _ = audit(plugin, log_file, [reply(no_user)], max_rounds=1)
        auth = next(
            t
            for t in findings(result)["4.2.3"]["by_record_type"]
            if t["pattern_id"] == "auth"
        )
        assert auth["state"] == "not_observed"
        assert auth["elements"][0]["field"] is None

    def test_allowed_values_constraint(self, catalogue):
        profile = {
            "catalogue": catalogue,
            "requirements": [
                {
                    "requirement_id": "R1",
                    "obligation": "must",
                    "assessable_from": "record_content",
                    "elements": [
                        {
                            "element": "outcome",
                            "constraints": {"allowed_values": ["success", "failure"]},
                        }
                    ],
                }
            ],
        }
        stats = vd.FieldStats("category")
        for value in ["success"] * 70 + ["failure"] * 20 + ["OK"] * 10:
            stats.add(value)
        patterns = [
            {
                "pattern_id": "p",
                "kind": "regex",
                "regex": "x",
                "fields": {"res": {"element": "outcome", "value_type": "category"}},
            }
        ]
        test = {
            "records": 100,
            "matched": 100,
            "unmatched": 0,
            "coverage": 1.0,
            "patterns": [
                {"pattern_id": "p", "records": 100, "fields": {"res": stats.summary()}}
            ],
        }
        finding = az.assess(profile, patterns, test, vd)["findings"][0]
        assert finding["records_with_all_elements"] == 90
        assert finding["state"] == "partially_observed"

    def test_assess_action_makes_no_model_call(
        self, plugin, log_file, result, tmp_path
    ):
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(
            json.dumps(result.result["extraction_spec"]), encoding="utf-8"
        )
        again = plugin.execute(
            {
                "action": "assess",
                "file_path": str(log_file),
                "profile_path": str(PROFILE_EXAMPLE),
                "state_path": str(spec_file),
            },
            FakeContext(llm=None),
        )
        assert again.ok, again.message
        assert again.result["status"] == "assessed_without_model"
        assert again.result["sent_to_model"]["lines"] == 0
        assert {k: v["state"] for k, v in findings(again).items()} == {
            k: v["state"] for k, v in findings(result).items()
        }


class TestOutputs:
    @pytest.fixture
    def run(self, plugin, log_file):
        result, _, context = audit(
            plugin, log_file, [reply(PATTERN_A, PATTERN_B, PATTERN_C)]
        )
        assert result.ok, result.message
        return result, context, log_file

    def test_six_artifacts_registered(self, run):
        _, context, _ = run
        kinds = [a.metadata["kind"] for a in context.registered]
        assert kinds == [
            "audit_result",
            "alignment_report",
            "extraction_spec",
            "extraction_bigquery",
            "extraction_splunk",
            "extraction_elastic",
        ]

    def test_bigquery_regexes_reproduce_the_tested_extraction(self, run):
        import re2

        result, _, log_file = run
        spec = result.result["extraction_spec"]
        lines = log_file.read_text(encoding="utf-8").splitlines()
        checked = 0
        for record_type in spec["record_types"]:
            if record_type["kind"] != "regex":
                continue
            full = re2.compile(record_type["regex"])
            for line in lines:
                match = full.fullmatch(line)
                if match is None:
                    continue
                for field in record_type["fields"]:
                    single = re2.compile(
                        rn.single_group_regex(record_type["regex"], field["name"])
                    )
                    assert single.groups == 1
                    assert single.search(line).group(1) == match.group(field["name"])
                checked += 1
        assert checked == COUNT_A + COUNT_B

    def test_renderings_say_what_was_not_executed(self, run):
        result, context, _ = run
        by_kind = {a.metadata["kind"]: a for a in context.registered}
        splunk = open(by_kind["extraction_splunk"].file_path, encoding="utf-8").read()
        assert "rendered_not_executed" in splunk
        assert "EXTRACT-auth = ^(?<program>" in splunk
        elastic = json.loads(
            open(by_kind["extraction_elastic"].file_path, encoding="utf-8").read()
        )
        assert "rendered_not_executed" in elastic["description"]
        assert [next(iter(p)) for p in elastic["processors"]][:2] == ["json", "grok"]
        sql = open(by_kind["extraction_bigquery"].file_path, encoding="utf-8").read()
        assert "REGEXP_EXTRACT" in sql and "JSON_VALUE(raw, '$.user.name')" in sql

    def test_java_time_format(self):
        assert rn.java_time_format("%d/%b/%Y:%H:%M:%S %z") == "dd/MMM/yyyy:HH:mm:ss Z"
        assert rn.java_time_format("%Y-%m-%dT%H:%M:%S") == "yyyy-MM-dd'T'HH:mm:ss"
        assert rn.java_time_format("epoch_ms") == "UNIX_MS"
        assert rn.java_time_format("%c") is None

    def test_report_describes_and_does_not_certify(self, run):
        _, context, _ = run
        report_path = next(
            a.file_path
            for a in context.registered
            if a.metadata["kind"] == "alignment_report"
        )
        report = open(report_path, encoding="utf-8").read()
        assert "not a certification" in report
        assert "Requirements a log sample cannot show" in report
        assert "compliant" not in report.lower()
        assert "draft_unreviewed" not in report  # the example profile is reviewed

    def test_report_leads_with_an_unreviewed_profile(self, plugin, log_file, tmp_path):
        profile = json.loads(PROFILE_EXAMPLE.read_text(encoding="utf-8"))
        profile["review_status"] = "draft_unreviewed"
        draft = tmp_path / "draft.json"
        draft.write_text(json.dumps(profile), encoding="utf-8")
        context = FakeContext(llm=FakeLLM([reply(PATTERN_A, PATTERN_B, PATTERN_C)]))
        result = plugin.execute(
            {"action": "audit", "file_path": str(log_file), "profile_path": str(draft)},
            context,
        )
        report_path = next(
            a.file_path
            for a in context.registered
            if a.metadata["kind"] == "alignment_report"
        )
        report = open(report_path, encoding="utf-8").read().splitlines()
        assert "draft_unreviewed" in report[2]
        assert "draft_unreviewed" in plugin.summarize_for_llm(result)

    def test_summary_leads_with_status_and_stays_in_budget(self, run, plugin):
        result, _, _ = run
        summary = plugin.summarize_for_llm(result)
        assert summary.startswith("Mapping complete")
        assert len(summary) < 4000

    def test_result_is_json_serialisable_and_holds_no_residue(self, run):
        result, context, _ = run
        text = open(context.registered[0].file_path, encoding="utf-8").read()
        saved = json.loads(text)
        assert "_residue" not in saved["mapping_state"]
        assert saved["mapping_state"]["test"]["matched"] == TOTAL - COUNT_JUNK
