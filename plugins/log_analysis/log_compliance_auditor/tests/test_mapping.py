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

    def test_allowed_values_constraint(self, catalogue, tmp_path):
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
        log = tmp_path / "res.log"
        log.write_text(
            "\n".join(
                f"res={value}"
                for value in ["success"] * 70 + ["failure"] * 20 + ["OK"] * 10
            ),
            encoding="utf-8",
        )
        patterns = [
            {
                "pattern_id": "p",
                "kind": "regex",
                "regex": r"^res=(?P<res>\S+)$",
                "fields": {"res": {"element": "outcome", "value_type": "category"}},
            }
        ]
        test = ml.run_patterns(
            log, patterns, sv, vd, value_elements=az.constrained_value_elements(profile)
        )
        finding = az.assess(profile, patterns, test, vd)["findings"][0]
        assert finding["records_with_all_elements"] == 90
        assert finding["state"] == "partially_observed"

    def test_alternatives_need_only_one_member(self, catalogue, tmp_path):
        def requirement(rid, obligation, elements):
            return {
                "requirement_id": rid,
                "obligation": obligation,
                "assessable_from": "record_content",
                "summary": rid,
                "elements": elements,
            }

        origin = {
            "any_of": [{"element": "host"}, {"element": "source_component"}],
            "label": "origin",
        }
        profile = {
            "catalogue": catalogue,
            "requirements": [
                requirement("FLAT", "must", [{"element": "host"}, {"element": "source_component"}]),
                requirement("GROUP", "may", [origin]),
                requirement("MIXED", "must", [{"element": "actor_identity"}, origin]),
            ],
        }
        log = tmp_path / "origin.log"
        log.write_text(
            "\n".join(
                ["host=h1 user=a"] * 60 + ["svc=api user=a"] * 30 + ["user=a"] * 10
            ),
            encoding="utf-8",
        )
        patterns = [
            {
                "pattern_id": "h",
                "kind": "regex",
                "regex": r"^host=(?P<host>\S+) user=(?P<user>\S+)$",
                "fields": {
                    "host": {"element": "host", "value_type": "identity"},
                    "user": {"element": "actor_identity", "value_type": "identity"},
                },
            },
            {
                "pattern_id": "s",
                "kind": "regex",
                "regex": r"^svc=(?P<svc>\S+) user=(?P<user>\S+)$",
                "fields": {
                    "svc": {"element": "source_component", "value_type": "identity"},
                    "user": {"element": "actor_identity", "value_type": "identity"},
                },
            },
            {
                "pattern_id": "u",
                "kind": "regex",
                "regex": r"^user=(?P<user>\S+)$",
                "fields": {
                    "user": {"element": "actor_identity", "value_type": "identity"}
                },
            },
        ]
        assert az.wanted_elements(profile) == [
            n
            for n in catalogue["elements"]
            if n in ("host", "source_component", "actor_identity")
        ]
        test = ml.run_patterns(log, patterns, sv, vd)
        f = {x["requirement_id"]: x for x in az.assess(profile, patterns, test, vd)["findings"]}
        assert f["FLAT"]["records_with_all_elements"] == 0
        assert f["GROUP"]["records_with_all_elements"] == 90
        assert f["MIXED"]["records_with_all_elements"] == 90
        assert f["MIXED"]["needs"][1] == {
            "elements": ["host", "source_component"],
            "any_of": True,
            "label": "origin",
            "records": 90,
            "share": 0.9,
        }
        assert {e["element"]: e["records"] for e in f["GROUP"]["elements"]} == {
            "host": 60,
            "source_component": 30,
        }

        assert rn._needs_lines(f["FLAT"]) == [
            "All required elements present in 0 of 100 records (0.0%)."
        ]
        assert rn._needs_lines(f["GROUP"]) == [
            "Optional. At least one of the elements below is present in "
            "90 of 100 records (90.0%)."
        ]
        mixed = "\n".join(rn._needs_lines(f["MIXED"]))
        assert "Needs: actor_identity; origin: one of host / source_component." in mixed
        assert "- One of host / source_component: 90 of 100 records." in mixed
        short = "; ".join(rn._short_types(f["MIXED"]))
        assert "`u` (10 of its records: none of host / source_component)" in short
        assert "`h`" not in short and "`s`" not in short

    def test_only_presence_rules_are_counted(self, catalogue, tmp_path):
        def requirement(rid, kind, elements):
            item = {
                "requirement_id": rid,
                "obligation": "must",
                "assessable_from": "record_content",
                "summary": rid,
                "elements": elements,
            }
            if kind:
                item["kind"] = kind
            return item

        user = [{"element": "actor_identity"}]
        profile = {
            "catalogue": catalogue,
            "review_status": "reviewed",
            "standard": {"title": "T", "version": "1"},
            "requirements": [
                requirement("OLD", None, user),
                requirement("HAS", "presence", user),
                requirement("BAN", "prohibition", [{"element": "message"}]),
                requirement("LOGGED", "event_selection", user),
                requirement("VALID", "quality", []),
                requirement("ODD", "vibes", user),
                requirement("NOTHING", "presence", []),
            ],
        }
        log = tmp_path / "u.log"
        log.write_text("\n".join(["user=a"] * 40), encoding="utf-8")
        patterns = [
            {
                "pattern_id": "u",
                "kind": "regex",
                "regex": r"^user=(?P<user>\S+)$",
                "fields": {
                    "user": {"element": "actor_identity", "value_type": "identity"}
                },
            }
        ]
        test = ml.run_patterns(log, patterns, sv, vd)
        assessment = az.assess(profile, patterns, test, vd)
        f = {x["requirement_id"]: x for x in assessment["findings"]}
        assert f["OLD"]["state"] == f["HAS"]["state"] == "observed"
        for rid in ("BAN", "LOGGED", "VALID", "ODD", "NOTHING"):
            assert f[rid]["state"] == "not_evaluated", rid
            assert "share" not in f[rid] and "records_with_all_elements" not in f[rid]
        assert "prohibition" in f["BAN"]["basis"]
        assert f["BAN"]["reference_elements"] == [{"element": "message", "records": 0}]
        assert f["LOGGED"]["reference_elements"] == [
            {"element": "actor_identity", "records": 40}
        ]
        assert "reference_elements" not in f["VALID"]
        assert "vibes" in f["ODD"]["basis"]
        assert assessment["requirements_assessed"] == 2
        assert assessment["not_counted_by_kind"] == {
            "prohibition": 1,
            "event_selection": 1,
            "quality": 1,
        }
        # A banned element is still mapped, so its count can be shown.
        assert "message" in az.wanted_elements(profile)

        profile["profile_version"] = "1.0"
        profile_file = tmp_path / "kinds.json"
        profile_file.write_text(json.dumps(profile), encoding="utf-8")
        plugin = tool.LogComplianceAuditor()
        context = FakeContext(llm=FakeLLM([reply(patterns[0])]))
        result = plugin.execute(
            {
                "action": "audit",
                "file_path": str(log),
                "profile_path": str(profile_file),
            },
            context,
        )
        assert result.ok, result.message
        assert "1 event_selection" in plugin.summarize_for_llm(result)
        report = open(
            next(
                a.file_path
                for a in context.registered
                if a.metadata["kind"] == "alignment_report"
            ),
            encoding="utf-8",
        ).read()
        assert "## Requirements about records that were not counted" in report
        assert "### Prohibitions" in report and "### Event selection" in report
        assert "For reference, in this sample: message in 0 of 40." in report
        assert "### BAN" not in report and "### LOGGED" not in report

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


class TestJavaStackTrace:
    """A live Catalina log: the exception line starts at column 0."""

    def test_unindented_exception_line_is_a_continuation(self, tmp_path):
        log = tmp_path / "catalina.log"
        log.write_text(
            "15-Sep-2026 10:14:32.000 SEVERE [exec-1] com.a.B.c Request failed\n"
            "java.sql.SQLTransientConnectionException: pool timed out after 30000ms.\n"
            "\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)\n"
            "Caused by: java.net.SocketTimeoutException: connect timed out\n"
            "15-Sep-2026 10:14:33.000 INFO [exec-2] com.a.B.d Completed request\n"
            "Error: this unqualified line is a record of its own\n",
            encoding="utf-8",
        )
        records = list(sv.iter_records(log))
        assert [(number, extra) for number, _, extra in records] == [
            (1, 3),
            (5, 0),
            (6, 0),
        ]


class TestRunEvidence:
    """What a run keeps so that two runs can be compared."""

    LINES = [
        "evt=LOGIN user=alice",
        "evt=LOGOUT",
        "user=bob",
        "evt=READ user=carol",
    ]

    def _log(self, tmp_path):
        log = tmp_path / "mixed.log"
        log.write_text("\n".join(self.LINES), encoding="utf-8")
        return log

    def _patterns(self, user_regex=r"\S+"):
        field = lambda element: {
            "element": element,
            "value_type": "identity",
        }  # noqa: E731
        return [
            {
                "pattern_id": "both",
                "kind": "regex",
                "regex": rf"^evt=(?P<evt>\S+) user=(?P<user>{user_regex})$",
                "fields": {"evt": field("event_type"), "user": field("actor_identity")},
            },
            {
                "pattern_id": "evt_only",
                "kind": "regex",
                "regex": r"^evt=(?P<evt>\S+)$",
                "fields": {"evt": field("event_type")},
            },
            {
                "pattern_id": "user_only",
                "kind": "regex",
                "regex": r"^user=(?P<user>\S+)$",
                "fields": {"user": field("actor_identity")},
            },
        ]

    def test_combination_count_is_exact_not_an_upper_bound(self, catalogue, tmp_path):
        test = ml.run_patterns(self._log(tmp_path), self._patterns(), sv, vd)
        profile = {
            "catalogue": catalogue,
            "requirements": [
                {
                    "requirement_id": "R",
                    "obligation": "must",
                    "assessable_from": "record_content",
                    "elements": [
                        {"element": "event_type"},
                        {"element": "actor_identity"},
                    ],
                }
            ],
        }
        finding = az.assess(profile, self._patterns(), test, vd)["findings"][0]
        # 3 records carry event_type and 3 carry actor_identity; only 2 carry both.
        assert finding["records_with_all_elements"] == 2
        assert finding["count_is_exact"] is True
        assert {e["element"]: e["records"] for e in finding["elements"]} == {
            "event_type": 3,
            "actor_identity": 3,
        }

    def test_signature_follows_what_was_captured_not_the_regex(self, tmp_path):
        log = self._log(tmp_path)
        one = ml.run_patterns(log, self._patterns(), sv, vd)
        renamed = self._patterns(user_regex=r"[a-z]+")
        for pattern in renamed:
            pattern["pattern_id"] = "x_" + pattern["pattern_id"]
        two = ml.run_patterns(log, renamed, sv, vd)
        assert one["split_signature"] == two["split_signature"]
        assert one["elements"]["actor_identity"]["signature"] == (
            two["elements"]["actor_identity"]["signature"]
        )
        assert one["elements"]["event_type"]["value_counts"] == {
            "LOGIN": 1,
            "LOGOUT": 1,
            "READ": 1,
        }

    def test_signature_changes_when_another_field_is_the_element(self, tmp_path):
        log = self._log(tmp_path)
        one = ml.run_patterns(log, self._patterns(), sv, vd)
        swapped = self._patterns()
        swapped[0]["fields"]["evt"]["element"] = None
        two = ml.run_patterns(log, swapped, sv, vd)
        assert one["split_signature"] == two["split_signature"]
        assert one["elements"]["event_type"]["signature"] != (
            two["elements"]["event_type"]["signature"]
        )

    def test_same_scripted_run_has_the_same_fingerprints(self, plugin, tmp_path):
        log = build_log(tmp_path / "app.log")
        runs = []
        for _ in range(2):
            context = FakeContext(FakeLLM([reply(PATTERN_A, PATTERN_B, PATTERN_C)] * 4))
            result = plugin.execute(
                {
                    "action": "audit",
                    "file_path": str(log),
                    "profile_path": str(PROFILE_EXAMPLE),
                },
                context,
            )
            runs.append(result.result["run"])
        assert runs[0]["inputs_fingerprint"] == runs[1]["inputs_fingerprint"]
        assert runs[0]["outcome_fingerprint"] == runs[1]["outcome_fingerprint"]
        assert runs[0]["log_sha256"] and runs[0]["profile_sha256"]


def build_syslog(path, with_pri=False):
    """BSD syslog: three programs, each with its own message shapes."""
    pri = "<38>" if with_pri else ""
    lines = []
    for i in range(120):
        lines.append(
            f"{pri}Sep {1 + i % 9:2d} 10:{i % 60:02d}:{i % 60:02d} web01 CRON[{900 + i}]: "
            f"({'root' if i % 2 else 'backup'}) CMD (/usr/local/bin/job{i % 4})"
        )
    for i in range(60):
        lines.append(
            f"{pri}Sep 10 11:{i % 60:02d}:00 web01 sshd[{2000 + i}]: "
            f"Accepted publickey for user{i % 5} from 10.0.0.{1 + i % 50} port {40000 + i} ssh2"
        )
    for i in range(20):
        lines.append(
            f"{pri}Sep 11 12:00:{i:02d} web01 kernel: something odd happened in zone {i} "
            f"while the moon was {['full', 'new', 'half'][i % 3]}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


CRON_MSG = {
    "pattern_id": "cron_cmd",
    "program": "CRON",
    "describes": "cron job start",
    "message_regex": r"^\((?P<user>[^)]+)\) CMD \((?P<command>.*)\)$",
    "fields": {
        "user": {"element": "actor_identity"},
        "command": {"element": "target_object"},
    },
}
SSHD_MSG = {
    "pattern_id": "sshd_accept",
    "program": "sshd",
    "message_regex": (
        r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src>\S+) "
        r"port (?P<port>\d+) ssh2"
    ),
    "fields": {
        "user": {"element": "actor_identity"},
        "src": {"element": "source_address"},
        "method": {"element": None},
    },
}


class TestSyslogEnvelope:
    """The header is the tool's; the model only breaks messages down per program."""

    def test_survey_recognises_the_envelope_and_clusters_by_program(self, tmp_path):
        survey = sv.survey_file(build_syslog(tmp_path / "sys.log"))
        envelope = survey["envelope"]
        assert envelope["kind"] == "syslog_bsd"
        assert envelope["records"] == 200 and envelope["share"] == 1.0
        assert envelope["with_pri"] == 0
        assert envelope["with_pid"] == 180
        assert [(p["program"], p["records"]) for p in envelope["programs"]] == [
            ("CRON", 120),
            ("sshd", 60),
            ("kernel", 20),
        ]
        assert {c["program"] for c in survey["clusters"]} == {"CRON", "sshd", "kernel"}
        assert "CMD" in survey["clusters"][0]["samples"][0]["message"]
        assert survey["clusters"][0]["samples"][0]["text"].startswith("Sep")

    def test_pri_is_counted_when_present(self, tmp_path):
        survey = sv.survey_file(build_syslog(tmp_path / "sys.log", with_pri=True))
        assert survey["envelope"]["with_pri"] == 200

    def test_application_log_has_no_envelope(self, log_file):
        assert sv.survey_file(log_file)["envelope"] is None

    def _audit(self, plugin, tmp_path, replies):
        log = build_syslog(tmp_path / "sys.log")
        context = FakeContext(FakeLLM(replies))
        result = plugin.execute(
            {
                "action": "audit",
                "file_path": str(log),
                "profile_path": str(PROFILE_EXAMPLE),
            },
            context,
        )
        return result, context

    def test_model_is_asked_for_messages_only_grouped_by_program(
        self, plugin, tmp_path
    ):
        _, context = self._audit(plugin, tmp_path, [reply(CRON_MSG, SSHD_MSG), reply()])
        prompt = context.llm_query.prompts[0]
        assert "=== program CRON ===" in prompt and "=== program sshd ===" in prompt
        listing = prompt.split("MESSAGES NOT YET BROKEN DOWN")[1]
        assert "(root) CMD (/usr/local/bin/job" in listing
        assert "web01 CRON[" not in listing
        assert "Never compare or merge messages of different programs" in prompt

    def test_envelope_fields_do_not_depend_on_the_model(self, plugin, tmp_path):
        result, _ = self._audit(plugin, tmp_path, ["no patterns here"] * 4)
        assert result.ok
        data = result.result
        assert data["assessment"]["records_mapped"] == 200
        elements = data["assessment"]["elements"]
        assert elements["timestamp"]["records"] == 200
        assert elements["host"]["records"] == 200
        assert elements["source_component"]["value_counts"] == {
            "CRON": 120,
            "sshd": 60,
            "kernel": 20,
        }
        assert elements["process_id"]["records"] == 180
        assert data["depth"]["records_broken_down"] == 0
        assert "actor_identity" not in elements

    def test_message_patterns_apply_to_their_program_only(self, plugin, tmp_path):
        result, context = self._audit(
            plugin, tmp_path, [reply(CRON_MSG, SSHD_MSG), reply()]
        )
        data = result.result
        assert data["status"] == "converged"
        types = {t["pattern_id"]: t for t in data["extraction_spec"]["record_types"]}
        assert types["cron_cmd"]["records"] == 120
        assert types["cron_cmd"]["program"] == "CRON"
        assert types["sshd_accept"]["records"] == 60
        assert types["envelope"]["records"] == 20
        assert data["extraction_spec"]["record_types"][-1]["pattern_id"] == "envelope"
        assert data["depth"]["records_broken_down"] == 180
        assert data["depth"]["share"] == 0.9
        elements = data["assessment"]["elements"]
        assert elements["actor_identity"]["records"] == 180
        assert elements["message"]["records"] == 200
        assert elements["timestamp"]["records"] == 200
        # 0.9 is above the depth target, so no second round was spent.
        assert len(context.llm_query.prompts) == 1
        summary = plugin.summarize_for_llm(result)
        assert "Envelope: syslog_bsd" in summary and "PRI present in 0" in summary

    def test_a_cron_pattern_cannot_take_an_sshd_record(self, plugin, tmp_path):
        greedy = dict(CRON_MSG, message_regex=r"(?P<everything>.*)", fields={})
        result, _ = self._audit(plugin, tmp_path, [reply(greedy), reply()])
        types = {
            t["pattern_id"]: t for t in result.result["extraction_spec"]["record_types"]
        }
        assert types["cron_cmd"]["records"] == 120
        assert types["envelope"]["records"] == 80

    def test_group_named_like_a_header_field_is_renamed(self, catalogue):
        raw = dict(
            CRON_MSG,
            message_regex=r"\((?P<host>[^)]+)\) CMD \((?P<command>.*)\)",
            fields={"host": {"element": "actor_identity"}},
        )
        pattern, notes = ml.compose_message_pattern(
            raw, sv.envelope_by_kind("syslog_bsd"), catalogue, "x"
        )
        assert pattern is not None, notes
        assert pattern["fields"]["msg_host"]["element"] == "actor_identity"
        assert pattern["fields"]["host"]["element"] == "host"

    def test_message_pattern_without_a_program_is_refused(self, catalogue):
        raw = {k: v for k, v in CRON_MSG.items() if k != "program"}
        pattern, notes = ml.compose_message_pattern(
            raw, sv.envelope_by_kind("syslog_bsd"), catalogue, "x"
        )
        assert pattern is None and "program" in notes[0]

    def test_assess_from_the_spec_keeps_the_envelope_last(self, plugin, tmp_path):
        result, context = self._audit(
            plugin, tmp_path, [reply(CRON_MSG, SSHD_MSG), reply()]
        )
        spec = result.result["outputs"]["extraction_spec"]["file"]
        again = plugin.execute(
            {
                "action": "assess",
                "file_path": str(tmp_path / "sys.log"),
                "profile_path": str(PROFILE_EXAMPLE),
                "state_path": spec,
            },
            FakeContext(None),
        )
        assert again.ok
        assert again.result["run"]["outcome_fingerprint"] == (
            result.result["run"]["outcome_fingerprint"]
        )
        assert again.result["depth"]["records_broken_down"] == 180


class TestUnderSplit:
    """A header and .* maps every record and finds nothing in it."""

    HEADER_ONLY = {
        "pattern_id": "generic",
        "kind": "regex",
        "regex": r"^(?P<ts>\S+) (?P<level>[A-Z]+) (?P<rest>.*)$",
        "fields": {
            "ts": {"element": "timestamp", "format": "iso8601"},
            "level": {"element": "severity"},
            "rest": {"element": "message"},
        },
    }
    LOGIN = {
        "pattern_id": "login",
        "kind": "regex",
        "regex": (
            r"^(?P<ts>\S+) (?P<level>[A-Z]+) login user=(?P<user>\S+) "
            r"from=(?P<src>\S+) result=(?P<result>\S+) trace=(?P<trace>\S+)$"
        ),
        "fields": {
            "ts": {"element": "timestamp", "format": "iso8601"},
            "level": {"element": "severity"},
            "user": {"element": "actor_identity"},
            "src": {"element": "source_address"},
            "result": {"element": "outcome"},
            "trace": {"element": "session_id"},
        },
    }

    def _log(self, tmp_path):
        log = tmp_path / "app.log"
        log.write_text(
            "\n".join(
                f"2026-03-01T10:{i % 60:02d}:00Z INFO login user=u{i % 7} "
                f"from=10.0.0.{1 + i % 90} result={'ok' if i % 3 else 'denied'} trace=t{i:05d}"
                for i in range(200)
            ),
            encoding="utf-8",
        )
        return log

    def test_header_and_free_text_is_flagged(self, tmp_path, catalogue):
        log = self._log(tmp_path)
        pattern, _ = ml.normalise_pattern(self.HEADER_ONLY, catalogue, "g")
        test = ml.run_patterns(log, [pattern], sv, vd)
        shallow = ml.shallow_patterns(test, [pattern])
        assert [(i["pattern_id"], i["field"]) for i in shallow] == [("generic", "rest")]
        assert ml.depth(test, [pattern])["share"] == 0.0

    def test_a_split_record_is_not_flagged(self, tmp_path, catalogue):
        log = self._log(tmp_path)
        pattern, _ = ml.normalise_pattern(self.LOGIN, catalogue, "l")
        test = ml.run_patterns(log, [pattern], sv, vd)
        assert ml.shallow_patterns(test, [pattern]) == []
        assert ml.depth(test, [pattern])["share"] == 1.0

    def test_a_round_is_spent_asking_for_a_deeper_split(self, plugin, tmp_path):
        log = self._log(tmp_path)
        context = FakeContext(FakeLLM([reply(self.HEADER_ONLY), reply(self.LOGIN)]))
        result = plugin.execute(
            {
                "action": "audit",
                "file_path": str(log),
                "profile_path": str(PROFILE_EXAMPLE),
            },
            context,
        )
        assert len(context.llm_query.prompts) == 2
        second = context.llm_query.prompts[1]
        assert "PATTERNS THAT MATCH BUT DO NOT BREAK THE RECORD DOWN" in second
        assert "login user=u" in second
        data = result.result
        assert data["status"] == "converged"
        assert data["depth"]["share"] == 1.0
        assert data["assessment"]["elements"]["actor_identity"]["records"] == 200

    def test_free_prose_is_accepted_after_one_more_round(self, plugin, tmp_path):
        log = self._log(tmp_path)
        context = FakeContext(FakeLLM([reply(self.HEADER_ONLY), reply()]))
        result = plugin.execute(
            {
                "action": "audit",
                "file_path": str(log),
                "profile_path": str(PROFILE_EXAMPLE),
            },
            context,
        )
        data = result.result
        assert data["status"] == "converged"
        assert "held as free text" in data["stop_reason"]
        assert data["depth"]["records_held_as_free_text"] == 200
        assert (
            "leaves most of the line in one free-text field"
            in plugin.summarize_for_llm(result)
        )
