#!/usr/bin/env python3
"""Measure how repeatable a log compliance audit is.

Runs ``log_compliance_auditor`` N times on one log against one requirement
profile, through the real shell and a real provider, and reports how often the
runs agree:

- per element, whether every run chose a field that captured the same values
  from the same records (the element signature);
- per requirement, whether every run reached the same finding;
- whether the runs split the file into the same record types.

Agreement is measured between runs, not against a right answer. ``--truth``
adds a comparison with a ground-truth value count where one exists.

    python scripts/audit_repeatability.py \\
        --log plugins/log_analysis/examples/ymmv_legacy_invoicing_database_audit.log \\
        --profile path/to/profile.json --runs 5 \\
        --truth-file plugins/log_analysis/examples/ymmv_legacy_invoicing_database_audit.ground_truth.json \\
        --truth actor_identity=actor_counts

Needs provider keys in the environment or in the repository's ``.env``. Every
run sends sample lines of the log to the selected provider.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _newest_result(artifacts: Path, seen: set[Path]) -> Path | None:
    fresh = [
        p
        for p in artifacts.glob("log_compliance_auditor_result_*.json")
        if p not in seen
    ]
    return max(fresh, key=lambda p: p.stat().st_mtime) if fresh else None


def run_audits(args: argparse.Namespace, workspace: Path) -> list[dict]:
    sys.path.insert(0, str(REPO))
    os.chdir(REPO)
    try:
        from dotenv import load_dotenv

        load_dotenv(REPO / ".env", override=False)
    except ImportError:
        pass
    os.environ["EVENTMILL_WORKSPACE"] = str(workspace)
    os.environ.pop("K_SERVICE", None)

    from framework.cli.shell import EventMillShell

    shell = EventMillShell(workspace_path=workspace)
    quiet = io.StringIO()

    def cmd(line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            shell.onecmd(line)
        quiet.write(buffer.getvalue())
        return buffer.getvalue()

    cmd("connect")
    cmd("new audit-repeatability")
    cmd("pillar log_analysis")
    if args.provider:
        cmd(f"use {args.provider} for log_compliance_auditor")
    cmd(f"load {Path(args.log).resolve().as_posix()} log_stream")
    cmd(f"load {Path(args.profile).resolve().as_posix()} json_events")
    if args.baseline:
        cmd(f"load {Path(args.baseline).resolve().as_posix()} json_events")
    ids = [a.artifact_id for a in shell.session_manager.list_artifacts()]
    if len(ids) < (3 if args.baseline else 2):
        raise SystemExit("could not load the log and profile:\n" + quiet.getvalue())
    command = (
        f"run log_compliance_auditor --artifact_id {ids[0]} "
        f"--profile_artifact_id {ids[1]}"
    )
    if args.baseline:
        command += f" --baseline_artifact_id {ids[2]}"
    if args.max_rounds:
        command += f" --max_rounds {args.max_rounds}"

    artifacts = workspace / "artifacts"
    seen: set[Path] = set()
    results: list[dict] = []
    for number in range(1, args.runs + 1):
        started = time.time()
        output = cmd(command)
        path = _newest_result(artifacts, seen)
        if path is None:
            tail = " ".join(output.strip().splitlines()[-3:])
            print(f"run {number}: no result ({tail[:200]})", flush=True)
            results.append({"failed": tail[:400]})
        else:
            seen.add(path)
            result = json.loads(path.read_text(encoding="utf-8"))
            result["_file"] = str(path)
            results.append(result)
            print(
                f"run {number}: {result['status']}, "
                f"{result['assessment']['records_mapped']} of "
                f"{result['assessment']['records']} records, "
                f"{result['rounds_run']} round(s), {time.time() - started:.0f}s",
                flush=True,
            )
        # Output files are stamped to the second.
        time.sleep(1.2)
    return results


def _agreement(values: list) -> tuple[float, Counter]:
    counts = Counter(json.dumps(v, sort_keys=True) for v in values)
    return (max(counts.values()) / len(values) if values else 0.0), counts


def summarise(results: list[dict], truth: dict[str, dict]) -> dict:
    good = [r for r in results if "assessment" in r]
    summary: dict = {
        "runs": len(results),
        "runs_with_a_result": len(good),
        "statuses": dict(Counter(r["status"] for r in good)),
        "rounds": [r["rounds_run"] for r in good],
        "lines_sent": [r["sent_to_model"]["lines"] for r in good],
        "elapsed_seconds": [r["elapsed_seconds"] for r in good],
        "records": sorted({r["assessment"]["records"] for r in good}),
        "records_mapped": [r["assessment"]["records_mapped"] for r in good],
        "inputs_fingerprints": dict(
            Counter(r["run"]["inputs_fingerprint"] for r in good)
        ),
        "outcome_fingerprints": dict(
            Counter(r["run"]["outcome_fingerprint"] for r in good)
        ),
    }
    if not good:
        return summary
    share, _ = _agreement([r["assessment"]["split_signature"] for r in good])
    summary["record_split_agreement"] = round(share, 3)
    summary["record_types"] = [
        sum(1 for t in r["extraction_spec"]["record_types"] if t["records"])
        for r in good
    ]

    elements: dict[str, dict] = {}
    names = sorted({n for r in good for n in r["assessment"]["elements"]})
    for name in names:
        entries = [r["assessment"]["elements"].get(name) for r in good]
        share, _ = _agreement([e["signature"] if e else None for e in entries])
        item = {
            "agreement": round(share, 3),
            "mapped_in_runs": sum(1 for e in entries if e),
            "records": [e["records"] if e else 0 for e in entries],
            "fields": [
                sorted({f.split(".", 1)[1] for f in e["fields"]}) if e else []
                for e in entries
            ],
        }
        if name in truth:
            item["matches_truth_in_runs"] = sum(
                1 for e in entries if e and e.get("value_counts") == truth[name]
            )
        elements[name] = item
    summary["elements"] = elements

    findings: dict[str, dict] = {}
    for finding in good[0]["assessment"]["findings"]:
        if finding["state"] in ("not_assessable_from_sample", "not_evaluated"):
            continue
        rid = finding["requirement_id"]
        per_run = []
        for r in good:
            match = next(
                (f for f in r["assessment"]["findings"] if f["requirement_id"] == rid),
                None,
            )
            per_run.append(
                (match["state"], match.get("records_with_all_elements"))
                if match
                else ("absent", None)
            )
        state_share, state_counts = _agreement([p[0] for p in per_run])
        count_share, _ = _agreement([p[1] for p in per_run])
        findings[rid] = {
            "state_agreement": round(state_share, 3),
            "count_agreement": round(count_share, 3),
            "states": {json.loads(k): v for k, v in state_counts.items()},
            "records": [p[1] for p in per_run],
        }
    summary["findings"] = findings
    summary["findings_with_one_state"] = sum(
        1 for f in findings.values() if f["state_agreement"] == 1.0
    )
    summary["findings_with_one_count"] = sum(
        1 for f in findings.values() if f["count_agreement"] == 1.0
    )
    summary["findings_assessed"] = len(findings)
    return summary


def print_summary(summary: dict) -> None:
    print()
    print(
        f"{summary['runs_with_a_result']} of {summary['runs']} runs gave a result. "
        f"Statuses: {summary['statuses']}. Rounds: {summary['rounds']}."
    )
    if not summary["runs_with_a_result"]:
        return
    print(
        f"Records {summary['records']}, mapped {summary['records_mapped']}, "
        f"record types {summary['record_types']}, same split in "
        f"{summary['record_split_agreement']:.0%} of runs."
    )
    print(
        f"Distinct outcomes: {len(summary['outcome_fingerprints'])} "
        f"across {summary['runs_with_a_result']} runs "
        f"({len(summary['inputs_fingerprints'])} distinct input fingerprint(s))."
    )
    print()
    print(f"{'element':22} {'agree':>6} {'mapped':>7}  records per run / fields")
    for name, item in summary["elements"].items():
        truth = (
            f"  truth {item['matches_truth_in_runs']}/{summary['runs_with_a_result']}"
            if "matches_truth_in_runs" in item
            else ""
        )
        fields = Counter(",".join(f) for f in item["fields"])
        print(
            f"{name:22} {item['agreement']:>6.0%} "
            f"{item['mapped_in_runs']:>3}/{summary['runs_with_a_result']:<3}  "
            f"{item['records']} {dict(fields)}{truth}"
        )
    print()
    print(
        f"Findings: {summary['findings_with_one_state']} of "
        f"{summary['findings_assessed']} had the same state in every run; "
        f"{summary['findings_with_one_count']} had the same record count."
    )
    for rid, item in summary["findings"].items():
        if item["count_agreement"] < 1.0:
            print(f"  {rid:10} states {item['states']} records {item['records']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--log", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--provider", help="provider id to pin, e.g. anthropic")
    parser.add_argument("--baseline", help="extraction spec to audit against")
    parser.add_argument("--max-rounds", type=int, dest="max_rounds")
    parser.add_argument("--truth-file", dest="truth_file")
    parser.add_argument(
        "--truth",
        action="append",
        default=[],
        metavar="ELEMENT=KEY",
        help="compare an element's value counts with this key of --truth-file",
    )
    parser.add_argument("--workspace", help="defaults to a new temporary directory")
    parser.add_argument("--out", help="write the summary JSON here")
    args = parser.parse_args()

    truth: dict[str, dict] = {}
    if args.truth:
        if not args.truth_file:
            parser.error("--truth needs --truth-file")
        document = json.loads(Path(args.truth_file).read_text(encoding="utf-8"))
        for pair in args.truth:
            element, _, key = pair.partition("=")
            if not isinstance(document.get(key), dict):
                parser.error(f"{key!r} is not an object in {args.truth_file}")
            truth[element] = document[key]

    workspace = Path(
        args.workspace or tempfile.mkdtemp(prefix="eventmill_repeatability_")
    ).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    print(f"workspace: {workspace}", flush=True)
    results = run_audits(args, workspace)
    summary = summarise(results, truth)
    summary["log"] = Path(args.log).name
    summary["profile"] = Path(args.profile).name
    summary["provider"] = args.provider or "session default"
    summary["baseline"] = Path(args.baseline).name if args.baseline else None
    summary["result_files"] = [r.get("_file") for r in results]
    print_summary(summary)
    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\nsummary written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
