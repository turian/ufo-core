import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[3]
CI = ROOT / ".github" / "workflows" / "ci.yaml"
NON_PR_FORCES_TRUE = "github.event_name != 'pull_request' ||"
CROSS_CUTTING = ("testsupport/**", ".github/**", "*")
UNFILTERED_ROOTS = frozenset({"assets", "servers"})
GATED_JOBS = {"wheel": "wheel", "client": "client"}
UNGATED_JOBS = ("checks", "sandbox-client", "test-shard", "integration")


def _jobs() -> dict[str, dict]:
    loaded = yaml.load(CI.read_text(), Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    jobs = loaded["jobs"]
    assert isinstance(jobs, dict)
    return jobs


def _filters() -> dict[str, list[str]]:
    steps = _jobs()["triage"]["steps"]
    filter_steps = [s for s in steps if s.get("id") == "filter"]
    assert len(filter_steps) == 1
    loaded = yaml.load(filter_steps[0]["with"]["filters"], Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    return loaded


def _check_triage_runs_on_pull_requests_only_and_forces_every_lane_on_push() -> None:
    triage = _jobs()["triage"]
    for expression in triage["outputs"].values():
        assert NON_PR_FORCES_TRUE in expression
    (filter_step,) = [s for s in triage["steps"] if s.get("id") == "filter"]
    assert filter_step["if"] == "github.event_name == 'pull_request'"


def _check_cross_cutting_inputs_light_every_lane() -> None:
    for name, patterns in _filters().items():
        for pattern in CROSS_CUTTING:
            assert pattern in patterns, f"{name} misses {pattern}"


def _check_every_tracked_top_level_path_is_classified() -> None:
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    roots = {path.split("/", 1)[0] for path in tracked if "/" in path}
    claimed = {
        pattern.split("/", 1)[0]
        for patterns in _filters().values()
        for pattern in patterns
        if not pattern.startswith("!") and "/" in pattern
    }
    unclassified = roots - claimed - UNFILTERED_ROOTS
    assert not unclassified, f"classify {sorted(unclassified)} in the triage filters"


def _check_every_lane_decision_is_consumed_and_every_consumer_names_a_lane() -> None:
    jobs = _jobs()
    declared = set(jobs["triage"]["outputs"])
    consumed = {
        match
        for job in jobs.values()
        for match in re.findall(r"needs\.triage\.outputs\.(\w+)", str(job))
    }
    assert consumed == declared
    for job_id, lane in GATED_JOBS.items():
        job = jobs[job_id]
        assert "triage" in job["needs"], job_id
        assert job["if"] == f"needs.triage.outputs.{lane} == 'true'", job_id
    for job_id in UNGATED_JOBS:
        job = jobs[job_id]
        assert "if" not in job, job_id
        assert "triage" not in job.get("needs", ""), job_id


def _check_required_contexts_come_from_an_unfiltered_pull_request_trigger() -> None:
    loaded = yaml.load(CI.read_text(), Loader=yaml.BaseLoader)
    assert loaded["on"]["pull_request"] == ""
    jobs = _jobs()
    for context in ("test", "checks"):
        assert "name" not in jobs[context], context


def _check_gate_rejects_current_head_cancellation_and_asserts_every_need() -> None:
    gate = _jobs()["test"]
    assert gate["if"] == "always()"
    assert gate["permissions"] == {"contents": "read", "pull-requests": "read"}
    cancelled, *assertions = gate["steps"]
    assert cancelled["if"] == "${{ contains(needs.*.result, 'cancelled') }}"
    assert cancelled["env"]["RUN_SHA"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    assert 'gh api "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER" --jq .head.sha' in cancelled["run"]
    assert 'gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/$GITHUB_REF_NAME"' in cancelled["run"]
    assert 'test "$CURRENT_SHA" != "$RUN_SHA"' in cancelled["run"]
    assert all(step["if"] == "${{ !contains(needs.*.result, 'cancelled') }}" for step in assertions)
    script = "\n".join(step["run"] for step in assertions)
    assert gate["needs"] == ["triage", "test-shard", "integration", "wheel", "client"]
    for need in gate["needs"]:
        lane = GATED_JOBS.get(need)
        expected = (
            "success"
            if lane is None
            else f"\"${{{{ needs.triage.outputs.{lane} == 'true' && 'success' || 'skipped' }}}}\""
        )
        assert f'test "${{{{ needs.{need}.result }}}}" = {expected}' in script, need


def _check_paths_filter_action_is_pinned_to_a_commit() -> None:
    (filter_step,) = [s for s in _jobs()["triage"]["steps"] if s.get("id") == "filter"]
    assert re.fullmatch(
        r"dorny/paths-filter@[0-9a-f]{40}",
        filter_step["uses"],
    )


def _check_test_shards_run_the_one_client_ci_built() -> None:
    jobs = _jobs()
    producer = jobs["sandbox-client"]
    uploaded = [
        step for step in producer["steps"] if step.get("uses") == "actions/upload-artifact@v4"
    ]
    assert any(step.get("run") == "cargo build --release --locked" for step in producer["steps"])
    assert len(uploaded) == 1
    assert uploaded[0]["with"] == {
        "name": "sandbox-client",
        "path": "client/target/release/ufo",
        "if-no-files-found": "error",
        "retention-days": "1",
    }
    shard = jobs["test-shard"]
    assert shard["needs"] == "sandbox-client"
    downloaded = [
        step for step in shard["steps"] if step.get("uses") == "actions/download-artifact@v4"
    ]
    assert downloaded == [
        {
            "uses": "actions/download-artifact@v4",
            "with": {"name": "sandbox-client", "path": "client/target/release"},
        }
    ]
    assert any(
        step.get("run")
        == (
            "chmod +x client/target/release/ufo\n"
            'echo "$GITHUB_WORKSPACE/client/target/release" >> "$GITHUB_PATH"\n'
        )
        for step in shard["steps"]
    )


def _check_python_suite_runs_in_ten_shards() -> None:
    shards = _jobs()["test-shard"]["strategy"]["matrix"]["shard"]
    assert shards == [f"{index}/10" for index in range(1, 11)]


def _check_test_shards_do_not_build_the_workflow_linter() -> None:
    steps = _jobs()["test-shard"]["steps"]
    assert any(
        step.get("run") == "uv sync --extra matrix-e2ee --no-install-package actionlint-py"
        for step in steps
    )
    assert any(
        step.get("run") == 'UV_NO_SYNC=1 make test SHARD="${{ matrix.shard }}"' for step in steps
    )


def _check_integration_shards_start_with_the_run() -> None:
    jobs = _jobs()
    assert jobs["integration"] == {"uses": "./.github/workflows/integration.yaml"}


def test_ci_triage_contract() -> None:
    checks = tuple(value for name, value in globals().items() if name.startswith("_check_"))
    assert len(checks) == 11
    for check in checks:
        check()
