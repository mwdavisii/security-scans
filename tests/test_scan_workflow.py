"""Policy tests for .github/workflows/scan.yml, the reusable workflow that app repos call."""

import re
from pathlib import Path

import pytest
import yaml

TREE = Path(__file__).resolve().parents[1]
WORKFLOW = TREE / ".github/workflows/scan.yml"
TEXT = WORKFLOW.read_text()


def code(text):
    """The text without whole-line comments, so a comment that explains a rule does not trip the rule."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
FORK_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"
ALLOWED_EXPR = [r"github\.token", r"github\.server_url", r"github\.repository", r"github\.run_id",
                r"github\.event\.pull_request\.number", r"needs\.(semgrep|trivy)\.result", r"job\.workflow_repository", r"job\.workflow_sha", r"steps\.[\w-]+\.outputs\.[\w-]+"]


def load():
    doc = yaml.safe_load(TEXT)
    doc["on"] = doc.pop(True, doc.get("on"))
    return doc


DOC = load()
JOBS = DOC["jobs"]
SCAN_JOBS = ["semgrep", "trivy"]


def steps(job):
    return JOBS[job]["steps"]


def step(job, name):
    return next(s for s in steps(job) if s.get("name", "").startswith(name))


def test_it_is_a_reusable_workflow_and_nothing_else():
    assert list(DOC["on"]) == ["workflow_call"]
    assert "pull_request_target" not in TEXT and "workflow_run" not in TEXT
    call = DOC["on"]["workflow_call"]
    assert not call, "no inputs and no secrets: a caller cannot weaken the scans"
    assert "secrets." not in code(TEXT)


def test_tuning_lives_in_this_repo_as_constants():
    assert DOC["env"]["REGISTRY_RULESETS"] == "p/default" and DOC["env"]["IGNORE_UNFIXED"] == "true"
    assert "inputs." not in code(TEXT)


def test_check_names_are_the_job_ids():
    """The caller's job is named security-scans, so the checks are 'security-scans / semgrep' and 'security-scans / trivy'."""
    assert set(JOBS) == {"semgrep", "trivy", "comment"}
    for job in JOBS.values():
        assert "name" not in job, "a job name would change the check name that Gate 1 requires"
        assert "strategy" not in job, "a matrix would change the check names"


def test_permissions_are_minimal_and_only_the_comment_job_can_write():
    assert DOC["permissions"] == {}
    for name in SCAN_JOBS:
        assert JOBS[name]["permissions"] == {"contents": "read"}, name
    assert JOBS["comment"]["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert "id-token" not in TEXT and "security-events" not in TEXT and "checks: write" not in TEXT


def test_every_job_has_a_timeout_and_a_fresh_runner():
    for job in JOBS.values():
        assert job["runs-on"] == "ubuntu-24.04" and isinstance(job["timeout-minutes"], int) and job["timeout-minutes"] <= 30


def test_actions_are_pinned_by_sha_and_images_by_digest():
    for job in JOBS.values():
        for s in job["steps"]:
            if "uses" in s:
                assert SHA_PIN.match(s["uses"]), s["uses"]
    for key in ("SEMGREP_IMAGE", "TRIVY_IMAGE"):
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@sha256:[0-9a-f]{64}", DOC["env"][key]), key
    assert "semgrep/semgrep@" in DOC["env"]["SEMGREP_IMAGE"] and "aquasec/trivy@" in DOC["env"]["TRIVY_IMAGE"]
    for match in re.finditer(r"_IMAGE:\s*(\S+)", TEXT):
        assert re.search(r"@sha256:[0-9a-f]{64}$", match.group(1))


@pytest.mark.parametrize("job", JOBS)
def test_checkouts_keep_no_credentials_and_scripts_come_from_this_workflows_own_commit(job):
    checkouts = [s for s in steps(job) if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == (2 if job in SCAN_JOBS else 1)
    for c in checkouts:
        assert c["with"]["persist-credentials"] is False
    if job in SCAN_JOBS:
        assert checkouts[0]["with"]["path"] == "src" and "repository" not in checkouts[0]["with"] and "ref" not in checkouts[0]["with"]
    scans = checkouts[-1]
    assert scans["with"]["repository"] == "${{ job.workflow_repository }}" and scans["with"]["ref"] == "${{ job.workflow_sha }}"
    assert scans["with"]["path"] == "scans" and set(scans["with"]["sparse-checkout"].split()) <= {"scripts", "rules"}


def guard_script():
    return step("semgrep", "Check where the scripts come from")["run"]


@pytest.mark.parametrize("job", JOBS)
def test_the_first_step_refuses_to_run_unless_the_scripts_come_from_another_repo_at_a_commit(job):
    """If job.workflow_repository or job.workflow_sha were ever empty, actions/checkout would fall back to the CALLING repo
    and the job would run scripts the pull request controls. Fail closed before any checkout."""
    first = steps(job)[0]
    assert first["name"] == "Check where the scripts come from" and "uses" not in first and "if" not in first
    assert first["env"] == {"WORKFLOW_REPOSITORY": "${{ job.workflow_repository }}", "WORKFLOW_SHA": "${{ job.workflow_sha }}",
                            "CALLER_REPOSITORY": "${{ github.repository }}"}
    assert first["run"] == guard_script()


@pytest.mark.parametrize("repo,sha,caller,ok", [
    ("sec/security-scans", "a" * 40, "me/app", True),
    ("Sec-Team/security.scans_x", "0123456789abcdef" * 2 + "01234567", "me/app", True),
    ("", "a" * 40, "me/app", False),
    ("sec/security-scans", "", "me/app", False),
    ("me/app", "a" * 40, "me/app", False),
    ("ME/App", "a" * 40, "me/app", False),
    ("sec/security-scans", "a" * 39, "me/app", False),
    ("sec/security-scans", "a" * 41, "me/app", False),
    ("sec/security-scans", "A" * 40, "me/app", False),
    ("sec/security-scans", "main", "me/app", False),
    ("sec", "a" * 40, "me/app", False),
    ("sec/a/b", "a" * 40, "me/app", False),
    ("sec/x; id", "a" * 40, "me/app", False),
    ("sec/x\nme/app", "a" * 40, "me/app", False),
])
def test_the_guard_script_behaviour(repo, sha, caller, ok):
    import subprocess
    out = subprocess.run(["bash", "-c", guard_script()], env={"PATH": "/usr/bin:/bin", "WORKFLOW_REPOSITORY": repo, "WORKFLOW_SHA": sha, "CALLER_REPOSITORY": caller},
                         capture_output=True, text=True)
    assert (out.returncode == 0) == ok, out.stdout + out.stderr


def test_the_guard_fails_when_a_variable_is_unset():
    import subprocess
    out = subprocess.run(["bash", "-c", guard_script()], env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    assert out.returncode != 0


def all_steps():
    for name, job in JOBS.items():
        for s in job["steps"]:
            yield name, s


def test_run_blocks_take_no_expressions_and_fail_closed():
    for job, s in all_steps():
        run = s.get("run", "")
        assert "${{" not in run, f"{job}: pass expressions through env:"
        if "\n" in run.strip():
            assert run.lstrip().startswith("set -euo pipefail"), f"{job}: {s.get('name')}"
        assert "|| true" not in run


def test_only_allowlisted_contexts_are_used():
    for expr in re.findall(r"\$\{\{\s*(.*?)\s*\}\}", TEXT):
        assert any(re.fullmatch(a, expr) for a in ALLOWED_EXPR), expr
    for bad in ("github.head_ref", "github.event.pull_request.title", "github.event.pull_request.head.ref"):
        assert not any(re.fullmatch(a, bad) for a in ALLOWED_EXPR)


def test_the_token_is_only_given_to_the_comment_jobs_posting_step_and_the_head_repo_only_to_ifs():
    for job, s in all_steps():
        posts = job == "comment" and s.get("name", "").startswith("Comment on the PR")
        assert ("GH_TOKEN" in s.get("env", {})) == posts, f"{job}: {s.get('name')}"
    assert "github.token" not in TEXT.replace("GH_TOKEN: ${{ github.token }}", "")
    for job, s in all_steps():
        for key in ("run", "env", "with"):
            assert "head.repo" not in str(s.get(key, ""))


def test_the_comment_job_skips_fork_prs_runs_after_the_scans_and_never_touches_the_app_repo():
    job = JOBS["comment"]
    assert job["needs"] == ["semgrep", "trivy"]
    assert job["if"] == f"always() && github.event_name == 'pull_request' && {FORK_GUARD}"
    checkouts = [s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1 and checkouts[0]["with"]["path"] == "scans"
    assert not any(s.get("with", {}).get("path") == "src" for s in job["steps"])
    downloads = [s for s in job["steps"] if s.get("uses", "").startswith("actions/download-artifact@")]
    assert {d["with"]["name"] for d in downloads} == {"security-scans-semgrep", "security-scans-trivy"}
    for d in downloads:
        assert d.get("continue-on-error") is True
    run = "\n".join(s.get("run", "") for s in job["steps"])
    assert "docker" not in run and "src/" not in run, "nothing from the app repo is run"
    post = step("comment", "Comment on the PR")
    assert post.get("continue-on-error") is True and post["env"]["PR"] == "${{ github.event.pull_request.number }}"
    assert "post_comment.sh" in post["run"] and "sarif_report.py" in post["run"], "the markdown is rebuilt from the SARIF by the trusted script"


def test_scan_jobs_have_no_comment_step_and_no_pull_request_write():
    for job in SCAN_JOBS:
        assert not any("post_comment" in s.get("run", "") for s in steps(job))


@pytest.mark.parametrize("job", SCAN_JOBS)
def test_report_then_upload_in_that_order_and_upload_always_runs(job):
    names = [s.get("name", s.get("uses", "")) for s in steps(job)]
    report = next(i for i, n in enumerate(names) if n.startswith("Report"))
    upload = next(i for i, n in enumerate(names) if n.startswith("actions/upload-artifact"))
    assert report < upload and steps(job)[upload]["if"] == "always()" and steps(job)[report]["if"] == "always()"
    assert steps(job)[upload]["with"]["name"] == f"security-scans-{job}"
    assert "out/image.tar" not in steps(job)[upload]["with"]["path"]


def test_semgrep_job_runs_the_script_and_fails_on_error_severity():
    run = step("semgrep", "Run Semgrep")
    assert run["run"].strip() == "bash scans/scripts/run_semgrep.sh"
    assert "env" not in run or "REGISTRY_RULESETS" not in run["env"], "the ruleset comes from the workflow's own constant"
    report = step("semgrep", "Report")["run"]
    assert "--tool semgrep" in report and "--fail-on error" in report and "--annotate" in report
    assert "$GITHUB_STEP_SUMMARY" in report and "out/semgrep.sarif" in report and "--root src" in report


def test_trivy_job_scans_the_repo_builds_without_pushing_then_scans_the_image():
    names = [s.get("name", "") for s in steps("trivy")]
    order = [next(i for i, n in enumerate(names) if n.startswith(p)) for p in ("Trivy: repository", "Build the image", "Trivy: image", "Report")]
    assert order == sorted(order)
    build = step("trivy", "Build the image")
    assert build["id"] == "build" and build["run"].strip() == "bash scans/scripts/build_image.sh"
    assert step("trivy", "Trivy: image")["if"] == "steps.build.outputs.built == 'true'"
    report = step("trivy", "Report")["run"]
    assert "--tool trivy" in report and "--fail-on error" in report and "out/trivy-fs.sarif" in report and "out/trivy-image.sarif" in report


def test_no_job_registry_login_push_or_docker_socket():
    scripts = "".join(code(p.read_text()) for p in (TREE / "scripts").iterdir() if p.suffix in (".sh", ".py"))
    for forbidden in ("docker login", "docker push", "docker.sock", "--privileged", "--push", "--secret", "--ssh", "docker/login-action"):
        assert forbidden not in code(TEXT) + scripts, forbidden


def test_scripts_the_workflow_calls_exist_and_are_executable_by_bash():
    for name in re.findall(r"scans/scripts/([\w.]+)", TEXT):
        assert (TREE / "scripts" / name).is_file(), name


def test_the_comment_job_passes_each_scan_jobs_result_to_the_reporter():
    env = step("comment", "Comment on the PR")["env"]
    assert env["SEMGREP_RESULT"] == "${{ needs.semgrep.result }}" and env["TRIVY_RESULT"] == "${{ needs.trivy.result }}"
    assert "--job-result" in step("comment", "Comment on the PR")["run"]


GH_STUB = """#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
if "--paginate" in a:
    print("[]")
else:
    body = next(x for x in a if x.startswith("body=@"))[6:]
    open(os.environ["OUT_DIR"] + "/" + os.path.basename(body), "w").write(open(body).read())
"""


@pytest.mark.parametrize("sarif", ["missing", "clean", "findings"])
@pytest.mark.parametrize("res", ["success", "failure", "cancelled", "skipped"])
def test_the_comment_never_says_passed_unless_the_job_succeeded_and_the_sarif_is_clean(tmp_path, res, sarif):
    import json
    import os
    import subprocess
    work = tmp_path / "work"
    (work / "semgrep").mkdir(parents=True)
    (work / "trivy").mkdir()
    (work / "scans").symlink_to(TREE)
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": (
        [{"ruleId": "r", "level": "error", "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}]
        if sarif == "findings" else [])}]}
    if sarif != "missing":
        (work / "semgrep/semgrep.sarif").write_text(json.dumps(doc))
        (work / "trivy/trivy-fs.sarif").write_text(json.dumps(doc))
    bin_dir, out_dir = tmp_path / "bin", tmp_path / "out"
    bin_dir.mkdir()
    out_dir.mkdir()
    (bin_dir / "gh").write_text(GH_STUB)
    (bin_dir / "gh").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "OUT_DIR": str(out_dir), "GH_TOKEN": "t", "PR": "3", "GITHUB_REPOSITORY": "me/app",
           "RUN_URL": "https://github.com/me/app/actions/runs/1", "SEMGREP_RESULT": res, "TRIVY_RESULT": res}
    run = step("comment", "Comment on the PR")["run"]
    done = subprocess.run(["bash", "-c", run], cwd=work, env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    for tool in ("semgrep", "trivy"):
        text = (out_dir / f"{tool}.md").read_text()
        should_pass = res == "success" and sarif == "clean"
        assert (": passed" in text) == should_pass, (tool, text)
        assert (": FAILED" in text) == (not should_pass)
        if sarif == "missing" or (res != "success" and sarif == "clean"):
            assert "the scan didn't finish; see the check log" in text
