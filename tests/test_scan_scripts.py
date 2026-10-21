"""The shell scripts the workflow runs, exercised with a stub `docker` and `gh` on PATH that record every call."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SEMGREP = "example/semgrep@sha256:" + "a" * 64
TRIVY = "example/trivy@sha256:" + "b" * 64

DOCKER_STUB = f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if os.environ.get("STUB_FAIL") and os.environ["STUB_FAIL"] in args:
    sys.exit(3)
for i, a in enumerate(args):
    if i and args[i - 1] == "-v" and a.endswith(":/src:ro") and os.environ.get("STUB_TREE"):
        root = a.split(":")[0]
        listing = sorted(os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) for f in fs)
        open(os.environ["STUB_TREE"], "w").write(json.dumps({{"files": listing, "ignore": open(os.path.join(root, ".semgrepignore")).read() if os.path.exists(os.path.join(root, ".semgrepignore")) else None}}))
mounts = [a.split(":")[0] for i, a in enumerate(args) if i and args[i - 1] == "-v" and a.endswith(":/out")]
for flag, name in (("--output", None),):
    if flag in args and mounts and args[args.index(flag) + 1].startswith("/out/"):
        open(os.path.join(mounts[0], args[args.index(flag) + 1][5:]), "w").write('{{"version": "2.1.0", "runs": []}}')
if args[:1] == ["save"]:
    open(args[args.index("--output") + 1], "w").write("tar")
"""

GH_STUB = f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[:1] == ["api"] and "--paginate" in args:
    sys.stdout.write(os.environ.get("STUB_COMMENTS", "[]"))
"""


@pytest.fixture
def env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in (("docker", DOCKER_STUB), ("gh", GH_STUB)):
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)
    (tmp_path / "src").mkdir()
    (tmp_path / "scans/security-scans").mkdir(parents=True)
    log = tmp_path / "calls.log"
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "STUB_LOG": str(log), "GITHUB_OUTPUT": str(tmp_path / "gh_output")}


def run(env, tmp_path, script, *args, **extra):
    return subprocess.run(["bash", str(SCRIPTS / script), *args], cwd=tmp_path, env={**env, **extra}, capture_output=True, text=True)


def calls(env):
    path = Path(env["STUB_LOG"])
    return [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []


# ---- run_semgrep.sh ----

def test_semgrep_runs_pinned_image_read_only_with_the_vendored_rules_and_no_telemetry(env, tmp_path):
    out = run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=SEMGREP, REGISTRY_RULESETS="p/default")
    assert out.returncode == 0, out.stderr
    [call] = calls(env)
    assert call[0] == "run" and SEMGREP in call
    assert "--read-only" in call and "--cap-drop" in call and "no-new-privileges" in call
    joined = " ".join(call)
    assert ":/src:ro" in joined and ":/security-scans:ro" in joined
    assert "--config /security-scans" in joined and "--config p/default" in joined
    assert "--metrics off" in joined and "--disable-version-check" in joined and "--sarif" in joined
    assert "--network" not in call, "registry rules need the network, so the default network is used"
    assert (tmp_path / "out/semgrep.sarif").is_file()


def test_semgrep_scans_a_copy_without_files_that_let_the_repository_hide_findings(env, tmp_path):
    src = tmp_path / "src"
    for rel, text in {".git/config": "x", ".gitignore": "hidden/\n", ".semgrepignore": "everything\n", "sub/.gitignore": "*\n",
                      "sub/.semgrepignore": "*\n", "hidden/h.py": "x", "tests/t.py": "x", "app.py": "x"}.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    out = run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=SEMGREP, REGISTRY_RULESETS="", STUB_TREE=str(tmp_path / "tree.json"))
    assert out.returncode == 0, out.stderr
    tree = json.loads((tmp_path / "tree.json").read_text())
    assert tree["files"] == [".semgrepignore", "app.py", "hidden/h.py", "tests/t.py"]
    assert tree["ignore"] == (SCRIPTS.parent / "rules/semgrepignore").read_text() and "everything" not in tree["ignore"]
    assert (src / ".gitignore").read_text() == "hidden/\n", "the source tree itself is not modified"
    call = calls(env)[0]
    for flag in ("--disable-nosem",):
        assert flag in call
    assert call[call.index("--max-target-bytes") + 1] == "0", "a padded file must not be skipped"


def test_semgrep_with_no_registry_rulesets_runs_without_a_network(env, tmp_path):
    assert run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=SEMGREP, REGISTRY_RULESETS="").returncode == 0
    [call] = calls(env)
    assert call[call.index("--network") + 1] == "none"
    assert "--config" in call and " ".join(call).count("--config") == 1


@pytest.mark.parametrize("image", ["", "example/semgrep:latest", "example/semgrep@sha256:abc", "ghcr.io/x@sha256:" + "G" * 64])
def test_semgrep_refuses_an_unpinned_image(env, tmp_path, image):
    out = run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=image, REGISTRY_RULESETS="")
    assert out.returncode != 0 and calls(env) == []


@pytest.mark.parametrize("rulesets", ["p/default; rm -rf /", "$(id)", "p/default --config /etc", "-x", "a b\nc"])
def test_semgrep_refuses_odd_ruleset_names(env, tmp_path, rulesets):
    out = run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=SEMGREP, REGISTRY_RULESETS=rulesets)
    assert out.returncode != 0 and calls(env) == []


def test_semgrep_failure_fails_the_script(env, tmp_path):
    out = run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=SEMGREP, REGISTRY_RULESETS="", STUB_FAIL="semgrep")
    assert out.returncode != 0


def test_tool_output_is_fenced_with_stop_commands(env, tmp_path):
    out = run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=SEMGREP, REGISTRY_RULESETS="")
    lines = out.stdout.splitlines()
    start = [l for l in lines if l.startswith("::stop-commands::")]
    assert len(start) == 1
    token = start[0].split("::")[-1]
    assert len(token) >= 32 and f"::{token}::" in lines
    assert lines.index(start[0]) < lines.index(f"::{token}::")


def test_the_stop_commands_token_differs_between_runs(env, tmp_path):
    tokens = {run(env, tmp_path, "run_semgrep.sh", SEMGREP_IMAGE=SEMGREP, REGISTRY_RULESETS="").stdout.split("::stop-commands::")[1].split()[0] for _ in range(3)}
    assert len(tokens) == 3


# ---- run_trivy.sh ----

def test_trivy_fs_scans_all_three_scanners_for_high_and_critical(env, tmp_path):
    out = run(env, tmp_path, "run_trivy.sh", "fs", TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED="false")
    assert out.returncode == 0, out.stderr
    [call] = calls(env)
    joined = " ".join(call)
    assert TRIVY in call and "--read-only" in call and "--cap-drop" in call
    assert "fs" in call and "--scanners vuln,misconfig,secret" in joined and "--severity HIGH,CRITICAL" in joined and "--format sarif" in joined
    assert ":/src:ro" in joined and "--ignore-unfixed" not in call
    assert "--exit-code" not in call, "the report script decides pass or fail from the SARIF"
    assert (tmp_path / "out/trivy-fs.sarif").is_file()


def test_trivy_ignore_unfixed_is_configurable(env, tmp_path):
    run(env, tmp_path, "run_trivy.sh", "fs", TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED="true")
    assert "--ignore-unfixed" in calls(env)[0]


@pytest.mark.parametrize("value", ["yes", "1", "TRUE", "true; x"])
def test_trivy_ignore_unfixed_accepts_only_true_or_false(env, tmp_path, value):
    out = run(env, tmp_path, "run_trivy.sh", "fs", TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED=value)
    assert out.returncode != 0 and calls(env) == []


def test_trivy_image_scans_the_saved_tar_not_the_docker_socket(env, tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out/image.tar").write_text("tar")
    out = run(env, tmp_path, "run_trivy.sh", "image", TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED="false")
    assert out.returncode == 0, out.stderr
    [call] = calls(env)
    joined = " ".join(call)
    assert "image" in call and "--input /out/image.tar" in joined and "--scanners vuln,secret" in joined
    assert "docker.sock" not in joined
    assert (tmp_path / "out/trivy-image.sarif").is_file()


def test_trivy_image_without_a_tar_fails(env, tmp_path):
    assert run(env, tmp_path, "run_trivy.sh", "image", TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED="false").returncode != 0


def test_trivy_offline_mode_uses_the_cached_database_without_a_network(env, tmp_path):
    run(env, tmp_path, "run_trivy.sh", "fs", TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED="false", SCANS_TRIVY_OFFLINE="true")
    call = calls(env)[0]
    assert call[call.index("--network") + 1] == "none" and "--skip-db-update" in call


def test_trivy_does_not_read_ignore_files_from_the_scanned_tree(env, tmp_path):
    run(env, tmp_path, "run_trivy.sh", "fs", TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED="false")
    call = calls(env)[0]
    assert "-w" not in call and "--workdir" not in call, "the container's working directory must not be the scanned tree"
    assert not any(a.endswith(":/") or a.endswith(":/work") for a in call)


@pytest.mark.parametrize("args", [[], ["other"], ["fs", "extra"]])
def test_trivy_takes_exactly_fs_or_image(env, tmp_path, args):
    assert run(env, tmp_path, "run_trivy.sh", *args, TRIVY_IMAGE=TRIVY, IGNORE_UNFIXED="false").returncode != 0 and calls(env) == []


def test_trivy_refuses_an_unpinned_image(env, tmp_path):
    assert run(env, tmp_path, "run_trivy.sh", "fs", TRIVY_IMAGE="aquasec/trivy:latest", IGNORE_UNFIXED="false").returncode != 0 and calls(env) == []


# ---- build_image.sh ----

def test_build_builds_the_root_dockerfile_saves_a_tar_and_removes_the_image(env, tmp_path):
    (tmp_path / "src/Dockerfile").write_text("FROM scratch\n")
    out = run(env, tmp_path, "build_image.sh")
    assert out.returncode == 0, out.stderr
    got = calls(env)
    build, save, rmi = got[0], got[1], got[-1]
    assert build[0] == "build" and build[build.index("--file") + 1] == "src/Dockerfile" and build[-1] == "src"
    assert "--push" not in build and "--output" not in build and "--secret" not in build and "--ssh" not in build
    assert "--network" not in build, "RUN steps need the package indexes"
    assert save[0] == "save" and (tmp_path / "out/image.tar").is_file()
    assert rmi[:2] == ["image", "rm"] or rmi[0] == "rmi"
    assert "built=true" in Path(env["GITHUB_OUTPUT"]).read_text()


def test_build_with_a_custom_network_for_local_runs(env, tmp_path):
    (tmp_path / "src/Dockerfile").write_text("FROM scratch\n")
    run(env, tmp_path, "build_image.sh", SCANS_BUILD_NETWORK="host")
    build = calls(env)[0]
    assert build[build.index("--network") + 1] == "host"


def test_build_without_a_dockerfile_is_a_noted_skip(env, tmp_path):
    out = run(env, tmp_path, "build_image.sh")
    assert out.returncode == 0 and calls(env) == [] and "built=false" in Path(env["GITHUB_OUTPUT"]).read_text()
    assert "::notice" in out.stdout


def test_build_refuses_a_symlinked_dockerfile(env, tmp_path):
    (tmp_path / "elsewhere").write_text("FROM scratch\n")
    (tmp_path / "src/Dockerfile").symlink_to(tmp_path / "elsewhere")
    assert run(env, tmp_path, "build_image.sh").returncode != 0 and calls(env) == []


def test_a_failed_build_fails_and_still_removes_nothing_it_did_not_make(env, tmp_path):
    (tmp_path / "src/Dockerfile").write_text("FROM scratch\n")
    out = run(env, tmp_path, "build_image.sh", STUB_FAIL="build")
    assert out.returncode != 0 and not (tmp_path / "out/image.tar").exists()


# ---- post_comment.sh ----

BASE = {"GH_TOKEN": "t", "GITHUB_REPOSITORY": "me/app", "PR": "7"}


def comment(env, tmp_path, tool="semgrep", comments="[]", **extra):
    body = tmp_path / "body.md"
    body.write_text(f"<!-- security-scans:{tool} -->\nhello\n")
    return run(env, tmp_path, "post_comment.sh", tool, str(body), **BASE, STUB_COMMENTS=comments, **extra)


def test_first_run_creates_one_comment(env, tmp_path):
    out = comment(env, tmp_path)
    assert out.returncode == 0, out.stderr
    posts = [c for c in calls(env) if "POST" in c]
    assert len(posts) == 1 and posts[0][1].endswith("repos/me/app/issues/7/comments") or "repos/me/app/issues/7/comments" in posts[0]


def test_later_runs_update_the_bots_own_comment_for_that_tool_only(env, tmp_path):
    existing = json.dumps([
        {"id": 1, "user": {"login": "github-actions[bot]"}, "body": "<!-- security-scans:trivy -->\nold"},
        {"id": 2, "user": {"login": "github-actions[bot]"}, "body": "<!-- security-scans:semgrep -->\nold"},
        {"id": 3, "user": {"login": "someone"}, "body": "<!-- security-scans:semgrep -->\nforged"},
        {"id": 4, "user": {"login": "github-actions[bot]"}, "body": "golden-road drift summary"},
    ])
    out = comment(env, tmp_path, comments=existing)
    assert out.returncode == 0, out.stderr
    patches = [c for c in calls(env) if "PATCH" in c]
    assert len(patches) == 1 and "repos/me/app/issues/comments/2" in patches[0]
    assert not [c for c in calls(env) if "POST" in c]


def test_a_comment_by_another_user_with_the_marker_is_never_edited(env, tmp_path):
    existing = json.dumps([{"id": 9, "user": {"login": "attacker"}, "body": "<!-- security-scans:semgrep -->\nx"}])
    comment(env, tmp_path, comments=existing)
    assert not [c for c in calls(env) if "PATCH" in c] and [c for c in calls(env) if "POST" in c]


@pytest.mark.parametrize("override", [{"PR": "7; x"}, {"PR": ""}, {"GITHUB_REPOSITORY": "no-slash"}, {"GITHUB_REPOSITORY": "a/b/c"}])
def test_comment_refuses_odd_environment(env, tmp_path, override):
    body = tmp_path / "body.md"
    body.write_text("x")
    out = run(env, tmp_path, "post_comment.sh", "semgrep", str(body), **{**BASE, **override})
    assert out.returncode != 0 and calls(env) == []


@pytest.mark.parametrize("tool", ["Sem Grep", "a;b", "", "-x", "../x"])
def test_comment_refuses_odd_tool_names(env, tmp_path, tool):
    body = tmp_path / "body.md"
    body.write_text("x")
    assert run(env, tmp_path, "post_comment.sh", tool, str(body), **BASE).returncode != 0 and calls(env) == []


def test_comment_body_must_start_with_the_tools_marker(env, tmp_path):
    body = tmp_path / "body.md"
    body.write_text("no marker here\n")
    assert run(env, tmp_path, "post_comment.sh", "semgrep", str(body), **BASE).returncode != 0 and calls(env) == []


def test_scripts_fail_closed_and_never_swallow_errors():
    for path in SCRIPTS.glob("*.sh"):
        if path.name == "lib.sh":
            continue  # sourced by scripts that set the options
        text = path.read_text()
        assert "set -euo pipefail" in text, path.name
        for line in text.splitlines():
            assert "|| true" not in line or line.lstrip().startswith("trap "), f"{path.name}: {line}"
        assert "eval " not in text, path.name
