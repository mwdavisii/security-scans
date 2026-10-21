"""Run the vendored rules and scripts/run_semgrep.sh against the real, digest-pinned Semgrep image (no network needed)."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TREE = Path(__file__).resolve().parents[1]
IMAGE = re.search(r"SEMGREP_IMAGE: (\S+)", (TREE / ".github/workflows/scan.yml").read_text()).group(1)
SCRIPTS = TREE / "scripts"
pytestmark = [pytest.mark.docker, pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")]


def docker(*args):
    return subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp", "--read-only",
                           "--tmpfs", "/tmp", *args], capture_output=True, text=True)


def test_every_vendored_rule_matches_its_annotated_examples():
    out = docker("-v", f"{TREE / 'rules'}:/security-scans:ro", "-w", "/security-scans", IMAGE, "semgrep", "--test", "--metrics", "off",
                 "--disable-version-check", "--config", "/security-scans", "/security-scans")
    assert out.returncode == 0 and "All tests passed" in out.stdout + out.stderr, out.stdout + out.stderr


def scan(tmp_path, files):
    src = tmp_path / "src"
    for rel, text in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    env = {**os.environ, "SEMGREP_IMAGE": IMAGE, "REGISTRY_RULESETS": ""}
    out = subprocess.run(["bash", str(SCRIPTS / "run_semgrep.sh")], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    report = subprocess.run([sys.executable, str(SCRIPTS / "sarif_report.py"), "--tool", "semgrep", "--fail-on", "error", "--annotate", "--root", str(src),
                             str(tmp_path / "out/semgrep.sarif")], capture_output=True, text=True)
    return report


VULN = "import subprocess\n\n\ndef ping(host):\n    return subprocess.run('ping ' + host, shell=True)\n"


def test_a_clean_tree_passes(tmp_path):
    assert scan(tmp_path, {"app.py": "def ok():\n    return 1\n"}).returncode == 0


def test_an_injectable_route_fails_with_an_annotation_on_the_line(tmp_path):
    report = scan(tmp_path, {"app.py": VULN})
    assert report.returncode == 1 and "::error file=app.py,line=5" in report.stdout and "subprocess-shell-true" in report.stdout


@pytest.mark.parametrize("hide", [
    {".semgrepignore": "app.py\n"},
    {".gitignore": "app.py\n"},
    {"app.py": VULN.replace("shell=True)", "shell=True)  # nosemgrep")},
    {"app.py": VULN.replace("shell=True)", "shell=True)  # nosem")},
], ids=["semgrepignore", "gitignore", "nosemgrep-comment", "nosem-comment"])
def test_the_repository_cannot_hide_a_finding(tmp_path, hide):
    assert scan(tmp_path, {"app.py": VULN, **hide}).returncode == 1


def test_files_under_tests_are_scanned_too(tmp_path):
    assert scan(tmp_path, {"tests/test_x.py": VULN}).returncode == 1
