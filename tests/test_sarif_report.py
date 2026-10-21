"""Tests for scripts/sarif_report.py: SARIF in, workflow-command annotations, markdown, and an exit code out."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import sarif_report as sr  # noqa: E402


def result(rule="r1", level="error", text="msg", uri="app.py", line=3, end=None, **extra):
    out = {"ruleId": rule, "level": level, "message": {"text": text},
           "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line, "endLine": end or line}}}]}
    out.update(extra)
    return out


def sarif(results, rules=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": rules or []}}, "results": results}]}


def write(tmp_path, doc, name="in.sarif"):
    path = tmp_path / name
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc)
    return path


def run(tmp_path, doc, *args):
    path = write(tmp_path, doc)
    return subprocess.run([sys.executable, str(SCRIPTS / "sarif_report.py"), "--tool", "semgrep", *args, str(path)], capture_output=True, text=True)


# ---- escaping ----

def test_escape_data_neutralizes_newlines_and_percent():
    assert sr.escape_data("a%b\r\nc") == "a%25b%0D%0Ac"


def test_escape_property_also_escapes_colon_and_comma():
    assert sr.escape_property("a:b,c%\n") == "a%3Ab%2Cc%25%0A"


def test_an_attacker_message_cannot_start_a_second_command():
    ann = sr.annotations([sr.Finding("error", "r", "x\n::error::forged\n::stop-commands::tok", "app.py", 1, 1)], root=None)
    assert len(ann) == 1 and "\n" not in ann[0] and "\r" not in ann[0]
    assert ann[0].startswith("::error ") and ann[0].count("::error") == 1


def test_control_characters_are_removed():
    assert "\x1b" not in sr.clean("a\x1b[31mred\x00b")


# ---- parsing ----

def test_level_comes_from_result_then_rule_default_then_warning():
    rules = [{"id": "a", "defaultConfiguration": {"level": "error"}}, {"id": "b"}]
    doc = sarif([result("a", level=None), result("b", level=None), result("c", level="note")], rules)
    for item in doc["runs"][0]["results"]:
        if item["level"] is None:
            del item["level"]
    got = {f.rule_id: f.level for f in sr.findings(doc)}
    assert got == {"a": "error", "b": "warning", "c": "note"}


def test_rule_default_level_is_found_by_rule_index():
    rules = [{"id": "other"}, {"id": "a", "defaultConfiguration": {"level": "error"}}]
    item = result("a")
    del item["level"]
    item["ruleIndex"] = 1
    assert sr.findings(sarif([item], rules))[0].level == "error"


def test_results_marked_suppressed_are_still_findings():
    """The scan runs with inline suppression comments disabled and Semgrep then reports the line with an inSource
    suppression marker: a comment in the repository under test must not be able to hide a finding."""
    doc = sarif([result("a", suppressions=[{"kind": "inSource"}]), result("b")])
    assert [f.rule_id for f in sr.findings(doc)] == ["a", "b"]


def test_identical_findings_are_listed_once():
    assert len(sr.findings(sarif([result("a"), result("a"), result("a", line=4)]))) == 2


def test_multi_line_messages_are_joined_and_capped():
    f = sr.findings(sarif([result("a", text="Package: x\nInstalled: 1\n" + "y" * 1000)]))[0]
    assert "\n" not in f.message and len(f.message) <= sr.MAX_MESSAGE


def test_secret_findings_never_carry_the_tool_message_or_snippet():
    rules = [{"id": "aws-key", "shortDescription": {"text": "AWS Access Key ID"}, "properties": {"tags": ["secret", "CRITICAL"]}}]
    item = result("aws-key", text="Artifact: f\nMatch: key=AKIAABCDEFGHIJKLMNOP")
    item["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "key=AKIAABCDEFGHIJKLMNOP"}
    f = sr.findings(sarif([item], rules))[0]
    assert f.message == "AWS Access Key ID"
    md = sr.markdown("trivy", [f], "error", None)
    assert "AKIA" not in md and "AKIA" not in "".join(sr.annotations([f], root=None))


@pytest.mark.parametrize("bad", ["", "not json", "[]", "{}", '{"runs": 5}', '{"runs": [5]}', '{"runs": [{"results": 5}]}', '{"runs": [{"results": [5]}]}',
                                 '{"runs": [{"results": [{"ruleId": "a", "level": "loud", "message": {"text": "m"}}]}]}'])
def test_unusable_sarif_is_an_error_not_a_pass(tmp_path, bad):
    out = run(tmp_path, bad, "--fail-on", "error")
    assert out.returncode == 2, out.stdout


def test_a_missing_file_is_an_error(tmp_path):
    out = subprocess.run([sys.executable, str(SCRIPTS / "sarif_report.py"), "--tool", "semgrep", str(tmp_path / "nope.sarif")], capture_output=True, text=True)
    assert out.returncode == 2


def test_empty_results_pass(tmp_path):
    out = run(tmp_path, sarif([]), "--fail-on", "error", "--annotate")
    assert out.returncode == 0 and out.stdout.strip() == ""


# ---- annotations ----

def test_annotation_shape_and_levels():
    found = [sr.Finding("error", "r.e", "bad", "app.py", 3, 5), sr.Finding("warning", "r.w", "meh", "b.py", 1, 1), sr.Finding("note", "r.n", "fyi", "c.py", 2, 2)]
    lines = sr.annotations(found, root=None)
    assert lines[0] == "::error file=app.py,line=3,endLine=5,title=r.e::bad"
    assert lines[1].startswith("::warning file=b.py,line=1,endLine=1,title=r.w::")
    assert lines[2].startswith("::notice file=c.py,line=2,endLine=2,title=r.n::")


def test_annotation_count_is_capped_per_level_with_one_truncation_notice():
    found = [sr.Finding("error", f"r{i}", "m", "app.py", i + 1, i + 1) for i in range(25)]
    lines = sr.annotations(found, root=None)
    assert sum(l.startswith("::error ") for l in lines) == 10
    notices = [l for l in lines if l.startswith("::notice")]
    assert len(notices) == 1 and "15 more" in notices[0]
    assert len(lines) <= 30


def test_notice_findings_leave_room_for_the_truncation_notice():
    found = [sr.Finding("note", f"r{i}", "m", "app.py", i + 1, i + 1) for i in range(30)]
    lines = sr.annotations(found, root=None)
    assert sum(l.startswith("::notice") for l in lines) <= 10


def test_errors_are_annotated_before_warnings():
    found = [sr.Finding("warning", f"w{i}", "m", "a.py", 1, 1) for i in range(30)] + [sr.Finding("error", "e", "m", "z.py", 1, 1)]
    lines = sr.annotations(sr.sort_findings(found), root=None)
    assert lines[0].startswith("::error ")


def test_file_is_dropped_when_not_in_the_scanned_tree(tmp_path):
    (tmp_path / "app.py").write_text("x\n")
    for uri in ("../etc/passwd", "/etc/passwd", "file:///etc/passwd", "nope.py", "img:tag (debian 12)", ""):
        line = sr.annotations([sr.Finding("error", "r", "m", uri, 1, 1)], root=tmp_path)[0]
        assert "file=" not in line, uri
    assert "file=app.py" in sr.annotations([sr.Finding("error", "r", "m", "app.py", 1, 1)], root=tmp_path)[0]


def test_symlinks_out_of_the_tree_are_not_annotated(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link.py").symlink_to(outside)
    assert "file=" not in sr.annotations([sr.Finding("error", "r", "m", "link.py", 1, 1)], root=root)[0]


def test_location_is_kept_in_the_message_when_the_file_is_dropped(tmp_path):
    line = sr.annotations([sr.Finding("error", "r", "bad", "img:tag (debian 12)", 1, 1)], root=tmp_path)[0]
    assert "img:tag (debian 12)" in line.replace("%3A", ":").replace("%2C", ",")


# ---- fail-on threshold ----

@pytest.mark.parametrize("level,fail_on,code", [("error", "error", 1), ("warning", "error", 0), ("note", "error", 0), ("warning", "warning", 1),
                                                ("note", "warning", 0), ("note", "note", 1), ("error", "none", 0)])
def test_exit_code_follows_the_threshold(tmp_path, level, fail_on, code):
    assert run(tmp_path, sarif([result(level=level)]), "--fail-on", fail_on).returncode == code


def test_findings_beyond_the_annotation_cap_still_fail(tmp_path):
    out = run(tmp_path, sarif([result(f"r{i}", line=i + 1) for i in range(40)]), "--fail-on", "error", "--annotate")
    assert out.returncode == 1 and out.stdout.count("::error ") == 10


def test_default_threshold_is_error(tmp_path):
    assert run(tmp_path, sarif([result(level="error")])).returncode == 1
    assert run(tmp_path, sarif([result(level="warning")])).returncode == 0


# ---- markdown ----

def test_markdown_has_the_marker_verdict_and_counts():
    md = sr.markdown("semgrep", [sr.Finding("error", "r.e", "bad", "app.py", 3, 3), sr.Finding("warning", "r.w", "meh", "b.py", 1, 1)], "error", "https://example.com/run/1")
    assert md.startswith("<!-- security-scans:semgrep -->\n")
    assert "FAILED" in md and "1 error" in md and "1 warning" in md and "https://example.com/run/1" in md
    assert "app.py:3" in md


def test_markdown_for_a_clean_run_says_passed():
    md = sr.markdown("trivy", [], "error", None)
    assert "passed" in md.lower() and "FAILED" not in md


def test_markdown_neutralizes_mentions_html_images_and_fence_breaks():
    nasty = "@everyone <img src=x onerror=1> ![x](http://e.com/a.png) [l](http://e.com) `` ``` # 1 :tada:"
    md = sr.markdown("semgrep", [sr.Finding("error", "r", nasty, "app.py", 1, 1)], "error", None)
    # the message appears exactly once, inside a code span whose fence is longer than any backtick run in it
    assert md.count("@everyone") == 1 and md.count("<img") == 1
    assert sr.code_span(nasty) in md
    assert sr.code_span(nasty).startswith("````") and "\n" not in sr.code_span(nasty)


def test_rule_ids_and_paths_are_code_spans_too():
    md = sr.markdown("semgrep", [sr.Finding("error", "@rule<b>", "m", "dir/@file`x.py", 1, 1)], "error", None)
    assert sr.code_span("@rule<b>") in md and sr.code_span("dir/@file`x.py:1") in md


def test_markdown_is_capped_in_listed_findings_and_in_size():
    found = [sr.Finding("error", f"rule-{i}", "m" * 300, f"dir/file{i}.py", i + 1, i + 1) for i in range(500)]
    md = sr.markdown("semgrep", found, "error", None)
    assert len(md) <= sr.MAX_MARKDOWN and "more" in md and md.count("rule-") <= sr.MAX_LISTED + 2


def test_markdown_tool_name_is_validated():
    with pytest.raises(ValueError):
        sr.markdown("sem grep -->", [], "error", None)


def test_code_span_survives_backticks():
    span = sr.code_span("a`b``c")
    assert span.startswith("```") and span.endswith("```") and "a`b``c" in span


def test_run_url_must_be_https():
    assert "javascript:" not in sr.markdown("semgrep", [], "error", "javascript:alert(1)")


# ---- end to end ----

def test_cli_writes_annotations_markdown_and_summary(tmp_path):
    md, summary = tmp_path / "out.md", tmp_path / "summary.md"
    summary.write_text("earlier\n")
    out = run(tmp_path, sarif([result("sql", text="concatenated query", uri="app.py", line=7)]), "--fail-on", "error", "--annotate",
              "--markdown", str(md), "--summary", str(summary), "--root", str(tmp_path))
    assert out.returncode == 1
    assert md.read_text().startswith("<!-- security-scans:semgrep -->")
    assert summary.read_text().startswith("earlier\n") and "sql" in summary.read_text()


def test_findings_outside_the_repo_get_the_outside_label(tmp_path):
    (tmp_path / "app.py").write_text("x\n")
    doc = sarif([result("a", uri="/out/image.tar", line=1), result("b", uri="app.py", line=1)])
    out = run(tmp_path, doc, "--annotate", "--root", str(tmp_path), "--outside-label", "container image", "--markdown", str(tmp_path / "o.md"))
    assert "file=app.py" in out.stdout and "(location: container image)" in out.stdout and "/out/image.tar" not in out.stdout
    assert "/out/image.tar" not in (tmp_path / "o.md").read_text() and "`container image`" in (tmp_path / "o.md").read_text()


def test_cli_merges_several_sarif_files(tmp_path):
    a, b = write(tmp_path, sarif([result("a")]), "a.sarif"), write(tmp_path, sarif([result("b", line=9)]), "b.sarif")
    out = subprocess.run([sys.executable, str(SCRIPTS / "sarif_report.py"), "--tool", "trivy", "--annotate", str(a), str(b)], capture_output=True, text=True)
    assert out.stdout.count("::error ") == 2


def test_cli_reports_unreadable_input_in_the_markdown_too(tmp_path):
    md = tmp_path / "out.md"
    out = run(tmp_path, "garbage", "--markdown", str(md))
    assert out.returncode == 2 and "no usable results" in md.read_text().lower()


def test_script_is_stdlib_only():
    text = (SCRIPTS / "sarif_report.py").read_text()
    import ast
    modules = {n.names[0].name.split(".")[0] for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Import)}
    modules |= {n.module.split(".")[0] for n in ast.walk(ast.parse(text)) if isinstance(n, ast.ImportFrom) and n.module}
    assert modules <= set(sys.stdlib_module_names), modules


# ---- job result ----

@pytest.mark.parametrize("job_result", ["success", "failure", "cancelled", "skipped"])
@pytest.mark.parametrize("content", ["clean", "findings", "missing"])
def test_the_verdict_never_says_passed_when_the_job_was_not_successful(tmp_path, job_result, content):
    md = tmp_path / "o.md"
    path = tmp_path / "in.sarif"
    if content != "missing":
        path.write_text(json.dumps(sarif([result()] if content == "findings" else [])))
    out = subprocess.run([sys.executable, str(SCRIPTS / "sarif_report.py"), "--tool", "trivy", "--job-result", job_result, "--markdown", str(md), str(path)],
                         capture_output=True, text=True)
    text = md.read_text()
    should_pass = job_result == "success" and content == "clean"
    assert ("passed" in text.split("\n")[1]) == should_pass, text
    assert ("FAILED" in text) == (not should_pass)
    assert (out.returncode == 0) == should_pass
    unfinished = "the scan didn't finish; see the check log"
    assert (unfinished in text) == (content == "missing" or (job_result != "success" and content == "clean"))


def test_an_unknown_job_result_counts_as_not_successful():
    assert "FAILED" in sr.markdown("trivy", [], "error", None, "weird; value")
    assert "passed" in sr.markdown("trivy", [], "error", None, "success")
    assert "passed" in sr.markdown("trivy", [], "error", None)
