#!/usr/bin/env python3
"""Turn SARIF scan results into GitHub annotations, a markdown report, and an exit code. Standard library only.

    sarif_report.py --tool NAME [--root DIR] [--fail-on error|warning|note|none] [--annotate]
                    [--markdown FILE] [--summary FILE] [--run-url URL] [--outside-label TEXT] [--job-result RESULT] SARIF [SARIF ...]

Exit codes: 0 no finding at or above the threshold, 1 at least one, 2 the input was missing or not usable SARIF
(an unreadable result is never a pass).

SARIF content comes from tools that read attacker-controlled files, so every string is treated as hostile:
- Results marked suppressed in the SARIF are still findings (see findings()).
- Annotations are workflow commands. Newlines, `%`, and (in properties) `:` and `,` are escaped, `::` inside text is
  broken up, and control characters are removed, so a message cannot start a second command.
- The markdown puts every tool-supplied string in a code span, so it cannot ping people, link, embed images, or
  inject HTML.
- Secret findings never carry the tool's message or snippet: only the rule's short description is shown.
- A file path is attached to an annotation only if it is a relative path to a regular file inside --root.
"""

import argparse
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

LEVELS = ("error", "warning", "note")
_RANK = {"error": 0, "warning": 1, "note": 2}
THRESHOLDS = (*LEVELS, "none")
# GitHub shows at most 10 annotations of each kind per step. The notice slot has one spare for the truncation notice.
ANNOTATION_LIMITS = {"error": 10, "warning": 10, "note": 9}
_COMMAND = {"error": "error", "warning": "warning", "note": "notice"}
MAX_MESSAGE = 400
MAX_LISTED = 30
MAX_MARKDOWN = 60000
_TOOL = re.compile(r"[a-z][a-z0-9-]{0,30}")
_URL = re.compile(r"https://[A-Za-z0-9._~:/?=&%+@-]{1,500}")


class ReportError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    level: str
    rule_id: str
    message: str
    file: str
    line: int | None
    end_line: int | None


def clean(text) -> str:
    """Drop control, format (bidi), and line/paragraph separator characters; keep \\n, \\r, \\t for later handling."""
    return "".join(c for c in str(text) if c in "\n\r\t" or unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp"))


def one_line(text, limit=MAX_MESSAGE) -> str:
    joined = " ".join(part.strip() for part in clean(text).splitlines() if part.strip())
    return joined if len(joined) <= limit else joined[: limit - 3] + "..."


def escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def code_span(text: str) -> str:
    """A markdown code span that holds `text` verbatim: the fence is longer than any backtick run inside."""
    text = " ".join(clean(text).split())
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


# ---- parsing ----

def _dict(value, what):
    if not isinstance(value, dict):
        raise ReportError(f"SARIF: {what} is not an object")
    return value


def _int(value):
    return value if type(value) is int and value >= 1 else None


def _rule_for(item, rules):
    index = item.get("ruleIndex")
    if type(index) is int and 0 <= index < len(rules) and rules[index].get("id") in (None, item.get("ruleId")):
        return rules[index]
    return next((r for r in rules if r.get("id") == item.get("ruleId")), {})


def _is_secret(rule) -> bool:
    tags = (rule.get("properties") or {}).get("tags")
    return isinstance(tags, list) and any(isinstance(t, str) and t.lower() == "secret" for t in tags)


def _rule_text(rule):
    short = rule.get("shortDescription")
    text = short.get("text") if isinstance(short, dict) else None
    return one_line(text or rule.get("name") or "secret detected", 120)


def findings(doc) -> list[Finding]:
    """The findings of a parsed SARIF document, deduplicated and sorted. Raises ReportError on anything unexpected."""
    runs = _dict(doc, "the document").get("runs")
    if not isinstance(runs, list) or not runs:
        raise ReportError("SARIF: no runs")
    out = {}
    for run in runs:
        run = _dict(run, "a run")
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        rules = [r for r in rules if isinstance(r, dict)] if isinstance(rules, list) else []
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ReportError("SARIF: results is not a list")
        for item in results:
            item = _dict(item, "a result")
            # A result marked suppressed is still a finding: Semgrep runs with inline suppression comments disabled and
            # then reports such a line with an inSource marker, and a comment in the repository must not hide it.
            rule = _rule_for(item, rules)
            level = item.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            if level not in ("none", *LEVELS):
                raise ReportError(f"SARIF: unknown level {level!r}")
            level = "note" if level == "none" else level
            rule_id = one_line(item.get("ruleId") or rule.get("id") or "unknown-rule", 200)
            if _is_secret(rule):
                message = _rule_text(rule)
            else:
                message = one_line((item.get("message") or {}).get("text") or "")
            file, line, end = "", None, None
            locations = item.get("locations")
            if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation") or {}
                uri = (physical.get("artifactLocation") or {}).get("uri")
                file = one_line(uri, 300) if isinstance(uri, str) else ""
                region = physical.get("region") or {}
                line = _int(region.get("startLine"))
                end = _int(region.get("endLine")) or line
            finding = Finding(level, rule_id, message, file, line, end)
            out[finding] = None
    return sort_findings(list(out))


def sort_findings(found):
    return sorted(found, key=lambda f: (_RANK[f.level], f.file, f.line or 0, f.rule_id, f.message))


def load_sarif(path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read {path}: {exc.__class__.__name__}") from None


# ---- annotations ----

def _safe_file(uri: str, root) -> str | None:
    if not uri or "://" in uri or uri.startswith(("/", "\\")) or "\\" in uri:
        return None
    parts = Path(uri).parts
    if not parts or ".." in parts or any(":" in p for p in parts):
        return None
    rel = "/".join(parts)
    if root is not None:
        base = os.path.realpath(root)
        target = os.path.realpath(os.path.join(base, rel))
        if os.path.commonpath([base, target]) != base or not os.path.isfile(target):
            return None
    return rel


def _neutral(text: str) -> str:
    return text.replace("::", ": :")


def annotations(found, root) -> list[str]:
    """Workflow-command lines for the findings, capped per level; a notice says how many were left out."""
    lines, shown, skipped = [], {level: 0 for level in LEVELS}, 0
    for f in found:
        if shown[f.level] >= ANNOTATION_LIMITS[f.level]:
            skipped += 1
            continue
        shown[f.level] += 1
        safe = _safe_file(f.file, root)
        message = _neutral(one_line(f.message))
        props = []
        if safe:
            props.append(f"file={escape_property(safe)}")
            if f.line:
                props += [f"line={f.line}", f"endLine={f.end_line or f.line}"]
        elif f.file:
            message = f"{message} (location: {_neutral(f.file)})"
        props.append(f"title={escape_property(_neutral(f.rule_id))}")
        lines.append(f"::{_COMMAND[f.level]} {','.join(props)}::{escape_data(message)}")
    if skipped:
        lines.append(f"::notice title=security-scans::{skipped} more finding{'s' if skipped != 1 else ''} not annotated; see the job summary and the SARIF artifact")
    return lines


def relabel_outside(found, root, label):
    """Findings whose file is not a file inside root (a path in a container image, say) show `label` instead of a path."""
    out = {}
    for f in found:
        inside = _safe_file(f.file, root) is not None
        out[f if inside else Finding(f.level, f.rule_id, f.message, label, None, None)] = None
    return sort_findings(list(out))


# ---- markdown ----

def _count(found, level):
    n = sum(f.level == level for f in found)
    return f"{n} {level}{'' if n == 1 else 's'}"


def failing(found, fail_on) -> bool:
    return fail_on != "none" and any(_RANK[f.level] <= _RANK[fail_on] for f in found)


UNFINISHED = "the scan didn't finish; see the check log"


def markdown(tool: str, found, fail_on: str, run_url, job_result=None) -> str:
    """job_result is the scan job's own result (needs.<job>.result). Anything but "success" means the check is red, so
    the report must not say "passed", even when the SARIF that exists looks clean."""
    if not _TOOL.fullmatch(tool):
        raise ValueError("invalid tool name")
    ran_ok = job_result is None or job_result == "success"
    bad = failing(found, fail_on) or not ran_ok
    head = [f"<!-- security-scans:{tool} -->", f"### security-scans / {tool}: {'FAILED' if bad else 'passed'}", ""]
    counts = ", ".join(_count(found, level) for level in LEVELS)
    rule = f"Findings at level `{fail_on}` or above fail this check." if fail_on != "none" else "This run only reports; no level fails the check."
    head.append(f"{counts}. {rule}")
    if not ran_ok and not failing(found, fail_on):
        head.append(f"\nNote: {UNFINISHED} (job result: {code_span(str(job_result)[:20])}).")
    if run_url and _URL.fullmatch(run_url):
        head.append(f"\n[Run log and SARIF artifact]({run_url})")
    body = [""]
    for f in found[:MAX_LISTED]:
        where = code_span(f"{f.file}:{f.line}" if f.file and f.line else f.file) if f.file else "(no location)"
        body.append(f"- **{f.level}** {code_span(f.rule_id)} in {where}: {code_span(f.message)}")
    if len(found) > MAX_LISTED:
        body.append(f"\n...and {len(found) - MAX_LISTED} more not listed here. The SARIF artifact of the run has all of them.")
    text = "\n".join(head + body) + "\n"
    if len(text) > MAX_MARKDOWN:
        text = text[: MAX_MARKDOWN - 40].rsplit("\n", 1)[0] + "\n\n(truncated)\n"
    return text


def unusable_markdown(tool: str, reason: str) -> str:
    return (f"<!-- security-scans:{tool} -->\n### security-scans / {tool}: FAILED\n\n"
            f"No usable results were produced ({code_span(reason)}): {UNFINISHED}. This check cannot pass.\n")


# ---- command line ----

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--tool", required=True)
    p.add_argument("--root", type=Path)
    p.add_argument("--fail-on", choices=THRESHOLDS, default="error")
    p.add_argument("--annotate", action="store_true")
    p.add_argument("--markdown", type=Path)
    p.add_argument("--summary", type=Path)
    p.add_argument("--run-url")
    p.add_argument("--job-result", help="the scan job's result (success, failure, cancelled, skipped); anything but success never reports a pass")
    p.add_argument("--outside-label", help="shown instead of the path for findings whose file is not a file inside --root")
    p.add_argument("files", nargs="+", type=Path)
    args = p.parse_args(argv)
    if not _TOOL.fullmatch(args.tool):
        print("invalid --tool", file=sys.stderr)
        return 2
    try:
        found = sort_findings(list({f: None for path in args.files for f in findings(load_sarif(path))}))
    except ReportError as exc:
        text = unusable_markdown(args.tool, str(exc))
        if args.markdown:
            args.markdown.write_text(text, encoding="utf-8")
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as handle:
                handle.write(text)
        print(f"::error title=security-scans::{escape_data(_neutral(one_line(str(exc))))}")
        return 2
    if args.outside_label:
        found = relabel_outside(found, args.root, one_line(args.outside_label, 60))
    if args.annotate:
        for line in annotations(found, args.root):
            print(line)
    text = markdown(args.tool, found, args.fail_on, args.run_url, args.job_result)
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(text)
    unfinished = args.job_result is not None and args.job_result != "success"
    return 1 if failing(found, args.fail_on) or unfinished else 0


if __name__ == "__main__":
    sys.exit(main())
