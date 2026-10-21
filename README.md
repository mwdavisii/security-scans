# security-scans

A reusable GitHub Actions workflow that runs the code and container scans for an app repository and reports the result where the contributor already looks: the PR's checks, line annotations, the job summary, and one comment per tool.

It stands in for the security team's scanning service in the golden road. **Who owns it:** the security team, in a real organization. They choose the scanners and rules, set the thresholds, triage false positives, and bump the pinned scanner images. The platform team never runs, wraps, or re-scores these scanners: the platform's release gate only reads whether the checks named below passed. In the personal proof of concept, the account that owns the app repos owns this repo as well.

Nothing here runs in the app repo's own workflows, so an app contributor changes the scans only by changing this repo, which they do not control.

## Checks it produces

| Check name | What it runs | Fails the check on |
|---|---|---|
| `security-scans / semgrep` | Semgrep CE with the vendored `rules/` plus the registry ruleset `p/default` | any finding of severity ERROR |
| `security-scans / trivy` | `trivy fs` (vulnerabilities, misconfigurations, secrets) on the repository, then `docker build` of the root `Dockerfile` (not pushed) and `trivy image` on the result (vulnerabilities, secrets) | any HIGH or CRITICAL finding (unfixed vulnerabilities are skipped by default) |

The names come from the caller's job id (`security-scans`) and the job ids in `scan.yml` (`semgrep`, `trivy`). Changing either changes the check names, and the app's ruleset and the platform's required-check list must change with them.

Each scan job also writes line annotations (at most 10 errors, 10 warnings, and 10 notices per job, because that is all GitHub shows; a notice says how many were left out), a job summary, and a SARIF artifact (`security-scans-semgrep`, `security-scans-trivy`). On pull requests from the same repo, a third job, `security-scans / comment` (not a required check), creates or updates one comment per tool, found by a hidden marker and by its author (the Actions bot). It rebuilds the markdown from the SARIF artifacts with this repo's script and never checks out or runs anything from the app repo. On fork PRs it is skipped, because the token is read-only there; the checks, annotations, and summaries still run. The comment is also given each scan job's own result: if a job did not succeed (an image build failed, say), its comment says FAILED and "the scan didn't finish; see the check log", never passed, even when the SARIF that exists is clean.

## How an app repo calls it

```yaml
# .github/workflows/security-scans.yml in the app repo
name: security-scans
on:
  pull_request:
  push:
    branches: [main]
permissions: {}
jobs:
  security-scans:            # this job id is part of the check names
    permissions:
      contents: read
      pull-requests: write   # only for the PR comment
    uses: <owner>/security-scans/.github/workflows/scan.yml@main
```

There are no inputs and no secrets, so a calling repo cannot weaken the scans. The Semgrep registry rulesets (`REGISTRY_RULESETS`, default `p/default`; empty means only the vendored rules, with no network) and `IGNORE_UNFIXED` (default `true`: skip Trivy vulnerabilities that have no fixed version yet) are constants at the top of `scan.yml`, so tuning them is a change to this repo.

The repo must be public, or the calling repos must be able to read it. The caller's `GITHUB_TOKEN` cannot read another private or internal repository, so for a private security-scans repo the workflow's own checkout of its scripts would fail. **For a GitHub Enterprise port, ship the scripts and rules inside a digest-pinned `security-scans` container image** (the jobs run in or call that image) instead of a second checkout. That also removes the dependence on `job.workflow_repository` and `job.workflow_sha`.

**The checkout is guarded.** The first step of every job fails unless `job.workflow_repository` is `owner/name`, differs from the calling repository, and `job.workflow_sha` is a 40-character commit. Without it, an empty value would make `actions/checkout` fall back to the calling repo, and the job would run scripts the pull request controls.

## What it runs, and why these choices

**Rules.** Semgrep runs the vendored `rules/` (a few rules for command and SQL injection, `eval`, and unsafe deserialization in Python and JavaScript, each with annotated examples that `semgrep --test` checks) and the registry ruleset `p/default`. Registry rules are fetched at run time, so they need the network and change over time; the vendored rules do not. The registry rules were not copied in, because their license restricts redistribution (check the current terms before vendoring them), so the vendored set is original and small. The proof-run findings come from the vendored set, so they do not depend on the network. The security team should replace `p/default` with a pinned, vendored set of its own.

**Scanner images** are pinned by digest in `scan.yml` (`SEMGREP_IMAGE`, `TRIVY_IMAGE`), and every action is pinned by commit SHA. Update them deliberately, from one place.

**The scanners cannot be told to look away.** The repository under test is copied without its `.gitignore`, `.semgrepignore`, and `.git`, and the copy gets this repo's own `rules/semgrepignore`. Semgrep runs with inline suppression comments disabled, and the report counts a result the tool marks as suppressed. Trivy runs from a directory that is not the repository, so a `trivy.yaml` or `.trivyignore` in the repository is never read. Files under `tests/` are scanned, because the image build copies them. A false positive is therefore fixed in this repo (a rule change), not with a comment in the app. Limits that remain: a file that makes Semgrep time out on enough rules is skipped by Semgrep, and the scans find known patterns, not every bug.

**Tool output is treated as hostile.** The scanners print text taken from the repository, so their output runs between `::stop-commands::` and a random end token, and `scripts/sarif_report.py` escapes everything it turns into annotations. In the markdown, every tool-supplied string is in a code span, so it cannot mention people, link, or embed HTML. Secret findings show only the rule name, never the match.

**The Dockerfile build runs repository code.** `docker build` of the root `Dockerfile` executes its `RUN` steps (a package install, for an app built by the golden road). What limits it: the scan job's token is `contents: read` only (the comment job that can write is separate and runs nothing from the repo); checkout does not keep credentials; there is no registry login, no `--secret`, no `--ssh`, and no Docker socket mounted anywhere; the build context is the repo only; the image is saved to a tar file for Trivy and then deleted, never pushed; and the runner is a fresh VM that is thrown away. The `RUN` steps need the package indexes, so the build keeps the default network, and a build cannot drop capabilities. The platform's own drift check does not build anything, so this is a new exposure that comes with scanning the image; in an app repo the Dockerfile is generated and the drift check flags any edit to it, but that check runs at the same time as this job, so it does not protect this job. A repo without a root `Dockerfile` skips the image scan with a notice.

**Permissions.** The workflow's default is `permissions: {}`. The two scan jobs get `contents: read` only. The separate `comment` job gets `contents: read` and `pull-requests: write`, and its token goes only to the step that posts the comment. There is no `id-token`, no `security-events`, no `checks: write`, no secrets, and no trigger that hands secrets to forks.

**Other limits.** Trivy honours an inline `#trivy:ignore` comment in infrastructure-as-code files that are not generated, so a hand-written file can suppress its own misconfiguration finding. The SARIF artifacts on a public repo can be downloaded by any signed-in GitHub user; Trivy masks secret matches in them, and the reporter never prints them. Findings in the platform-pinned base image of an app (a fixed HIGH or CRITICAL in the Debian layer) fail `security-scans / trivy` for every app built on it, and the app team cannot fix them: the owner is whoever owns the builder, by bumping the base image and regenerating the apps.

## Known gap: the result can be forged inside the app repo

Every check that a workflow in the app repo posts comes from the same GitHub app (GitHub Actions, id 15368). The platform pins required checks to a source, but this one source is shared: **anyone who can change a workflow in the app repo can add a job called `security-scans / semgrep` that simply passes.** The ruleset's code-owner review of `.github/` and the platform's release gate both rest on that one name. The real fix is for this workflow to sign its result with its own identity (cosign), and for the release to verify that signature instead of a check name. That is not done here.

## Local runs and tests

Every step the workflow takes is a script in `scripts/`, so you can run it locally with Docker. From a directory that has the repository under test in `./src`:

```bash
export SEMGREP_IMAGE=<the digest from scan.yml> TRIVY_IMAGE=<the digest from scan.yml>
REGISTRY_RULESETS="" bash <this repo>/scripts/run_semgrep.sh            # vendored rules only, no network
IGNORE_UNFIXED=true bash <this repo>/scripts/run_trivy.sh fs            # needs the network for the database
python3 <this repo>/scripts/sarif_report.py --tool semgrep --root src --annotate out/semgrep.sarif
```

`SCANS_TRIVY_OFFLINE=true`, `SCANS_TRIVY_CACHE`, `SCANS_BUILD_NETWORK`, `SCANS_SEMGREP_NETWORK`, and `SCANS_TRIVY_NETWORK` are documented in the scripts' headers.

```bash
pip install pytest pyyaml
pytest                 # script, report, and workflow-policy tests; no Docker, no network
pytest -m docker       # also runs the pinned Semgrep image against the rules (Docker, no network)
```
