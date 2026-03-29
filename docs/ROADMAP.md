# VISaR Roadmap

VISaR is built for data engineers and data platform teams who need to rigorously evaluate open-source software before bringing it into their environment. This tool solves a real need in regulated domains such as defence, aviation, and healthcare where software ingestion carries compliance obligations.

The two core use cases this roadmap serves:

1. **Evaluate external projects** - assess an open-source library, framework, or tool before it enters your environment or approved software list.
2. **Validate your own projects** - verify your own codebase before a wider release or production deployment.

For live tracking of individual issues and pull requests, see [GitHub Issues](https://github.com/AtLongLastAnalytics/visar/issues).

---

## v1.1.0 - Stability, Usability & Reporting ✅ Shipped

This release hardened the core pipeline, expanded output options, and introduced batch and dashboard capabilities.

### Bug Fixes

| Fix | Description |
|-----|-------------|
| OSV API timeout | Added `timeout=30` to all OSV API calls - prevents indefinite hangs on slow or unresponsive responses |
| Fragile path resolution | Replaced `os.getcwd()/..` with `DATA_DIR` from `config.py` in `check_datafolder_exists()` |
| Shell injection risk | Replaced `shell=True` subprocess call in `docker_funcs.py` with a list-based command - eliminates shell injection vector |
| Silent empty results | VISaR now prints `"No vulnerabilities found."` and exits cleanly (code 0) when a scan returns no results |
| CSV sort order | Scan output is now sorted by severity (CRITICAL → HIGH → MODERATE → LOW) before writing |

### Features

**Batch scanning (`--batch FILE`)**
Scan multiple repositories in a single run by supplying a text file of GitHub URLs - one per line, `#` comments and blank lines ignored. A structured summary is printed on completion showing total, succeeded, and failed counts.

**Multiple output formats (`--output-format csv|json`)**
Choose between `csv` (default, ready for Excel or any spreadsheet tool) and `json` (structured, suitable for downstream tooling or dashboards). Output is sorted by severity in both formats.

**Interactive HTML dashboard (`dashboard.py`)**
Generate a single self-contained `dashboard.html` from all scan outputs in your `data/` directory. Features include: severity summary cards, dataset dropdown, date filter, severity filter pills, expandable detail rows, sortable columns, and direct OSV deep-links per finding.

**Cross-platform support**
Removed hard dependency on `pywin32`. VISaR now runs on Windows, macOS, and Linux. Setup scripts (`setup.ps1` / `setup.sh`) provided for both platforms.

**CI pipeline**
GitHub Actions workflow runs the full test suite and linter on every push and pull request to `main`. Status badge published in README.

---

## Short-Term Goals

Focused on making VISaR produce outputs that can serve as formal compliance artifacts, extending scan inputs to support local codebases, and enriching vulnerability data with CVE/CVSS information.

### Planned Features

**Local directory scanning (`--local PATH`)**
Point VISaR at a local directory rather than a GitHub URL. The directory is mounted into the OSSF Scorecard Docker container for scanning - no internet access to GitHub required.

This extends VISaR's reach in two important ways:
- *Evaluate downloaded projects*: clone a repository to an intermediate machine, transfer the files, and scan locally - useful in network-restricted or partially air-gapped workflows.
- *Validate your own code*: scan a local working copy of your own project before tagging a release or submitting for deployment approval.

Output files follow the same naming convention, using the directory name in place of the GitHub owner/repo slug.

**Pass/fail severity threshold (`--fail-on SEVERITY`)**
Set a minimum severity level that causes VISaR to exit with a non-zero code if any matching findings are returned. For example, `--fail-on CRITICAL` exits 1 if one or more CRITICAL vulnerabilities are found, and 0 otherwise.

This enables VISaR to be wired into internal approval pipelines or shell scripts as an automated gate - no manual inspection required to get a yes/no result.

**Formal evidence report**
Generate a structured single-repository report (HTML) that includes scan metadata alongside findings: repository or path scanned, scan date and time, VISaR version, output format, and severity summary. Designed to be attached directly to a software approval request, change control submission, or compliance dossier.

**Date-scoped re-assessment (`--since DATE`)**
Only surface vulnerabilities published after a specified date. Supports periodic re-assessments of already-approved software - useful for quarterly compliance reviews or pre-upgrade checks where you only need to know what has changed since the last approval.

**CVE and CVSS enrichment**
Extend OSV enrichment to also surface CVE IDs and CVSS base scores alongside GHSA/PYSEC identifiers. CVSS scores provide a standardised numeric severity signal that is widely expected in compliance artefacts and can be used to drive risk-scoring logic downstream.

**Repository-level risk score**
Aggregate individual vulnerability severities into a single numeric risk score per repository (e.g. a weighted sum: CRITICAL × 10 + HIGH × 5 + MODERATE × 2 + LOW × 1). Included in both output files and the evidence report. Enables side-by-side comparison of repositories and supports approved-software-list decisions where a quantitative threshold is required.

**Configuration file support (`visar.toml`)**
Allow a `visar.toml` file at the project root as an alternative to environment variables and CLI flags - useful for teams who want repeatable scan configurations checked into version control (with credentials excluded). CLI flags continue to take precedence over file-based config.

---

## Long-Term Goals

Designed for teams operating in air-gapped or heavily network-restricted environments where external API calls are not possible, and where full dependency tree evaluation is a compliance requirement.

### Planned Features

**Offline / air-gap mode**
Download and cache the [OSV database](https://osv.dev/docs/#section/Data) locally. In offline mode, VISaR resolves vulnerability IDs against the local cache rather than making live API calls. Paired with a locally mirrored OSSF Scorecard Docker image, this enables a fully self-contained scan with no outbound network dependency.

This is the primary enabler for use in classified or strictly controlled environments.

**SBOM input support (CycloneDX / SPDX)**
Accept a Software Bill of Materials file as scan input and evaluate all components listed within it. Supports CycloneDX JSON and SPDX JSON - the two dominant standards following the US Executive Order on Improving the Nation's Cybersecurity (EO 14028).

Rather than scanning a single repository, VISaR queries the OSV database for every component in the SBOM, producing a consolidated findings report across the full dependency tree. Suitable for evaluating complex frameworks (e.g. Apache Airflow, dbt) where transitive dependencies carry the majority of the risk surface.

**Scan history and delta reports**
Store scan results in a local SQLite database. On each re-scan, VISaR produces a delta report: new vulnerabilities since the last scan, vulnerabilities that have been resolved, and a trend count over time. Transforms VISaR from a point-in-time evaluation tool into an ongoing monitoring capability for approved software on your internal list.

**Dashboard trend charts**
Extend the HTML dashboard with a timeline view showing vulnerability counts over time for repositories that have been scanned multiple times. Charts are embedded inline (no external dependencies) and complement the existing delta report by making drift visible at a glance.

**Dashboard text search**
Add a free-text search box to the dashboard to filter findings by vulnerability ID, severity, or description keywords. All data is already embedded in the HTML - this is a pure JavaScript enhancement that significantly improves usability when reviewing large result sets.
