# Changelog

All notable changes to VISaR are documented here.

## [1.1.0] - 2026-03-25

### Added
- **Batch scan mode** (`--batch repos.txt`) — scan multiple repositories from a text file in one command.
- **Interactive HTML dashboard** (`dashboard.py`) — generates a self-contained `dashboard.html` embedding all scan datasets, with severity filter pills, a date range filter, dataset dropdown, and expandable vulnerability detail rows.
- **OSV API enrichment** — each finding is now annotated with a severity rating and plain-text description from the [OSV Database](https://osv.dev/).
- **JSON output format** — `--output-format json` writes results as a structured JSON array alongside the existing CSV option.
- **Cross-platform support** — Mac/Linux setup script (`scripts/setup.sh`) added; `pywin32` dependency is now Windows-only.
- **Example data files** — `data/example-owner-repo_vulnids.csv` and `.json` provided so the dashboard can be explored without running a real scan.

### Changed
- Migrated from `pip` + `requirements.txt` to `uv` + `pyproject.toml` for environment and dependency management.
- Exit codes formalised: `0` = success (including no vulnerabilities found), `1` = scan failure.

## [1.0.0] - 2025-05-12

### Added
- Initial release: single-repository vulnerability scanning via OSSF Scorecard + OSV API enrichment.
- CSV output written to the `data/` directory, named by date and repository.
- Structured run logging to the `logs/` directory (rotating log files).
- GitHub Actions CI pipeline: lint (ruff), format check, and unit tests on every push and pull request to `main`.
- Apache 2.0 license.
