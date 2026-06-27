"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.2.0

File: dashboard_funcs.py
Description: This module contains functions for generating a single
self-contained HTML dashboard that embeds all VISaR scan datasets and
lets the user switch between them via a dropdown. Supports reading both
CSV and JSON formats produced by helper_funcs.py writers.
"""

# import standard libraries
import base64
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import List

# import helper functions
from ..models import Finding
from .logger_config import setup_logger

# initialize logger
logger = setup_logger(__name__)

# Severity sort order — mirrors _SEVERITY_ORDER in helper_funcs.py
_SEVERITY_ORDER: dict = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}

# Presentation assets live as sibling files so editors can syntax-highlight
# them and the SHA-256 hashes used in the CSP stay stable across builds.
# Read once at module load — these don't change at runtime.
_ASSETS_DIR: Path = Path(__file__).resolve().parent
_HTML_CSS: str = (_ASSETS_DIR / "dashboard.css").read_text(encoding="utf-8")
_HTML_JS: str = (_ASSETS_DIR / "dashboard.js").read_text(encoding="utf-8")

# Embed the company logo as a base64 data URI so the dashboard stays a single
# self-contained HTML file (no external image fetch). CSP's img-src already
# allows data: URIs.
_LOGO_BYTES: bytes = (_ASSETS_DIR / "logo-rectangle.png").read_bytes()
_LOGO_DATA_URI: str = "data:image/png;base64," + base64.b64encode(_LOGO_BYTES).decode(
    "ascii"
)


def _csp_sha256(content: str) -> str:
    """
    Return a CSP source expression that hash-pins the exact UTF-8 bytes of
    `content`. Browsers compare this hash against the bytes between the
    opening and closing tag of an inline <script> or <style>, so the content
    must be emitted byte-for-byte identical to what is hashed here.

    Args:
        content (str): Exact text that will appear between the tag.

    Returns:
        str: A CSP source like ``'sha256-AbCdEf...='``.
    """
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _read_csv_data(data_file: Path) -> List[Finding]:
    """
    Read vulnerability data from a VISaR CSV output file.

    Expects a header row with columns VulnerabilityID, Severity, and Details,
    as produced by write_vulnerability_details_to_csv in helper_funcs.py.

    Args:
        data_file (Path): Path to the CSV file to read.

    Returns:
        List[Finding]: Findings loaded from the CSV file.
    """
    findings: List[Finding] = []
    with data_file.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            findings.append(Finding.from_output_record(row))
    return findings


def _read_json_data(data_file: Path) -> List[Finding]:
    """
    Read vulnerability data from a VISaR JSON output file.

    Expects a JSON array of objects with keys VulnerabilityID, Severity, and
    Details, as produced by write_vulnerability_details_to_json in
    helper_funcs.py.

    Args:
        data_file (Path): Path to the JSON file to read.

    Returns:
        List[Finding]: Findings loaded from the JSON file.
    """
    with data_file.open("r", encoding="utf-8") as f:
        records = json.load(f)
    return [Finding.from_output_record(record) for record in records]


def _prepare_dataset(data_file: Path, findings: List[Finding]) -> dict:
    """
    Build a dataset dict from scan data and its source filename.

    Parses scan date and repository name from the filename stem, sorts rows by
    severity, and computes per-severity counts. The resulting dict is the unit
    of data consumed by write_multi_dashboard.

    Expected filename stem: YYYYMMDD-owner-repo_vulnids
    (e.g. 20260320-streamlit-streamlit_vulnids)

    Args:
        data_file (Path): Source file, used only for metadata parsing.
        findings (List[Finding]): Findings loaded from the output file.

    Returns:
        dict: Dataset dict with keys: label, repo, repoUrl, date, isoDate,
              total, counts (CRITICAL/HIGH/MODERATE/LOW/OTHER), rows.
    """
    # Parse scan metadata from the output filename
    stem = data_file.stem  # "20260320-owner-repo_vulnids"
    base = stem.replace("_vulnids", "")  # "20260320-owner-repo"
    date_part, _, repo_part = base.partition("-")
    # repo_part is "owner-repo"; the first segment is the GitHub owner and the
    # remainder (which may itself contain hyphens) is the repository name.
    owner, _, repo_name = repo_part.partition("-")
    repo_url = f"https://github.com/{owner}/{repo_name}" if owner and repo_name else ""
    try:
        dt = datetime.strptime(date_part, "%Y%m%d")
        scan_date = dt.strftime("%d %b %Y")
        iso_date = dt.strftime("%Y-%m-%d")
    except ValueError:
        scan_date = date_part
        iso_date = date_part

    # Sort rows by severity for consistent display
    sorted_findings = sorted(
        findings,
        key=lambda finding: _SEVERITY_ORDER.get(finding.severity.upper(), 99),
    )

    # Build per-severity counts for the summary cards; anything outside the
    # known four levels (e.g. NONE returned by some OSV entries) goes to OTHER
    counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "OTHER": 0}
    for finding in sorted_findings:
        sev_key = finding.severity.upper()
        if sev_key in _SEVERITY_ORDER:
            counts[sev_key] += 1
        else:
            counts["OTHER"] += 1

    rows = [
        {
            "id": finding.vulnerability_id,
            "severity": finding.severity,
            "detail": finding.details,
        }
        for finding in sorted_findings
    ]

    return {
        "label": f"{repo_part} ({scan_date})",
        "repo": repo_part,
        "repoUrl": repo_url,
        "date": scan_date,
        "isoDate": iso_date,
        "total": sum(counts.values()),
        "counts": counts,
        "rows": rows,
    }


def write_multi_dashboard(datasets: List[dict], output_file: Path) -> None:
    """
    Write a single HTML dashboard embedding one or more scan datasets.

    All datasets are serialised as a JSON array and embedded in a <script>
    block. The page renders the first dataset on load; the dropdown switches
    between them without a page reload. No external dependencies — CSS and JS
    are inlined.

    The CSP that ships in the page hash-pins every inline <script> and <style>
    block — no 'unsafe-inline'. This means injecting a script via a malicious
    detail string is blocked by the browser even if escaping ever fails.

    Each dataset dict must contain the keys produced by _prepare_dataset:
    label, repo, repoUrl, date, isoDate, total,
    counts (CRITICAL/HIGH/MODERATE/LOW/OTHER), rows (list of {id, severity, detail}).

    Args:
        datasets (List[dict]): Ordered list of dataset dicts, one per scan.
        output_file (Path): File path where the HTML will be written.

    Returns:
        None
    """
    # Serialise datasets as JSON for embedding; escape </ to prevent a
    # malicious detail string from closing the <script> block prematurely
    datasets_json = json.dumps(datasets, ensure_ascii=False)
    datasets_json = datasets_json.replace("</", "<\\/")

    # Exact bytes for each inline block must be hashed BEFORE substitution
    # into the template, and emitted byte-identical inside the tag. Any change
    # (even a single space) invalidates the hash and the browser refuses to run.
    data_script = f"var DATASETS = {datasets_json};"
    csp = (
        "default-src 'none'; "
        f"script-src {_csp_sha256(data_script)} {_csp_sha256(_HTML_JS)}; "
        f"style-src {_csp_sha256(_HTML_CSS)}; "
        "img-src 'self' data:; font-src data:;"
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="{csp}">
  <title>VISaR | AtLongLast Analytics</title>
  <style>{_HTML_CSS}</style>
</head>
<body>
  <header class="page-header">
    <div class="header-left">
      <a class="brand-link" href="https://atlonglastanalytics.com" target="_blank" rel="noopener noreferrer" aria-label="AtLongLast Analytics">
        <img class="brand-logo" src="{_LOGO_DATA_URI}" alt="AtLongLast Analytics" width="900" height="320">
      </a>
      <span class="divider" aria-hidden="true"></span>
      <a class="logo" href="https://github.com/AtLongLastAnalytics/visar" target="_blank" rel="noopener noreferrer">VISaR</a>
      <span class="tagline">Vulnerability Identification, Scanning &amp; Reporting</span>
    </div>
    <div class="header-right">
      <span><strong>Repo:</strong> <span id="hdr-repo">&mdash;</span></span>
      <span><strong>Scanned:</strong> <span id="hdr-date">&mdash;</span></span>
    </div>
  </header>
  <main class="main">
    <aside class="sidebar" aria-label="Dashboard help and links">
    <details class="about-panel" open>
      <summary aria-label="About this dashboard">About this dashboard</summary>
      <div class="about-body">
        <p>
          <strong>VISaR</strong> (Vulnerability Identification, Scanning &amp; Reporting)
          is a free, open-source supply-chain vulnerability scanner built for
          data engineers and data-platform teams evaluating open-source software
          under regulated and audit-grade requirements &mdash; defence, aviation,
          healthcare, and other contexts where you need to evidence what was
          scanned, when, and what changed between scans. It works just as well
          for individual developers vetting a single project.
        </p>
        <p>
          The dashboard is a single self-contained HTML file. No network requests,
          no trackers, no external fonts &mdash; safe to open in air-gapped review
          environments. Every inline script and style is SHA-256 pinned in the CSP.
        </p>
        <p><strong>How to use it</strong></p>
        <ul>
          <li><strong>Pick a repo and scan date</strong> from the two dropdowns at the top of the controls.</li>
          <li><strong>Filter by severity</strong> by clicking any of the six cards (Critical, High, Moderate, Low, Other, Total). Click Total to clear the filter.</li>
          <li><strong>Search</strong> by vulnerability ID (CVE / GHSA / PYSEC) or by any text inside the details field.</li>
          <li><strong>Diff against an earlier scan</strong> &mdash; when a prior scan of the same repo exists, the comparison bar shows what changed. Use the <em>Compare</em> dropdown to diff against the <em>previous scan</em> or, cumulatively, against the <em>first scan</em>. Use <em>Changes only</em> to hide unchanged rows, or <em>Show resolved</em> to bring back rows that have dropped out of the latest scan.</li>
          <li><strong>Review the scan history</strong> at the bottom of the page &mdash; a per-scan table (total, new, resolved, reclassified) and a trend chart of total findings over time for the selected repo.</li>
          <li><strong>Copy a vulnerability ID</strong> with the small clipboard button next to it &mdash; useful when pasting into a ticket.</li>
          <li><strong>Download CSV</strong> exports the currently-visible rows (respecting filter, search, and the active diff) for sharing with developers or attaching to an audit packet.</li>
        </ul>
        <div class="about-links">
          <a href="https://github.com/AtLongLastAnalytics/visar" target="_blank" rel="noopener noreferrer">Source code on GitHub &rarr;</a>
          <a href="https://atlonglastanalytics.com/software/visar/" target="_blank" rel="noopener noreferrer">VISaR on AtLongLast Analytics &rarr;</a>
        </div>
      </div>
    </details>
    </aside>
    <div class="content">
    <div class="stats-grid" role="group" aria-label="Severity filters">
      <div class="stat-card total active" role="button" tabindex="0" aria-pressed="true" data-filter="all">
        <div class="stat-count" id="stat-total">0</div>
        <div class="stat-label">Total</div>
      </div>
      <div class="stat-card critical" role="button" tabindex="0" aria-pressed="false" data-filter="CRITICAL">
        <div class="stat-count" id="stat-critical">0</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card high" role="button" tabindex="0" aria-pressed="false" data-filter="HIGH">
        <div class="stat-count" id="stat-high">0</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card moderate" role="button" tabindex="0" aria-pressed="false" data-filter="MODERATE">
        <div class="stat-count" id="stat-moderate">0</div>
        <div class="stat-label">Moderate</div>
      </div>
      <div class="stat-card low" role="button" tabindex="0" aria-pressed="false" data-filter="LOW">
        <div class="stat-count" id="stat-low">0</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card other" role="button" tabindex="0" aria-pressed="false" data-filter="OTHER">
        <div class="stat-count" id="stat-other">0</div>
        <div class="stat-label">Other</div>
      </div>
    </div>
    <div class="controls">
      <div class="controls-row">
        <label class="ctl-label" for="repo-select">Repo</label>
        <select id="repo-select" class="dataset-select" aria-label="Select repository"></select>
        <a id="repo-link" class="repo-link" target="_blank" rel="noopener noreferrer" hidden></a>
        <label class="ctl-label" for="date-select">Scan</label>
        <select id="date-select" class="date-select" aria-label="Select scan date"></select>
      </div>
      <div class="controls-row">
        <input
          type="search"
          id="search-input"
          class="search-input"
          placeholder="Search by ID or details&hellip;"
          aria-label="Search vulnerabilities by ID or details"
          autocomplete="off"
          spellcheck="false"
        >
        <span id="result-count" class="result-count" aria-live="polite"></span>
        <button type="button" id="download-csv" class="action-btn" aria-label="Download filtered view as CSV" title="Download CSV of currently visible rows">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path>
            <polyline points="7 10 12 15 17 10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
          Download CSV
        </button>
      </div>
    </div>
    <div class="diff-bar" id="diff-bar" role="region" aria-label="Comparison with a baseline scan" hidden>
      <div class="diff-summary">
        <label class="ctl-label" for="baseline-select">Compare</label>
        <select id="baseline-select" class="baseline-select" aria-label="Choose the baseline scan to compare against">
          <option value="previous">vs previous scan</option>
          <option value="first">vs first scan (cumulative)</option>
        </select>
        <span class="diff-label">vs <strong id="diff-baseline-date">&mdash;</strong>:</span>
        <span class="diff-stat new"><strong id="diff-count-new">0</strong> new</span>
        <span class="diff-stat changed"><strong id="diff-count-changed">0</strong> reclassified</span>
        <span class="diff-stat resolved"><strong id="diff-count-resolved">0</strong> resolved</span>
      </div>
      <div class="diff-actions">
        <button type="button" id="toggle-changes-only" class="action-btn" aria-pressed="false" aria-label="Show only rows that changed since the baseline scan">Changes only</button>
        <button type="button" id="toggle-resolved" class="action-btn" aria-pressed="false" aria-label="Include rows that were resolved since the baseline scan">Show resolved</button>
      </div>
    </div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th class="sortable" data-sort="id">
              Vulnerability ID <span class="sort-icon"></span>
            </th>
            <th class="sortable" data-sort="severity">
              Severity <span class="sort-icon"></span>
            </th>
            <th>Details</th>
            <th class="expand-th"></th>
          </tr>
        </thead>
        <tbody id="vuln-tbody"></tbody>
      </table>
      <div id="empty-state" class="empty-state" role="status" aria-live="polite" hidden></div>
    </div>
    <section class="scan-history" id="scan-history" aria-label="Scan history for this repository" hidden>
      <div class="history-head">
        <h2 class="history-title">Scan history &mdash; <span id="history-repo">&mdash;</span></h2>
        <span class="history-sub">Each scan compared against the one before it</span>
      </div>
      <div class="history-layout">
        <div class="history-chart-wrap">
          <div class="history-chart-title">Total findings over time</div>
          <div id="history-chart" class="history-chart" role="img" aria-label="Line chart of total findings per scan over time"></div>
        </div>
        <div class="history-table-wrap">
          <table class="history-table">
            <thead>
              <tr>
                <th scope="col">Scan date</th>
                <th scope="col" class="num">Total</th>
                <th scope="col" class="num">New</th>
                <th scope="col" class="num">Resolved</th>
                <th scope="col" class="num">Reclassified</th>
              </tr>
            </thead>
            <tbody id="history-tbody"></tbody>
          </table>
        </div>
      </div>
    </section>
    </div>
  </main>
  <footer class="footer">
    Generated by <a href="https://github.com/AtLongLastAnalytics/visar" target="_blank" rel="noopener noreferrer">VISaR</a>
    &mdash; <a href="https://atlonglastanalytics.com" target="_blank" rel="noopener noreferrer">AtLongLast Analytics</a>
  </footer>
  <script>{data_script}</script>
  <script>{_HTML_JS}</script>
</body>
</html>"""

    # newline="" prevents Windows CRLF translation inside the inline
    # <script>/<style> tags, which would change their byte content and
    # invalidate the SHA-256 CSP hashes.
    with open(output_file, "w", encoding="utf-8", newline="") as f:
        f.write(html_content)


def generate_dashboard_from_file(data_file: Path) -> Path:
    """
    Read a single VISaR data file and generate a self-contained HTML dashboard.

    Convenience wrapper around generate_dashboard_from_dir for single-file
    use. The HTML output is written alongside the input file with a .html
    extension.

    Args:
        data_file (Path): Path to a VISaR output file (.csv or .json).

    Returns:
        Path: Path to the generated HTML file.

    Raises:
        FileNotFoundError: If data_file does not exist.
        ValueError: If the file extension is not .csv or .json.
    """
    if not data_file.exists():
        raise FileNotFoundError(f"Data file not found: {data_file}")

    suffix = data_file.suffix.lower()
    if suffix == ".csv":
        logger.info("Reading CSV data from %s", data_file.name)
        findings = _read_csv_data(data_file)
    elif suffix == ".json":
        logger.info("Reading JSON data from %s", data_file.name)
        findings = _read_json_data(data_file)
    else:
        raise ValueError(f"Unsupported file format '{suffix}'. Expected .csv or .json.")

    dataset = _prepare_dataset(data_file, findings)
    output_file = data_file.with_suffix(".html")
    logger.info("Generating HTML dashboard: %s", output_file.name)
    write_multi_dashboard([dataset], output_file)
    return output_file


def generate_dashboard_from_dir(data_dir: Path) -> Path:
    """
    Read all VISaR data files in a directory and generate one HTML dashboard.

    Discovers all *_vulnids.csv and *_vulnids.json files. Where both formats
    exist for the same stem, JSON takes precedence. Datasets are sorted by
    scan date (newest first) so the most recent scan is selected by default.
    The output is written as visar_dashboard.html inside data_dir.

    Args:
        data_dir (Path): Directory containing VISaR output files.

    Returns:
        Path: Path to the generated visar_dashboard.html file.

    Raises:
        FileNotFoundError: If data_dir does not exist.
        ValueError: If data_dir is not a directory, or no data files are found.
    """
    if not data_dir.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")
    if not data_dir.is_dir():
        raise ValueError(f"Expected a directory, got a file: {data_dir}")

    # Discover data files; JSON takes precedence over CSV for the same stem
    csv_files = {f.stem: f for f in data_dir.glob("*_vulnids.csv")}
    json_files = {f.stem: f for f in data_dir.glob("*_vulnids.json")}
    merged = {**csv_files, **json_files}  # json overwrites csv for same stem

    if not merged:
        raise ValueError(
            f"No VISaR data files (*_vulnids.csv or *_vulnids.json) found in {data_dir}"
        )

    # Sort stems by date prefix descending so the newest scan is first in the
    # dropdown. The YYYYMMDD prefix sorts identically as string and integer,
    # but using the prefix explicitly documents the assumption — a filename
    # whose layout drifts would otherwise silently land in the wrong order.
    sorted_stems = sorted(
        merged.keys(),
        key=lambda s: s.split("-", 1)[0],
        reverse=True,
    )

    datasets = []
    for stem in sorted_stems:
        data_file = merged[stem]
        suffix = data_file.suffix.lower()
        try:
            if suffix == ".csv":
                findings = _read_csv_data(data_file)
            else:
                findings = _read_json_data(data_file)
            datasets.append(_prepare_dataset(data_file, findings))
            logger.info("Loaded %s (%d entries)", data_file.name, len(findings))
        except Exception as e:
            logger.warning("Skipping %s — could not read: %s", data_file.name, e)

    if not datasets:
        raise ValueError(f"No data could be loaded from files in {data_dir}")

    output_file = data_dir / "visar_dashboard.html"
    logger.info(
        "Generating dashboard with %d dataset(s): %s", len(datasets), output_file.name
    )
    write_multi_dashboard(datasets, output_file)
    return output_file
