"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: dashboard_funcs.py
Description: This module contains functions for generating a single
self-contained HTML dashboard that embeds all VISaR scan datasets and
lets the user switch between them via a dropdown. Supports reading both
CSV and JSON formats produced by helper_funcs.py writers.
"""

# import standard libraries
import csv
from datetime import datetime
import json
from pathlib import Path
from typing import List, Tuple

# import helper functions
from helpers.logger_config import setup_logger

# initialize logger
logger = setup_logger(__name__)

# Severity sort order — mirrors _SEVERITY_ORDER in helper_funcs.py
_SEVERITY_ORDER: dict = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}

# HTML template components — defined at module level to keep the writer
# function focused on data transformation, not presentation markup
_HTML_CSS: str = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #0a0a0a;
    color: #f0fdf4;
    min-height: 100vh;
    font-size: 14px;
    line-height: 1.5;
}
.page-header {
    background: #0a0a0a;
    color: #fff;
    padding: 1rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    border-bottom: 1px solid #262626;
}
.header-left { display: flex; align-items: center; gap: 1rem; }
.logo { font-size: 1.25rem; font-weight: 800; letter-spacing: 0.08em; color: #4ade80; text-decoration: none; }
.tagline { font-size: 0.8rem; color: #6b7280; }
.header-right { display: flex; gap: 1.5rem; font-size: 0.8rem; color: #6b7280; }
.header-right strong { color: #d4d4d4; }
.main { max-width: 1400px; margin: 0 auto; padding: 1.5rem 2rem; }
.stats-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 1rem;
    margin-bottom: 1.5rem;
}
.stat-card {
    background: #171717;
    border-radius: 0.625rem;
    padding: 1.125rem 1.25rem;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.2);
    border-top: 3px solid transparent;
}
.stat-card.total    { border-top-color: #6b7280; }
.stat-card.critical { border-top-color: #ef4444; }
.stat-card.high     { border-top-color: #f97316; }
.stat-card.moderate { border-top-color: #f59e0b; }
.stat-card.low      { border-top-color: #3b82f6; }
.stat-card.other    { border-top-color: #8b5cf6; }
.stat-count { font-size: 1.875rem; font-weight: 700; line-height: 1; margin-bottom: 0.3rem; }
.stat-card.total    .stat-count { color: #6b7280; }
.stat-card.critical .stat-count { color: #f87171; }
.stat-card.high     .stat-count { color: #fb923c; }
.stat-card.moderate .stat-count { color: #fbbf24; }
.stat-card.low      .stat-count { color: #60a5fa; }
.stat-card.other    .stat-count { color: #a78bfa; }
.stat-label {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #71717a;
}
.controls {
    background: #171717;
    border-radius: 0.625rem;
    padding: 0.875rem 1.25rem;
    margin-bottom: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4);
    border: 1px solid #262626;
}
.controls-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
}
.date-select {
    padding: 0.5rem 0.875rem;
    border: 1.5px solid #262626;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    color: #f0fdf4;
    background: #1a1a1a;
    cursor: pointer;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
}
.date-select:focus {
    border-color: #4ade80;
    background: #1a1a1a;
    box-shadow: 0 0 0 3px rgba(74,222,128,0.15);
}
.dataset-select {
    flex: 1;
    min-width: 240px;
    padding: 0.5rem 0.875rem;
    border: 1.5px solid #262626;
    border-radius: 0.5rem;
    font-size: 0.875rem;
    color: #f0fdf4;
    background: #1a1a1a;
    cursor: pointer;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
}
.dataset-select:focus {
    border-color: #4ade80;
    background: #1a1a1a;
    box-shadow: 0 0 0 3px rgba(74,222,128,0.15);
}
.filter-group { display: flex; gap: 0.4rem; flex-wrap: wrap; }
.filter-btn {
    padding: 0.35rem 0.85rem;
    border: 1.5px solid #262626;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
    background: #1a1a1a;
    color: #a1a1aa;
    transition: all 0.15s;
    white-space: nowrap;
}
.filter-btn:hover { border-color: #404040; color: #f0fdf4; background: #262626; }
.filter-btn.active { border-color: transparent; color: white; }
.filter-btn[data-filter="all"].active      { background: #52525b; }
.filter-btn[data-filter="CRITICAL"].active { background: #ef4444; }
.filter-btn[data-filter="HIGH"].active     { background: #f97316; }
.filter-btn[data-filter="MODERATE"].active { background: #f59e0b; }
.filter-btn[data-filter="LOW"].active      { background: #3b82f6; }
.filter-btn[data-filter="OTHER"].active    { background: #8b5cf6; }
.result-count { font-size: 0.75rem; color: #71717a; white-space: nowrap; }
.table-wrapper {
    background: #171717;
    border-radius: 0.625rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4), 0 1px 2px rgba(0,0,0,0.2);
    overflow: hidden;
    border: 1px solid #262626;
}
table { width: 100%; border-collapse: collapse; }
thead tr { background: #1a1a1a; }
thead th {
    padding: 0.75rem 1.25rem;
    text-align: left;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #6b7280;
    border-bottom: 1px solid #262626;
    white-space: nowrap;
}
thead th.sortable { cursor: pointer; user-select: none; }
thead th.sortable:hover { color: #f0fdf4; background: #262626; }
thead th.expand-th { width: 2.5rem; }
.sort-icon { display: inline-block; margin-left: 0.3rem; }
th.sorted-asc  .sort-icon::after { content: '\2191'; opacity: 0.8; }
th.sorted-desc .sort-icon::after { content: '\2193'; opacity: 0.8; }
th.sortable:not(.sorted-asc):not(.sorted-desc) .sort-icon::after { content: '\21C5'; opacity: 0.4; }
tbody tr { border-bottom: 1px solid #262626; transition: background 0.1s; }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: #262626; }
tbody tr.hidden { display: none; }
td { padding: 0.75rem 1.25rem; font-size: 0.875rem; vertical-align: top; }
.id-cell { white-space: nowrap; min-width: 180px; }
.id-cell a {
    color: #10b981;
    text-decoration: none;
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    font-size: 0.8rem;
    font-weight: 500;
}
.id-cell a:hover { text-decoration: underline; color: #059669; }
.id-sep { color: #71717a; font-size: 0.75rem; }
.badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 999px;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    white-space: nowrap;
}
.badge.critical { background: #3f0f0f; color: #f87171; }
.badge.high     { background: #3f1a0a; color: #fb923c; }
.badge.moderate { background: #3f2d04; color: #fbbf24; }
.badge.low      { background: #0f1f3f; color: #60a5fa; }
.badge.other    { background: #1e1240; color: #a78bfa; }
.detail-cell { color: #a1a1aa; line-height: 1.6; }
.det-text {
    white-space: pre-wrap;
    word-break: break-word;
    display: block;
    max-width: 680px;
    max-height: 4.8rem;
    overflow: hidden;
    transition: max-height 0.25s ease;
}
tr.expanded .det-text { max-height: 9999px; }
.expand-col { width: 2.5rem; padding: 0.5rem 0.375rem; text-align: center; vertical-align: middle; }
.expand-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.5rem;
    height: 1.5rem;
    border: 1.5px solid #262626;
    border-radius: 50%;
    background: #1a1a1a;
    color: #6b7280;
    font-size: 1rem;
    line-height: 1;
    cursor: pointer;
    transition: all 0.15s;
}
.expand-btn:hover { border-color: #4ade80; color: #10b981; background: #14532d; }
.empty-state { text-align: center; padding: 3rem 1rem; color: #71717a; font-size: 0.875rem; }
.footer { text-align: center; padding: 1.5rem; font-size: 0.75rem; color: #6b7280; }
.footer a { color: #6b7280; text-decoration: none; }
.footer a:hover { text-decoration: underline; color: #4ade80; }
@media (max-width: 1100px) {
    .stats-grid { grid-template-columns: repeat(3, 1fr); }
}
@media (max-width: 900px) {
    .main { padding: 1rem; }
}
@media (max-width: 600px) {
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .page-header { padding: 0.875rem 1rem; }
    .id-cell { min-width: 140px; }
    .dataset-select { min-width: 0; width: 100%; }
}
"""

# All rendering is done in JS — rows are built dynamically from DATASETS so
# that switching between scans only requires a dropdown change, not a page load
_HTML_JS: str = """
(function () {
    'use strict';

    var tbody         = document.getElementById('vuln-tbody');
    var filterBtns    = Array.from(document.querySelectorAll('.filter-btn'));
    var resultCount   = document.getElementById('result-count');
    var emptyState    = document.getElementById('empty-state');
    var datasetSelect = document.getElementById('dataset-select');
    var dateSelect    = document.getElementById('date-filter');

    var SEV_ORDER    = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3 };
    var activeFilter = 'all';
    var sortCol      = 'severity';
    var sortDir      = 'asc';
    var rows         = [];

    var TRUNCATE = 300;

    // Escape HTML special characters when building innerHTML from data values
    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // Build OSV link(s) — handles composite IDs like "PYSEC-xxx / GHSA-xxx"
    function buildIdHtml(id) {
        return id.split(' / ').map(function (p) {
            p = p.trim();
            return '<a href="https://osv.dev/vulnerability/' + esc(p) + '"'
                + ' target="_blank" rel="noopener noreferrer">' + esc(p) + '</a>';
        }).join('<span class="id-sep"> / </span>');
    }

    function buildDetailHtml(det) {
        return '<span class="det-text">' + esc(det) + '</span>';
    }

    // Return the badge CSS class — unknown severities render as "other"
    function badgeClass(sev) {
        return SEV_ORDER.hasOwnProperty(sev) ? sev.toLowerCase() : 'other';
    }

    function updateStats(ds) {
        document.getElementById('stat-total').textContent    = ds.total;
        document.getElementById('stat-critical').textContent = ds.counts.CRITICAL;
        document.getElementById('stat-high').textContent     = ds.counts.HIGH;
        document.getElementById('stat-moderate').textContent = ds.counts.MODERATE;
        document.getElementById('stat-low').textContent      = ds.counts.LOW;
        document.getElementById('stat-other').textContent    = ds.counts.OTHER;
        document.getElementById('hdr-repo').textContent      = ds.repo;
        document.getElementById('hdr-date').textContent      = ds.date;
        document.title = 'VISaR \u2014 ' + ds.repo;
    }

    function renderDataset(ds) {
        updateStats(ds);
        tbody.innerHTML = '';
        rows = ds.rows.map(function (r) {
            var tr = document.createElement('tr');
            tr.dataset.severity = r.severity;
            var needsExpand = r.detail.length > TRUNCATE;
            tr.innerHTML =
                '<td class="id-cell">' + buildIdHtml(r.id) + '</td>'
                + '<td><span class="badge ' + badgeClass(r.severity) + '">'
                + esc(r.severity) + '</span></td>'
                + '<td class="detail-cell">' + buildDetailHtml(r.detail) + '</td>'
                + '<td class="expand-col">' + (needsExpand
                    ? '<button class="expand-btn" onclick="toggleRow(this)">+</button>'
                    : '') + '</td>';
            tbody.appendChild(tr);
            return tr;
        });
        // Reset vulnerability filter controls when switching datasets
        activeFilter = 'all';
        filterBtns.forEach(function (b) { b.classList.remove('active'); });
        filterBtns[0].classList.add('active');
        sortCol = 'severity';
        sortDir = 'asc';
        document.querySelectorAll('th.sortable').forEach(function (t) {
            t.classList.remove('sorted-asc', 'sorted-desc');
        });
        document.querySelector('th[data-sort="severity"]').classList.add('sorted-asc');
        applyView();
    }

    function applyView() {
        var n = 0;
        rows.forEach(function (tr) {
            var sev  = tr.dataset.severity;
            var show = activeFilter === 'all'
                || sev === activeFilter
                || (activeFilter === 'OTHER' && !SEV_ORDER.hasOwnProperty(sev));
            tr.classList.toggle('hidden', !show);
            if (show) n++;
        });
        resultCount.textContent = n + ' of ' + rows.length + ' vulnerabilities';
        emptyState.style.display = n === 0 ? '' : 'none';
    }

    function reSort() {
        rows.sort(function (a, b) {
            if (sortCol === 'severity') {
                var av = SEV_ORDER.hasOwnProperty(a.dataset.severity)
                    ? SEV_ORDER[a.dataset.severity] : 99;
                var bv = SEV_ORDER.hasOwnProperty(b.dataset.severity)
                    ? SEV_ORDER[b.dataset.severity] : 99;
                return sortDir === 'asc' ? av - bv : bv - av;
            }
            var at = a.querySelector('.id-cell').textContent.trim().toLowerCase();
            var bt = b.querySelector('.id-cell').textContent.trim().toLowerCase();
            return sortDir === 'asc' ? at.localeCompare(bt) : bt.localeCompare(at);
        });
        rows.forEach(function (tr) { tbody.appendChild(tr); });
        applyView();
    }

    // Rebuild the dataset dropdown based on the current date filter,
    // then auto-load the first matching dataset
    function rebuildDatasetSelect() {
        var dateQ = dateSelect.value;
        datasetSelect.innerHTML = '';
        var firstIdx = -1;
        DATASETS.forEach(function (ds, i) {
            if (!dateQ || ds.isoDate === dateQ) {
                var opt = document.createElement('option');
                opt.value = i;
                opt.textContent = ds.label;
                datasetSelect.appendChild(opt);
                if (firstIdx === -1) { firstIdx = i; }
            }
        });
        if (firstIdx !== -1) {
            datasetSelect.value = firstIdx;
            renderDataset(DATASETS[firstIdx]);
        } else {
            // No matches — clear the table
            tbody.innerHTML = '';
            rows = [];
            applyView();
        }
    }

    filterBtns.forEach(function (btn) {
        btn.addEventListener('click', function () {
            filterBtns.forEach(function (b) { b.classList.remove('active'); });
            btn.classList.add('active');
            activeFilter = btn.dataset.filter;
            applyView();
        });
    });

    dateSelect.addEventListener('change', rebuildDatasetSelect);

    Array.from(document.querySelectorAll('th.sortable')).forEach(function (th) {
        th.addEventListener('click', function () {
            var col = th.dataset.sort;
            if (sortCol === col) {
                sortDir = sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                sortCol = col;
                sortDir = 'asc';
            }
            document.querySelectorAll('th.sortable').forEach(function (t) {
                t.classList.remove('sorted-asc', 'sorted-desc');
            });
            th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
            reSort();
        });
    });

    // Toggle row detail expansion — called from expand button onclick
    window.toggleRow = function (btn) {
        var tr = btn.closest('tr');
        var expanded = tr.classList.toggle('expanded');
        btn.textContent = expanded ? '\u2212' : '+';
    };

    // Populate the date filter from DATASETS
    (function initFilters() {
        var seenDates = {};
        DATASETS.forEach(function (ds) {
            if (ds.isoDate && !seenDates[ds.isoDate]) {
                seenDates[ds.isoDate] = true;
                var opt = document.createElement('option');
                opt.value = ds.isoDate;
                opt.textContent = ds.date;
                dateSelect.appendChild(opt);
            }
        });
    }());

    // Populate the dataset dropdown and render the first dataset on load
    DATASETS.forEach(function (ds, i) {
        var opt = document.createElement('option');
        opt.value = i;
        opt.textContent = ds.label;
        datasetSelect.appendChild(opt);
    });

    datasetSelect.addEventListener('change', function () {
        renderDataset(DATASETS[parseInt(datasetSelect.value, 10)]);
    });

    if (DATASETS.length > 0) {
        renderDataset(DATASETS[0]);
    }
}());
"""


def _read_csv_data(data_file: Path) -> Tuple[List[str], List[str], List[str]]:
    """
    Read vulnerability data from a VISaR CSV output file.

    Expects a header row with columns VulnerabilityID, Severity, and Details,
    as produced by write_vulnerability_details_to_csv in helper_funcs.py.

    Args:
        data_file (Path): Path to the CSV file to read.

    Returns:
        Tuple[List[str], List[str], List[str]]: vuln_ids, details, severities.
    """
    vuln_ids, details, severities = [], [], []
    with data_file.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vuln_ids.append(row["VulnerabilityID"])
            severities.append(row["Severity"])
            details.append(row["Details"])
    return vuln_ids, details, severities


def _read_json_data(data_file: Path) -> Tuple[List[str], List[str], List[str]]:
    """
    Read vulnerability data from a VISaR JSON output file.

    Expects a JSON array of objects with keys VulnerabilityID, Severity, and
    Details, as produced by write_vulnerability_details_to_json in
    helper_funcs.py.

    Args:
        data_file (Path): Path to the JSON file to read.

    Returns:
        Tuple[List[str], List[str], List[str]]: vuln_ids, details, severities.
    """
    with data_file.open("r", encoding="utf-8") as f:
        records = json.load(f)
    vuln_ids = [r["VulnerabilityID"] for r in records]
    severities = [r["Severity"] for r in records]
    details = [r["Details"] for r in records]
    return vuln_ids, details, severities


def _prepare_dataset(
    data_file: Path,
    vuln_ids: List[str],
    details: List[str],
    severities: List[str],
) -> dict:
    """
    Build a dataset dict from scan data and its source filename.

    Parses scan date and repository name from the filename stem, sorts rows by
    severity, and computes per-severity counts. The resulting dict is the unit
    of data consumed by write_multi_dashboard.

    Expected filename stem: YYYYMMDD-owner-repo_vulnids
    (e.g. 20260320-streamlit-streamlit_vulnids)

    Args:
        data_file (Path): Source file, used only for metadata parsing.
        vuln_ids (List[str]): List of vulnerability IDs.
        details (List[str]): List of vulnerability detail strings.
        severities (List[str]): List of severity values.

    Returns:
        dict: Dataset dict with keys: label, repo, date, isoDate, total,
              counts (CRITICAL/HIGH/MODERATE/LOW/OTHER), rows.
    """
    # Parse scan metadata from the output filename
    stem = data_file.stem  # "20260320-owner-repo_vulnids"
    base = stem.replace("_vulnids", "")  # "20260320-owner-repo"
    date_part, _, repo_part = base.partition("-")
    try:
        dt = datetime.strptime(date_part, "%Y%m%d")
        scan_date = dt.strftime("%d %b %Y")
        iso_date = dt.strftime("%Y-%m-%d")
    except ValueError:
        scan_date = date_part
        iso_date = date_part

    # Sort rows by severity for consistent display
    sorted_rows = sorted(
        zip(vuln_ids, severities, details), key=lambda x: _SEVERITY_ORDER.get(x[1], 99)
    )

    # Build per-severity counts for the summary cards; anything outside the
    # known four levels (e.g. NONE returned by some OSV entries) goes to OTHER
    counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "OTHER": 0}
    for _, sev, _ in sorted_rows:
        sev_key = sev.upper()
        if sev_key in _SEVERITY_ORDER:
            counts[sev_key] += 1
        else:
            counts["OTHER"] += 1

    rows = [
        {"id": vid, "severity": sev, "detail": det} for vid, sev, det in sorted_rows
    ]

    return {
        "label": f"{repo_part} ({scan_date})",
        "repo": repo_part,
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

    Each dataset dict must contain the keys produced by _prepare_dataset:
    label, repo, date, isoDate, total, counts (CRITICAL/HIGH/MODERATE/LOW/OTHER),
    rows (list of {id, severity, detail}).

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

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VISaR | AtLongLast Analytics</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>{_HTML_CSS}</style>
</head>
<body>
  <header class="page-header">
    <div class="header-left">
      <a class="logo" href="https://github.com/AtLongLastAnalytics/visar" target="_blank" rel="noopener noreferrer">VISaR</a>
      <span class="tagline">Vulnerability Identification, Scanning &amp; Reporting &mdash; by <a href="https://atlonglastanalytics.com" target="_blank" rel="noopener noreferrer" style="color:inherit;text-decoration:none;">AtLongLast Analytics</a></span>
    </div>
    <div class="header-right">
      <span><strong>Repo:</strong> <span id="hdr-repo">&mdash;</span></span>
      <span><strong>Scanned:</strong> <span id="hdr-date">&mdash;</span></span>
    </div>
  </header>
  <main class="main">
    <div class="stats-grid">
      <div class="stat-card total">
        <div class="stat-count" id="stat-total">0</div>
        <div class="stat-label">Total</div>
      </div>
      <div class="stat-card critical">
        <div class="stat-count" id="stat-critical">0</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card high">
        <div class="stat-count" id="stat-high">0</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card moderate">
        <div class="stat-count" id="stat-moderate">0</div>
        <div class="stat-label">Moderate</div>
      </div>
      <div class="stat-card low">
        <div class="stat-count" id="stat-low">0</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card other">
        <div class="stat-count" id="stat-other">0</div>
        <div class="stat-label">Other</div>
      </div>
    </div>
    <div class="controls">
      <div class="controls-row">
        <select id="dataset-select" class="dataset-select"></select>
        <select id="date-filter" class="date-select">
          <option value="">All dates</option>
        </select>
      </div>
      <div class="controls-row">
        <div class="filter-group">
          <button class="filter-btn active" data-filter="all">All</button>
          <button class="filter-btn" data-filter="CRITICAL">Critical</button>
          <button class="filter-btn" data-filter="HIGH">High</button>
          <button class="filter-btn" data-filter="MODERATE">Moderate</button>
          <button class="filter-btn" data-filter="LOW">Low</button>
          <button class="filter-btn" data-filter="OTHER">Other</button>
        </div>
        <span id="result-count" class="result-count"></span>
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
      <div id="empty-state" class="empty-state" style="display:none">
        No vulnerabilities match your current filter.
      </div>
    </div>
  </main>
  <footer class="footer">
    Generated by <a href="https://github.com/AtLongLastAnalytics/visar" target="_blank" rel="noopener noreferrer">VISaR</a>
    &mdash; <a href="https://atlonglastanalytics.com" target="_blank" rel="noopener noreferrer">AtLongLast Analytics</a>
  </footer>
  <script>var DATASETS = {datasets_json};</script>
  <script>{_HTML_JS}</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
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
        vuln_ids, details, severities = _read_csv_data(data_file)
    elif suffix == ".json":
        logger.info("Reading JSON data from %s", data_file.name)
        vuln_ids, details, severities = _read_json_data(data_file)
    else:
        raise ValueError(f"Unsupported file format '{suffix}'. Expected .csv or .json.")

    dataset = _prepare_dataset(data_file, vuln_ids, details, severities)
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
    The output is written as dashboard.html inside data_dir.

    Args:
        data_dir (Path): Directory containing VISaR output files.

    Returns:
        Path: Path to the generated dashboard.html file.

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

    # Sort stems descending so the newest scan is first in the dropdown
    sorted_stems = sorted(merged.keys(), reverse=True)

    datasets = []
    for stem in sorted_stems:
        data_file = merged[stem]
        suffix = data_file.suffix.lower()
        try:
            if suffix == ".csv":
                vuln_ids, details, severities = _read_csv_data(data_file)
            else:
                vuln_ids, details, severities = _read_json_data(data_file)
            datasets.append(_prepare_dataset(data_file, vuln_ids, details, severities))
            logger.info("Loaded %s (%d entries)", data_file.name, len(vuln_ids))
        except Exception as e:
            logger.warning("Skipping %s — could not read: %s", data_file.name, e)

    if not datasets:
        raise ValueError(f"No data could be loaded from files in {data_dir}")

    output_file = data_dir / "dashboard.html"
    logger.info(
        "Generating dashboard with %d dataset(s): %s", len(datasets), output_file.name
    )
    write_multi_dashboard(datasets, output_file)
    return output_file
