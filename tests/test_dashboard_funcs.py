"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: test_dashboard_funcs.py
Description: This module contains a test suite for functions in the
    helpers.dashboard_funcs module. The test suite for each function is
    contained in its own class.
"""

# import testing libraries
import unittest
from pathlib import Path
import tempfile
import csv
import json
import logging

logging.disable(logging.CRITICAL)

from visar.models import Finding
from visar.helpers.dashboard_funcs import (
    write_multi_dashboard,
    generate_dashboard_from_file,
    generate_dashboard_from_dir,
    _read_csv_data,
    _read_json_data,
    _prepare_dataset,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_dataset(label, findings):
    """Build a minimal dataset dict for use in write_multi_dashboard tests."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
    sorted_rows = sorted(
        findings, key=lambda finding: sev_order.get(finding.severity.upper(), 99)
    )
    counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "OTHER": 0}
    for finding in sorted_rows:
        sev = finding.severity.upper()
        if sev in ("CRITICAL", "HIGH", "MODERATE", "LOW"):
            counts[sev] += 1
        else:
            counts["OTHER"] += 1
    return {
        "label": label,
        "repo": "test-repo",
        "date": "20 Mar 2026",
        "isoDate": "2026-03-20",
        "total": sum(counts.values()),
        "counts": counts,
        "rows": [
            {
                "id": finding.vulnerability_id,
                "severity": finding.severity,
                "detail": finding.details,
            }
            for finding in sorted_rows
        ],
    }


class TestWriteMultiDashboard(unittest.TestCase):
    """
    Test cases for the write_multi_dashboard function.
    """

    def _write_and_read(self, datasets):
        """Write dashboard to a temp file and return its content as a string."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "dashboard.html"
            write_multi_dashboard(datasets, out_path)
            return out_path.read_text(encoding="utf-8")

    def test_writes_valid_html_structure(self):
        """
        Output contains all required HTML document structure elements.
        """
        content = self._write_and_read([])
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("<html", content)
        self.assertIn("<head>", content)
        self.assertIn("<body>", content)
        self.assertIn("</html>", content)

    def test_datasets_embedded_as_json(self):
        """
        All dataset data is embedded in the HTML as a DATASETS JS variable.
        """
        ds = _make_dataset(
            "test (20 Mar 2026)",
            [Finding("GHSA-1111-2222-3333", "HIGH", "Details.")],
        )
        content = self._write_and_read([ds])
        self.assertIn("var DATASETS =", content)
        self.assertIn("GHSA-1111-2222-3333", content)

    def test_sorted_by_severity_within_dataset(self):
        """
        Rows in the embedded JSON appear in CRITICAL-first severity order.
        """
        ds = _make_dataset(
            "test",
            [Finding("HIGH-1", "HIGH", "d"), Finding("CRITICAL-1", "CRITICAL", "d")],
        )
        content = self._write_and_read([ds])
        self.assertLess(content.index("CRITICAL-1"), content.index("HIGH-1"))

    def test_empty_datasets_list_writes_valid_html(self):
        """
        An empty datasets list produces a valid HTML document with DATASETS=[].
        """
        content = self._write_and_read([])
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("var DATASETS = []", content)

    def test_multiple_datasets_all_embedded(self):
        """
        All datasets passed in are present in the embedded JSON.
        """
        ds1 = _make_dataset(
            "repo-one (20 Mar 2026)", [Finding("GHSA-1111-2222-3333", "HIGH", "d")]
        )
        ds2 = _make_dataset(
            "repo-two (20 Mar 2026)", [Finding("GHSA-4444-5555-6666", "LOW", "d")]
        )
        content = self._write_and_read([ds1, ds2])
        self.assertIn("GHSA-1111-2222-3333", content)
        self.assertIn("GHSA-4444-5555-6666", content)

    def test_script_injection_prevented(self):
        """
        A '</script>' sequence inside detail text is escaped so it cannot
        break out of the embedded <script> block.
        """
        ds = _make_dataset(
            "test",
            [
                Finding(
                    "GHSA-1111-2222-3333",
                    "HIGH",
                    '</script><script>alert("xss")</script>',
                )
            ],
        )
        content = self._write_and_read([ds])
        # the dangerous closing tag must not appear unescaped in the output
        self.assertNotIn("</script><script>alert", content)
        # it must be present in its escaped form
        self.assertIn("<\\/script>", content)

    def test_repo_select_element_present(self):
        """
        Output contains the repo dropdown select element.
        """
        content = self._write_and_read([])
        self.assertIn('id="repo-select"', content)

    def test_date_select_present(self):
        """
        Output contains the per-repo scan-date select element.
        """
        content = self._write_and_read([])
        self.assertIn('id="date-select"', content)

    def test_dashboard_has_no_external_font_dependencies(self):
        """
        Output is self-contained and does not pull fonts from Google CDN.
        """
        content = self._write_and_read([])
        self.assertNotIn("fonts.googleapis.com", content)
        self.assertNotIn("fonts.gstatic.com", content)
        self.assertNotIn('rel="preconnect"', content)

    def test_dashboard_csp_is_hash_pinned(self):
        """
        Output CSP hash-pins every inline script and style and disallows
        'unsafe-inline'. This is the meaningful hardening for a security
        tool aimed at regulated adopters.
        """
        import re

        content = self._write_and_read([])
        csp_match = re.search(
            r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">',
            content,
        )
        self.assertIsNotNone(csp_match, "CSP meta tag missing")
        csp = csp_match.group(1)

        self.assertIn("default-src 'none'", csp)
        self.assertIn("img-src 'self' data:", csp)
        self.assertIn("font-src data:", csp)
        # No relaxations — hash-pinning replaces them entirely
        self.assertNotIn("'unsafe-inline'", csp)
        self.assertNotIn("'unsafe-eval'", csp)
        # Both inline scripts (data + main JS) and the inline style block
        # contribute hashes. Expect at least 2 script hashes and 1 style hash.
        self.assertGreaterEqual(len(re.findall(r"'sha256-[A-Za-z0-9+/=]+'",
                                               csp.split(";")[1])), 2)
        self.assertGreaterEqual(len(re.findall(r"'sha256-[A-Za-z0-9+/=]+'",
                                               csp.split(";")[2])), 1)


class TestReadCsvData(unittest.TestCase):
    """
    Test cases for the _read_csv_data function.
    """

    def test_reads_all_columns(self):
        """
        Returns the correct findings from a CSV file.
        """
        rows = [
            ["GHSA-1111-2222-3333", "HIGH", "A high severity issue."],
            ["GHSA-4444-5555-6666", "LOW", "A low severity issue."],
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8", newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerow(["VulnerabilityID", "Severity", "Details"])
            writer.writerows(rows)
            tmp_path = Path(f.name)
        try:
            self.assertEqual(
                _read_csv_data(tmp_path),
                [
                    Finding("GHSA-1111-2222-3333", "HIGH", "A high severity issue."),
                    Finding("GHSA-4444-5555-6666", "LOW", "A low severity issue."),
                ],
            )
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_empty_csv_returns_empty_lists(self):
        """
        A CSV with only a header row returns an empty findings list.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8", newline=""
        ) as f:
            csv.writer(f).writerow(["VulnerabilityID", "Severity", "Details"])
            tmp_path = Path(f.name)
        try:
            self.assertEqual(_read_csv_data(tmp_path), [])
        finally:
            tmp_path.unlink(missing_ok=True)


class TestReadJsonData(unittest.TestCase):
    """
    Test cases for the _read_json_data function.
    """

    def test_reads_all_fields(self):
        """
        Returns the correct findings from a JSON file.
        """
        records = [
            {
                "VulnerabilityID": "GHSA-1111-2222-3333",
                "Severity": "CRITICAL",
                "Details": "Critical issue.",
            },
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(records, f)
            tmp_path = Path(f.name)
        try:
            self.assertEqual(
                _read_json_data(tmp_path),
                [Finding("GHSA-1111-2222-3333", "CRITICAL", "Critical issue.")],
            )
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_empty_json_array_returns_empty_lists(self):
        """
        An empty JSON array returns an empty findings list.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump([], f)
            tmp_path = Path(f.name)
        try:
            self.assertEqual(_read_json_data(tmp_path), [])
        finally:
            tmp_path.unlink(missing_ok=True)


class TestGenerateDashboardFromFile(unittest.TestCase):
    """
    Test cases for the generate_dashboard_from_file function.
    """

    def test_generates_html_from_csv(self):
        """
        Returns a Path to an .html file when given a valid CSV input.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "20260320-test-repo_vulnids.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["VulnerabilityID", "Severity", "Details"])
                writer.writerow(["GHSA-1111-2222-3333", "HIGH", "Details."])
            result = generate_dashboard_from_file(csv_path)
            self.assertEqual(result.suffix, ".html")
            self.assertTrue(result.exists())

    def test_generates_html_from_json(self):
        """
        Returns a Path to an .html file when given a valid JSON input.
        """
        records = [
            {
                "VulnerabilityID": "GHSA-1111-2222-3333",
                "Severity": "HIGH",
                "Details": "Details.",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "20260320-test-repo_vulnids.json"
            with json_path.open("w", encoding="utf-8") as f:
                json.dump(records, f)
            result = generate_dashboard_from_file(json_path)
            self.assertEqual(result.suffix, ".html")
            self.assertTrue(result.exists())

    def test_output_placed_alongside_input(self):
        """
        The generated HTML file is placed in the same directory as the input.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "20260320-test-repo_vulnids.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["VulnerabilityID", "Severity", "Details"])
                writer.writerow(["GHSA-1111-2222-3333", "HIGH", "Details."])
            result = generate_dashboard_from_file(csv_path)
            self.assertEqual(result.parent, csv_path.parent)

    def test_raises_filenotfounderror_for_missing_file(self):
        """
        Raises FileNotFoundError when the data file does not exist.
        """
        with self.assertRaises(FileNotFoundError):
            generate_dashboard_from_file(Path("/nonexistent/path/file.csv"))

    def test_raises_valueerror_for_unsupported_format(self):
        """
        Raises ValueError when the file extension is not .csv or .json.
        """
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmp_path = Path(f.name)
        try:
            with self.assertRaises(ValueError):
                generate_dashboard_from_file(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)


class TestGenerateDashboardFromDir(unittest.TestCase):
    """
    Test cases for the generate_dashboard_from_dir function.
    """

    def _write_csv(self, path, rows=None):
        """Write a minimal VISaR CSV file."""
        rows = rows or [["GHSA-1111-2222-3333", "HIGH", "Details."]]
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["VulnerabilityID", "Severity", "Details"])
            writer.writerows(rows)

    def _write_json(self, path, records=None):
        """Write a minimal VISaR JSON file."""
        records = records or [
            {
                "VulnerabilityID": "GHSA-1111-2222-3333",
                "Severity": "HIGH",
                "Details": "Details.",
            }
        ]
        with path.open("w", encoding="utf-8") as f:
            json.dump(records, f)

    def test_generates_dashboard_html_in_dir(self):
        """
        Writes visar_dashboard.html inside the data directory.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            self._write_csv(data_dir / "20260320-test-repo_vulnids.csv")
            result = generate_dashboard_from_dir(data_dir)
            self.assertEqual(result.name, "visar_dashboard.html")
            self.assertTrue(result.exists())

    def test_loads_multiple_files(self):
        """
        All data files in the directory appear as datasets in the dashboard.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            self._write_csv(
                data_dir / "20260320-repo-one_vulnids.csv",
                [["GHSA-1111-2222-3333", "HIGH", "Details."]],
            )
            self._write_json(
                data_dir / "20260310-repo-two_vulnids.json",
                [
                    {
                        "VulnerabilityID": "GHSA-4444-5555-6666",
                        "Severity": "LOW",
                        "Details": "Details.",
                    }
                ],
            )
            result = generate_dashboard_from_dir(data_dir)
            content = result.read_text(encoding="utf-8")
            self.assertIn("GHSA-1111-2222-3333", content)
            self.assertIn("GHSA-4444-5555-6666", content)

    def test_json_takes_precedence_over_csv_for_same_stem(self):
        """
        When both .csv and .json exist for the same stem, JSON is used.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            # CSV has one ID, JSON has a different one — JSON should win
            self._write_csv(
                data_dir / "20260320-test-repo_vulnids.csv",
                [["GHSA-1111-2222-3333", "HIGH", "CSV version."]],
            )
            self._write_json(
                data_dir / "20260320-test-repo_vulnids.json",
                [
                    {
                        "VulnerabilityID": "GHSA-9999-8888-7777",
                        "Severity": "HIGH",
                        "Details": "JSON version.",
                    }
                ],
            )
            result = generate_dashboard_from_dir(data_dir)
            content = result.read_text(encoding="utf-8")
            self.assertIn("GHSA-9999-8888-7777", content)
            self.assertNotIn("GHSA-1111-2222-3333", content)

    def test_raises_filenotfounderror_for_missing_dir(self):
        """
        Raises FileNotFoundError when the directory does not exist.
        """
        with self.assertRaises(FileNotFoundError):
            generate_dashboard_from_dir(Path("/nonexistent/data/dir"))

    def test_raises_valueerror_when_no_data_files_found(self):
        """
        Raises ValueError when the directory contains no VISaR data files.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(ValueError):
                generate_dashboard_from_dir(Path(tmp_dir))


class TestPrepareDataset(unittest.TestCase):
    """
    Test cases for the _prepare_dataset function.
    """

    def _make_file(self, tmp_dir, stem):
        """Return a Path with the given stem inside tmp_dir (no file needed)."""
        return Path(tmp_dir) / f"{stem}.json"

    def test_unknown_severity_goes_to_other(self):
        """
        Severities outside CRITICAL/HIGH/MODERATE/LOW (e.g. NONE from the
        OSV API) are counted under OTHER and included in the total.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = self._make_file(tmp_dir, "20260320-test-repo_vulnids")
            ds = _prepare_dataset(
                p,
                [
                    Finding("GHSA-1111-2222-3333", "HIGH", "d1"),
                    Finding("GHSA-4444-5555-6666", "NONE", "d2"),
                ],
            )
            self.assertEqual(ds["counts"]["HIGH"], 1)
            self.assertEqual(ds["counts"]["OTHER"], 1)
            self.assertEqual(ds["total"], 2)

    def test_total_equals_sum_of_counts(self):
        """
        Total always equals sum(counts.values()) for any mix of severities.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = self._make_file(tmp_dir, "20260320-test-repo_vulnids")
            ds = _prepare_dataset(
                p,
                [
                    Finding("GHSA-1", "CRITICAL", "d"),
                    Finding("GHSA-2", "HIGH", "d"),
                    Finding("GHSA-3", "LOW", "d"),
                ],
            )
            self.assertEqual(ds["total"], sum(ds["counts"].values()))

    def test_iso_date_field_present_and_correct(self):
        """
        isoDate is formatted as YYYY-MM-DD from the filename date prefix.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = self._make_file(tmp_dir, "20260320-test-repo_vulnids")
            ds = _prepare_dataset(p, [])
            self.assertEqual(ds["isoDate"], "2026-03-20")

    def test_iso_date_matches_date_field(self):
        """
        isoDate and date represent the same calendar date, just different
        formats.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = self._make_file(tmp_dir, "20260101-owner-repo_vulnids")
            ds = _prepare_dataset(p, [])
            self.assertEqual(ds["isoDate"], "2026-01-01")
            self.assertEqual(ds["date"], "01 Jan 2026")


if __name__ == "__main__":
    unittest.main()
