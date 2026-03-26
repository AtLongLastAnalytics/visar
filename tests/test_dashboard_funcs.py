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
import sys

logging.disable(logging.CRITICAL)

# add the src/ directory to sys.path to import the module
sys.path.insert(0, "./src")

from helpers.dashboard_funcs import (
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


def _make_dataset(label, vuln_ids, details, severities):
    """Build a minimal dataset dict for use in write_multi_dashboard tests."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
    sorted_rows = sorted(
        zip(vuln_ids, severities, details), key=lambda x: sev_order.get(x[1], 99)
    )
    counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "OTHER": 0}
    for _, sev, _ in sorted_rows:
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
        "rows": [{"id": v, "severity": s, "detail": d} for v, s, d in sorted_rows],
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
            "test (20 Mar 2026)", ["GHSA-1111-2222-3333"], ["Details."], ["HIGH"]
        )
        content = self._write_and_read([ds])
        self.assertIn("var DATASETS =", content)
        self.assertIn("GHSA-1111-2222-3333", content)

    def test_sorted_by_severity_within_dataset(self):
        """
        Rows in the embedded JSON appear in CRITICAL-first severity order.
        """
        ds = _make_dataset(
            "test", ["HIGH-1", "CRITICAL-1"], ["d", "d"], ["HIGH", "CRITICAL"]
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
            "repo-one (20 Mar 2026)", ["GHSA-1111-2222-3333"], ["d"], ["HIGH"]
        )
        ds2 = _make_dataset(
            "repo-two (20 Mar 2026)", ["GHSA-4444-5555-6666"], ["d"], ["LOW"]
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
            ["GHSA-1111-2222-3333"],
            ['</script><script>alert("xss")</script>'],
            ["HIGH"],
        )
        content = self._write_and_read([ds])
        # the dangerous closing tag must not appear unescaped in the output
        self.assertNotIn("</script><script>alert", content)
        # it must be present in its escaped form
        self.assertIn("<\\/script>", content)

    def test_dropdown_select_element_present(self):
        """
        Output contains the dataset dropdown select element.
        """
        content = self._write_and_read([])
        self.assertIn('id="dataset-select"', content)

    def test_date_filter_select_present(self):
        """
        Output contains the date filter select element.
        """
        content = self._write_and_read([])
        self.assertIn('id="date-filter"', content)


class TestReadCsvData(unittest.TestCase):
    """
    Test cases for the _read_csv_data function.
    """

    def test_reads_all_columns(self):
        """
        Returns the correct vuln_ids, details, and severities from a CSV file.
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
            vuln_ids, details, severities = _read_csv_data(tmp_path)
            self.assertEqual(vuln_ids, ["GHSA-1111-2222-3333", "GHSA-4444-5555-6666"])
            self.assertEqual(severities, ["HIGH", "LOW"])
            self.assertEqual(
                details, ["A high severity issue.", "A low severity issue."]
            )
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_empty_csv_returns_empty_lists(self):
        """
        A CSV with only a header row returns three empty lists.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8", newline=""
        ) as f:
            csv.writer(f).writerow(["VulnerabilityID", "Severity", "Details"])
            tmp_path = Path(f.name)
        try:
            vuln_ids, details, severities = _read_csv_data(tmp_path)
            self.assertEqual(vuln_ids, [])
            self.assertEqual(details, [])
            self.assertEqual(severities, [])
        finally:
            tmp_path.unlink(missing_ok=True)


class TestReadJsonData(unittest.TestCase):
    """
    Test cases for the _read_json_data function.
    """

    def test_reads_all_fields(self):
        """
        Returns the correct vuln_ids, details, and severities from a JSON file.
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
            vuln_ids, details, severities = _read_json_data(tmp_path)
            self.assertEqual(vuln_ids, ["GHSA-1111-2222-3333"])
            self.assertEqual(severities, ["CRITICAL"])
            self.assertEqual(details, ["Critical issue."])
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_empty_json_array_returns_empty_lists(self):
        """
        An empty JSON array returns three empty lists.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump([], f)
            tmp_path = Path(f.name)
        try:
            vuln_ids, details, severities = _read_json_data(tmp_path)
            self.assertEqual(vuln_ids, [])
            self.assertEqual(details, [])
            self.assertEqual(severities, [])
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
        Writes dashboard.html inside the data directory.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            self._write_csv(data_dir / "20260320-test-repo_vulnids.csv")
            result = generate_dashboard_from_dir(data_dir)
            self.assertEqual(result.name, "dashboard.html")
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
                ["GHSA-1111-2222-3333", "GHSA-4444-5555-6666"],
                ["d1", "d2"],
                ["HIGH", "NONE"],
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
                ["GHSA-1", "GHSA-2", "GHSA-3"],
                ["d", "d", "d"],
                ["CRITICAL", "HIGH", "LOW"],
            )
            self.assertEqual(ds["total"], sum(ds["counts"].values()))

    def test_iso_date_field_present_and_correct(self):
        """
        isoDate is formatted as YYYY-MM-DD from the filename date prefix.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = self._make_file(tmp_dir, "20260320-test-repo_vulnids")
            ds = _prepare_dataset(p, [], [], [])
            self.assertEqual(ds["isoDate"], "2026-03-20")

    def test_iso_date_matches_date_field(self):
        """
        isoDate and date represent the same calendar date, just different
        formats.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = self._make_file(tmp_dir, "20260101-owner-repo_vulnids")
            ds = _prepare_dataset(p, [], [], [])
            self.assertEqual(ds["isoDate"], "2026-01-01")
            self.assertEqual(ds["date"], "01 Jan 2026")


if __name__ == "__main__":
    unittest.main()
