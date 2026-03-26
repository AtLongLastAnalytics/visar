"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: test_main.py
Description: This module contains a test suite for functions in main.py.
    The test suite for each function is contained in its own class.
"""

# import testing libraries
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

import logging

logging.disable(logging.CRITICAL)

# add the src/ directory to sys.path to import main module
sys.path.insert(0, "./src")

import main
from main import (
    cleanup_temp_files,
    call_osv_api,
    execute_docker_commands,
    perform_data_transformation,
    print_batch_summary,
    run_prerequisite_checks,
    scan_single_repository,
    write_output,
)


class TestRunPrerequisiteChecks(unittest.TestCase):
    """
    Test cases for the run_prerequisite_checks function.
    """

    @patch("main.dof.check_dockerimage_exists", return_value=True)
    @patch("main.dof.check_docker_isrunning", return_value=True)
    @patch("main.hf.check_datafolder_exists")
    @patch("main.hf.verify_github_token", return_value=True)
    @patch("main.hf.validate_github_url", return_value=True)
    def test_all_checks_pass(
        self, mock_url, mock_token, mock_folder, mock_docker, mock_image
    ):
        """
        No exit is called when all prerequisite checks pass.
        """
        run_prerequisite_checks("https://github.com/u/r", "token123")
        mock_url.assert_called_once_with("https://github.com/u/r")
        mock_token.assert_called_once_with("token123")
        mock_docker.assert_called_once()
        mock_image.assert_called_once()
        mock_folder.assert_called_once()

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.hf.validate_github_url", return_value=False)
    def test_invalid_url_exits(self, mock_url, mock_exit):
        """
        exit_with_error is called when the GitHub URL is invalid.
        """
        with self.assertRaises(SystemExit):
            run_prerequisite_checks("not-a-url", "token")
        mock_exit.assert_called_once()

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.hf.verify_github_token", return_value=False)
    @patch("main.hf.validate_github_url", return_value=True)
    def test_invalid_token_exits(self, mock_url, mock_token, mock_exit):
        """
        exit_with_error is called when the GitHub token is invalid.
        """
        with self.assertRaises(SystemExit):
            run_prerequisite_checks("https://github.com/u/r", "badtoken")
        mock_exit.assert_called_once()

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.dof.check_docker_isrunning", return_value=False)
    @patch("main.hf.verify_github_token", return_value=True)
    @patch("main.hf.validate_github_url", return_value=True)
    def test_docker_not_running_exits(
        self, mock_url, mock_token, mock_docker, mock_exit
    ):
        """
        exit_with_error is called when Docker is not running.
        """
        with self.assertRaises(SystemExit):
            run_prerequisite_checks("https://github.com/u/r", "token")
        mock_exit.assert_called_once()

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.dof.check_dockerimage_exists", return_value=False)
    @patch("main.dof.check_docker_isrunning", return_value=True)
    @patch("main.hf.verify_github_token", return_value=True)
    @patch("main.hf.validate_github_url", return_value=True)
    def test_docker_image_missing_exits(
        self, mock_url, mock_token, mock_docker, mock_image, mock_exit
    ):
        """
        exit_with_error is called when the Docker image does not exist locally.
        """
        with self.assertRaises(SystemExit):
            run_prerequisite_checks("https://github.com/u/r", "token")
        mock_exit.assert_called_once()


class TestExecuteDockerCommands(unittest.TestCase):
    """
    Test cases for the execute_docker_commands function.
    """

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.hf.retry_call", return_value=False)
    @patch("main.dof.format_docker_command", return_value=["docker", "run"])
    def test_summary_command_fails_exits(self, mock_format, mock_retry, mock_exit):
        """
        exit_with_error is called when the summary Docker command fails.
        """
        with self.assertRaises(SystemExit):
            execute_docker_commands(
                "https://github.com/u/r", "token", Path("/tmp/summary.txt")
            )
        mock_exit.assert_called_once()

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.hf.retry_call", side_effect=[True, False])
    @patch("main.dof.format_docker_command", return_value=["docker", "run"])
    def test_details_command_fails_exits(self, mock_format, mock_retry, mock_exit):
        """
        exit_with_error is called when the detailed Docker command fails.
        """
        with self.assertRaises(SystemExit):
            execute_docker_commands(
                "https://github.com/u/r", "token", Path("/tmp/summary.txt")
            )
        mock_exit.assert_called_once()

    @patch("main.hf.exit_with_error")
    @patch("main.hf.retry_call", return_value=True)
    @patch("main.dof.format_docker_command", return_value=["docker", "run"])
    def test_both_commands_succeed(self, mock_format, mock_retry, mock_exit):
        """
        No exit is called when both Docker commands succeed.
        """
        execute_docker_commands(
            "https://github.com/u/r", "token", Path("/tmp/summary.txt")
        )
        mock_exit.assert_not_called()


class TestPerformDataTransformation(unittest.TestCase):
    """
    Test cases for the perform_data_transformation function.
    """

    @patch("main.osv.update_idlist", return_value=["GHSA-1111-2222-3333"])
    @patch("main.hf.merge_items_with_slash", return_value=["GHSA-1111-2222-3333"])
    @patch("main.hf.extract_vulnerability_ids", return_value=["GHSA-1111-2222-3333"])
    @patch("main.hf.prepend_line")
    def test_success_returns_vuln_ids(
        self, mock_prepend, mock_extract, mock_merge, mock_update
    ):
        """
        Returns processed vuln_ids on the happy path.
        """
        import tempfile as _tempfile

        with _tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("GHSA-1111-2222-3333")
            tmp_path = Path(f.name)
        try:
            with patch("main.TEMP_FILE", tmp_path):
                result = perform_data_transformation(
                    "https://github.com/u/r", Path("/tmp/summary.txt")
                )
            self.assertEqual(result, ["GHSA-1111-2222-3333"])
        finally:
            tmp_path.unlink(missing_ok=True)

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.cleanup_temp_files")
    @patch("main.TEMP_FILE")
    def test_temp_file_missing_exits(self, mock_temp, mock_cleanup, mock_exit):
        """
        exit_with_error is called when TEMP_FILE does not exist.
        """
        mock_temp.exists.return_value = False
        with self.assertRaises(SystemExit):
            perform_data_transformation(
                "https://github.com/u/r", Path("/tmp/summary.txt")
            )
        mock_exit.assert_called_once()

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.cleanup_temp_files")
    @patch("main.hf.prepend_line", side_effect=FileNotFoundError)
    @patch("main.hf.extract_vulnerability_ids", return_value=[])
    @patch("main.hf.merge_items_with_slash", return_value=[])
    def test_file_not_found_exception_exits(
        self, mock_merge, mock_extract, mock_prepend, mock_cleanup, mock_exit
    ):
        """
        cleanup and exit_with_error are called on FileNotFoundError.
        """
        import tempfile as _tempfile

        with _tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            tmp_path = Path(f.name)
        try:
            with patch("main.TEMP_FILE", tmp_path):
                with self.assertRaises(SystemExit):
                    perform_data_transformation(
                        "https://github.com/u/r", Path("/tmp/summary.txt")
                    )
            mock_cleanup.assert_called_once()
            mock_exit.assert_called_once()
        finally:
            tmp_path.unlink(missing_ok=True)

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.cleanup_temp_files")
    @patch("main.hf.prepend_line", side_effect=Exception("unexpected"))
    @patch("main.hf.extract_vulnerability_ids", return_value=[])
    @patch("main.hf.merge_items_with_slash", return_value=[])
    def test_unexpected_exception_exits(
        self, mock_merge, mock_extract, mock_prepend, mock_cleanup, mock_exit
    ):
        """
        cleanup and exit_with_error are called on unexpected exceptions.
        """
        import tempfile as _tempfile

        with _tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            tmp_path = Path(f.name)
        try:
            with patch("main.TEMP_FILE", tmp_path):
                with self.assertRaises(SystemExit):
                    perform_data_transformation(
                        "https://github.com/u/r", Path("/tmp/summary.txt")
                    )
            mock_cleanup.assert_called_once()
            mock_exit.assert_called_once()
        finally:
            tmp_path.unlink(missing_ok=True)


class TestCallOsvApi(unittest.TestCase):
    """
    Test cases for the call_osv_api function.
    """

    @patch("main.hf.retry_call", return_value=(["detail"], ["HIGH"]))
    def test_success_returns_tuple(self, mock_retry):
        """
        Returns (details, severities) tuple on success.
        """
        details, severities = call_osv_api(["GHSA-1111-2222-3333"])
        self.assertEqual(details, ["detail"])
        self.assertEqual(severities, ["HIGH"])

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.cleanup_temp_files")
    @patch("main.hf.retry_call", side_effect=Exception("OSV error"))
    def test_exception_exits(self, mock_retry, mock_cleanup, mock_exit):
        """
        cleanup and exit_with_error are called when retry_call raises.
        """
        with self.assertRaises(SystemExit):
            call_osv_api(["GHSA-1111-2222-3333"])
        mock_cleanup.assert_called_once()
        mock_exit.assert_called_once()


class TestWriteOutput(unittest.TestCase):
    """
    Test cases for the write_output function.
    """

    @patch("main.hf.write_vulnerability_details_to_csv")
    def test_csv_format_calls_csv_writer(self, mock_writer):
        """
        The CSV writer is called with a path ending in _vulnids.csv.
        """
        write_output("20260320-user-repo", ["ID"], ["det"], ["HIGH"], "csv")
        mock_writer.assert_called_once()
        output_path = mock_writer.call_args[0][3]
        self.assertTrue(str(output_path).endswith("_vulnids.csv"))

    @patch("main.hf.write_vulnerability_details_to_json")
    def test_json_format_calls_json_writer(self, mock_writer):
        """
        The JSON writer is called with a path ending in _vulnids.json.
        """
        write_output("20260320-user-repo", ["ID"], ["det"], ["HIGH"], "json")
        mock_writer.assert_called_once()
        output_path = mock_writer.call_args[0][3]
        self.assertTrue(str(output_path).endswith("_vulnids.json"))

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.cleanup_temp_files")
    @patch(
        "main.hf.write_vulnerability_details_to_csv",
        side_effect=Exception("write error"),
    )
    def test_exception_triggers_cleanup_and_exit(
        self, mock_writer, mock_cleanup, mock_exit
    ):
        """
        cleanup_temp_files and exit_with_error are called when writer raises.
        """
        with self.assertRaises(SystemExit):
            write_output("20260320-user-repo", ["ID"], ["det"], ["HIGH"], "csv")
        mock_cleanup.assert_called_once()
        mock_exit.assert_called_once()


class TestCleanupTempFiles(unittest.TestCase):
    """
    Test cases for the cleanup_temp_files function.
    """

    @patch("main.TEMP_FILE")
    def test_file_exists_is_unlinked(self, mock_temp):
        """
        unlink() is called when TEMP_FILE exists.
        """
        mock_temp.exists.return_value = True
        cleanup_temp_files()
        mock_temp.unlink.assert_called_once()

    @patch("main.TEMP_FILE")
    def test_file_not_exists_no_unlink(self, mock_temp):
        """
        unlink() is not called when TEMP_FILE does not exist.
        """
        mock_temp.exists.return_value = False
        cleanup_temp_files()
        mock_temp.unlink.assert_not_called()

    @patch("main.TEMP_FILE")
    def test_unlink_exception_logs_warning(self, mock_temp):
        """
        An exception during unlink is caught and does not crash the pipeline.
        """
        mock_temp.exists.return_value = True
        mock_temp.unlink.side_effect = Exception("permission denied")
        # should not raise
        cleanup_temp_files()


class TestPrintBatchSummary(unittest.TestCase):
    """
    Test cases for the print_batch_summary function.
    """

    def test_all_succeeded(self):
        """
        Prints correct count with zero failures.
        """
        # should not raise; spot-check stdout via capturing
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_batch_summary(2, ["url1", "url2"], [])
        output = buf.getvalue()
        self.assertIn("2/2", output)
        self.assertNotIn("FAILED", output)

    def test_some_failed(self):
        """
        Failed URLs appear in the printed summary.
        """
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_batch_summary(2, ["url1"], ["url2"])
        output = buf.getvalue()
        self.assertIn("1/2", output)
        self.assertIn("FAILED: url2", output)

    def test_all_failed(self):
        """
        Prints zero succeeded when all URLs failed.
        """
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_batch_summary(2, [], ["url1", "url2"])
        output = buf.getvalue()
        self.assertIn("0/2", output)
        self.assertIn("FAILED: url1", output)
        self.assertIn("FAILED: url2", output)


class TestScanSingleRepository(unittest.TestCase):
    """
    Test cases for the scan_single_repository function.
    """

    def _patch_all(self, vuln_ids=None):
        """Helper: patch all pipeline sub-functions."""
        if vuln_ids is None:
            vuln_ids = ["GHSA-1111-2222-3333"]
        patches = {
            "run_prerequisite_checks": patch("main.run_prerequisite_checks"),
            "hf_format_filename": patch(
                "main.hf.format_filename", return_value="20260320-u-repo"
            ),
            "DATA_DIR": patch("main.DATA_DIR", new=Path("/tmp")),
            "execute_docker_commands": patch("main.execute_docker_commands"),
            "perform_data_transformation": patch(
                "main.perform_data_transformation", return_value=vuln_ids
            ),
            "call_osv_api": patch(
                "main.call_osv_api", return_value=(["detail"], ["HIGH"])
            ),
            "write_output": patch("main.write_output"),
            "cleanup_temp_files": patch("main.cleanup_temp_files"),
        }
        return patches

    def test_happy_path_csv(self):
        """
        Full pipeline runs for output_format='csv' without error.
        """
        patches = self._patch_all()
        mocks = {k: p.start() for k, p in patches.items()}
        try:
            scan_single_repository("https://github.com/u/r", "csv")
            mocks["write_output"].assert_called_once()
            _, _, _, _, fmt = mocks["write_output"].call_args[0]
            self.assertEqual(fmt, "csv")
        finally:
            for p in patches.values():
                p.stop()

    def test_happy_path_json(self):
        """
        Full pipeline runs for output_format='json'.
        """
        patches = self._patch_all()
        mocks = {k: p.start() for k, p in patches.items()}
        try:
            scan_single_repository("https://github.com/u/r", "json")
            _, _, _, _, fmt = mocks["write_output"].call_args[0]
            self.assertEqual(fmt, "json")
        finally:
            for p in patches.values():
                p.stop()

    def test_no_vulns_found_exits_zero(self):
        """
        When vuln_ids is empty, cleanup is called and sys.exit(0) is raised.
        """
        patches = self._patch_all(vuln_ids=[])
        mocks = {k: p.start() for k, p in patches.items()}
        try:
            with self.assertRaises(SystemExit) as ctx:
                scan_single_repository("https://github.com/u/r", "csv")
            self.assertEqual(ctx.exception.code, 0)
            mocks["cleanup_temp_files"].assert_called_once()
            mocks["write_output"].assert_not_called()
        finally:
            for p in patches.values():
                p.stop()

    def test_prerequisite_failure_propagates_systemexit(self):
        """
        SystemExit from run_prerequisite_checks propagates to the caller.
        """
        with patch("main.run_prerequisite_checks", side_effect=SystemExit(1)):
            with self.assertRaises(SystemExit) as ctx:
                scan_single_repository("https://github.com/u/r", "csv")
            self.assertEqual(ctx.exception.code, 1)


class TestMain(unittest.TestCase):
    """
    Test cases for the main() function.
    """

    @patch("main.scan_single_repository")
    @patch("sys.argv", ["main.py", "https://github.com/u/r"])
    def test_single_mode_repo_url(self, mock_scan):
        """
        scan_single_repository is called once with the repo URL and 'csv'.
        """
        with self.assertRaises(SystemExit) as ctx:
            main.main()
        mock_scan.assert_called_once_with("https://github.com/u/r", "csv")
        self.assertEqual(ctx.exception.code, 0)

    @patch("main.scan_single_repository")
    @patch("sys.argv", ["main.py", "https://github.com/u/r", "--output-format", "json"])
    def test_single_mode_with_json_format(self, mock_scan):
        """
        --output-format json passes 'json' to scan_single_repository.
        """
        with self.assertRaises(SystemExit):
            main.main()
        mock_scan.assert_called_once_with("https://github.com/u/r", "json")

    @patch("main.print_batch_summary")
    @patch("main.scan_single_repository")
    @patch(
        "main.hf.read_batch_file",
        return_value=["https://github.com/u/r1", "https://github.com/u/r2"],
    )
    @patch("sys.argv", ["main.py", "--batch", "repos.txt"])
    def test_batch_mode_all_success(self, mock_read, mock_scan, mock_summary):
        """
        Batch mode scans all repos and exits 0 when all succeed.
        """
        with self.assertRaises(SystemExit) as ctx:
            main.main()
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(mock_scan.call_count, 2)
        mock_summary.assert_called_once()
        total, succeeded, failed = mock_summary.call_args[0]
        self.assertEqual(total, 2)
        self.assertEqual(len(succeeded), 2)
        self.assertEqual(len(failed), 0)

    @patch("main.print_batch_summary")
    @patch("main.scan_single_repository", side_effect=[None, SystemExit(1)])
    @patch(
        "main.hf.read_batch_file",
        return_value=["https://github.com/u/r1", "https://github.com/u/r2"],
    )
    @patch("sys.argv", ["main.py", "--batch", "repos.txt"])
    def test_batch_mode_one_fails(self, mock_read, mock_scan, mock_summary):
        """
        When one URL fails, the other still scans and summary shows failure.
        """
        with self.assertRaises(SystemExit) as ctx:
            main.main()
        self.assertEqual(ctx.exception.code, 1)
        total, succeeded, failed = mock_summary.call_args[0]
        self.assertEqual(len(succeeded), 1)
        self.assertEqual(len(failed), 1)

    @patch("main.print_batch_summary")
    @patch("main.scan_single_repository", side_effect=SystemExit(0))
    @patch("main.hf.read_batch_file", return_value=["https://github.com/u/r1"])
    @patch("sys.argv", ["main.py", "--batch", "repos.txt"])
    def test_batch_mode_exit_zero_counts_as_success(
        self, mock_read, mock_scan, mock_summary
    ):
        """
        A SystemExit(0) from scan (no vulns found) counts as a success in
        batch mode.
        """
        with self.assertRaises(SystemExit) as ctx:
            main.main()
        self.assertEqual(ctx.exception.code, 0)
        total, succeeded, failed = mock_summary.call_args[0]
        self.assertEqual(len(succeeded), 1)
        self.assertEqual(len(failed), 0)

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.hf.read_batch_file", return_value=[])
    @patch("sys.argv", ["main.py", "--batch", "repos.txt"])
    def test_batch_mode_empty_file(self, mock_read, mock_exit):
        """
        exit_with_error is called when the batch file has no valid URLs.
        """
        with self.assertRaises(SystemExit):
            main.main()
        mock_exit.assert_called_once()

    @patch("main.hf.exit_with_error", side_effect=SystemExit(1))
    @patch("main.hf.read_batch_file", side_effect=FileNotFoundError)
    @patch("sys.argv", ["main.py", "--batch", "missing.txt"])
    def test_batch_mode_file_not_found(self, mock_read, mock_exit):
        """
        exit_with_error is called when the batch file does not exist.
        """
        with self.assertRaises(SystemExit):
            main.main()
        mock_exit.assert_called_once()

    @patch("sys.argv", ["main.py"])
    def test_neither_repo_url_nor_batch_exits(self):
        """
        Providing neither repo_url nor --batch causes a parser error (exit 2).
        """
        with self.assertRaises(SystemExit) as ctx:
            main.main()
        self.assertEqual(ctx.exception.code, 2)

    @patch("sys.argv", ["main.py", "https://github.com/u/r", "--batch", "repos.txt"])
    def test_both_repo_url_and_batch_exits(self):
        """
        Providing both repo_url and --batch causes a parser error (exit 2).
        """
        with self.assertRaises(SystemExit) as ctx:
            main.main()
        self.assertEqual(ctx.exception.code, 2)

    @patch("main.scan_single_repository")
    @patch("sys.argv", ["main.py", "https://github.com/u/r"])
    def test_default_output_format_is_csv(self, mock_scan):
        """
        When --output-format is not specified, 'csv' is used.
        """
        with self.assertRaises(SystemExit):
            main.main()
        _, fmt = mock_scan.call_args[0]
        self.assertEqual(fmt, "csv")


if __name__ == "__main__":
    unittest.main()
