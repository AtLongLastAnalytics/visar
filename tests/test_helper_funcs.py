"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

# Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: test-helper_funcs.py
Description: This module contains a test suite for functions in the
    helpers.helper_funcs module. The test suite for each function is contained
    in it's own class.
"""

# import testing libraries
import unittest
from unittest.mock import patch, Mock
from pathlib import Path
import tempfile
import csv
import datetime
import os

# Import standard libraries
import sys
import logging

logging.disable(logging.CRITICAL)

# Add the src/ directory to sys.path to import the module
sys.path.insert(0, './src')

from helpers.helper_funcs import (
    check_datafolder_exists,
    exit_with_error,
    extract_vulnerability_ids,
    format_filename,
    merge_items_with_slash,
    prepend_line,
    retry_call,
    validate_github_url,
    verify_github_token,
    write_vulnerability_details_to_csv)

from config import GITHUB_CONFIG


class TestCheckDataFolderExists(unittest.TestCase):
    """
    Test cases for the check_datafolder_exists function.
    """
    @patch("os.path.exists")
    @patch("os.makedirs")
    @patch("os.getcwd", return_value="/fake/home/current")
    def test_data_folder_already_exists(
        self, mock_getcwd, mock_makedirs, mock_exists
    ):
        """
        Folder exists. Does not need to call os.makedirs.
        """
        # Setup the mock to indicate that the folder exists.
        mock_exists.return_value = True

        # Call the function under test.
        check_datafolder_exists()

        # Assert that os.makedirs was never invoked.
        mock_makedirs.assert_not_called()

    @patch("os.path.exists")
    @patch("os.makedirs")
    @patch("os.getcwd", return_value="/fake/home/current")
    def test_data_folder_created_when_missing(
        self, mock_getcwd, mock_makedirs, mock_exists
    ):
        """
        Folder does not exist. Attempt to create the folder using os.makedirs.
        """
        # Setup the mock to indicate that the folder does not exist.
        mock_exists.return_value = False

        # Call the function under test.
        check_datafolder_exists()

        # The function computes the data folder by determining the current
        # working directory's parent and joining it with "data".
        parent_dir = os.path.abspath(os.path.join("/fake/home/current", ".."))
        expected_path = os.path.join(parent_dir, "data")

        # Assert that os.makedirs was called once with the expected path.
        mock_makedirs.assert_called_once_with(expected_path)


class TestExitWithError(unittest.TestCase):
    """
    Test cases for the exit_with_error function.
    """
    @patch("helpers.helper_funcs.logger.error")
    @patch("helpers.helper_funcs.sys.exit")
    def test_exitwitherror_defaultcode(self, mock_exit, mock_logger_error):
        """
        Logs error message and exits with default code (1).
        """
        error_message = "Test error"

        # Call the function with the default exit code.
        exit_with_error(error_message)

        # Assert that logger.error was called once with relevant error message.
        mock_logger_error.assert_called_once_with(error_message)
        # Assert that sys.exit was called once with the default code 1.
        mock_exit.assert_called_once_with(1)

    @patch("helpers.helper_funcs.logger.error")
    @patch("helpers.helper_funcs.sys.exit")
    def test_exitwitherror_customcode(self, mock_exit, mock_logger_error):
        """
        Logs error message and exits with a provided custom exit code.
        """
        error_message = "Another test error"
        custom_code = 2

        # Call the function with a custom exit code.
        exit_with_error(error_message, custom_code)

        # Assert logger.error is called with the proper message.
        mock_logger_error.assert_called_once_with(error_message)
        # Assert sys.exit is called with the custom exit code.
        mock_exit.assert_called_once_with(custom_code)


class TestExtractVulnerabilityIds(unittest.TestCase):
    """
    Test cases for the extract_vulnerability_ids function.
    """
    def test_no_ids_found(self):
        """
        When no vulnerability IDs are in the input, an empty list is returned.
        """
        input_str = "No vulnerabilities found in this update."
        result = extract_vulnerability_ids(input_str)
        self.assertEqual(result, [])

    def test_single_pysec_id(self):
        """
        A single valid PYSEC vulnerability ID is correctly extracted.
        """
        input_str = "The vulnerability PYSEC-TEST-123 was detected."
        # "TEST" is 4 alphanumeric characters and "123" is between 2 and 5
        # characters.
        expected = ["PYSEC-TEST-123"]
        result = extract_vulnerability_ids(input_str)
        self.assertEqual(result, expected)

    def test_single_ghsa_id(self):
        """
        A single valid GHSA vulnerability ID is correctly extracted.
        """
        input_str = "An issue was reported: GHSA-ABCD-EFGH-IJKL."
        expected = ["GHSA-ABCD-EFGH-IJKL"]
        result = extract_vulnerability_ids(input_str)
        self.assertEqual(result, expected)

    def test_multiple_ids(self):
        """
        Multiple vulnerability IDs in the input string are all correctly
        extracted and that their order is preserved.
        """
        input_str = ("Multiple issues: PYSEC-QWER-12, GHSA-ZXCV-ASDF-QWER, "
                     "and PYSEC-IOPL-34567 / were detected.")
        # Expected matches include the optional trailing ' /' on last PYSEC ID.
        expected = [
                "PYSEC-QWER-12",
                "GHSA-ZXCV-ASDF-QWER",
                "PYSEC-IOPL-34567 /",
        ]
        result = extract_vulnerability_ids(input_str)
        self.assertEqual(result, expected)

    def test_edge_case_with_trailing_delimiter(self):
        """
        A PYSEC vulnerability ID with the optional trailing " /" is
        captured correctly.
        """
        input_str = "Edge case encountered: PYSEC-ABCD-12 /"
        expected = ["PYSEC-ABCD-12 /"]
        result = extract_vulnerability_ids(input_str)
        self.assertEqual(result, expected)


# Define a custom datetime subclass that returns a fixed date.
class FixedDatetime(datetime.datetime):
    @classmethod
    def today(cls):
        return cls(2025, 5, 3)


class TestFormatFilename(unittest.TestCase):
    """
    Test cases for the format_filename function.
    """
    @patch('helpers.helper_funcs.datetime', new=FixedDatetime)
    def test_formatfilename_basic(self):
        """
        A standard GitHub repository URL is correctly formatted.
        Expected: "20250503-username-repository"
        """
        repo_url = "https://github.com/username/repository"
        expected_filename = "20250503-username-repository"
        result = format_filename(repo_url)
        self.assertEqual(result, expected_filename)

    @patch('helpers.helper_funcs.datetime', new=FixedDatetime)
    def test_formatfilename_trailingslash(self):
        """
        A GitHub URL with a trailing slash is formatted correctly.
        Expected: "20250503-username-repository-"
        """
        repo_url = "https://github.com/username/repository/"
        expected_filename = "20250503-username-repository-"
        result = format_filename(repo_url)
        self.assertEqual(result, expected_filename)

    @patch('helpers.helper_funcs.datetime', new=FixedDatetime)
    def test_formatfilename_multiplesegments(self):
        """
        A GitHub URL with multiple path segments is formatted
        correctly.
        Expected: "20250503-username-subdir-repository"
        """
        repo_url = "https://github.com/username/subdir/repository"
        expected_filename = "20250503-username-subdir-repository"
        result = format_filename(repo_url)
        self.assertEqual(result, expected_filename)

    @patch('helpers.helper_funcs.datetime', new=FixedDatetime)
    def test_formatfilename_emptypath(self):
        """
        A URL with no repository path returns the date only.
        Expected: "20250503-"
        """
        repo_url = "https://github.com"
        expected_filename = "20250503-"
        result = format_filename(repo_url)
        self.assertEqual(result, expected_filename)


class TestMergeItemsWithSlash(unittest.TestCase):
    """
    Test cases for the merge_items_with_slash function.
    """
    def test_mergeitemswithslash_emptylist(self):
        """
        An empty list returns an empty list.
        """
        input_list = []
        expected = []
        result = merge_items_with_slash(input_list)
        self.assertEqual(result, expected)

    def test_mergeitemswithslash_nomergecandidates(self):
        """
        A list with no items ending with ' /' is returned unchanged.
        """
        input_list = ["Hello", "world", "Test"]
        expected = ["Hello", "world", "Test"]
        result = merge_items_with_slash(input_list)
        self.assertEqual(result, expected)

    def test_mergeitemswithslash_singlemerge(self):
        """
        An item ending with ' /' and followed by another, are merged.
        """
        input_list = ["Hello /", "world"]
        expected = ["Hello / world"]
        result = merge_items_with_slash(input_list)
        self.assertEqual(result, expected)

    def test_mergeitemswithslash_multiplemerges(self):
        """
        Multiple merge candidates within a list are correctly merged.
        """
        input_list = ["a /", "b", "c /", "d", "e"]
        expected = ["a / b", "c / d", "e"]
        result = merge_items_with_slash(input_list)
        self.assertEqual(result, expected)

    def test_mergeitemswithslash_trailingmergewithoutpartner(self):
        """
        An item ending with ' /' and no following partner is added unchanged.
        """
        input_list = ["a", "b /"]
        expected = ["a", "b /"]
        result = merge_items_with_slash(input_list)
        self.assertEqual(result, expected)

    def test_mergeitemswithslash_mixedmergeandnomerge(self):
        """
        A mix of merge candidates and non-merge items are processed correctly.
        """
        input_list = ["alpha", "b /", "gamma", "delta /", "epsilon", "zeta"]
        expected = ["alpha", "b / gamma", "delta / epsilon", "zeta"]
        result = merge_items_with_slash(input_list)
        self.assertEqual(result, expected)


class TestPrependLine(unittest.TestCase):
    """
    Test cases for the format_filename function.
    """
    def test_prependline_nonemptyfile(self):
        """
        A line is appended to the top of a non-empty file.
        """
        # Create a temporary directory and file
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "test_file.txt"
            original_content = "original content"
            # Write initial content to the file.
            file_path.write_text(original_content)

            # The line to prepend.
            prepend_text = "NEW LINE"
            # Call the function to prepend the line.
            prepend_line(file_path, prepend_text)

            # Read back the file content.
            updated_content = file_path.read_text()
            expected = f"{prepend_text}\n{original_content}"
            self.assertEqual(updated_content, expected)

    def test_prependline_emptyfile(self):
        """
        A line is appended to the top of an empty file.
        """
        # Create a temporary directory and file.
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "empty_file.txt"
            # Create an empty file.
            file_path.write_text("")

            prepend_text = "HEADER"
            prepend_line(file_path, prepend_text)

            updated_content = file_path.read_text()
            expected = f"{prepend_text}\n"
            self.assertEqual(updated_content, expected)


class TestRetryCall(unittest.TestCase):
    """
    Test cases for the retry_call function.
    """
    @patch("helpers.helper_funcs.time.sleep")
    @patch("helpers.helper_funcs.logger.warning")
    def test_retrycall_immediatesuccess(
        self, mock_logger_warning, mock_sleep
    ):
        """
        Result is returned immediately when the function succeeds on first try.
        """
        def successful_func():
            return "success"

        result = retry_call(successful_func)
        self.assertEqual(result, "success")
        mock_logger_warning.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("helpers.helper_funcs.time.sleep")
    @patch("helpers.helper_funcs.logger.warning")
    def test_retrycall_eventualsuccess(
        self, mock_logger_warning, mock_sleep
    ):
        """
        Retries once after failure and then succeeds.
        """
        mock_func = Mock(side_effect=[Exception("fail"), "eventual success"])
        mock_func.__name__ = "mock_function"  # Fix: Assign a name for logging

        result = retry_call(mock_func)
        self.assertEqual(result, "eventual success")
        self.assertEqual(mock_logger_warning.call_count, 1)
        self.assertEqual(mock_sleep.call_count, 1)
        self.assertEqual(mock_func.call_count, 2)

    @patch("helpers.helper_funcs.time.sleep")
    @patch("helpers.helper_funcs.logger.warning")
    def test_retrycall_allfail(self, mock_logger_warning, mock_sleep):
        """
        Last exception is raised when all attempts fail.
        """
        mock_func = Mock(side_effect=Exception("always fails"))
        mock_func.__name__ = "mock_function"  # Fix: Assign a name for logging

        with self.assertRaises(Exception) as context:
            retry_call(mock_func, retries=3, delay=0)

        # Fix: Ensure exception message matches
        self.assertEqual(str(context.exception), "always fails")
        self.assertEqual(mock_logger_warning.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)
        self.assertEqual(mock_func.call_count, 3)


class TestValidateGithubURL(unittest.TestCase):
    """
    Test cases for the validate_github_url function.
    """
    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_basic(self, mock_logger_error):
        """
        Return True for a valid GitHub repo URL with basic format.
        """
        url = "https://github.com/username/repository"
        self.assertTrue(validate_github_url(url))
        mock_logger_error.assert_not_called()

    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_trailingslash(self, mock_logger_error):
        """
        Return True for a valid Github repo URL with a trailing slash.
        """
        url = "https://github.com/username/repository/"
        self.assertTrue(validate_github_url(url))
        mock_logger_error.assert_not_called()

    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_hyphensandunderscores(self, mock_logger_error):
        """
        Return True for a valid GitHub repo URL with hyphens and underscores.
        """
        # \w includes letters, digits, and underscore so this is valid.
        url = "https://github.com/user-name/repo_name"
        self.assertTrue(validate_github_url(url))
        mock_logger_error.assert_not_called()

    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_httpprotocol(self, mock_logger_error):
        """
        Return False for a Github repo URL using http and not https.
        """
        url = "http://github.com/username/repository"
        self.assertFalse(validate_github_url(url))
        mock_logger_error.assert_called_once_with(
            "Invalid GitHub URL: %s", url
        )

    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_wrongdomain(self, mock_logger_error):
        """
        Return False for a URL with a domain other than github.
        """
        url = "https://gitlab.com/username/repository"
        self.assertFalse(validate_github_url(url))
        mock_logger_error.assert_called_once_with(
            "Invalid GitHub URL: %s", url
        )

    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_missingrepository(self, mock_logger_error):
        """
        Return Flase for a URL with a username but missing the repository.
        """
        url = "https://github.com/username"
        self.assertFalse(validate_github_url(url))
        mock_logger_error.assert_called_once_with(
            "Invalid GitHub URL: %s", url
        )

    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_extrapathsegment(self, mock_logger_error):
        """
        Return False for a URL with extra path segments after the repository.
        """
        url = "https://github.com/username/repository/extra"
        self.assertFalse(validate_github_url(url))
        mock_logger_error.assert_called_once_with(
            "Invalid GitHub URL: %s", url
        )

    @patch('helpers.helper_funcs.logger.error')
    def test_validategithuburl_emptyurl(self, mock_logger_error):
        """
        Return False for an empty URL.
        """
        url = ""
        self.assertFalse(validate_github_url(url))
        mock_logger_error.assert_called_once_with(
            "Invalid GitHub URL: %s", url
        )


class TestVerifyGithubToken(unittest.TestCase):
    @patch('helpers.helper_funcs.requests.get')
    @patch('helpers.helper_funcs.logger.error')
    def test_verifygithubtoken_valid(
        self, mock_logger_error, mock_requests_get
    ):
        """
        Return True when the token is valid and has "public_repo" scope.
        """
        token = "valid_token"
        # Prepare a mock response with status code 200 and the required scope
        response_mock = Mock()
        response_mock.status_code = 200
        response_mock.headers = {'X-OAuth-Scopes': "repo, public_repo, gist"}
        mock_requests_get.return_value = response_mock

        result = verify_github_token(token)
        self.assertTrue(result)
        mock_logger_error.assert_not_called()

        expected_headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        expected_url = f"{GITHUB_CONFIG['BASE_URL']}/user"
        mock_requests_get.assert_called_once_with(
            expected_url, headers=expected_headers
        )

    @patch('helpers.helper_funcs.requests.get')
    @patch('helpers.helper_funcs.logger.error')
    def test_verifygithubtoken_missingscope(
        self, mock_logger_error, mock_requests_get
    ):
        """
        Return False when the response is 200 but is missing the "public_repo"
        scope.
        """
        token = "token_without_scope"
        response_mock = Mock()
        response_mock.status_code = 200
        # most common isse is for token ton be missing 'public_repo' scope
        response_mock.headers = {'X-OAuth-Scopes': "repo, gist"}
        mock_requests_get.return_value = response_mock

        result = verify_github_token(token)
        self.assertFalse(result)
        mock_logger_error.assert_called_once_with(
            "GitHub token missing 'public_repo' scope"
        )

    @patch('helpers.helper_funcs.requests.get')
    @patch('helpers.helper_funcs.logger.error')
    def test_verifygithubtoken_unauthorized(
        self, mock_logger_error, mock_requests_get
    ):
        """
        Return False when the API returns a 401 Unauthorized.
        """
        token = "invalid_token"
        response_mock = Mock()
        response_mock.status_code = 401
        response_mock.headers = {}
        mock_requests_get.return_value = response_mock

        result = verify_github_token(token)
        self.assertFalse(result)
        mock_logger_error.assert_called_once_with("GitHub API error: %s", 401)

    @patch('helpers.helper_funcs.requests.get')
    @patch('helpers.helper_funcs.logger.error')
    def test_verifygithubtoken_requestexception(
        self, mock_logger_error, mock_requests_get
    ):
        """
        Return False and logs an error when a RequestException occurs.
        """
        import requests
        token = "any_token"
        mock_requests_get.side_effect = requests.exceptions.RequestException(
            "Network error"
        )

        result = verify_github_token(token)
        self.assertFalse(result)
        # This verifies that an error was logged. Specific message content is
        # less important.
        mock_logger_error.assert_called_once()


class TestWriteVulnerabilityDetailsToCSV(unittest.TestCase):
    """
    Test cases for the write_vulnerability_details_to_csv function.
    """
    def test_writevulnerabilitydetailstocsv_success(self):
        """
        Successfully writes vulnerability data to a CSV file.
        """
        vuln_ids = ["VULN-001", "VULN-002"]
        details = ["Detail for VULN-001", "Detail for VULN-002"]
        severities = ["High", "Medium"]

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "test_output.csv"
            write_vulnerability_details_to_csv(
                vuln_ids, details, severities, output_file
            )

            with output_file.open("r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)

        expected_rows = [
            ["VulnerabilityID", "Severity", "Details"],
            ["VULN-001", "High", "Detail for VULN-001"],
            ["VULN-002", "Medium", "Detail for VULN-002"]
        ]

        self.assertEqual(rows, expected_rows)

    def test_write_vulnerability_details_to_csv_empty_input(self):
        """
        Writes only the headers when an empty list is provided.
        """
        vuln_ids, details, severities = [], [], []

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "empty_output.csv"
            write_vulnerability_details_to_csv(
               vuln_ids, details, severities, output_file
            )

            with output_file.open("r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)

        expected_rows = [["VulnerabilityID", "Severity", "Details"]]

        self.assertEqual(rows, expected_rows)


if __name__ == '__main__':
    unittest.main()
