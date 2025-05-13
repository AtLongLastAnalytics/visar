"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

# Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: test-osv_funcs.py
Description: This module contains a test suite for functions in the
    helpers.osv_funcs module. The test suite for each function is contained in
    it's own class.
"""

# import testing libraries
import unittest
from unittest.mock import patch, Mock

# import standard libraries
import requests
import sys

import logging
logging.disable(logging.CRITICAL)

# Add the src/ directory to sys.path to import osv_funcs module
sys.path.insert(0, './src')

from config import OSV_CONFIG

from helpers.osv_funcs import (
    fetch_aliases,
    fetch_single_detail,
    fetch_details,
    update_idlist)


class TestFetchAliases(unittest.TestCase):
    """
    Test cases for the fetch_aliases function.
    """
    @patch('helpers.osv_funcs.session.get')
    def test_fetchaliases_success(self, mock_get):
        """
        Returns the list of aliases when the API call is successful.
        """
        vuln_id = "CVE-2020-1234"
        fake_aliases = ["ALIAS1", "ALIAS2"]
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'aliases': fake_aliases}
        mock_get.return_value = mock_response

        result = fetch_aliases(vuln_id)
        self.assertEqual(result, fake_aliases)
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vuln_id}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchaliases_noaliasesfound(self, mock_get):
        """
        Returns an empty list when the API call is successful but no aliases
        exist.
        """
        vuln_id = "CVE-2020-1234"
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}  # No 'aliases' key in JSON
        mock_get.return_value = mock_response

        result = fetch_aliases(vuln_id)
        self.assertEqual(result, [])
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vuln_id}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchaliases_non200response(self, mock_get):
        """
        Returns an empty list when the API response status code is not 200.
        """
        vuln_id = "CVE-2020-1234"
        mock_response = Mock()
        mock_response.status_code = 404  # Non-success status code
        mock_get.return_value = mock_response

        result = fetch_aliases(vuln_id)
        self.assertEqual(result, [])
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vuln_id}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchaliases_connectionerror(self, mock_get):
        """
        Returns an empty list when a ConnectionError occurs.
        """
        vuln_id = "CVE-2020-1234"
        mock_get.side_effect = ConnectionError("Connection failed")

        result = fetch_aliases(vuln_id)
        self.assertEqual(result, [])
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vuln_id}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchaliases_unexpectedexception(self, mock_get):
        """
        Returns an empty list when an unexpected exception occurs.
        """
        vuln_id = "CVE-2020-1234"
        mock_get.side_effect = Exception("Unexpected error")

        result = fetch_aliases(vuln_id)
        self.assertEqual(result, [])
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vuln_id}"
        mock_get.assert_called_once_with(expected_url)


class TestFetchDetails(unittest.TestCase):
    """
    Test cases for the fetch_details function.
    """
    @patch('helpers.osv_funcs.fetch_single_detail')
    def test_fetchdetails_emptylist(self, mock_fetch):
        """
        Returns empty lists when provided with an empty vulnerability list.
        """
        result = fetch_details([])
        self.assertEqual(result, ([], []))
        mock_fetch.assert_not_called()

    @patch('helpers.osv_funcs.fetch_single_detail')
    def test_fetchdetails_allsuccess(self, mock_fetch):
        """
        Returns correct lists when all vulnerability details are fetched
        successfully.
        """
        vuln_ids = ["vid1", "vid2"]
        # Simulate successful responses for each vulnerability ID.
        mock_fetch.side_effect = [
            ("detail1", "severity1"),
            ("detail2", "severity2")
        ]
        result = fetch_details(vuln_ids)
        self.assertEqual(result, (["detail1", "detail2"],
                                  ["severity1", "severity2"]))
        self.assertEqual(mock_fetch.call_count, 2)
        # Verify that each call received the correct vulnerability id.
        self.assertEqual(mock_fetch.call_args_list[0][0], ("vid1",))
        self.assertEqual(mock_fetch.call_args_list[1][0], ("vid2",))

    @patch('helpers.osv_funcs.fetch_single_detail')
    def test_fetchdetails_mixedresponses(self, mock_fetch):
        """
        Preserves the order of responses even when some vulnerability lookups
        return default values.
        """
        vuln_ids = ["vid1", "vid2", "vid3"]
        # Simulate a mix of successful and default responses.
        mock_fetch.side_effect = [
            ("detail1", "severity1"),  # For vid1
            # For vid2 (error/default)
            ("DETAILS NOT AVAILABLE", "SEVERITY NOT AVAILABLE"),
            ("detail3", "severity3")  # For vid3
        ]
        result = fetch_details(vuln_ids)
        self.assertEqual(result, (
            ["detail1", "DETAILS NOT AVAILABLE", "detail3"],
            ["severity1", "SEVERITY NOT AVAILABLE", "severity3"]
        ))
        self.assertEqual(mock_fetch.call_count, 3)
        # Optionally verify each call argument.
        self.assertEqual(mock_fetch.call_args_list[0][0], ("vid1",))
        self.assertEqual(mock_fetch.call_args_list[1][0], ("vid2",))
        self.assertEqual(mock_fetch.call_args_list[2][0], ("vid3",))


class TestFetchSingleDetail(unittest.TestCase):
    """
    Test cases for the fetch_single_detail function.
    """
    @patch('helpers.osv_funcs.session.get')
    def test_fetchsingledetail_success(self, mock_get):
        """
        Returns vulnerability detail and severity when API returns HTTP 200.
        """
        vid = 'CVE-2020-1234'
        expected_detail = "Vulnerability detail info"
        expected_severity = "High"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'details': expected_detail,
            'database_specific': {
                'severity': expected_severity
            }
        }
        mock_get.return_value = mock_response

        result = fetch_single_detail(vid)
        self.assertEqual(result, (expected_detail, expected_severity))
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vid}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchsingledetail_nodetails(self, mock_get):
        """
        Returns default detail/severity values when API returns HTTP 200 but
        the JSON lacks keys.
        """
        vid = 'CVE-2020-1234'
        # With no 'details' key the function returns 'No details available'
        # With no 'database_specific' dict, severity default is 'NOT AVAILABLE'
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        result = fetch_single_detail(vid)
        self.assertEqual(result, ("No details available", "NOT AVAILABLE"))
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vid}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchsingledetail_apierror(self, mock_get):
        """
        Returns default values when the API response status code is not 200.
        """
        vid = 'CVE-2020-1234'
        mock_response = Mock()
        mock_response.status_code = 500  # Simulate an API error
        mock_get.return_value = mock_response

        result = fetch_single_detail(vid)
        self.assertEqual(result, ("DETAILS NOT AVAILABLE",
                                  "SEVERITY NOT AVAILABLE"))
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vid}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchsingledetail_withslash(self, mock_get):
        """
        Extracts the vulnerability id when the input contains a '/' delimiter.
        """
        # When vulnerability id contains '/ ', use part after the delimiter
        vid_input = "PREFIX/ CVE-2020-1234"
        expected_vid = "CVE-2020-1234"
        expected_detail = "Detail for CVE-2020-1234"
        expected_severity = "Medium"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'details': expected_detail,
            'database_specific': {'severity': expected_severity}
        }
        mock_get.return_value = mock_response

        result = fetch_single_detail(vid_input)
        self.assertEqual(result, (expected_detail, expected_severity))
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{expected_vid}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchsingledetail_requestexception(self, mock_get):
        """
        Returns default values when a RequestException occurs.
        """

        vid = 'CVE-2020-1234'
        mock_get.side_effect = requests.exceptions.RequestException(
            "Connection error"
        )

        result = fetch_single_detail(vid)
        self.assertEqual(result, ("DETAILS NOT AVAILABLE",
                                  "SEVERITY NOT AVAILABLE"))
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vid}"
        mock_get.assert_called_once_with(expected_url)

    @patch('helpers.osv_funcs.session.get')
    def test_fetchsingledetail_unexpectedexception(self, mock_get):
        """
        Returns default values when an unexpected exception occurs.
        """
        vid = 'CVE-2020-1234'
        mock_get.side_effect = Exception("Unexpected error")

        result = fetch_single_detail(vid)
        self.assertEqual(result, ("DETAILS NOT AVAILABLE",
                                  "SEVERITY NOT AVAILABLE"))
        expected_url = f"{OSV_CONFIG['OSV_API_URL']}/{vid}"
        mock_get.assert_called_once_with(expected_url)


class TestUpdateIdlist(unittest.TestCase):
    """
    Test cases for the update_idlist function.
    """
    @patch('helpers.osv_funcs.fetch_aliases')
    def test_updateidlist_nonpysec(self, mock_fetch):
        """
        Any non-PYSEC IDs are left unchanged and fetch_aliases is not called.
        """
        input_ids = ["CVE-2020-1234"]
        result = update_idlist(input_ids)
        self.assertEqual(result, input_ids)
        mock_fetch.assert_not_called()

    @patch('helpers.osv_funcs.fetch_aliases')
    def test_updateidlist_pysecnoalias(self, mock_fetch):
        """
        Any PYSEC ID with no fetched aliases returns the original ID.
        """
        input_ids = ["PYSEC001"]
        mock_fetch.return_value = []  # No aliases found
        result = update_idlist(input_ids)
        self.assertEqual(result, ["PYSEC001"])
        mock_fetch.assert_called_once_with("PYSEC001")

    @patch('helpers.osv_funcs.fetch_aliases')
    def test_updateidlist_pysec_nomatchingalias(self, mock_fetch):
        """
        Any PYSEC ID with aliases returned but none starting with 'GHSA' is not
        updated.
        """
        input_ids = ["PYSEC002"]
        mock_fetch.return_value = ["ALIAS-001"]  # Alias does not match 'GHSA'
        result = update_idlist(input_ids)
        self.assertEqual(result, ["PYSEC002"])
        mock_fetch.assert_called_once_with("PYSEC002")

    @patch('helpers.osv_funcs.fetch_aliases')
    def test_updateidlist_pysecmatchingalias(self, mock_fetch):
        """
        Any PYSEC ID is updated when fetch_aliases returns an alias starting
        with 'GHSA'.
        """
        input_ids = ["PYSEC003"]
        mock_fetch.return_value = ["ALIAS-001", "GHSA-5678", "GHSA-9999"]
        result = update_idlist(input_ids)
        self.assertEqual(result, ["PYSEC003 / GHSA-5678"])
        mock_fetch.assert_called_once_with("PYSEC003")

    def test_updateidlist_alreadyupdated(self):
        """
        Any ID already containing an alias (with ' / ') is left unchanged.
        """
        input_ids = ["PYSEC004 / GHSA-1234"]
        result = update_idlist(input_ids)
        self.assertEqual(result, ["PYSEC004 / GHSA-1234"])

    @patch('helpers.osv_funcs.fetch_aliases')
    def test_updateidlistmixedids(self, mock_fetch):
        """
        Any mixed list of vulnerability IDs is processed correctly while
        preserving order.
        """
        input_ids = ["PYSEC005", "CVE-2020-1234", "PYSEC006"]

        # Setup side effect: fetch_aliases for each PYSEC ID returns different
        # responses.
        def side_effect(vid):
            if vid == "PYSEC005":
                return ["ALIAS-002"]  # No matching alias
            elif vid == "PYSEC006":
                return ["GHSA-7777"]  # Matching alias found
        mock_fetch.side_effect = side_effect

        result = update_idlist(input_ids)
        expected = ["PYSEC005", "CVE-2020-1234", "PYSEC006 / GHSA-7777"]
        self.assertEqual(result, expected)
        # Ensure fetch_aliases is called only for PYSEC005 and PYSEC006
        self.assertEqual(mock_fetch.call_count, 2)


if __name__ == '__main__':
    unittest.main()
