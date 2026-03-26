"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

# Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: test-docker_funcs.py
Description: This module contains a test suite for functions in the
    helpers.docker_funcs module. The test suite for each function is
    contained in its own class.
"""

# import testing libraries
import unittest
from unittest.mock import patch, Mock

# import standard libraries
import docker
import subprocess
import sys

import logging

logging.disable(logging.CRITICAL)

# add the src/ directory to sys.path to import docker_funcs module
sys.path.insert(0, "./src")

from helpers.docker_funcs import (
    check_docker_isrunning,
    check_dockerimage_exists,
    format_docker_command,
    run_docker_command,
)


class TestCheckDockerIsRunning(unittest.TestCase):
    """
    Test cases for the check_docker_isrunning function.
    """

    @patch("helpers.docker_funcs.subprocess.run")
    def test_dockerisrunning_success(self, mock_run):
        """
        Returns True when docker info executes successfully.
        """
        # simulate a successful run command (no exception raised).
        mock_run.return_value = Mock(returncode=0)

        result = check_docker_isrunning()
        self.assertTrue(result)
        mock_run.assert_called_once_with(
            ["docker", "info"], check=True, capture_output=True
        )

    @patch("helpers.docker_funcs.subprocess.run")
    def test_dockerisrunning_calledprocesserror(self, mock_run):
        """
        Returns False when subprocess.run raises a CalledProcessError.
        """
        # simulate a CalledProcessError (docker not running).
        mock_run.side_effect = subprocess.CalledProcessError(1, ["docker", "info"])

        result = check_docker_isrunning()
        self.assertFalse(result)
        mock_run.assert_called_once_with(
            ["docker", "info"], check=True, capture_output=True
        )

    @patch("helpers.docker_funcs.subprocess.run")
    def test_dockerisrunning_filenotfound(self, mock_run):
        """
        Returns False when subprocess.run raises a FileNotFoundError.
        """
        # simulate Docker not installed or Docker missing from PATH.
        mock_run.side_effect = FileNotFoundError

        result = check_docker_isrunning()
        self.assertFalse(result)
        mock_run.assert_called_once_with(
            ["docker", "info"], check=True, capture_output=True
        )


class TestDockerImageExists(unittest.TestCase):
    """
    Test cases for the check_dockerimage_exists function.
    """

    @patch("docker.from_env")
    def test_checkdockerimageexists_true(self, mock_docker_client):
        """
        Return True when the Docker image exists
        """
        mock_client = mock_docker_client.return_value
        mock_client.images.get.return_value = Mock()
        self.assertTrue(check_dockerimage_exists("test_image"))
        mock_client.images.get.assert_called_with("test_image")

    @patch("docker.from_env")
    def test_checkdockerimageexists_imagenotfound(self, mock_docker_client):
        """
        Return False when the Docker image is not found.
        """
        mock_client = mock_docker_client.return_value
        mock_client.images.get.side_effect = docker.errors.ImageNotFound(
            "Image not found"
        )
        self.assertFalse(check_dockerimage_exists("test_image"))
        mock_client.images.get.assert_called_with("test_image")

    @patch("docker.from_env")
    def test_checkdockerimageexists_apierror(self, mock_docker_client):
        """
        Return False when an API error occurs.
        """
        mock_client = mock_docker_client.return_value
        mock_client.images.get.side_effect = docker.errors.APIError("API error")
        self.assertFalse(check_dockerimage_exists("test_image"))
        mock_client.images.get.assert_called_with("test_image")


class TestFormatDockerCommand(unittest.TestCase):
    """
    Test cases for the format_docker_command function.
    """

    def test_formatdockercommand_summary(self):
        """
        Test format_docker_command generates the correct command for summary.
        """
        repo_url = "https://github.com/example/repo.git"
        github_token = "abc123"
        container_name = "example/container"
        expected_command = [
            "docker",
            "run",
            "--rm",
            "-e",
            "GITHUB_AUTH_TOKEN=abc123",
            "example/container",
            "--repo",
            "https://github.com/example/repo.git",
        ]
        actual_command = format_docker_command(repo_url, github_token, container_name)
        self.assertEqual(expected_command, actual_command)

    def test_formatdockercommand_vulnerabilities(self):
        """
        Test format_docker_command generates the correct command for
        vulnerability information.
        """
        repo_url = "https://github.com/example/repo.git"
        github_token = "abc123"
        container_name = "example/container"
        expected_command = [
            "docker",
            "run",
            "--rm",
            "-e",
            "GITHUB_AUTH_TOKEN=abc123",
            "example/container",
            "--repo",
            "https://github.com/example/repo.git",
            "--show-details",
            "--checks",
            "Vulnerabilities",
        ]
        actual_command = format_docker_command(
            repo_url, github_token, container_name, show_details=True
        )
        self.assertEqual(expected_command, actual_command)


class TestRunDockerCommand(unittest.TestCase):
    """
    Test cases for the run_docker_command function.
    """

    @patch("helpers.docker_funcs.subprocess.run")
    def test_rundockercommand_success(self, mock_subprocess_run):
        """
        Returns True when subprocess.run completes successfully.
        """
        mock_result = Mock()
        mock_result.stdout = ""
        mock_subprocess_run.return_value = mock_result
        command = ["docker", "run", "example/container"]
        self.assertTrue(run_docker_command(command))
        mock_subprocess_run.assert_called_with(
            command, text=True, capture_output=True, check=True
        )

    @patch("helpers.docker_funcs.subprocess.run")
    def test_rundockercommand_writes_output_file(self, mock_subprocess_run):
        """
        Writes stdout to output_file when provided.
        """
        import tempfile
        from pathlib import Path

        mock_result = Mock()
        mock_result.stdout = "scan output"
        mock_subprocess_run.return_value = mock_result
        command = ["docker", "run", "example/container"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            out_path = Path(f.name)
        try:
            run_docker_command(command, output_file=out_path)
            self.assertEqual(out_path.read_text(encoding="utf-8"), "scan output")
        finally:
            out_path.unlink(missing_ok=True)

    @patch("helpers.docker_funcs.subprocess.run")
    def test_rundockercommand_subprocesserror(self, mock_subprocess_run):
        """
        Returns False when subprocess.run raises a CalledProcessError.
        """
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["docker", "run"], output="Error output"
        )
        self.assertFalse(run_docker_command(["docker", "run"]))

    @patch("helpers.docker_funcs.subprocess.run")
    def test_rundockercommand_oserror(self, mock_subprocess_run):
        """
        Returns False when subprocess.run raises an OSError.
        """
        mock_subprocess_run.side_effect = OSError("OS error")
        self.assertFalse(run_docker_command(["docker", "run"]))

    @patch("helpers.docker_funcs.subprocess.run")
    def test_rundockercommand_unexpectederror(self, mock_subprocess_run):
        """
        Returns False when subprocess.run raises a generic Exception.
        """
        mock_subprocess_run.side_effect = Exception("Unexpected error")
        self.assertFalse(run_docker_command(["docker", "run"]))


if __name__ == "__main__":
    unittest.main()
