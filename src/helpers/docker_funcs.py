"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: docker_funcs.py
Description: This module contains functions to:
    - Check Docker is running
    - Check if a Docker image exists locally
    - Run Docker commands using subprocess
"""

# import standard libraries
from pathlib import Path
from typing import List, Optional
import subprocess
import docker

# import helper functions and configuration
from helpers.logger_config import setup_logger

# Initialize logger
logger = setup_logger(__name__)


def check_docker_isrunning() -> bool:
    """
    Check if Docker is running on the local machine.

    This function attempts to execute "docker info" using subprocess. If this
    runs successfully, Docker is considered running. If the command fails an
    error is logged stating that Docker isn't running or isn't installed.

    Returns:
        bool: True if Docker is running, False otherwise.
    """
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        logger.error("Docker is not running - CalledProcessError")
        return False
    except FileNotFoundError:
        logger.error("Docker is not installed or not in PATH")
        return False


def check_dockerimage_exists(image_name: str) -> bool:
    """
    Check if a Docker image exists locally.

    This function queries for a Docker image using the Docker SDK for Python.
    If the image cannot be found or an API error occurs during the lookup,
    the error is logged.

    Args:
        image_name (str): The name of the Docker image to search for.

    Returns:
        bool: True if the Docker image exists locally, False otherwise.
    """
    client = docker.from_env()
    try:
        client.images.get(image_name)
        return True
    except docker.errors.ImageNotFound:
        logger.error("Docker image not found: %s", image_name)
        return False
    except docker.errors.APIError as e:
        logger.error("Docker API error: %s", e)
        return False
    finally:
        client.close()


def format_docker_command(
    repo_url: str, github_token: str, container_name: str, show_details: bool = False
) -> List[str]:
    """
    Format a Docker command using the provided parameters.

    Constructs a Docker run command that sets an environment variable for
    GitHub authentication, specifies the image name, and specifies the
    repository URL to be scanned. Optionally, if show_details is True, the
    command is appended with additional flags to generate vulnerability info.

    Args:
        repo_url (str): The URL of the repository to be scanned.
        github_token (str): The GitHub authentication token.
        container_name (str): The name of the Docker container or image.
        show_details (bool, optional): Flag to include detailed output flags.
            Defaults to False.

    Returns:
        List[str]: The constructed Docker command as a list of arguments.
    """
    command = [
        "docker",
        "run",
        "--rm",
        "-e",
        f"GITHUB_AUTH_TOKEN={github_token}",
        container_name,
        "--repo",
        repo_url,
    ]

    if show_details:
        command += ["--show-details", "--checks", "Vulnerabilities"]

    return command


def run_docker_command(command: List[str], output_file: Optional[Path] = None) -> bool:
    """
    Execute the specified Docker command using subprocess.

    This function runs a Docker command using subprocess. If the command
    executes successfully, stdout is optionally written to output_file.
    In case of errors such as subprocess.CalledProcessError, OSError, or any
    other exceptions, the errors are logged.

    Args:
        command (List[str]): The Docker command to be executed as a list of
            arguments.
        output_file (Optional[Path]): If provided, stdout is written to this
            file path. Defaults to None.

    Returns:
        bool: True if executed successfully; False if an error occurred.
    """
    try:
        logger.debug("Running Docker command")
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        if output_file is not None:
            output_file.write_text(result.stdout, encoding="utf-8")
        logger.debug("Docker command executed successfully")
        return True

    except subprocess.CalledProcessError as e:
        logger.exception("Subprocess error - Docker command execution: %s", e)
    except OSError as e:
        logger.exception("OS error during Docker command execution: %s", e)
    except Exception as e:
        logger.exception("Unexpected error - Docker command execution: %s", e)
    return False
