"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: docker_funcs.py
Description: This module contains functions to:
    - Check Docker is running
    - Check if a Docker image exists locally
    - Run Docker commands using subprocess
"""

# import standard libraries
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


def format_docker_command(repo_url: str,
                          github_token: str,
                          container_name: str,
                          show_details: bool = False) -> str:
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
        str: The constructed Docker command.
    """
    base_command = (
        f"docker run -e GITHUB_AUTH_TOKEN={github_token} {container_name} "
        f"--repo {repo_url}"
    )

    if show_details:
        base_command += " --show-details --checks Vulnerabilities"

    return base_command


def run_docker_command(command: str) -> bool:
    """
    Execute the specified Docker command using subprocess.

    This function runs a Docker command using subprocess. If the
    command executes successfully (i.e., returns a 0 exit code), the function
    logs success. In case of errors such as subprocess.CalledProcessError,
    OSError, or any other exceptions, the errors are logged.

    Args:
        command (str): The Docker command to be executed.

    Returns:
        bool: True if executed successfully; False if an error occurred.
    """
    try:
        logger.debug("Running Docker command")
        result = subprocess.run(command, shell=True, text=True,
                                capture_output=True, check=True)

        if result.returncode == 0:
            logger.debug("Docker command executed successfully")
            return True
        else:
            logger.error(
                "Docker command failed with return code %s",
                result.returncode
            )
            logger.error(
                "Error Output: %s",
                result.stderr
            )
            return False

    except subprocess.CalledProcessError as e:
        logger.exception("Subprocess error - Docker command execution: %s", e)
    except OSError as e:
        logger.exception("OS error during Docker command execution: %s", e)
    except Exception as e:
        logger.exception("Unexpected error - Docker command execution: %s", e)
    return False
