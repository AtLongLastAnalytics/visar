"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: helper_funcs.py
Description: This module includes general purpose functions for data
transformation and file management.
"""

# import standard libraries
import csv
from datetime import datetime
import os
from pathlib import Path
import re
import requests
import sys
import time
from typing import Callable, List, Optional, Any, Union
from urllib.parse import urlparse

# import helper functions and configuration
from config import GITHUB_CONFIG
from helpers.logger_config import setup_logger

# initialize logger
logger = setup_logger(__name__)


def check_datafolder_exists():
    """
    Ensure the "data" folder exists in the root directory.

    This function checks if a folder named "data" exists in the root directory.
    If the folder doesn't exist, it creates the folder.

    Returns:
        None
    """

    # Get the absolute path for the root directory
    parent_dir = os.path.abspath(os.path.join(os.getcwd(), ".."))
    data_folder = os.path.join(parent_dir, "data")

    if not os.path.exists(data_folder):
        os.makedirs(data_folder)


def exit_with_error(message: str, code: int = 1) -> None:
    """
    Log an error message and exit the program with a specific non-zero code.

    This function logs the specified error message and then terminates the
    Python process with the provided exit code. This behavior ensures that
    automated systems/shell environments can detect that the script has failed.

    Args:
        message (str): The error message to log.
        code (int, optional): The exit code to use. Defaults to 1.
    """
    logger.error(message)
    sys.exit(code)


def extract_vulnerability_ids(input_string: str) -> Optional[List[str]]:
    """
    Extract vulnerability IDs from a given input string.

    This function uses a regular expression pattern to identify and extract all
    vulnerability IDs from the provided input string. The expected ID formats
    include "PYSEC-XXXX-XX" and "GHSA-XXXX-XXXX-XXXX". If matches are found, a
    list of vulnerability IDs is returned; else, an empty list is returned.

    Args:
        input_string (str): Input string that may contain vulnerability IDs.

    Returns:
        Optional[List[str]]: List of matched vulnerability IDs or an empty list
    """
    # define regex pattern of the two common vulnerability codes used by OSV
    vuln_id_pattern = r"(PYSEC-\w{4}-\w{2,5}(?: /)?|GHSA-\w{4}-\w{4}-\w{4})"

    # non-overlapping matches
    matches = re.findall(vuln_id_pattern, input_string)

    if matches:
        return list(matches)
    else:
        return []


def format_filename(repo_url: str) -> str:
    """
    Format a filename derived from a repository URL.

    This function parses the provided GitHub repository URL to generate a
    filename. Leading slashes are removed from the URL path and remaining
    slashes with hyphens. The current date (YYYYMMDD format) is prepended.

    Args:
        repo_url (str): The GitHub repository URL.

    Returns:
        str: The formatted filename.
    """
    parsed = urlparse(repo_url)
    # remove leading slash and replace slashes with hyphens
    formatted_path = parsed.path.lstrip('/').replace('/', '-')
    today_date = datetime.today().strftime('%Y%m%d')
    return f"{today_date}-{formatted_path}"


def merge_items_with_slash(input_list: List[str]) -> List[str]:
    """
    Merge consecutive items in a list when they are separated by a slash.

    This function iterates through the input list and checks if an item ends
    with " /". When this is true, the function merges the two consecutive
    items into one string separated by a space. Else, adds current item as is.

    Args:
        input_list (List[str]): The list of string items to merge.

    Returns:
        List[str]: A new list with merged results where applicable.
    """
    result = []
    i = 0
    while i < len(input_list):
        if input_list[i].endswith(" /") and i + 1 < len(input_list):
            result.append(f"{input_list[i]} {input_list[i + 1]}")
            i += 2
        else:
            result.append(input_list[i])
            i += 1
    return result


def prepend_line(file_path: Path, line: str) -> None:
    """
    Prepend a given line to the beginning of a file.

    This function reads the current content of the file specified by file_path,
    then writes a new file with the given line prepended to the original file.

    Args:
        file_path (Path): The path to the file.
        line (str): The line to prepend.
    """
    with file_path.open('r') as f:
        content = f.read()
    with file_path.open('w') as f:
        f.write(line + '\n' + content)


def retry_call(func: Callable, *args: Any, retries: int = 3,
               delay: Union[int, float] = 2, **kwargs: Any) -> Any:
    """
    Call a function and retry if an exception is encountered.

    This function attempts to call given function with the supplied arguments.
    If the function call raises an exception, it logs a warning and retries
    after a specified delay. The process is repeated up to the given number of
    retries. If all retries fail, the last exception is raised.

    Args:
        func (Callable): The function to be called.
        *args: Positional arguments to pass to the function.
        retries (int, optional): The number of retry attempts. Defaults to 3.
        delay (int or float, optional): The delay in seconds between retry
            attempts. Defaults to 2.
        **kwargs: Keyword arguments to pass to the function.

    Returns:
        Any: The result of the function call if it is successful.

    Raises:
        Exception: The last encountered exception if all retries fail.
    """
    for attempt in range(retries):
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            logger.warning(
                "Attempt %s for %s failed: %s",
                attempt + 1, func.__name__, e)
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise


def validate_github_url(url: str) -> bool:
    """
    Validate if the URL provided is a valid GitHub repository URL.

    This function checks if the URL matches the expected pattern of
    GitHub repository URLs (e.g., "https://github.com/username/repository").

    Args:
        url (str): The URL string to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    pattern = r'^https://github\.com/[\w-]+/[\w-]+(?:/)?$'
    if re.match(pattern, url):
        return True
    else:
        logger.error("Invalid GitHub URL: %s", url)
        return False


def verify_github_token(token: str) -> bool:
    """
    Verify that the GitHub token has the required permissions.

    This function sends a request to the GitHub API's endpoint with the
    provided token and examines the returned header value to ensure that the
    token includes the 'public_repo' scope.

    Args:
        token (str): The GitHub token to verify.

    Returns:
        bool: True if the token is valid and has the required permissions,
            False otherwise.
    """
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    try:
        response = requests.get(f"{GITHUB_CONFIG['BASE_URL']}/user",
                                headers=headers)

        if response.status_code == 200:
            scopes = response.headers.get('X-OAuth-Scopes', '')
            if 'public_repo' in scopes:
                return True
            else:
                logger.error("GitHub token missing 'public_repo' scope")
                return False

        elif response.status_code == 401:
            logger.error("GitHub API error: %s", response.status_code)
            return False

    except requests.exceptions.RequestException as e:
        logger.error("GitHub API request failed: %s", e)
        return False


def write_vulnerability_details_to_csv(vuln_ids: List[str], details: List[str],
                                       severities: List[str], output_file: Path
                                       ) -> None:
    """
    Write vulnerability details to a CSV file.

    This function writes rows of vulnerability information into a CSV file.
    Each row contains a vulnerability ID, severity, and associated details. The
    CSV file is written to the specified output_file path using UTF-8 encoding.

    Args:
        vuln_ids (List[str]): A list of vulnerability IDs.
        details (List[str]): A list containing vulnerability details.
        severities (List[str]): A list of vulnerability severity values.
        output_file (Path): The file path where the CSV will be written.
    """
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['VulnerabilityID', 'Severity', 'Details'])
        for vid, sev, det in zip(vuln_ids, severities, details):
            writer.writerow([vid, sev, det])
