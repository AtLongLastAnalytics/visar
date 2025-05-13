"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

# Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: main.py
Description: This script is the entry point to the
VULNERABILITY IDENTIFICATION, SCANNING and REPORTING application.
This script
    - checks prerequisites (folder setup, GitHub URL and token, Docker image)
    - runs the OSSF Scorecard in a Docker Container
    - extracts vulnerability ID codes from the OSSF Scorecard output
    - calls the OSV API to get vulnerability information
    - writes the results to a CSV file
    - cleans up temporary files

Usage:
    python pipeline.py <github_repository_url>

    For help:
        python pipeline.py -h
        python pipeline.py --help
"""

# import standard libraries
import argparse
from pathlib import Path
import sys
from typing import Any, Tuple

# import confiuration and helpers functions
from config import (
    DATA_DIR,
    TEMP_FILE,
    DOCKER_CONFIG,
    GITHUB_CONFIG,
    OSV_CONFIG,
)

from helpers.logger_config import setup_logger

import helpers.docker_funcs as dof
import helpers.helper_funcs as hf
import helpers.osv_funcs as osv

# initialize logger
logger = setup_logger(__name__)


def run_prerequisite_checks(repo_url: str, github_token: str) -> None:
    """
    Run all prerequisite checks required for the pipeline.

    This function checks the GitHub repository URL, GitHub token permissions,
    checks if Docker is running and confirms the Docker image exists locally.
    On failure, the process is terminated using hf.exit_with_error. Checks if
    the data folder exists and creates it if not.

    Args:
        repo_url (str): The URL of the GitHub repository.
        github_token (str): The GitHub authentication token.

    Returns:
        None
    """
    logger.info("Validating GitHub URL...")
    if not hf.validate_github_url(repo_url):
        hf.exit_with_error("Invalid GitHub repository URL")

    logger.info("Verifying GitHub token...")
    if not hf.verify_github_token(github_token):
        hf.exit_with_error("Invalid GitHub token")

    logger.info("Checking Docker is running...")
    if not dof.check_docker_isrunning():
        hf.exit_with_error("Docker is not running")

    logger.info("Checking Docker image exists...")
    if not dof.check_dockerimage_exists(DOCKER_CONFIG['CONTAINER_NAME']):
        hf.exit_with_error("Docker image does not exist locally")

    # if the data folder does not exist, Docker will error (with error code 1)
    hf.check_datafolder_exists()


def execute_docker_commands(repo_url: str, github_token: str,
                            summary_filename: Path) -> None:
    """
    Execute Docker commands to run the OSSF Scorecard.

    This function builds and runs two Docker commands: one generates summary
    output and one produces vulnerability ids.
    On failure, the process is terminated using hf.exit_with_error.

    Args:
        repo_url (str): The URL of the GitHub repository to scan.
        github_token (str): The GitHub authentication token.
        summary_filename (Path): The file path where summary output is stored.

    Returns:
        None
    """
    # execute summary command
    logger.info("Running OSSF Scorecard (summary)...")
    command_summary = dof.format_docker_command(
        repo_url,
        github_token,
        DOCKER_CONFIG['CONTAINER_NAME']
    )
    if not hf.retry_call(dof.run_docker_command,
                         f"{command_summary} > {summary_filename}",
                         retries=3,
                         delay=2):
        hf.exit_with_error("Failed to execute Docker command: summary")

    # execute detailed command
    logger.info("Running OSSF Scorecard (vulnerabilities)...")
    command_details = dof.format_docker_command(
        repo_url,
        github_token,
        DOCKER_CONFIG['CONTAINER_NAME'],
        show_details=True
    )
    if not hf.retry_call(dof.run_docker_command,
                         f"{command_details} > {TEMP_FILE}",
                         retries=DOCKER_CONFIG['MAX_RETRIES'],
                         delay=DOCKER_CONFIG['RETRY_DELAY']):
        hf.exit_with_error("Failed to execute Docker command: vulnerabilities")


def perform_data_transformation(repo_url: str, summary_filename: Path) -> Any:
    """
    Perform data transformation on the list of vulnerability ids.

    This function executes several transformation steps:
      - Reads vulnerability ids from TEMP_FILE.
      - Prepends the repository URL to the summary file.
      - Extracts vulnerability identifiers from the vulnerability id TMP file.
      - Merges and update the list of vulnerabilities using alias information.
    On failure, the process is terminated using hf.exit_with_error.

    Args:
        repo_url (str): The URL of the GitHub repository.
        summary_filename (Path): The path to the summary output file.

    Returns:
        Any: The processed list of vulnerability IDs.
    """
    try:
        logger.info("Performing data transformation...")
        if not TEMP_FILE.exists():
            hf.exit_with_error(f"Temporary file {TEMP_FILE} not found.")

        with open(TEMP_FILE, 'r') as file:
            file_contents: str = file.read()

        hf.prepend_line(summary_filename, repo_url)
        idmatches = hf.extract_vulnerability_ids(file_contents)
        vuln_ids = hf.merge_items_with_slash(idmatches)
        vuln_ids = osv.update_idlist(vuln_ids)
        return vuln_ids
    except FileNotFoundError:
        cleanup_temp_files()
        hf.exit_with_error("Temp. file not found during data transformation")
    except Exception as e:
        cleanup_temp_files()
        hf.exit_with_error(f"Unexpected error during data transformation: {e}")


def call_osv_api(vuln_ids: Any) -> Tuple[Any, Any]:
    """
    Call the OSV API to retrieve vulnerability details and severity.

    This function uses the provided list of vulnerability IDs to call the OSV
    API to retrieve details and severity information for each vulnerability.
    On failure, the process is terminated using hf.exit_with_error.

    Args:
        vuln_ids (Any): The vulnerability IDs to be looked up on the OSV API.

    Returns:
        Tuple[Any, Any]: A tuple containing:
            - Vulnerability details.
            - Vulnerability severity.
    """
    try:
        logger.info("Calling OSV API...")
        vuln_details, vuln_severity = hf.retry_call(
            osv.fetch_details,
            vuln_ids,
            retries=OSV_CONFIG['MAX_RETRIES'],
            delay=OSV_CONFIG['RETRY_DELAY']
        )
        return vuln_details, vuln_severity
    except Exception as e:
        cleanup_temp_files()
        hf.exit_with_error(f"Unexpected error during OSV API call: {e}")


def write_output_to_csv(data_filename: str, vuln_ids: Any,
                        vuln_details: Any, vuln_severity: Any) -> None:
    """
    Write vulnerability output data to a CSV file.

    This function writes vulnerability IDs, details, and severity to a CSV
    file. The output file is located in the DATA_DIR directory.
    On failure, the process is terminated using hf.exit_with_error.

    Args:
        data_filename (str): The base filename derived from the repository URL.
        vuln_ids (Any): The list of vulnerability IDs.
        vuln_details (Any): The vulnerability details data.
        vuln_severity (Any): The vulnerability severity data.

    Returns:
        None
    """
    try:
        logger.info("Writing data to CSV file...")
        output_csv_file: Path = DATA_DIR / f"{data_filename}_vulnids.csv"
        hf.write_vulnerability_details_to_csv(vuln_ids,
                                              vuln_details,
                                              vuln_severity, output_csv_file)
    except Exception as e:
        cleanup_temp_files()
        hf.exit_with_error(f"An error occurred when writing data to CSV: {e}")


def cleanup_temp_files() -> None:
    """
    Clean up temporary files generated during the pipeline process.

    This function attempts to remove TEMP_FILE if it exists. If cleanup fails,
    a warning is logged with the error details.

    Returns:
        None
    """
    logger.info("Cleaning up temporary files...")
    if TEMP_FILE.exists():
        try:
            TEMP_FILE.unlink()
        except Exception as e:
            logger.warning(
                "Failed to clean up temporary file %s. Error: %s",
                TEMP_FILE, e
            )


def main() -> None:
    """
    Orchestrate the Vulnerability Identification, Scanning and Reporting
    pipeline.

    This is the main entry point which:
      - parses the command-line argument for the GitHub repository URL.
      - runs prerequisite checks (check GitHub URL and token, checks Docker )
      - executes Docker commands to run the OSSF Scorecard.
      - performs data transformation on the OSSF Scorecard output.
      - calls the OSV API to retrieve additional vulnerability details.
      - writes the combined output to a CSV file.
      - cleans up temporary files generated during the process.

    Exits the program with status code 0 upon completion.

    Returns:
        None
    """
    # parse command-line argument for the repository URL
    parser = argparse.ArgumentParser(description="Scan a GitHub repository.")
    parser.add_argument(
        'repo_url',
        help=(
            "URL of the GitHub repository to scan. Example: "
            "https://github.com/matplotlib/matplotlib"
        )
    )
    args = parser.parse_args()
    repo_url: str = args.repo_url

    logger.info("PIPELINE STARTED!")
    logger.info("repo_url: %s", repo_url)

    # 1. run all prerequisite checks and generate filenames
    run_prerequisite_checks(repo_url, GITHUB_CONFIG['GITHUB_TOKEN'])
    data_filename: str = hf.format_filename(repo_url)
    summary_filename: Path = DATA_DIR / f"{data_filename}_summary.txt"

    # 2. execute Docker scorecard commands (summary and detailed)
    execute_docker_commands(repo_url, GITHUB_CONFIG['GITHUB_TOKEN'],
                            summary_filename)

    # 3. perform data transformation on the Docker output
    vuln_ids = perform_data_transformation(repo_url, summary_filename)

    # 4. retrieve vulnerability details from the OSV API
    vuln_details, vuln_severity = call_osv_api(vuln_ids)

    # 5. write the final output to a CSV file
    write_output_to_csv(data_filename, vuln_ids, vuln_details, vuln_severity)

    # 6. cleanup any temporary files created during processing
    cleanup_temp_files()

    logger.info("PIPELINE COMPLETED!")

    sys.exit(0)


if __name__ == '__main__':
    main()
