"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

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
    python main.py <github_repository_url>

    For help:
        python main.py -h
        python main.py --help
"""

# import standard libraries
import argparse
from pathlib import Path
import sys
from typing import Any, List, Tuple

# import configuration and helper functions
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
    if not dof.check_dockerimage_exists(DOCKER_CONFIG["CONTAINER_NAME"]):
        hf.exit_with_error("Docker image does not exist locally")

    # if the data folder does not exist, Docker will error (with error code 1)
    hf.check_datafolder_exists()


def execute_docker_commands(
    repo_url: str, github_token: str, summary_filename: Path
) -> None:
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
        repo_url, github_token, DOCKER_CONFIG["CONTAINER_NAME"]
    )
    if not hf.retry_call(
        dof.run_docker_command,
        command_summary,
        retries=3,
        delay=2,
        output_file=summary_filename,
    ):
        hf.exit_with_error("Failed to execute Docker command: summary")

    # execute detailed command
    logger.info("Running OSSF Scorecard (vulnerabilities)...")
    command_details = dof.format_docker_command(
        repo_url, github_token, DOCKER_CONFIG["CONTAINER_NAME"], show_details=True
    )
    if not hf.retry_call(
        dof.run_docker_command,
        command_details,
        retries=DOCKER_CONFIG["MAX_RETRIES"],
        delay=DOCKER_CONFIG["RETRY_DELAY"],
        output_file=TEMP_FILE,
    ):
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

        with open(TEMP_FILE, "r") as file:
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
            retries=OSV_CONFIG["MAX_RETRIES"],
            delay=OSV_CONFIG["RETRY_DELAY"],
        )
        return vuln_details, vuln_severity
    except Exception as e:
        cleanup_temp_files()
        hf.exit_with_error(f"Unexpected error during OSV API call: {e}")


def write_output(
    data_filename: str,
    vuln_ids: Any,
    vuln_details: Any,
    vuln_severity: Any,
    output_format: str,
) -> None:
    """
    Write vulnerability output data in the specified format.

    This function dispatches to the appropriate writer based on output_format.
    Supported formats are 'csv', 'json', and 'md'. The output file is placed
    in DATA_DIR with an extension matching the format. On any failure,
    cleanup_temp_files is called and the process is terminated using
    hf.exit_with_error.

    Args:
        data_filename (str): The base filename derived from the repository URL.
        vuln_ids (Any): The list of vulnerability IDs.
        vuln_details (Any): The vulnerability details data.
        vuln_severity (Any): The vulnerability severity data.
        output_format (str): One of 'csv', 'json', or 'md'.

    Returns:
        None
    """
    format_map = {
        "csv": ("_vulnids.csv", hf.write_vulnerability_details_to_csv),
        "json": ("_vulnids.json", hf.write_vulnerability_details_to_json),
    }
    suffix, writer = format_map[output_format]
    try:
        logger.info("Writing data to %s file...", output_format.upper())
        output_file: Path = DATA_DIR / f"{data_filename}{suffix}"
        writer(vuln_ids, vuln_details, vuln_severity, output_file)
    except Exception as e:
        cleanup_temp_files()
        hf.exit_with_error(
            f"An error occurred when writing data to {output_format}: {e}"
        )


def print_batch_summary(total: int, succeeded: List[str], failed: List[str]) -> None:
    """
    Print a summary of batch scan results to stdout and the logger.

    This function logs and prints the total number of repositories processed,
    the count of successful scans, and the count and URLs of failed scans.

    Args:
        total (int): Total number of repository URLs attempted.
        succeeded (List[str]): List of URLs that completed successfully.
        failed (List[str]): List of URLs that failed.

    Returns:
        None
    """
    print(f"\nBatch scan complete: {len(succeeded)}/{total} repositories succeeded.")
    if failed:
        print(f"{len(failed)} failed:")
        for url in failed:
            print(f"  FAILED: {url}")
    logger.info(
        "Batch complete: %d succeeded, %d failed out of %d",
        len(succeeded),
        len(failed),
        total,
    )


def scan_single_repository(repo_url: str, output_format: str) -> None:
    """
    Execute the full scanning pipeline for a single GitHub repository.

    This function runs all pipeline steps for one repository URL: prerequisite
    checks, Docker execution, data transformation, OSV API calls, and output
    writing. On any sub-step failure, hf.exit_with_error is called, which
    raises SystemExit. The caller is responsible for catching SystemExit when
    running in batch mode.

    Args:
        repo_url (str): The URL of the GitHub repository to scan.
        output_format (str): The output format — one of 'csv', 'json', or 'md'.

    Returns:
        None
    """
    logger.info("SCAN STARTED: %s", repo_url)

    # 1. run all prerequisite checks and generate filenames
    run_prerequisite_checks(repo_url, GITHUB_CONFIG["GITHUB_TOKEN"])
    data_filename: str = hf.format_filename(repo_url)
    summary_filename: Path = DATA_DIR / f"{data_filename}_summary.txt"

    # 2. execute Docker scorecard commands (summary and detailed)
    execute_docker_commands(repo_url, GITHUB_CONFIG["GITHUB_TOKEN"], summary_filename)

    # 3. perform data transformation on the Docker output
    vuln_ids = perform_data_transformation(repo_url, summary_filename)

    if not vuln_ids:
        print(f"No vulnerabilities found for {repo_url}.")
        logger.info("No vulnerabilities found for %s", repo_url)
        cleanup_temp_files()
        sys.exit(0)

    # 4. retrieve vulnerability details from the OSV API
    vuln_details, vuln_severity = call_osv_api(vuln_ids)

    # 5. write the final output in the requested format
    write_output(data_filename, vuln_ids, vuln_details, vuln_severity, output_format)

    # 6. cleanup any temporary files created during processing
    cleanup_temp_files()

    logger.info("SCAN COMPLETED: %s", repo_url)


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
                "Failed to clean up temporary file %s. Error: %s", TEMP_FILE, e
            )


def main() -> None:
    """
    Orchestrate the Vulnerability Identification, Scanning and Reporting
    pipeline.

    This is the main entry point which:
      - parses command-line arguments for the repository URL (or batch file),
        and the desired output format.
      - in single mode, runs the full scan pipeline for one repository.
      - in batch mode, reads repository URLs from a file and runs the pipeline
        for each URL, collecting results and printing a summary.

    Exits the program with status code 0 on success, 1 on failure.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(
        description="Scan a GitHub repository for vulnerabilities."
    )
    parser.add_argument(
        "repo_url",
        nargs="?",
        help=(
            "URL of the GitHub repository to scan. Example: "
            "https://github.com/matplotlib/matplotlib"
        ),
    )
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="Path to a text file containing one repository URL per line.",
    )
    parser.add_argument(
        "--output-format",
        choices=["csv", "json"],
        default="csv",
        dest="output_format",
        help=("Output format for the vulnerability report: csv (default) or json."),
    )
    args = parser.parse_args()

    if args.repo_url and args.batch:
        parser.error("Cannot specify both repo_url and --batch.")
    if not args.repo_url and not args.batch:
        parser.error("Must specify either a repo_url or --batch FILE.")

    output_format: str = args.output_format

    if args.batch:
        logger.info("BATCH PIPELINE STARTED!")
        try:
            repo_urls = hf.read_batch_file(args.batch)
        except FileNotFoundError:
            hf.exit_with_error(f"Batch file not found: {args.batch}")

        if not repo_urls:
            hf.exit_with_error("No valid repository URLs found in batch file.")

        total = len(repo_urls)
        succeeded: List[str] = []
        failed: List[str] = []

        for i, repo_url in enumerate(repo_urls, 1):
            print(f"\n[{i}/{total}] Scanning: {repo_url}")
            logger.info("Scanning repository %d/%d: %s", i, total, repo_url)
            try:
                scan_single_repository(repo_url, output_format)
                succeeded.append(repo_url)
            except SystemExit as e:
                if e.code == 0:
                    succeeded.append(repo_url)
                else:
                    logger.error("Scan failed for: %s", repo_url)
                    failed.append(repo_url)

        print_batch_summary(total, succeeded, failed)
        logger.info("BATCH PIPELINE COMPLETED!")
        sys.exit(1 if failed else 0)

    else:
        logger.info("PIPELINE STARTED!")
        logger.info("repo_url: %s", args.repo_url)
        scan_single_repository(args.repo_url, output_format)
        logger.info("PIPELINE COMPLETED!")
        sys.exit(0)


if __name__ == "__main__":
    main()
