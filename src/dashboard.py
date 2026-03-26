"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: dashboard.py
Description: Entry point for generating a single HTML dashboard from all
VISaR scan output files in a given directory. The dashboard embeds every
dataset and lets the user switch between scans via a dropdown — no
re-scanning required.

Usage:
    python dashboard.py                        # uses project data/ folder
    python dashboard.py <path-to-data-dir>     # explicit directory

    For help:
        python dashboard.py -h
        python dashboard.py --help
"""

# import standard libraries
import argparse
from pathlib import Path
import sys

# import helper functions
from helpers.logger_config import setup_logger
import helpers.dashboard_funcs as dash

# initialize logger
logger = setup_logger(__name__)

# default data directory is data/ in the project root, one level above src/
_DEFAULT_DATA_DIR: Path = Path(__file__).resolve().parent.parent / "data"


def main() -> None:
    """
    Generate a single HTML dashboard from all VISaR data files in a directory.

    Reads every *_vulnids.csv and *_vulnids.json file found in data_dir,
    embeds them all in one self-contained HTML file, and prints the output
    path on success. Exits with code 1 on any failure.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(
        description=(
            "Generate a single HTML dashboard from all VISaR scan output "
            "files in a directory."
        )
    )
    parser.add_argument(
        "data_dir",
        nargs="?",
        default=None,
        help=(
            "Path to directory containing VISaR output files (.csv or .json). "
            f"Defaults to {_DEFAULT_DATA_DIR}"
        ),
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir) if args.data_dir else _DEFAULT_DATA_DIR

    logger.info("DASHBOARD STARTED: %s", data_dir)

    try:
        output_file = dash.generate_dashboard_from_dir(data_dir)
        print(f"Dashboard generated: {output_file}")
        logger.info("DASHBOARD COMPLETED: %s", output_file.name)
        sys.exit(0)

    except FileNotFoundError as e:
        logger.error("Directory not found: %s", data_dir)
        print(f"Error: {e}")
        sys.exit(1)

    except ValueError as e:
        logger.error("Dashboard generation failed: %s", e)
        print(f"Error: {e}")
        sys.exit(1)

    except Exception as e:
        logger.error("Unexpected error generating dashboard: %s", e)
        print(f"Error: An unexpected error occurred — {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
