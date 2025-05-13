"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

# Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: config.py
Description: Configuration settings for the scanning pipeline.
             These settings include paths to directories, API endpoints,
             and container configurations for Docker, OSV, and GitHub services.
"""

# import standard libraries
import os
from pathlib import Path
from typing import Dict, Union, Optional
from dotenv import load_dotenv

# load environment variables
load_dotenv()

# define directories and files
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = BASE_DIR / "data"
TEMP_FILE: Path = BASE_DIR / "temp_output.txt"

# define Docker configuration
DOCKER_CONFIG: Dict[str, Union[str, int]] = {
    'CONTAINER_NAME': 'gcr.io/openssf/scorecard:stable',
    'MAX_RETRIES': 3,
    'RETRY_DELAY': 5
}

# define GitHub configuration
GITHUB_CONFIG: Dict[str, Optional[str]] = {
    'BASE_URL': 'https://api.github.com',
    'GITHUB_TOKEN': os.getenv('GITHUB_AUTH_TOKEN')
}

# validate critical environment variables.
if GITHUB_CONFIG['GITHUB_TOKEN'] is None:
    raise EnvironmentError(
        "GITHUB_AUTH_TOKEN environment variable is not set. "
        "Please check your .env file."
    )

# define OSV configuration
OSV_CONFIG: Dict[str, Union[str, int]] = {
    'OSV_API_URL': 'https://api.osv.dev/v1/vulns',
    'MAX_RETRIES': 3,
    'RETRY_DELAY': 10
}
