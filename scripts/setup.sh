#!/usr/bin/env bash
# =============================================================================
# Copyright (c) AtLongLast Analytics LLC
#
# Licensed under the Apache License, Version 2.0
#
# Project: https://github.com/AtLongLastAnalytics/visar
# Author: Robert Long
# Date: 2026-03
# Version: 1.1.0
#
# File: setup.sh
# Description: This shell script (located in the 'scripts' folder) uses uv to
#   create a Python virtual environment and install all project dependencies
#   from pyproject.toml. Run once from the project root before first use.
#
# Pre-requisite: uv must be installed.
#   Install: curl -LsSf https://astral.sh/uv/install.sh | sh
# =============================================================================

# resolve project root (parent of the scripts/ directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Project Root: $PROJECT_ROOT"

# verify uv is available
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed."
    echo "Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# uv sync creates the .venv and installs all dependencies from pyproject.toml
echo "Running uv sync..."
cd "$PROJECT_ROOT" && uv sync

echo "Environment setup complete."
