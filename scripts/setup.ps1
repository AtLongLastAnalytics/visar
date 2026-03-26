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
# File: setup.ps1
# Description: This PowerShell script (located in the 'scripts' folder) uses
#   uv to create a Python virtual environment and install all project
#   dependencies from pyproject.toml. Run once from the project root before
#   first use.
#
# Pre-requisite: uv must be installed.
#   Install: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
# =============================================================================

# define the project root as the parent directory of the 'scripts' folder
$scriptDir = $PSScriptRoot
$projectRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path

Write-Host "Project Root: $projectRoot"

# verify uv is available
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "Error: uv is not installed."
    Write-Host "Install it with: powershell -ExecutionPolicy ByPass -c `"irm https://astral.sh/uv/install.ps1 | iex`""
    exit 1
}

# uv sync creates the .venv and installs all dependencies from pyproject.toml
Write-Host "Running uv sync..."
Set-Location $projectRoot
uv sync

Write-Host "Environment setup complete."
