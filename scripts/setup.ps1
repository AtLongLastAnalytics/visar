# =============================================================================
# Copyright (c) AtLongLast Analytics LLC
#
# Licensed under the Apache License, Version 2.0
#
# Project: https://github.com/AtLongLastAnalytics/visar
# Author: Robert Long
# Date: 2025-05
# Version: 1.0.0
#
# File: setup.ps1
# Description: This PowerShell script (located in the 'scripts' folder) creates
#   a Python virtual environment in the project root, upgrades pip, installs
#   dependencies from the root-level requirements.txt, and runs unit tests from
#   the root-level tests folder.
# =============================================================================

# get the directory of the current script (setup.ps1 is in the 'scripts' folder)
$scriptDir = $PSScriptRoot

# define the project root as the parent directory of the 'scripts' folder
$projectRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path

Write-Host "Project Root: $projectRoot"

# define the virtual environment (.venv) path in the project root
$venvPath = Join-Path $projectRoot ".venv"

# if virtual environment exists, exit the script. If it doesn't, create it
if (Test-Path -Path $venvPath) {
    Write-Host "Virtual environment already exists at $venvPath. Exiting."
    exit
}

Write-Host "Creating virtual environment at $venvPath..."
python -m venv $venvPath

# activate the virtual environment
Write-Host "Activating virtual environment..."
. (Join-Path $venvPath "Scripts\Activate.ps1")

# upgrade pip to the latest version
Write-Host "Upgrading pip..."
python -m pip install --upgrade pip

# install dependencies from the root-level requirements.txt file
$requirementsFile = Join-Path $projectRoot "requirements.txt"
Write-Host "Installing dependencies from $requirementsFile..."
pip install -r $requirementsFile

Write-Host "Environment setup complete."

# run unit tests found in the tests folder (in the project root) using unittest
$testsDir = Join-Path $projectRoot "tests"
Write-Host "Running unit tests from $testsDir..."
python -m unittest discover -s $testsDir

Write-Host "Testing complete."