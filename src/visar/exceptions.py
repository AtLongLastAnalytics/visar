"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: exceptions.py
Description: Structured exception hierarchy for VISaR pipeline failures.
"""


class VisarError(Exception):
    """Base exception for VISaR pipeline failures."""


class VisarPrerequisiteError(VisarError):
    """Raised when environment or input prerequisites are not met."""


class VisarDockerError(VisarError):
    """Raised when Docker setup or execution fails."""


class VisarDataError(VisarError):
    """Raised when intermediate pipeline data cannot be processed."""


class VisarAPIError(VisarError):
    """Raised when external API interaction fails."""


class VisarOutputError(VisarError):
    """Raised when VISaR cannot write final output artifacts."""
