"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: models.py
Description: Shared data models used across the VISaR pipeline.
"""

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True, slots=True)
class Finding:
    """Represents one vulnerability finding emitted by the VISaR pipeline."""

    vulnerability_id: str
    severity: str
    details: str

    def to_output_record(self) -> dict[str, str]:
        """Return the persisted CSV/JSON record shape for this finding."""
        return {
            "VulnerabilityID": self.vulnerability_id,
            "Severity": self.severity,
            "Details": self.details,
        }

    @classmethod
    def from_output_record(cls, record: Mapping[str, str]) -> "Finding":
        """Build a finding from a CSV/JSON record using the persisted schema."""
        return cls(
            vulnerability_id=record["VulnerabilityID"],
            severity=record["Severity"],
            details=record["Details"],
        )