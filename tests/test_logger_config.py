"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2026-03
Version: 1.1.0

File: test_logger_config.py
Description: Tests for the logger configuration helpers.
"""

import json
import logging
import unittest
from unittest.mock import MagicMock, patch

from visar.helpers.logger_config import JsonLogFormatter, setup_logger


class TestJsonLogFormatter(unittest.TestCase):
    """Test cases for the JSON file log formatter."""

    def test_formats_record_as_json(self):
        """Structured file logs include stable keys and values."""
        formatter = JsonLogFormatter(datefmt="%Y-%m-%d %H:%M:%S")
        record = logging.LogRecord(
            name="visar.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=42,
            msg="Structured message",
            args=(),
            exc_info=None,
        )

        payload = json.loads(formatter.format(record))

        self.assertEqual(payload["level"], "INFO")
        self.assertEqual(payload["logger"], "visar.test")
        self.assertEqual(payload["message"], "Structured message")
        self.assertEqual(payload["line"], 42)
        self.assertIn("timestamp", payload)


class TestSetupLogger(unittest.TestCase):
    """Test cases for setup_logger handler configuration."""

    @patch("visar.helpers.logger_config.logging.StreamHandler")
    @patch("visar.helpers.logger_config.logging.handlers.RotatingFileHandler")
    def test_uses_json_formatter_for_file_handler(
        self, mock_rotating_file_handler, mock_stream_handler
    ):
        """File logs are structured JSON while console logs remain text."""
        logger = logging.getLogger("visar.tests.logger_config")
        logger.handlers.clear()

        file_handler = MagicMock()
        console_handler = MagicMock()
        mock_rotating_file_handler.return_value = file_handler
        mock_stream_handler.return_value = console_handler

        try:
            setup_logger("visar.tests.logger_config")
        finally:
            logger.handlers.clear()

        file_formatter = file_handler.setFormatter.call_args.args[0]
        console_formatter = console_handler.setFormatter.call_args.args[0]

        self.assertIsInstance(file_formatter, JsonLogFormatter)
        self.assertIsInstance(console_formatter, logging.Formatter)
        self.assertNotIsInstance(console_formatter, JsonLogFormatter)
