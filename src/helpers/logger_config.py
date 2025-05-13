"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: logger_config.py
Description: Module defining the logging details, file handler and
             console handler.
"""

# import standard libraries
from datetime import datetime
import logging
import logging.handlers
from pathlib import Path
import sys


def setup_logger(name: str) -> logging.Logger:
    """
    Configure and return a logger instance with both file and console handlers.

    This function creates a logger and sets the logging level to INFO. It
    checks if the logger already has handlers attached to avoid duplicates. If
    none exist, it creates a logging directory (named
    'logs'), sets up a rotating file handler that writes log messages to a
    file, and also adds a console handler to output logs to stdout. Both
    handlers use the same format with timestamp, log level, and log message.

    Args:
        name (str): The name to be assigned to the logger instance.

    Returns:
        logging.Logger: A configured logger instance with both file and
        console logging handlers.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # prevent adding handlers multiple times
    if logger.handlers:
        return logger

    # create logs directory if it doesn't exist
    log_dir = Path(__file__).parent.parent.parent / 'logs'
    log_dir.mkdir(exist_ok=True)

    # file handler with rotation to avoid large log files
    log_file = log_dir / f'visar_{datetime.now().strftime("%Y%m%d")}.log'
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10485760,  # 10MB
        backupCount=5
    )

    # console handler
    console_handler = logging.StreamHandler(sys.stdout)

    # formatting
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


if __name__ == '__main__':
    # Simple test to demonstrate logger usage.
    test_logger = setup_logger("test_logger")
    test_logger.debug("This is a debug message.")
    test_logger.info("Logger is set up and working.")
    test_logger.warning("This is a warning message.")
    test_logger.error("This is an error message.")
    test_logger.critical("This is critical!")
