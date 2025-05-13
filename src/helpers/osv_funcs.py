"""
Copyright (c) AtLongLast Analytics LLC

Licensed under the Apache License, Version 2.0

Project: https://github.com/AtLongLastAnalytics/visar
Author: Robert Long
Date: 2025-05
Version: 1.0.0

File: osv_funcs.py
Description: Module containing OSV-related functions to:
    - Fetch aliases for a given vulnerability ID from the OSV API
    - Fetch vulnerability details for a given vulnerability ID from the OSV API
    - Update vulnerability IDs with alias information from the OSV API
"""

# import standard libraries
from typing import List, Tuple
import requests

# import helper functions and configuration
from config import OSV_CONFIG
from helpers.logger_config import setup_logger

# initialize logger
logger = setup_logger(__name__)

# global session for reuse (improves performance for multiple requests)
session = requests.Session()


def fetch_aliases(vuln_id: str) -> List[str]:
    """
    Fetch aliases for a vulnerability ID from the OSV API.

    This function sends an HTTP GET request to the OSV API endpoint for a
    vulnerability ID. If successful (HTTP 200), it parses the JSON response
    and returns the list of aliases associated with the vulnerability.
    In case of an error, it logs the exception and returns an empty list.

    Args:
        vuln_id (str): The vulnerability identifier for which to fetch aliases

    Returns:
        List[str]: A list of alias strings for the specified vulnerability
            Returns an empty list if unsuccessful or if no aliases are found
    """
    try:
        response = session.get(f"{OSV_CONFIG['OSV_API_URL']}/{vuln_id}")
        if response.status_code == 200:
            data = response.json()
            return data.get('aliases', [])  # return [] if aliases not found
        return []
    except (ConnectionError, TimeoutError) as e:
        logger.error("Network-related error while calling OSV API: %s", e)
        return []
    except Exception as e:
        logger.error("Unexpected error fetching aliases %s: %s", vuln_id, e)
        return []


def fetch_details(vuln_ids: List[str]) -> Tuple[List[str], List[str]]:
    """
    Fetch vulnerability details and severities for a list of vulnerability IDs
    from the OSV API

    The function iterates over the provided list of vulnerability IDs, and for
    each ID, it calls the helper function to obtain the vulnerability details
    and severity. Two lists are maintained: one for details and one for
    severities. These lists preserve the order of the input vulnerability IDs.
    If an error occurs while processing a particular ID, default values are
    appended in its place.

    Args:
        vuln_ids (List[str]): A list of vulnerability ID strings to process.

    Returns:
        Tuple[List[str], List[str]]:
            A tuple containing two lists:
              - The first list consists of vulnerability details as strings.
              - The second list consists of the corresponding severity strings.
            Each index in the lists relates to the corresponding input
                vulnerability ID.
    """
    details, severities = [], []
    for vid in vuln_ids:
        detail, severity = fetch_single_detail(vid)
        details.append(detail)
        severities.append(severity)
    return details, severities


def fetch_single_detail(vid: str) -> Tuple[str, str]:
    """
    Fetch vulnerability details and severity for a single vulnerability ID from
    the OSV API.

    This helper function retrieves information from the OSV API for a given
    vulnerability ID. If the vulnerability ID contains a '/', it extracts the
    relevant portion by splitting on ' / '. When the API call is successful, it
    returns a tuple containing the vulnerability detail and severity. In case
    of any error (network-related, API error, or unexpected exception), default
    values are returned.

    Args:
        vid (str): The vulnerability ID delimiter is ' / '.

    Returns:
        Tuple[str, str]: A tuple where:
            - The first element is a string with the vulnerability details
              (or "DETAILS NOT AVAILABLE" if not provided or on error).
            - The second element is a string with the severity
              (or "SEVERITY NOT AVAILABLE" if not provided or on error).
    """
    try:
        # Handle formatting: if the ID contains '/', extract the second part.
        if '/' in vid:
            vid = vid.split('/ ')[1]

        response = session.get(f"{OSV_CONFIG['OSV_API_URL']}/{vid}")
        if response.status_code == 200:
            data = response.json()
            detail = data.get('details', 'No details available')
            severity = data.get('database_specific', {}).get('severity',
                                                             'NOT AVAILABLE')
            return detail, severity
        else:
            logger.error("API error for %s: %s", vid, response.status_code)
    except requests.exceptions.RequestException as e:
        logger.error("Network-related error calling OSV API; %s: %s", vid, e)
    except Exception as e:
        logger.error("Unexpected error calling OSV API; %s: %s", vid, e)

    # Default return values if any error occurs.
    return "DETAILS NOT AVAILABLE", "SEVERITY NOT AVAILABLE"


def update_idlist(vuln_ids: List[str]) -> List[str]:
    """
    Update vulnerability IDs with alias information from the OSV API.

    This function enriches a list of vulnerability IDs with alias information.
    For each vulnerability ID:
      - If the ID does not contain an alias (indicated by ' / ') and starts
      with the prefix 'PYSEC', it attempts to fetch aliases.
      - If a fetched alias starts with 'GHSA', the function appends the alias
      to the original ID, separated by ' / ', and marks the alias as added.
      - If no suitable alias is found or if the ID is already in an updated
      format, the original ID is kept.
    The function returns a new list with the updated vulnerability IDs.

    Args:
        vuln_ids (List[str]): A list of vulnerability ID strings that may
        require alias updates

    Returns:
        List[str]: A list of vulnerability ID strings, updated with alias
        information where applicable
    """
    result = []
    for vid in vuln_ids:
        if ' / ' not in vid and vid.startswith('PYSEC'):
            aliases = fetch_aliases(vid)
            alias_added = False
            for alias in aliases:
                if alias.startswith('GHSA'):
                    result.append(f"{vid} / {alias}")
                    alias_added = True
                    break
            if not alias_added:
                result.append(vid)
        else:
            result.append(vid)
    return result
