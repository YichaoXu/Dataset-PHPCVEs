"""
PHP CVE Dataset Collection Tool.

A command-line tool for collecting, downloading, and analyzing PHP-related CVEs
(Common Vulnerabilities and Exposures) with their associated GitHub commits.
"""

__version__ = "1.0.0"

from src.config import Config
from src.logger import logger
from src.collect import collect_cves


__all__ = ['Config', 'logger', 'collect_cves'] 