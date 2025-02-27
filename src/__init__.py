"""
PHP CVE Dataset Collection Tool.

A command-line tool for collecting, downloading, and analyzing PHP-related CVEs
(Common Vulnerabilities and Exposures) with their associated GitHub commits.
"""

__version__ = "1.0.0"

from .config import config
from .commands.collect import collect
from .commands.download import download
from .commands.statistic import statistic
from .commands.reclassify import reclassify
from .commands.clean import clean

__all__ = ['config', 'collect', 'download', 'statistic', 'reclassify', 'clean'] 