"""
Core functionality for PHP CVE Dataset Collection Tool.

This package provides core functionality for processing CVE data, analyzing
vulnerabilities, and classifying projects.
"""

from src.core.processor import CVEProcessor
from .downloader import CodeDownloader
from .validator import DataValidator

__all__ = ['CVEProcessor', 'CodeDownloader', 'DataValidator'] 