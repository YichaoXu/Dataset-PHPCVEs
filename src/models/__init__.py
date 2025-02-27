"""
Data models for PHP CVE Dataset Collection Tool.

This package provides data models for CVE records, CWE records, and repository information.
"""

from src.models.cve import CVERecord
from src.models.cwe import CWERecord
from src.models.repository import RepositoryRecord

__all__ = ['CVERecord', 'CWERecord', 'RepositoryRecord'] 