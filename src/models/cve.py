"""
CVE data model for PHP CVE Dataset Collection Tool.

This module provides a data model for CVE records, including parsing and
serialization functionality.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json
import re
from datetime import datetime

@dataclass
class CVERecord:
    """Represents a CVE record with associated metadata."""
    
    cve_id: str
    cwe_id: Optional[str] = None
    description: str = ""
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    repository: Optional[str] = None
    current_commit: Optional[str] = None
    previous_commit: Optional[str] = None
    project_type: str = "Unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CVERecord':
        """
        Create a CVERecord from a dictionary.
        
        Args:
            data: Dictionary containing CVE data
            
        Returns:
            CVERecord instance
        """
        # Parse dates if available
        published_date = None
        if "published_date" in data and data["published_date"]:
            try:
                published_date = datetime.fromisoformat(data["published_date"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        last_modified_date = None
        if "last_modified_date" in data and data["last_modified_date"]:
            try:
                last_modified_date = datetime.fromisoformat(data["last_modified_date"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        # Parse CVSS score
        cvss_score = None
        if "cvss_score" in data and data["cvss_score"]:
            try:
                cvss_score = float(data["cvss_score"])
            except (ValueError, TypeError):
                pass
        
        # Create record
        return cls(
            cve_id=data.get("cve_id", ""),
            cwe_id=data.get("cwe_id"),
            description=data.get("description", ""),
            published_date=published_date,
            last_modified_date=last_modified_date,
            severity=data.get("severity"),
            cvss_score=cvss_score,
            repository=data.get("repository"),
            current_commit=data.get("current_commit"),
            previous_commit=data.get("previous_commit"),
            project_type=data.get("project_type", "Unknown"),
            metadata={k: v for k, v in data.items() if k not in [
                "cve_id", "cwe_id", "description", "published_date", 
                "last_modified_date", "severity", "cvss_score", 
                "repository", "current_commit", "previous_commit", "project_type"
            ]}
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the record to a dictionary.
        
        Returns:
            Dictionary representation of the record
        """
        result = {
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified_date": self.last_modified_date.isoformat() if self.last_modified_date else None,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "repository": self.repository,
            "current_commit": self.current_commit,
            "previous_commit": self.previous_commit,
            "project_type": self.project_type
        }
        
        # Add metadata
        result.update(self.metadata)
        
        return result
    
    def __str__(self) -> str:
        """String representation of the record."""
        return f"CVE-{self.cve_id} (CWE-{self.cwe_id}): {self.description[:50]}..." 