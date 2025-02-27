"""
CWE data model for PHP CVE Dataset Collection Tool.

This module provides a data model for Common Weakness Enumeration (CWE) records.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any

@dataclass
class CWERecord:
    """Represents a CWE record with associated metadata."""
    
    cwe_id: str
    name: str
    description: str = ""
    likelihood: Optional[str] = None
    severity: Optional[str] = None
    parent_ids: List[str] = None
    child_ids: List[str] = None
    
    def __post_init__(self):
        """Initialize default values for lists."""
        if self.parent_ids is None:
            self.parent_ids = []
        if self.child_ids is None:
            self.child_ids = []
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CWERecord':
        """
        Create a CWERecord from a dictionary.
        
        Args:
            data: Dictionary containing CWE data
            
        Returns:
            CWERecord instance
        """
        return cls(
            cwe_id=data.get("cwe_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            likelihood=data.get("likelihood"),
            severity=data.get("severity"),
            parent_ids=data.get("parent_ids", []),
            child_ids=data.get("child_ids", [])
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the record to a dictionary.
        
        Returns:
            Dictionary representation of the record
        """
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "likelihood": self.likelihood,
            "severity": self.severity,
            "parent_ids": self.parent_ids,
            "child_ids": self.child_ids
        }
    
    def __str__(self) -> str:
        """String representation of the record."""
        return f"CWE-{self.cwe_id}: {self.name}" 