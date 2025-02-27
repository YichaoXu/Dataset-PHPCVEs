"""
Repository data model for PHP CVE Dataset Collection Tool.

This module provides a data model for GitHub repository information.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime

@dataclass
class RepositoryRecord:
    """Represents a GitHub repository record."""
    
    owner: str
    name: str
    url: str
    description: str = ""
    stars: int = 0
    forks: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    language: str = "PHP"
    topics: List[str] = field(default_factory=list)
    project_type: str = "Unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def full_name(self) -> str:
        """Get the full repository name (owner/name)."""
        return f"{self.owner}/{self.name}"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RepositoryRecord':
        """
        Create a RepositoryRecord from a dictionary.
        
        Args:
            data: Dictionary containing repository data
            
        Returns:
            RepositoryRecord instance
        """
        # Parse dates if available
        created_at = None
        if "created_at" in data and data["created_at"]:
            try:
                created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        updated_at = None
        if "updated_at" in data and data["updated_at"]:
            try:
                updated_at = datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        return cls(
            owner=data.get("owner", ""),
            name=data.get("name", ""),
            url=data.get("url", ""),
            description=data.get("description", ""),
            stars=int(data.get("stars", 0)),
            forks=int(data.get("forks", 0)),
            created_at=created_at,
            updated_at=updated_at,
            language=data.get("language", "PHP"),
            topics=data.get("topics", []),
            project_type=data.get("project_type", "Unknown"),
            metadata={k: v for k, v in data.items() if k not in [
                "owner", "name", "url", "description", "stars", "forks",
                "created_at", "updated_at", "language", "topics", "project_type"
            ]}
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the record to a dictionary.
        
        Returns:
            Dictionary representation of the record
        """
        result = {
            "owner": self.owner,
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "stars": self.stars,
            "forks": self.forks,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "language": self.language,
            "topics": self.topics,
            "project_type": self.project_type
        }
        
        # Add metadata
        result.update(self.metadata)
        
        return result
    
    def __str__(self) -> str:
        """String representation of the record."""
        return f"{self.full_name} ({self.project_type})" 