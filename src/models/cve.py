from dataclasses import dataclass
from typing import Optional, List, Dict, Any

@dataclass
class CVERecord:
    """Represents a processed CVE record."""
    cve_id: str
    cwe_type: str
    repository: str
    current_commit: str
    previous_commit: str
    project_type: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CVERecord':
        """Create a CVERecord from a dictionary."""
        return cls(
            cve_id=data['cve_id'],
            cwe_type=data['cwe_type'],
            repository=data['repository'],
            current_commit=data['current_commit'],
            previous_commit=data['previous_commit'],
            project_type=data['project_type']
        )
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary."""
        return {
            'cve_id': self.cve_id,
            'cwe_type': self.cwe_type,
            'repository': self.repository,
            'current_commit': self.current_commit,
            'previous_commit': self.previous_commit,
            'project_type': self.project_type
        } 