from dataclasses import dataclass
from typing import Optional, List, Dict, Any

@dataclass
class CVERecord:
    """Represents a processed CVE record."""
    cve_id: str
    cwe_type: Optional[str]
    repository: str
    current_commit: str
    previous_commit: str
    project_type: str
    
    def __init__(
        self, 
        cve_id: str, 
        cwe_type: Optional[str], 
        repository: str, 
        current_commit: str, 
        previous_commit: str, 
        project_type: str
    ):
        self.cve_id = cve_id
        self.cwe_type = cwe_type  # Can be None
        self.repository = repository
        self.current_commit = current_commit
        self.previous_commit = previous_commit
        self.project_type = project_type
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CVERecord':
        """Create a CVERecord from a dictionary."""
        return cls(
            cve_id=data['cve_id'],
            cwe_type=data.get('cwe_type'),  # Use get() to handle None
            repository=data['repository'],
            current_commit=data['current_commit'],
            previous_commit=data['previous_commit'],
            project_type=data['project_type']
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'cve_id': self.cve_id,
            'cwe_type': self.cwe_type,  # Can be None
            'repository': self.repository,
            'current_commit': self.current_commit,
            'previous_commit': self.previous_commit,
            'project_type': self.project_type
        } 