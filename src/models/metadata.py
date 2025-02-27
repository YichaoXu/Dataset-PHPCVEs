import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from src.utils.logger import Logger

class MetadataGenerator:
    """Generates metadata files for downloaded code."""
    
    @staticmethod
    def generate_metadata(cve_data: Dict[str, Any], cve_dir: Path) -> bool:
        """
        Generate metadata file for a downloaded CVE.
        
        Args:
            cve_data: Dictionary containing CVE information
            cve_dir: Directory where the CVE code is downloaded
            
        Returns:
            True if metadata was generated successfully, False otherwise
        """
        try:
            metadata = {
                "cve_id": cve_data.get("cve_id", ""),
                "cwe_type": cve_data.get("cwe_type", ""),
                "repository": cve_data.get("repository", ""),
                "current_commit": cve_data.get("current_commit", ""),
                "previous_commit": cve_data.get("previous_commit", ""),
                "project_type": cve_data.get("project_type", ""),
                "download_date": datetime.now().isoformat(),
                "download_status": "complete"
            }
            
            metadata_path = cve_dir / "metadata.json"
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
                
            return True
        except Exception as e:
            Logger.error(f"Failed to generate metadata: {str(e)}")
            return False
    
    @staticmethod
    def is_download_complete(cve_dir: Path) -> bool:
        """
        Check if a CVE has been completely downloaded.
        
        Args:
            cve_dir: Directory where the CVE code is downloaded
            
        Returns:
            True if the download is complete, False otherwise
        """
        metadata_path = cve_dir / "metadata.json"
        if not os.path.exists(metadata_path):
            return False
            
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                return metadata.get("download_status") == "complete"
        except Exception:
            return False 