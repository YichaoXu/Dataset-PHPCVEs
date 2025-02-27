import json
import time
from pathlib import Path
from typing import Dict

class MetadataGenerator:
    """Generate and validate CVE metadata"""
    @staticmethod
    def generate_metadata(cve_data: Dict, save_path: Path) -> Dict:
        """Generate metadata for a CVE"""
        metadata = {
            "cve_id": cve_data["cve_id"],
            "cwe_type": cve_data["cwe_type"],
            "repository": cve_data["repository"],
            "project_type": cve_data["project_type"],
            "commits": {
                "previous": cve_data["previous_commit"],
                "current": cve_data["current_commit"]
            },
            "download_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "download_status": "complete"
        }
        
        with open(save_path / "cve.meta.json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        return metadata

    @staticmethod
    def is_download_complete(cve_dir: Path) -> bool:
        """Check if CVE download is complete"""
        meta_file = cve_dir / "cve.meta.json"
        if not meta_file.exists():
            return False
            
        try:
            with open(meta_file, "r") as f:
                metadata = json.load(f)
            return metadata.get("download_status") == "complete"
        except Exception:
            return False 