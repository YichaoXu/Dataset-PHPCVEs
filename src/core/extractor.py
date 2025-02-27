import os
import shutil
from pathlib import Path
from src.utils.logger import Logger
from src.utils.zip_utils import verify_zip, extract_zip, find_file_in_zip
from src.config import config

class CVEExtractor:
    """Handles extraction of CVE data from zip files."""
    
    def __init__(self, inter_dir: Path, use_cache: bool = True):
        self.inter_dir = inter_dir
        self.use_cache = use_cache
        self.main_zip_path = inter_dir / "cve_data.zip"
        self.inner_zip_path = inter_dir / "cves.zip"
        self.cve_dir = inter_dir / "cves"
    
    def cve_data_exists(self) -> bool:
        """Check if CVE data directory exists."""
        return self.cve_dir.exists() and any(self.cve_dir.glob("*"))
    
    def get_cve_dir(self) -> Path:
        """Get the CVE data directory."""
        return self.cve_dir
    
    def extract_cve_data(self) -> bool:
        """Extract CVE data from zip files."""
        # Step 1: Extract inner zip from main zip if needed
        if not self.inner_zip_path.exists() or not self.use_cache:
            if not self._extract_inner_zip():
                return False
        
        # Step 2: Extract CVE data from inner zip
        return self._extract_from_inner_zip()
    
    def _extract_inner_zip(self) -> bool:
        """Extract the inner zip file from the main zip."""
        # Verify main zip
        if not verify_zip(self.main_zip_path, "Main"):
            return False
        
        try:
            Logger.info("Extracting inner zip file from main zip...")
            
            # Find and extract the inner zip file
            cves_zip_file = find_file_in_zip(self.main_zip_path, 'cves.zip')
            if not cves_zip_file:
                Logger.error("cves.zip not found in the main zip file")
                return False
            
            # Extract the inner zip file
            if not extract_zip(self.main_zip_path, cves_zip_file, self.inner_zip_path):
                return False
            
            Logger.success("Inner zip file extracted successfully")
            return True
        except Exception as e:
            Logger.error(f"Failed to extract inner zip file: {str(e)}")
            return False
    
    def _extract_from_inner_zip(self) -> bool:
        """Extract CVE data from the inner zip file."""
        # Verify inner zip
        if not verify_zip(self.inner_zip_path, "Inner"):
            return False
        
        # Clean up existing directory if it exists
        if self.cve_dir.exists():
            shutil.rmtree(self.cve_dir)
        
        try:
            Logger.info("Extracting CVE data from inner zip...")
            if not extract_zip(self.inner_zip_path, None, self.inter_dir):
                return False
            
            Logger.success("Extraction complete")
            return True
        except Exception as e:
            Logger.error(f"Failed to extract inner zip file: {str(e)}")
            return False 