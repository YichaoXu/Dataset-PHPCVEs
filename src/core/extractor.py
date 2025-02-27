import os
import shutil
import zipfile
from pathlib import Path
from src.utils.logger import Logger
from src.utils.file_utils import ensure_dir

class CVEExtractor:
    """Handles extraction of CVE data, specifically for two-level nested ZIP file structure."""
    
    def __init__(self, cache_dir: Path, cve_dir: Path, cve_zip_path: Path, use_cache: bool = True):
        """
        Initialize the extractor.
        
        Args:
            cache_dir: Directory to store extracted files
            cve_dir: Directory to extract CVE data to
            cve_zip_path: Path to the CVE ZIP file
            use_cache: Whether to use cached files
        """
        self.cache_dir = cache_dir
        self.cve_dir = cve_dir
        self.cve_zip_path = cve_zip_path
        self.use_cache = use_cache
        ensure_dir(self.cache_dir)
    
    def cve_data_exists(self) -> bool:
        """Check if CVE data directory exists and contains JSON files."""
        exists = self.cve_dir.exists() and any(self.cve_dir.glob("**/*.json"))
        if self.cve_dir.exists() and not exists:
            Logger.warning(f"CVE directory exists at {self.cve_dir} but contains no JSON files")
            files = list(self.cve_dir.glob("*"))
            if files:
                Logger.info(f"Directory contains {len(files)} items, first 5: {[f.name for f in files[:5]]}")
            else:
                Logger.info("Directory is empty")
        return exists
    
    def get_cve_dir(self) -> Path:
        """Get the CVE data directory."""
        return self.cve_dir
    
    def extract_cve_data(self) -> bool:
        """Extract CVE data, handling two-level nested ZIP files."""
        # Clean up existing directory
        if self.cve_dir.exists():
            shutil.rmtree(self.cve_dir)
        ensure_dir(self.cve_dir)
        
        try:
            # Step 1: Extract cves.zip from the main ZIP file
            Logger.info("Step 1: Extracting cves.zip from main ZIP file")
            
            # Verify main ZIP file
            self._verify_zip(self.cve_zip_path, "Main")
            
            # Extract cves.zip to temporary location
            temp_inner_zip = self.cache_dir / "cves_temp.zip"
            self._extract_inner_zip(self.cve_zip_path, temp_inner_zip)
            
            # Step 2: Extract CVE data from cves.zip
            Logger.info(f"Step 2: Extracting CVE data from cves.zip to {self.cve_dir}")
            
            # Verify inner ZIP file
            self._verify_zip(temp_inner_zip, "Inner")
            
            # Extract CVE data
            with zipfile.ZipFile(temp_inner_zip, 'r') as zip_ref:
                zip_ref.extractall(self.cve_dir)
            
            # Clean up temporary files
            os.remove(temp_inner_zip)
            
            # Verify extraction was successful
            json_files = list(self.cve_dir.glob("**/*.json"))
            if not json_files:
                Logger.error("No JSON files found after extraction")
                return False
            
            Logger.success(f"Extraction complete - found {len(json_files)} JSON files")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to extract CVE data: {str(e)}")
            return False
    
    def _verify_zip(self, zip_path: Path, zip_type: str) -> bool:
        """Verify that a ZIP file is valid."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                result = zip_ref.testzip()
                if result is not None:
                    Logger.error(f"{zip_type} ZIP file is corrupted: {result}")
                    return False
            Logger.info(f"{zip_type} ZIP file is valid")
            return True
        except zipfile.BadZipFile as e:
            Logger.error(f"{zip_type} ZIP file is corrupted: {str(e)}")
            return False
    
    def _extract_inner_zip(self, main_zip_path: Path, output_path: Path) -> bool:
        """Extract the inner ZIP file (cves.zip) from the main ZIP file."""
        try:
            with zipfile.ZipFile(main_zip_path, 'r') as zip_ref:
                # Find cves.zip
                cves_zip_file = None
                for file in zip_ref.namelist():
                    if file.endswith('cves.zip'):
                        cves_zip_file = file
                        break
                
                if not cves_zip_file:
                    Logger.error("cves.zip not found in the main ZIP file")
                    return False
                
                Logger.info(f"Found inner ZIP file: {cves_zip_file}")
                
                # Extract the inner ZIP file
                with zip_ref.open(cves_zip_file) as source, open(output_path, 'wb') as target:
                    shutil.copyfileobj(source, target)
                
                # Verify the extracted inner ZIP file
                if not os.path.exists(output_path) or os.path.getsize(output_path) < 1000:
                    Logger.error(f"Failed to extract inner ZIP file or file is too small: {output_path}")
                    return False
                
                Logger.success("Inner ZIP file extracted successfully")
                return True
        except Exception as e:
            Logger.error(f"Failed to extract inner ZIP file: {str(e)}")
            return False 