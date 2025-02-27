import os
import shutil
import requests
import zipfile
from pathlib import Path
from src.utils.logger import Logger
from src.utils.file_utils import ensure_dir
from src.config import config

class CodeDownloader:
    """GitHub code downloader"""
    @staticmethod
    def download_commit(repo_url: str, commit_hash: str, save_path: str) -> bool:
        """Download and validate commit archive"""
        try:
            repo_path = repo_url.replace("https://github.com/", "").strip()
            archive_url = f"https://github.com/{repo_path}/archive/{commit_hash}.zip"
            
            if os.path.exists(save_path): 
                shutil.rmtree(save_path)
            os.makedirs(save_path, exist_ok=False)
            
            response = requests.get(archive_url, stream=True)
            if response.status_code == 200:
                zip_path = f"{save_path}.zip"
                with open(zip_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                # Validate downloaded file
                if os.path.getsize(zip_path) < 1024:
                    Logger.error(f"Downloaded file too small: {zip_path}")
                    os.remove(zip_path)
                    return False
                    
                if not zipfile.is_zipfile(zip_path):
                    Logger.error(f"Invalid ZIP file: {zip_path}")
                    os.remove(zip_path)
                    return False
                    
                # Validate ZIP contents
                try:
                    with zipfile.ZipFile(zip_path, "r") as zip_ref:
                        # Check for zip corruption
                        if zip_ref.testzip() is not None:
                            Logger.error(f"Corrupted ZIP file: {zip_path}")
                            return False
                            
                        # Check if ZIP contains any files
                        if not zip_ref.namelist():
                            Logger.error(f"Empty ZIP file: {zip_path}")
                            return False
                            
                        zip_ref.extractall(save_path)
                except zipfile.BadZipFile:
                    Logger.error(f"Bad ZIP file: {zip_path}")
                    return False

                # Cleanup
                os.remove(zip_path)
                return True

            else:
                Logger.error(f"Failed to download {repo_url} commit {commit_hash}: {response.status_code}")
                return False

        except Exception as e:
            Logger.error(f"Download error: {e}")
            return False

class CVEDownloader:
    """Handles downloading of CVE data."""
    
    def __init__(self, cache_dir: Path, cve_zip_path: Path, use_cache: bool = True):
        """
        Initialize the downloader.
        
        Args:
            cache_dir: Directory to store downloaded files
            cve_zip_path: Path to the CVE zip file
            use_cache: Whether to use cached files
        """
        self.cache_dir = cache_dir
        self.use_cache = use_cache
        self.cve_zip_path = cve_zip_path
        ensure_dir(self.cache_dir)
    
    def download_cve_data(self) -> bool:
        """Download CVE data if needed."""
        if self.cve_zip_path.exists() and self.use_cache:
            Logger.info("Using existing main zip file")
            return True
        return self._download_main_zip()
    
    def _download_main_zip(self) -> bool:
        """Download the main CVE data zip file."""
        try:
            Logger.info("Downloading CVE dataset...")
            response = requests.get(config.cve_url)
            response.raise_for_status()
            
            with open(self.cve_zip_path, 'wb') as f:
                f.write(response.content)
            Logger.success("CVE data downloaded successfully")
            return True
        except requests.exceptions.RequestException as e:
            Logger.error(f"Failed to download CVE data: {str(e)}")
            return False 