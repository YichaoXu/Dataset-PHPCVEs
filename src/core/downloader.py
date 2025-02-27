import os
import shutil
import requests
import zipfile
from utils.logger import Logger

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