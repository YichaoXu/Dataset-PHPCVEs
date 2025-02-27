import zipfile
import shutil
from pathlib import Path
from src.utils.logger import Logger

def verify_zip(zip_path: Path, zip_type: str) -> bool:
    """Verify that a zip file is valid."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.testzip()
        Logger.info(f"{zip_type} zip file is valid")
        return True
    except zipfile.BadZipFile as e:
        Logger.error(f"The {zip_type} zip file is corrupted: {str(e)}")
        return False

def extract_zip(zip_path: Path, specific_file: str = None, extract_to: Path = None) -> bool:
    """Extract contents from a zip file."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            if specific_file:
                # Extract a specific file
                with zip_ref.open(specific_file) as source, open(extract_to, 'wb') as target:
                    shutil.copyfileobj(source, target)
            else:
                # Extract all files
                zip_ref.extractall(extract_to)
        return True
    except Exception as e:
        Logger.error(f"Failed to extract from zip: {str(e)}")
        return False

def find_file_in_zip(zip_path: Path, filename_pattern: str) -> str:
    """Find a file in a zip that matches the given pattern."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            all_files = zip_ref.namelist()
            Logger.info(f"Files in zip: {all_files[:5]}... (showing first 5)")
            
            for file in all_files:
                if file.endswith(filename_pattern):
                    return file
        return None
    except Exception as e:
        Logger.error(f"Error searching zip file: {str(e)}")
        return None 