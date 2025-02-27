import os
import zipfile
import shutil
from pathlib import Path
from src.utils.logger import Logger

def verify_zip(zip_path: Path, zip_type: str) -> bool:
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

def extract_zip(zip_path: Path, specific_file: str = None, extract_to: Path = None) -> bool:
    """Extract contents from a zip file."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            if specific_file:
                # Extract a specific file
                if extract_to:
                    # If extract_to is a directory, create it
                    if not extract_to.parent.exists():
                        extract_to.parent.mkdir(parents=True, exist_ok=True)
                    
                    with zip_ref.open(specific_file) as source, open(extract_to, 'wb') as target:
                        shutil.copyfileobj(source, target)
                else:
                    # Extract to current directory
                    zip_ref.extract(specific_file)
            else:
                # Extract all files
                if extract_to:
                    # Ensure the directory exists
                    extract_to.mkdir(parents=True, exist_ok=True)
                    zip_ref.extractall(extract_to)
                else:
                    zip_ref.extractall()
        return True
    except Exception as e:
        Logger.error(f"Failed to extract from zip: {str(e)}")
        return False

def find_file_in_zip(zip_path: Path, filename_pattern: str) -> str:
    """Find a file in a zip that matches the given pattern."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            all_files = zip_ref.namelist()
            
            # Log the first few files for debugging
            if all_files:
                Logger.info(f"Files in zip: {all_files[:5]}... (showing first 5 of {len(all_files)} files)")
            else:
                Logger.warning("Zip file is empty")
                return None
            
            # First look for exact matches
            for file in all_files:
                if file.endswith(filename_pattern):
                    Logger.info(f"Found exact match: {file}")
                    return file
            
            # If no exact match, look for partial matches
            for file in all_files:
                if filename_pattern.lower() in file.lower():
                    Logger.info(f"Found partial match: {file}")
                    return file
            
            Logger.warning(f"No file matching '{filename_pattern}' found in zip")
            return None
    except Exception as e:
        Logger.error(f"Error searching zip file: {str(e)}")
        return None 