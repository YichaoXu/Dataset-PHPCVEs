"""
File utilities for PHP CVE Dataset Collection Tool.

This module provides file-related utility functions, including directory creation,
file copying, and file reading/writing.
"""

import os
import shutil
import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from src.utils.logger import Logger

def ensure_dir(directory: Path) -> Path:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory: Directory path
        
    Returns:
        Path to the directory
    """
    os.makedirs(directory, exist_ok=True)
    return directory

def copy_file(src: Path, dst: Path) -> bool:
    """
    Copy a file from source to destination.
    
    Args:
        src: Source file path
        dst: Destination file path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        shutil.copy2(src, dst)
        return True
    except Exception as e:
        Logger.error(f"Error copying file from {src} to {dst}: {str(e)}")
        return False

def read_json_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Read a JSON file.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Dictionary containing JSON data or None if file cannot be read
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        Logger.error(f"Error reading JSON file {file_path}: {str(e)}")
        return None

def write_json_file(data: Dict[str, Any], file_path: Path) -> bool:
    """
    Write data to a JSON file.
    
    Args:
        data: Data to write
        file_path: Path to JSON file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        Logger.error(f"Error writing JSON file {file_path}: {str(e)}")
        return False

def read_csv_file(file_path: Path) -> List[Dict[str, str]]:
    """
    Read a CSV file.
    
    Args:
        file_path: Path to CSV file
        
    Returns:
        List of dictionaries containing CSV data
    """
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception as e:
        Logger.error(f"Error reading CSV file {file_path}: {str(e)}")
        return []

def write_csv_file(data: List[Dict[str, Any]], file_path: Path) -> bool:
    """
    Write data to a CSV file.
    
    Args:
        data: Data to write
        file_path: Path to CSV file
        
    Returns:
        True if successful, False otherwise
    """
    if not data:
        Logger.warning(f"No data to write to {file_path}")
        return False
    
    try:
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            fieldnames = data[0].keys()
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        return True
    except Exception as e:
        Logger.error(f"Error writing CSV file {file_path}: {str(e)}")
        return False

def get_file_size(file_path: Path) -> int:
    """
    Get file size in bytes.
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes
    """
    try:
        return os.path.getsize(file_path)
    except Exception:
        return 0

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: File size in bytes
        
    Returns:
        Formatted file size string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024 or unit == 'GB':
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024 