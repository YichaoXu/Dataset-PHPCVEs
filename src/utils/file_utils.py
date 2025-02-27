import os
import shutil
from pathlib import Path
from src.utils.logger import Logger

def ensure_dir(dir_path: Path) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(dir_path, exist_ok=True)

def copy_file(src_path: Path, dest_path: Path) -> None:
    """Copy file from source to destination."""
    ensure_dir(dest_path.parent)
    shutil.copy2(src_path, dest_path) 