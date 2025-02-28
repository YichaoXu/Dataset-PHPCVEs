import os
from pathlib import Path
from dataclasses import dataclass

@dataclass
class Config: 
    DATASET_HOME: Path = Path(os.path.dirname(__file__)).parent
    DS_CACHE_PATH: Path = DATASET_HOME / ".cache"
    DS_INTER_PATH: Path = DATASET_HOME / ".inter"
    CVELISTV5_URL: str = "https://github.com/CVEProject/cvelistV5/releases/download/cve_2025-02-14_1700Z/2025-02-14_all_CVEs_at_midnight.zip.zip" 
