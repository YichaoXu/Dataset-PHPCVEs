import csv
from pathlib import Path
from utils.logger import Logger

class DataValidator:
    """Dataset format validator"""
    REQUIRED_FIELDS = {'cve_id', 'cwe_type', 'repository', 'current_commit', 'previous_commit', 'project_type'}

    @staticmethod
    def validate_dataset(path: Path) -> bool:
        try:
            if not path.exists():
                Logger.error(f"Dataset file not found: {path}")
                return False
                
            with open(path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    Logger.error("Invalid CSV file: no headers found")
                    return False
                    
                missing_fields = DataValidator.REQUIRED_FIELDS - set(reader.fieldnames)
                if missing_fields:
                    Logger.error(f"Missing required fields: {', '.join(missing_fields)}")
                    return False
                    
                # Validate data integrity
                for row_num, row in enumerate(reader, start=2):
                    if not all(row.get(field) for field in DataValidator.REQUIRED_FIELDS):
                        Logger.warning(f"Row {row_num} has missing values")
                        
                return True
        except Exception as e:
            Logger.error(f"Dataset validation failed: {e}")
            return False 