import os
import csv
from pathlib import Path
from src.utils.logger import Logger
from src.config import config

class DataValidator:
    """Validates dataset files and structures."""
    
    @staticmethod
    def validate_dataset(dataset_path: Path) -> bool:
        """
        Validate that the dataset CSV file exists and has the required columns.
        
        Args:
            dataset_path: Path to the dataset CSV file
            
        Returns:
            True if the dataset is valid, False otherwise
        """
        if not os.path.exists(dataset_path):
            Logger.error(f"Dataset file not found: {dataset_path}")
            return False
            
        try:
            with open(dataset_path, 'r') as f:
                reader = csv.reader(f)
                header = next(reader)
                
                required_columns = [
                    'cve_id', 'cwe_type', 'repository', 
                    'current_commit', 'previous_commit', 'project_type'
                ]
                
                missing_columns = [col for col in required_columns if col not in header]
                
                if missing_columns:
                    Logger.error(f"Dataset missing required columns: {', '.join(missing_columns)}")
                    return False
                    
                # Check if there's at least one row of data
                try:
                    next(reader)
                except StopIteration:
                    Logger.warning("Dataset is empty (no data rows)")
                    return False
                    
                return True
                
        except Exception as e:
            Logger.error(f"Error validating dataset: {str(e)}")
            return False 