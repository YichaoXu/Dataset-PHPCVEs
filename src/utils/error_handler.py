import time
from typing import Callable, Any, Optional, TypeVar
from src.utils.logger import Logger

T = TypeVar('T')

class ErrorHandler:
    """Centralized error handling for the application."""
    
    @staticmethod
    def with_retry(func, *args, max_retries=3, retry_delay=5, error_msg=None):
        """
        Execute a function with retry logic.
        
        Args:
            func: Function to execute
            *args: Arguments to pass to the function
            max_retries: Maximum number of retries
            retry_delay: Delay between retries in seconds
            error_msg: Custom error message prefix
            
        Returns:
            Result of the function or None if all retries fail
        """
        for attempt in range(1, max_retries + 1):
            try:
                return func(*args)
            except Exception as e:
                if error_msg:
                    Logger.warning(f"{error_msg} (attempt {attempt}/{max_retries}): {str(e)}")
                else:
                    Logger.warning(f"Error (attempt {attempt}/{max_retries}): {str(e)}")
                
                if attempt < max_retries:
                    time.sleep(retry_delay)
                else:
                    Logger.error(f"Failed after {max_retries} attempts")
                    return None
    
    @staticmethod
    def try_multiple_encodings(file_path, encodings=None):
        """Try to open a file with multiple encodings."""
        if encodings is None:
            encodings = ['utf-8', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read(), encoding
            except UnicodeDecodeError:
                continue
        
        raise UnicodeError(f"Could not decode file {file_path} with any of the encodings: {encodings}")
    
    @staticmethod
    def safe_execute(func: Callable[..., T], *args, default_value: Any = None, **kwargs) -> T:
        """Execute a function safely, returning a default value on error."""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            Logger.warning(f"Error executing {func.__name__}: {str(e)}")
            return default_value 