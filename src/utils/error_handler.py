import time
from typing import Callable, Any, Optional, TypeVar
from src.utils.logger import Logger

T = TypeVar('T')

class ErrorHandler:
    """Centralized error handling for the application."""
    
    @staticmethod
    def with_retry(
        func: Callable[..., T], 
        *args, 
        max_retries: int = 3, 
        retry_delay: int = 5,
        error_msg: str = "Operation failed",
        **kwargs
    ) -> Optional[T]:
        """Execute a function with retry logic."""
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                Logger.warning(f"{error_msg} (attempt {attempt+1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
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