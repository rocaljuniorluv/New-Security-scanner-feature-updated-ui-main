import logging
import sys
from pathlib import Path
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console

class Logger:
    _instance: Optional['Logger'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.console = Console()
            self.setup_logging()
            self.initialized = True
            
    def setup_logging(self, level: str = 'INFO', log_file: str = 'security_scanner.log') -> None:
        """
        Set up logging configuration
        
        Args:
            level: Logging level
            log_file: Path to log file
        """
        # Create logs directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                RichHandler(console=self.console, rich_tracebacks=True),
                logging.FileHandler(log_file)
            ]
        )
        
        self.logger = logging.getLogger('security_scanner')
        
    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)
        
    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)
        
    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)
        
    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)
        
    def critical(self, message: str) -> None:
        """Log critical message"""
        self.logger.critical(message)
        
    def exception(self, message: str) -> None:
        """Log exception with traceback"""
        self.logger.exception(message) 