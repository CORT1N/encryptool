"""Logger utility for the application."""
import logging
import sys
from typing import Any


class Logger:
    """Singleton logger class for the application."""

    def __init__(self, name: str = "app", level: int = logging.INFO) -> None:
        """Initialize the logger with a name and level."""
        self.logger = logging.getLogger(name)
        if not self.logger.hasHandlers():
            self.logger.setLevel(level)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "%Y-%m-%d %H:%M:%S",
            )
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def debug(self, msg: str, *args, **kwargs) -> None:
        """Log a debug message."""
        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        """Log an info message."""
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        """Log a warning message."""
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        """Log an error message."""
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs) -> None:
        """Log a critical message."""
        self.logger.critical(msg, *args, **kwargs)

logger = Logger(level=logging.DEBUG)
