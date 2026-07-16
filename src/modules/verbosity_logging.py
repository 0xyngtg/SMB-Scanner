import logging
from enum import IntEnum

logger : logging.Logger= logging.getLogger(__name__)

class CustomColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord):
        no_style = "\033[0m"
        bold = "\033[1m"
        grey = "\033[90m"
        yellow = "\033[93m"
        red = "\033[31m"
        red_light = "\033[91m"
        start_style = {
            "DEBUG": grey,
            "INFO": no_style,
            "WARNING": yellow,
            "ERROR": red_light,
            "CRITICAL": no_style,
        }.get(record.levelname, no_style)
        end_style = no_style
        return f'{start_style}{super().format(record)}{end_style}'
class VerbosityLevel(IntEnum):
    LEVEL_1 = logging.WARNING # Warning
    LEVEL_2 = logging.INFO # Info (console only)
    LEVEL_3 = logging.INFO # Info (console + log file)
    LEVEL_4 = logging.DEBUG # Debug (console + log file)

def set_consolehandler(verbosity_level: VerbosityLevel) -> logging.StreamHandler:
    """Set up a console handler for logging to the console."""
    console_formatter = CustomColorFormatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(verbosity_level)
    console_handler.setFormatter(console_formatter)
    return console_handler

def set_filehandler(log_file: str, verbosity_level: VerbosityLevel) -> logging.FileHandler:
    """Set up a file handler for logging to a file."""
    file_formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)s | %(message)s',
        datefmt="%H:%M:%S"
    )
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setLevel(verbosity_level)
    file_handler.setFormatter(file_formatter)
    return file_handler

def set_verbosity(verbosity_level: VerbosityLevel, log_file: str | None) -> None:
    """Set up logging accordingly to the user command line options. Log files will be written to the current directory if the user does not specify a path."""
    logger.setLevel(verbosity_level)
    
    # Console handler
    console_handler: logging.StreamHandler = set_consolehandler(verbosity_level)
    logger.addHandler(console_handler)
    
    # File handler (only for level 3 and 4)
    if verbosity_level in (VerbosityLevel.LEVEL_3, VerbosityLevel.LEVEL_4) and log_file:
        file_handler = set_filehandler(log_file, verbosity_level)
        logger.addHandler(file_handler)
    
    logger.propagate = False

def run(log_file: str | None, verbosity_option: bool | None) -> None:
    if log_file and verbosity_option:
        set_verbosity(VerbosityLevel.LEVEL_4, log_file)
    elif log_file and not verbosity_option:
        set_verbosity(VerbosityLevel.LEVEL_3, log_file)
    elif not log_file and verbosity_option:
        set_verbosity(VerbosityLevel.LEVEL_2, log_file=None)
    else:
        set_verbosity(VerbosityLevel.LEVEL_1, log_file=None)
