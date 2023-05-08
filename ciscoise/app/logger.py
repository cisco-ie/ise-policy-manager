import sys, os
import logging

LOGGER_DIR = "logs/"

class Logger(object):

    def __init__(self):
        if not os.path.exists(LOGGER_DIR):
            os.mkdir(LOGGER_DIR)

        self.logger = logging.getLogger(__name__)

        fmt = logging.Formatter(
            "%(name)s: %(asctime)s | %(levelname)s | %(message)s"
        )
        stdoutHandler = logging.StreamHandler(stream=sys.stdout)
        self.logger.addHandler(stdoutHandler)

        fileHandler = logging.FileHandler(LOGGER_DIR+"logs.txt")
        self.logger.addHandler(fileHandler)

        fileHandler.setFormatter(fmt)
        
        self.logger.setLevel(logging.INFO)