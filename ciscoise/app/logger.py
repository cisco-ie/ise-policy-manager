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
        fileHandler = logging.FileHandler(LOGGER_DIR+"logs.txt")

        fileHandler.setFormatter(fmt)
        self.logger.addHandler(fileHandler)

        self.logger.setLevel(logging.INFO)