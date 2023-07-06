import sys, os
import logging
from logging.handlers import RotatingFileHandler

LOGGER_DIR = "../logs/"

class Logger(object):

    def __init__(self):
        if not os.path.exists(LOGGER_DIR):
            os.mkdir(LOGGER_DIR)

        self.logger = logging.getLogger(__name__)
        if not self.logger.hasHandlers():
            fmt = logging.Formatter("%(name)s: %(asctime)s | %(levelname)s | %(message)s")
        
            #fileHandler = logging.FileHandler(LOGGER_DIR+"logs.txt")
            fileHandler = RotatingFileHandler(LOGGER_DIR+"logs.txt", backupCount=5, maxBytes=5000000)
            stdoutHandler = logging.StreamHandler(stream=sys.stdout)

            fileHandler.setFormatter(fmt)
            stdoutHandler.setFormatter(fmt)

            self.logger.addHandler(fileHandler)
            self.logger.addHandler(stdoutHandler)

            self.logger.setLevel(logging.INFO)
