import logging
import sys

"""
A somewhat painful way required to set up our own logger
and still be able to use a custom format
"""


class Loggy(object):

    CRITICAL = logging.CRITICAL
    ERROR = logging.ERROR
    WARNING = logging.WARNING
    INFO = logging.INFO
    DEBUG = logging.DEBUG

    def __init__(self,
                 logger_name,
                 logger_format="%(asctime)s %(levelname)s: %(message)s",
                 logger_default_level=INFO):

        self._logger = logging.getLogger(logger_name)
        self._logger_format = logging.Formatter(logger_format)
        self._logger.setLevel(logger_default_level)
        self._default_level = logger_default_level

        # setup definitions for later.. makes pycharm happy about
        # strict PEP requirements
        self._logger_to_stderr = None
        self._logger_to_stdout = None
        self._logger_to_file = None

    def logger(self):
        return self._logger

    def setup_log_to_stderr(self, log_level=None):
        if log_level is None:
            log_level = self._default_level
        self._logger_to_stderr = logging.StreamHandler(stream=sys.stderr)
        self._logger_to_stderr.setLevel(level=log_level)
        self._logger_to_stderr.setFormatter(self._logger_format)
        self._logger.addHandler(self._logger_to_stderr)
        return self

    def setup_log_to_stdout(self, log_level=None):
        if log_level is None:
            log_level = self._default_level
        self._logger_to_stdout = logging.StreamHandler(stream=sys.stdout)
        self._logger_to_stdout.setLevel(level=log_level)
        self._logger_to_stdout.setFormatter(self._logger_format)
        self._logger.addHandler(self._logger_to_stdout)
        return self

    def setup_log_to_file(self, file_path, log_level=None):
        if log_level is None:
            log_level = self._default_level
        self._logger_to_file = \
            logging.FileHandler(file_path, mode='a', delay=False)
        self._logger_to_file.setLevel(level=log_level)
        self._logger_to_file.setFormatter(self._logger_format)
        self._logger.addHandler(self._logger_to_file)
        return self
