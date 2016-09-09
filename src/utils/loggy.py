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

    AC_STDOUT_DEBUG = "STDOUT_DEBUG"
    AC_STDOUT = "STDOUT"
    AC_FILE = "FILE"

    def __init__(self,
                 logger_format=None,
                 log_level=INFO,
                 log_file_location='connector.log',
                 auto_config_flags=list()):

        # logger format
        if logger_format is None:
            logger_format = "%(asctime)s %(levelname)s - [%(thread)d] " \
                            "%(filename)s:%(lineno)s - %(funcName)s : " \
                            "%(message)s"

        # grab and config the root logger
        self._logger = logging.getLogger()
        self._logger_format = logging.Formatter(logger_format)
        self._logger.setLevel(log_level)
        self._default_level = log_level

        # setup definitions for later.. makes pycharm happy about
        # strict PEP requirements
        self._logger_to_stderr = None
        self._logger_to_stdout = None
        self._logger_to_file = None

        # for ease of use, we have some quick configs that can be used
        if auto_config_flags:
            if Loggy.AC_STDOUT_DEBUG in auto_config_flags:
                self.setup_log_to_stdout(Loggy.DEBUG)
            if Loggy.AC_STDOUT in auto_config_flags:
                self.setup_log_to_stdout(log_level)
            if Loggy.AC_FILE in auto_config_flags:
                self.setup_log_to_file(log_file_location, log_level=log_level)

        # Output an initialized banner
        self._logger.info("---------------------- "
                          "LOGGER Started "
                          "---------------------- ")

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
