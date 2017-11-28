import logging


class NullHandler(logging.Handler):
    def emit(self, record):
        pass


logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())
