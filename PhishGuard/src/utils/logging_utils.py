import logging


class CustomFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None):
        # Define widths for each column
        self.logger_name_width = 9
        self.level_name_width = 8
        self.filename_width = 30
        self.func_name_width = 25
        self.message_width = 50

        # Update the format string to include the widths
        if fmt is None:
            fmt = (f'%(asctime)s - '
                   f'%(levelname)-{self.level_name_width}s - '
                   f'%(name)-{self.logger_name_width}s - '
                   f'%(filename)-{self.filename_width}s - '
                   f'%(funcName)-{self.func_name_width}s - '
                   f'%(message)-{self.message_width}s')
        super().__init__(fmt, datefmt)

    def format(self, record):
        # Adjust the record's message to fit within the specified width
        record.message = self._truncate(record.getMessage(), self.message_width)
        return super().format(record)

    def _truncate(self, message, width):
        """ Truncate or pad message to fit the specified width. """
        if len(message) > width:
            return message[:width - 3] + '...'
        return message.ljust(width)


# Configure logging
def setup_logging():
    formatter = CustomFormatter()
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
