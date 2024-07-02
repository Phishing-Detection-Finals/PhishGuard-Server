class UrlNotValidException(Exception):
    """Exception raised when an input url invalid."""

    def __init__(self):
        super().__init__("the url that entered, is not valid")
