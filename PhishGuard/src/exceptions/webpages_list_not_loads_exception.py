class WebpagesListNotLoadsException(Exception):
    """Exception raised when the trusted list does not return."""

    def __init__(self):
        super().__init__("Error: webpage list not loading")
