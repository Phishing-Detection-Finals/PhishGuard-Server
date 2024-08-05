class WebpageInaccessibleException(Exception):
    """Exception raised when a webpage is inaccessible."""

    def __init__(self, url: str):
        super().__init__(f"the entered url - {url} is inaccessible")
