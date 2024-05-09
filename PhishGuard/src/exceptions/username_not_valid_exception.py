class UsernameNotValidException(Exception):
    """Exception raised when an input username invalid."""

    def __init__(self):
        super().__init__("the username that entered, is not valid")
