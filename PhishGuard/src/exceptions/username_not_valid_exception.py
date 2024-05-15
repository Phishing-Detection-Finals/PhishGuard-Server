class UsernameNotValidException(Exception):
    """Exception raised when an input username invalid."""

    def __init__(self, message: str):
        super().__init__(f"the username that entered, is not valid - {message}")
