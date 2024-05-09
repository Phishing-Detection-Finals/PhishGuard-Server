class OffensiveUsernameException(Exception):
    """Exception raised when an input username inappropriate."""

    def __init__(self):
        super().__init__("the username that entered, is not inappropriate")
