class UserNotExistsException(Exception):
    """Exception raised when a user does not exist."""

    def __init__(self, user_email: str):
        super().__init__(f"user with Email '{user_email}' does not exist.")
