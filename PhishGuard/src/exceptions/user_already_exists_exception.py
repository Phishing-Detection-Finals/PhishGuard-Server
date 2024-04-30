class UserAlreadyExistsException(Exception):
    """Exception raised when a user already exist."""

    def __init__(self, user_email: str):
        super().__init__(f"user with Email '{user_email}' already exists.")
