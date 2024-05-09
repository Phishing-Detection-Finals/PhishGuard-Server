class PasswordStrengthException(Exception):
    """Exception raised when an input password not strong enough."""

    def __init__(self, message: str):
        super().__init__(f"the password that entered, is not strong enough - {message}")
