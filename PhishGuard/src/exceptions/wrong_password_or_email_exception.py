class WrongPasswordsOrEmail(Exception):
    """Exception raised when a user entered wrong password or email."""

    def __init__(self):
        super().__init__("The email or password you entered is incorrect. Please try again.")
