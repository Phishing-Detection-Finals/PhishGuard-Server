class WrongPasswordException(Exception):
    """Exception raised when a user entered wrong password."""

    def __init__(self):
        super().__init__("The password you entered is incorrect. Please try again.")
