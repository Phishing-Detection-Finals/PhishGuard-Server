class PreviousPasswordException(Exception):
    """Exception raised when a user try to update password to he's previous one"""

    def __init__(self):
        super().__init__("Cannot update password: the new password is the same as the previous one.")
