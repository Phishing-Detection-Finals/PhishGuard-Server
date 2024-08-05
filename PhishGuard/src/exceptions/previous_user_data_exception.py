from ..enums.user_param_enum import UserParam


class PreviousUserDataException(Exception):
    """Exception raised when a user try to update parameter to he's previous one"""

    def __init__(self, user_parameter: UserParam):
        super().__init__(f"Cannot update {user_parameter.value}: "
                         f"the new {user_parameter.value} is the same as the previous one.")
