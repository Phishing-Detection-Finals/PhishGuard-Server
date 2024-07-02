from email_validator import validate_email
from .exceptions.password_strength_exception import PasswordStrengthException
# from .exceptions.offensive_username_exception import OffensiveUsernameException
from .exceptions.username_not_valid_exception import UsernameNotValidException
from .exceptions.missing_required_fields_exception import MissingRequiredFieldsException
from .exceptions.url_not_valid_exception import UrlNotValidException
from .constants import Constants
# from profanity_check import predict  # for checking offensive username
import validators


class Validator():
    @staticmethod
    def validate_user_json(user_json: dict, is_username_included: bool = True) -> None:
        user_json["email"] = Validator.validate_email_to_normalized(email=user_json.get("email"))
        Validator.validate_password_strength(password=user_json.get("password"))
        if is_username_included:
            Validator.validate_username(username=user_json.get("username"))

    @staticmethod
    def validate_required_fields(data: dict, required_fields: list[str]) -> None:
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            raise MissingRequiredFieldsException(missing_fields=missing_fields)

    @staticmethod
    def validate_email_to_normalized(email: str) -> str:
        valid_normalized = validate_email(email.lower(), check_deliverability=False)
        return valid_normalized.normalized

    @staticmethod
    def validate_username(username: str) -> None:
        if not Constants.USERNAME_MIN_CHARS <= len(username) <= Constants.USERNAME_MAX_CHARS:
            raise UsernameNotValidException(message=Constants.MIN_MAX_CHARS_USERNAME_EXCEPTION_MESSAGE)

        # is_offensive = predict([username])  # returns an array 0 - good, 1 - bad
        # if is_offensive[0] == 1:
        #     raise OffensiveUsernameException()

    @staticmethod
    def validate_password_strength(password: str) -> None:
        # Check if password length is at least 8 characters
        if len(password) < 8:
            raise PasswordStrengthException("Password must be at least 8 characters long.")

        # Check if password contains at least one uppercase letter
        if not any(char.isupper() for char in password):
            raise PasswordStrengthException("Password must contain at least one uppercase letter.")

        # Check if password contains at least one lowercase letter
        if not any(char.islower() for char in password):
            raise PasswordStrengthException("Password must contain at least one lowercase letter.")

        # Check if password contains at least one digit
        if not any(char.isdigit() for char in password):
            raise PasswordStrengthException("Password must contain at least one digit.")

        # Check if password contains at least one special character
        if not any(char in Constants.SPECIAL_CHARACTERS for char in password):
            raise PasswordStrengthException("Password must contain at least one special character.")

    @staticmethod
    def validate_url(url: str) -> None:
        if not validators.url(url):
            raise UrlNotValidException()
