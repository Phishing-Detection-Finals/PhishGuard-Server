from email_validator import validate_email
from .exceptions.password_strength_exception import PasswordStrengthException
# from .exceptions.offensive_username_exception import OffensiveUsernameException
from .exceptions.username_not_valid_exception import UsernameNotValidException
from .exceptions.missing_required_fields_exception import MissingRequiredFieldsException
from .exceptions.url_not_valid_exception import UrlNotValidException
from .constants import Constants
# from profanity_check import predict  # for checking offensive username
import validators
import logging


class Validator:
    @staticmethod
    def validate_user_json(user_json: dict, is_username_included: bool = True) -> None:
        logging.debug(f"Validating user JSON: {user_json}")
        user_json["email"] = Validator.validate_email_to_normalized(email=user_json.get("email"))
        Validator.validate_password_strength(password=user_json.get("password"))
        if is_username_included:
            Validator.validate_username(username=user_json.get("username"))

    @staticmethod
    def validate_required_fields(data: dict, required_fields: list[str]) -> None:
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            logging.error(f"Missing required fields: {missing_fields}")
            raise MissingRequiredFieldsException(missing_fields=missing_fields)
        else:
            logging.debug("All required fields are present.")

    @staticmethod
    def validate_email_to_normalized(email: str) -> str:
        valid_normalized = validate_email(email.lower(), check_deliverability=False)
        return valid_normalized.normalized

    @staticmethod
    def validate_username(username: str) -> None:
        if not Constants.USERNAME_MIN_CHARS <= len(username) <= Constants.USERNAME_MAX_CHARS:
            logging.error(f"Username '{username}' does not meet length requirements.")
            raise UsernameNotValidException(message=Constants.MIN_MAX_CHARS_USERNAME_EXCEPTION_MESSAGE)
        else:
            logging.debug(f"Username '{username}' is valid.")

        # is_offensive = predict([username])  # returns an array 0 - good, 1 - bad
        # if is_offensive[0] == 1:
        #     logging.warning(f"Username '{username}' is offensive.")
        #     raise OffensiveUsernameException()

    @staticmethod
    def validate_password_strength(password: str) -> None:

        # Check if password length is at least 8 characters
        if len(password) < 8:
            logging.error("Password is too short.")
            raise PasswordStrengthException("Password must be at least 8 characters long.")

        # Check if password contains at least one uppercase letter
        if not any(char.isupper() for char in password):
            logging.error("Password does not contain an uppercase letter.")
            raise PasswordStrengthException("Password must contain at least one uppercase letter.")

        # Check if password contains at least one lowercase letter
        if not any(char.islower() for char in password):
            logging.error("Password does not contain a lowercase letter.")
            raise PasswordStrengthException("Password must contain at least one lowercase letter.")

        # Check if password contains at least one digit
        if not any(char.isdigit() for char in password):
            logging.error("Password does not contain a digit.")
            raise PasswordStrengthException("Password must contain at least one digit.")

        # Check if password contains at least one special character
        if not any(char in Constants.SPECIAL_CHARACTERS for char in password):
            logging.error("Password does not contain a special character.")
            raise PasswordStrengthException("Password must contain at least one special character.")
        logging.debug("Password meets all strength requirements.")

    @staticmethod
    def validate_url(url: str) -> None:
        if not validators.url(url):
            logging.error(f"Invalid URL: {url}")
            raise UrlNotValidException()
        else:
            logging.debug(f"URL '{url}' is valid.")
