# from .data.user import User
from email_validator import validate_email


# TODO add tests for validation
class Validator():
    @staticmethod
    def validate_user_json(user_json: dict):
        user_json["email"] = Validator.validate_email_to_normalized(email=user_json.get("email"))

    @staticmethod
    def validate_email_to_normalized(email: str) -> str:
        return validate_email(email).get("email")
