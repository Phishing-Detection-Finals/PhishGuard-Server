from ..data.user import User
from flask_jwt_extended import create_access_token, create_refresh_token
from ..constants import Constants
import logging


class UsersUtils:

    @staticmethod
    def json_to_user(user_json: dict) -> User:
        user = User()
        user.email = user_json.get("email")
        user.username = user_json.get("username")
        user.set_hash_password(password=user_json.get("password"))
        logging.debug(f"Created User object from JSON: {user_json}")
        return user

    @staticmethod
    def generate_jwt_tokens_and_login_message(user: User) -> dict:
        access_token, refresh_token = UsersUtils.generate_jwt_access_and_refresh_tokens(user_email=user.email)
        formatted_message = Constants.SUCCESSFULLY_LOGIN_MESSAGE.format(user_email=user.email)
        response_dict = UsersUtils.generate_message_with_tokens(message=formatted_message, access_token=access_token,
                                                                refresh_token=refresh_token)
        response_dict["user_details"] = user.to_dict()
        logging.debug(f"Generated JWT tokens and login message for user: {user.email}")
        return response_dict

    @staticmethod
    def generate_jwt_tokens_and_update_email_message(new_email: str) -> dict:
        access_token, refresh_token = UsersUtils.generate_jwt_access_and_refresh_tokens(user_email=new_email)
        formatted_message = Constants.SUCCESSFULLY_UPDATED_EMAIL_MESSAGE.format(email=new_email)
        message_with_tokens = UsersUtils.generate_message_with_tokens(message=formatted_message, access_token=access_token,
                                                                      refresh_token=refresh_token)
        logging.debug(f"Generated JWT tokens and email update message for new email: {new_email}")
        return message_with_tokens

    @staticmethod
    def generate_jwt_access_and_refresh_tokens(user_email: str) -> tuple[str, str]:
        access_token = UsersUtils.generate_jwt_access_token(user_email=user_email)
        refresh_token = UsersUtils.generate_jwt_refresh_token(user_email=user_email)
        logging.debug(f"Generated access and refresh tokens for user email: {user_email}")
        return access_token, refresh_token

    @staticmethod
    def generate_jwt_access_token(user_email: str) -> str:
        access_token = create_access_token(identity=user_email)
        logging.debug(f"Generated access token for user email: {user_email}")
        return access_token

    @staticmethod
    def generate_jwt_refresh_token(user_email: str) -> str:
        refresh_token = create_refresh_token(identity=user_email)
        logging.debug(f"Generated refresh token for user email: {user_email}")
        return refresh_token

    @staticmethod
    def generate_message_with_tokens(message: str, access_token: str, refresh_token: str) -> dict:
        message_with_tokens = {
            "message": message,
            "tokens": UsersUtils.generate_tokens_dict(access_token=access_token, refresh_token=refresh_token)
        }
        logging.debug("Generated message with tokens.")
        return message_with_tokens

    @staticmethod
    def generate_tokens_dict(access_token: str = None, refresh_token: str = None) -> dict:
        tokens = {
            key: value for key, value in {
                "access_token": access_token,
                "refresh_token": refresh_token
            }.items() if value is not None
        }
        logging.debug(f"Generated tokens dictionary: {tokens}")
        return tokens

    @staticmethod
    def is_new_password_equals_to_old_password(user: User, new_password: str) -> bool:
        is_same_password = user.check_password_hash(password=new_password)
        if is_same_password:
            logging.debug("New password is the same as the old password.")
        else:
            logging.debug("New password is different from the old password.")
        return is_same_password
