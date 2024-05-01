from .data.user import User
from flask_jwt_extended import create_access_token, create_refresh_token
from .constants import Constants


class UsersUtils():

    @staticmethod
    def json_to_user(user_json: dict) -> User:
        user = User()
        user.email = user_json.get("email")
        user.username = user_json.get("username")
        user.set_hash_password(password=user_json.get("password"))
        return user

    @staticmethod
    def generate_jwt_tokens_and_login_message(user: User) -> dict:
        access_token, refresh_token = UsersUtils.generate_jwt_tokens(user_email=user.email)
        formatted_message = Constants.SUCCESSFULLY_LOGIN_MESSAGE.format(user_email=user.email)
        return UsersUtils.generate_message_with_tokens(message=formatted_message, access_token=access_token,
                                                       refresh_token=refresh_token)

    @staticmethod
    def generate_jwt_tokens(user_email: str) -> tuple[str, str]:
        access_token = create_access_token(identity=user_email)
        refresh_token = create_refresh_token(identity=user_email)
        return access_token, refresh_token

    @staticmethod
    def generate_message_with_tokens(message: str, access_token: str, refresh_token: str) -> dict:
        return {
            "message": message,
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        }
