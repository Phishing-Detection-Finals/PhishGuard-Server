from ..data.user import User
from flask_jwt_extended import create_access_token, create_refresh_token
from ..constants import Constants


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
        access_token, refresh_token = UsersUtils.generate_jwt_access_and_refresh_tokens(user_email=user.email)
        formatted_message = Constants.SUCCESSFULLY_LOGIN_MESSAGE.format(user_email=user.email)
        return UsersUtils.generate_message_with_tokens(message=formatted_message, access_token=access_token,
                                                       refresh_token=refresh_token)

    @staticmethod
    def generate_jwt_access_and_refresh_tokens(user_email: str) -> tuple[str, str]:
        access_token = UsersUtils.generate_jwt_access_token(user_email=user_email)
        refresh_token = UsersUtils.generate_jwt_refresh_token(user_email=user_email)
        return access_token, refresh_token

    @staticmethod
    def generate_jwt_access_token(user_email: str) -> dict:
        return create_access_token(identity=user_email)

    @staticmethod
    def generate_jwt_refresh_token(user_email: str) -> str:
        return create_refresh_token(identity=user_email)

    @staticmethod
    def generate_message_with_tokens(message: str, access_token: str, refresh_token: str) -> dict:
        return {
            "message": message,
            "tokens": UsersUtils.generate_tokens_dict(access_token=access_token, refresh_token=refresh_token)
        }

    @staticmethod
    def generate_tokens_dict(access_token: str = None, refresh_token: str = None):
        tokens = {
            key: value for key, value in {
                "access_token": access_token,
                "refresh_token": refresh_token
            }.items() if value is not None
        }
        return tokens

    @staticmethod
    def is_new_password_equals_to_old_password(user: User, new_password: str) -> bool:
        if user.check_password_hash(password=new_password):
            return True
        return False
