from .data.user import User


class Utils():

    @staticmethod
    def json_to_user(user_json: dict) -> User:
        user = User()
        user.email = user_json.get("email")
        user.username = user_json.get("username")
        user.set_hash_password(password=user_json.get("password"))
        return user
