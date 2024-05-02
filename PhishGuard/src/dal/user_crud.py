from ..data.user import User
# from ..exceptions.wrong_password_or_email_exception import WrongPasswordsOrEmail
from ..exceptions.user_not_exists_exception import UserNotExistsException


class UserCRUD():

    @staticmethod
    def get_user_by_email(email: str) -> User:
        user = User.objects(email=email).first()
        if user:
            return user
        raise UserNotExistsException

    @staticmethod
    def create_user(user: User) -> dict:
        user.save()
        return {"user_id": str(user._id)}

    @staticmethod
    def is_user_with_email_exists(email: str) -> bool:
        user = User.objects(email=email).first()
        if user:
            return True
        return False

    @staticmethod
    def delete_user(user_email: str) -> None:
        user = User.objects(email=user_email).first()
        if user:
            user.delete()
            return
        raise UserNotExistsException

    @staticmethod
    def update_username(user_email: str, new_username: str) -> None:
        user = User.objects(email=user_email).first()
        if user:
            user.username = new_username
            user.save()
            return
        raise UserNotExistsException
