from ..data.user import User
# from ..exceptions.wrong_password_or_email_exception import WrongPasswordsOrEmail
from ..exceptions.user_not_exists_exception import UserNotExistsException


class UserCRUD():

    @staticmethod
    def get_user_by_email(email: str) -> User:
        user = User.objects(email=email).first()
        if user:
            return user
        raise UserNotExistsException(user_email=email)

    @staticmethod
    def create_user(user: User) -> dict:
        user.save()
        return {"user_email": str(user.email)}

    @staticmethod
    def is_user_with_email_exists(email: str) -> bool:
        try:
            UserCRUD.get_user_by_email(email=email)
            return True
        except UserNotExistsException:
            return False

    @staticmethod
    def delete_user(user_email: str) -> None:
        user = UserCRUD.get_user_by_email(email=user_email)
        user.delete()

    @staticmethod
    def update_username(user_email: str, new_username: str) -> None:
        user = UserCRUD.get_user_by_email(email=user_email)
        user.username = new_username
        user.save()

    @staticmethod
    def update_email(user_email: str, new_email: str) -> None:
        user = UserCRUD.get_user_by_email(email=user_email)
        user.email = new_email
        user.save()

    @staticmethod
    def update_password(user_email: str, new_password: str) -> None:
        user = UserCRUD.get_user_by_email(email=user_email)
        User.set_hash_password(self=user, password=new_password)
        user.save()
