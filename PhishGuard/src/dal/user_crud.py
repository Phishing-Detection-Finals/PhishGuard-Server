from ..data.user import User
from ..exceptions.wrong_password_or_email_exception import WrongPasswordsOrEmail


class UserCRUD():

    @staticmethod
    def get_user_by_email(email: str) -> User:
        user = User.objects(email=email).first()
        if user:
            return user
        raise WrongPasswordsOrEmail()

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
