from ..data.user import User
from ..exceptions.user_not_exists_exception import UserNotExistsException


class UserCRUD():

    @staticmethod
    def get_user_by_email(email: str) -> dict:
        user = User.objects(email=email).first()
        if user:
            return user.to_dict()
        raise UserNotExistsException(email)

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
