from ..dal.user_crud import UserCRUD
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
# from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..utils import Utils


class UserService():
    def __init__(self) -> None:
        pass

    def get_user_by_email(self, email: str):
        UserCRUD.get_user_by_email(email=email)

    def signup_user(self, user_json: dict) -> dict:
        user = Utils.json_to_user(user_json=user_json)

        # if user exists, you cannot create a new one with the same email
        if (UserCRUD.is_user_with_email_exists(email=user.email)):
            raise UserAlreadyExistsException(user_email=user.email)

        return UserCRUD.create_user(user=user)

    def login_user(self, user_json):
        # TODO continue and maybe later change get user by email, to find, in order to create hash/find hash
        # if(not UserCRUD.is_user_with_email_exists(email=user.email))
        return
