from ..dal.user_crud import UserCRUD
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.wrong_password_or_email_exception import WrongPasswordsOrEmail
from ..user_utils import UsersUtils


class UserService():
    def __init__(self) -> None:
        pass

    def get_user_by_email(self, email: str):
        UserCRUD.get_user_by_email(email=email).to_dict()

    def signup_user(self, user_json: dict) -> dict:
        user = UsersUtils.json_to_user(user_json=user_json)

        # if user exists, you cannot create a new one with the same email
        if (UserCRUD.is_user_with_email_exists(email=user.email)):
            raise UserAlreadyExistsException(user_email=user.email)

        return UserCRUD.create_user(user=user)

    def login_user(self, user_json: dict) -> dict:
        user = UserCRUD.get_user_by_email(email=user_json.get("email"))
        if user.check_password_hash(password=user_json.get("password")):
            return UsersUtils.generate_jwt_tokens_and_login_message(user=user)
        raise WrongPasswordsOrEmail()
