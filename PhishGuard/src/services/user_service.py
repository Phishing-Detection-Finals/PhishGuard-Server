from ..dal.user_crud import UserCRUD
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.wrong_password_exception import WrongPasswordException
# from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..utils.user_utils import UsersUtils
from ..constants import Constants


class UserService():
    def __init__(self) -> None:
        pass

    # TODO implement validation of all of the data
    def get_user_details_by_email(self, email: str):
        return UserCRUD.get_user_by_email(email=email).to_dict()

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
        raise WrongPasswordException()

    def refresh_user_access(self, identity: str) -> dict:
        return UsersUtils.generate_tokens_dict(access_token=UsersUtils.generate_jwt_access_token(user_email=identity))

    def delete_user(self, user_email: str) -> dict:
        UserCRUD.delete_user(user_email=user_email)
        return {"message": Constants.SUCCESSFULLY_DELETED_USER_MESSAGE}

    def update_username(self, user_email: str, payload_data: dict):
        # TODO add checks for None username and other validation

        new_username = payload_data.get("username")
        UserCRUD.update_username(user_email, new_username)
        return {"message": Constants.SUCCESSFULLY_UPDATED_USERNAME_MESSAGE.format(username=new_username)}
