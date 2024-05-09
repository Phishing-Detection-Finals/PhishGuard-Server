from ..dal.user_crud import UserCRUD
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.wrong_password_exception import WrongPasswordException
from ..exceptions.previous_user_data_exception import PreviousUserDataException
# from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..utils.user_utils import UsersUtils
from ..validator import Validator
from ..constants import Constants
from ..user_param_enum import UserParam


class UserService():
    def __init__(self) -> None:
        pass

    # TODO implement validation of all of the data
    def get_user_details_by_email(self, email: str):
        user_email = Validator.validate_email_to_normalized(email=email)
        return UserCRUD.get_user_by_email(email=user_email).to_dict()

    def signup_user(self, user_json: dict) -> dict:
        # validate user email and assigning normalized email
        Validator.validate_user_json(user_json=user_json)
        user = UsersUtils.json_to_user(user_json=user_json)

        # if user exists, you cannot create a new one with the same email
        if (UserCRUD.is_user_with_email_exists(email=user.email)):
            raise UserAlreadyExistsException(user_email=user.email)

        return UserCRUD.create_user(user=user)

    def login_user(self, user_json: dict) -> dict:
        # validate user email and assigning normalized email
        Validator.validate_user_json(user_json=user_json)
        user = UserCRUD.get_user_by_email(email=user_json.get("email"))
        if user.check_password_hash(password=user_json.get("password")):
            return UsersUtils.generate_jwt_tokens_and_login_message(user=user)
        raise WrongPasswordException()

    def refresh_user_access(self, identity: str) -> dict:
        return UsersUtils.generate_tokens_dict(access_token=UsersUtils.generate_jwt_access_token(user_email=identity))

    def delete_user(self, identity: str) -> dict:
        UserCRUD.delete_user(user_email=identity)
        return {"message": Constants.SUCCESSFULLY_DELETED_USER_MESSAGE}

    def update_username(self, identity: str, new_username: dict) -> dict:
        Validator.validate_username(username=new_username)
        user = UserCRUD.get_user_by_email(email=identity)
        if user.username == new_username:
            raise PreviousUserDataException(user_parameter=UserParam.USERNAME)
        UserCRUD.update_username(user_email=identity, new_username=new_username)
        return {"message": Constants.SUCCESSFULLY_UPDATED_USERNAME_MESSAGE.format(username=new_username)}

    def update_email(identity: str, new_email: str) -> dict:
        # check if the new email equals to current one
        user = UserCRUD.get_user_by_email(email=identity)
        new_email = Validator.validate_email_to_normalized(email=new_email)
        if user.email == new_email:
            raise PreviousUserDataException(user_parameter=UserParam.EMAIL)

        if UserCRUD.is_user_with_email_exists(email=new_email):
            raise UserAlreadyExistsException(user_email=new_email)

        UserCRUD.update_email(user_email=identity, new_email=new_email)
        return {"message": Constants.SUCCESSFULLY_UPDATED_EMAIL_MESSAGE.format(email=new_email)}

    def update_password(identity: str, new_password: str) -> dict:
        Validator.validate_password_strength(password=new_password)
        user = UserCRUD.get_user_by_email(email=identity)
        if UsersUtils.is_new_password_equals_to_old_password(user=user, new_password=new_password):
            raise PreviousUserDataException(user_parameter=UserParam.PASSWORD)
        UserCRUD.update_password(user_email=identity, new_password=new_password)
        return {"message": Constants.SUCCESSFULLY_UPDATED_PASSWORD_MESSAGE}
