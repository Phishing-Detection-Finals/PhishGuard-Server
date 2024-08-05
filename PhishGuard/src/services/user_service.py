from ..dal.user_crud import UserCRUD
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.wrong_password_exception import WrongPasswordException
from ..exceptions.previous_user_data_exception import PreviousUserDataException
from ..exceptions.missing_required_fields_exception import MissingRequiredFieldsException
# from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..utils.user_utils import UsersUtils
from ..validator import Validator
from ..constants import Constants
from ..user_param_enum import UserParam


class UserService():
    def __init__(self) -> None:
        pass

    def get_user_details_by_email(self, email: str) -> dict:
        user_email = Validator.validate_email_to_normalized(email=email)
        return UserCRUD.get_user_by_email(email=user_email).to_dict()

    def signup_user(self, user_json: dict) -> dict:
        user_email = user_json.get("email")
        # if user exists, you cannot create a new one with the same email
        if (UserCRUD.is_user_with_email_exists(email=user_email)):
            raise UserAlreadyExistsException(user_email=user_email)

        # validate user email and assigning normalized email
        Validator.validate_user_json(user_json=user_json)
        user = UsersUtils.json_to_user(user_json=user_json)

        return UserCRUD.create_user(user=user)

    def login_user(self, user_json: dict) -> dict:
        # validate user email and assigning normalized email
        Validator.validate_user_json(user_json=user_json, is_username_included=False)
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

    def update_email(self, identity: str, new_email: str) -> dict:
        # check if the new email equals to current one
        user = UserCRUD.get_user_by_email(email=identity)
        new_email = Validator.validate_email_to_normalized(email=new_email)
        if user.email == new_email:
            raise PreviousUserDataException(user_parameter=UserParam.EMAIL)

        if UserCRUD.is_user_with_email_exists(email=new_email):
            raise UserAlreadyExistsException(user_email=new_email)

        UserCRUD.update_email(user_email=identity, new_email=new_email)
        return UsersUtils.generate_jwt_tokens_and_update_email_message(new_email=new_email)

    def update_password(self, identity: str, new_password: str) -> dict:
        Validator.validate_password_strength(password=new_password)
        user = UserCRUD.get_user_by_email(email=identity)
        if UsersUtils.is_new_password_equals_to_old_password(user=user, new_password=new_password):
            raise PreviousUserDataException(user_parameter=UserParam.PASSWORD)
        UserCRUD.update_password(user_email=identity, new_password=new_password)
        return {"message": Constants.SUCCESSFULLY_UPDATED_PASSWORD_MESSAGE}

    def update_settings(self, identity: str, updates: dict) -> dict:
        if not any(key in updates for key in ['username', 'email', 'password']):
            raise MissingRequiredFieldsException()

        try:
            original_password_hash, original_email, original_username = UserService().get_original_user_data(identity=identity)

            if 'username' in updates:
                UserService().update_username(identity=identity, new_username=updates.get("username"))

            if 'password' in updates:
                UserService().update_password(identity=identity, new_password=updates.get("password"))

            if 'email' in updates:
                UserService().update_email(identity=identity, new_email=updates.get("email"))

            return {"message": "Successfully updated user settings"}

        except Exception as e:
            # in case of an exception, revert to the original user
            UserCRUD.revert_user_to_original(user_email=identity, original_password_hash=original_password_hash,
                                             original_email=original_email, original_username=original_username)
            raise e

    def get_original_user_data(self, identity: str) -> tuple[str, str, str]:
        original_user = UserCRUD.get_user_by_email(email=identity)
        return original_user.password_hash, original_user.email, original_user.username