from ..dal.user_crud import UserCRUD
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.wrong_password_exception import WrongPasswordException
from ..exceptions.previous_user_data_exception import PreviousUserDataException
from ..exceptions.missing_required_fields_exception import MissingRequiredFieldsException
# from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..utils.user_utils import UsersUtils
from ..validator import Validator
from ..constants import Constants
from ..enums.user_param_enum import UserParam
import logging


class UserService:
    def __init__(self) -> None:
        logging.debug("Initializing UserService")
        pass

    def get_user_details_by_email(self, email: str) -> dict:
        logging.debug(f"Fetching user details for email: {email}")
        user_email = Validator.validate_email_to_normalized(email=email)
        user_details = UserCRUD.get_user_by_email(email=user_email).to_dict()
        logging.debug(f"User details: {user_details}")
        return user_details

    def signup_user(self, user_json: dict) -> dict:
        user_email = user_json.get("email")
        logging.debug(f"Signing up user with email: {user_email}")
        # if user exists, you cannot create a new one with the same email
        if UserCRUD.is_user_with_email_exists(email=user_email):
            logging.error(f"User with email {user_email} already exists")
            raise UserAlreadyExistsException(user_email=user_email)

        # validate user email and assigning normalized email
        Validator.validate_user_json(user_json=user_json)
        user = UsersUtils.json_to_user(user_json=user_json)

        created_user = UserCRUD.create_user(user=user)
        logging.debug(f"User created successfully: {created_user}")
        return created_user

    def login_user(self, user_json: dict) -> dict:
        # validate user email and assigning normalized email
        logging.debug(f"Logging in user with email: {user_json.get('email')}")
        Validator.validate_user_json(user_json=user_json, is_username_included=False)
        user = UserCRUD.get_user_by_email(email=user_json.get("email"))

        if user.check_password_hash(password=user_json.get("password")):
            login_message = UsersUtils.generate_jwt_tokens_and_login_message(user=user)
            logging.debug(f"User logged in successfully: {login_message}")
            return login_message

        logging.error("Wrong password provided")
        raise WrongPasswordException()

    def refresh_user_access(self, identity: str) -> dict:
        logging.debug(f"Refreshing access for user with email: {identity}")
        tokens = UsersUtils.generate_tokens_dict(access_token=UsersUtils.generate_jwt_access_token(user_email=identity))
        logging.debug(f"Generated tokens: {tokens}")
        return tokens

    def delete_user(self, identity: str) -> dict:
        logging.debug(f"Deleting user with email: {identity}")
        UserCRUD.delete_user(user_email=identity)
        message = {"message": Constants.SUCCESSFULLY_DELETED_USER_MESSAGE}
        logging.debug(f"User deleted: {message}")
        return message

    def update_username(self, identity: str, new_username: dict) -> dict:
        logging.debug(f"Updating username for user with email: {identity} to {new_username}")
        Validator.validate_username(username=new_username)
        user = UserCRUD.get_user_by_email(email=identity)

        if user.username == new_username:
            logging.error("New username is the same as the old username")
            raise PreviousUserDataException(user_parameter=UserParam.USERNAME)
        UserCRUD.update_username(user_email=identity, new_username=new_username)
        message = {"message": Constants.SUCCESSFULLY_UPDATED_USERNAME_MESSAGE.format(username=new_username)}
        logging.debug(f"Username updated successfully: {message}")
        return message

    def update_email(self, identity: str, new_email: str) -> dict:
        logging.debug(f"Updating email for user with email: {identity} to {new_email}")
        # check if the new email equals to current one
        user = UserCRUD.get_user_by_email(email=identity)
        new_email = Validator.validate_email_to_normalized(email=new_email)

        if user.email == new_email:
            logging.error("New email is the same as the old email")
            raise PreviousUserDataException(user_parameter=UserParam.EMAIL)

        if UserCRUD.is_user_with_email_exists(email=new_email):
            logging.error(f"Email {new_email} already exists")
            raise UserAlreadyExistsException(user_email=new_email)

        UserCRUD.update_email(user_email=identity, new_email=new_email)
        update_message = UsersUtils.generate_jwt_tokens_and_update_email_message(new_email=new_email)
        logging.debug(f"Email updated successfully: {update_message}")
        return update_message

    def update_password(self, identity: str, new_password: str) -> dict:
        logging.debug(f"Updating password for user with email: {identity}")
        Validator.validate_password_strength(password=new_password)
        user = UserCRUD.get_user_by_email(email=identity)

        if UsersUtils.is_new_password_equals_to_old_password(user=user, new_password=new_password):
            logging.error("New password is the same as the old password")
            raise PreviousUserDataException(user_parameter=UserParam.PASSWORD)

        UserCRUD.update_password(user_email=identity, new_password=new_password)
        message = {"message": Constants.SUCCESSFULLY_UPDATED_PASSWORD_MESSAGE}
        logging.debug(f"Password updated successfully: {message}")
        return message

    def update_settings(self, identity: str, updates: dict) -> dict:
        logging.debug(f"Updating settings for user with email: {identity}")
        if not any(key in updates for key in ['username', 'email', 'password']):
            logging.error("No valid fields to update")
            raise MissingRequiredFieldsException()

        try:
            original_password_hash, original_email, original_username = UserService().get_original_user_data(identity=identity)
            logging.debug(f"Original user data fetched for rollback")

            if 'username' in updates:
                UserService().update_username(identity=identity, new_username=updates.get("username"))

            if 'password' in updates:
                UserService().update_password(identity=identity, new_password=updates.get("password"))

            if 'email' in updates:
                UserService().update_email(identity=identity, new_email=updates.get("email"))

            message = {"message": "Successfully updated user settings"}
            logging.debug(f"Settings updated successfully: {message}")
            return message

        except Exception as e:
            logging.error(f"Exception occurred during settings update: {e}")
            # in case of an exception, revert to the original user
            UserCRUD.revert_user_to_original(user_email=identity, original_password_hash=original_password_hash,
                                             original_email=original_email, original_username=original_username)
            logging.debug("Reverted to original user data")
            raise e

    def get_original_user_data(self, identity: str) -> tuple[str, str, str]:
        logging.debug(f"Fetching original user data for email: {identity}")
        original_user = UserCRUD.get_user_by_email(email=identity)
        return original_user.password_hash, original_user.email, original_user.username