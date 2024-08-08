from ..data.user import User
from ..exceptions.user_not_exists_exception import UserNotExistsException
import logging


class UserCRUD:

    @staticmethod
    def get_user_by_email(email: str) -> User:
        logging.debug(f"Attempting to retrieve user by email: {email}")
        user = User.objects(email=email).first()
        if user:
            logging.info(f"User found: {email}")
            return user
        logging.warning(f"User not found: {email}")
        raise UserNotExistsException(user_email=email)

    @staticmethod
    def create_user(user: User) -> dict:
        logging.debug(f"Attempting to create user: {user.email}")
        user.save()
        logging.info(f"User created: {user.email}")
        return {"user_email": str(user.email)}

    @staticmethod
    def is_user_with_email_exists(email: str) -> bool:
        try:
            UserCRUD.get_user_by_email(email=email)
            logging.info(f"User exists: {email}")
            return True
        except UserNotExistsException:
            logging.info(f"User does not exist: {email}")
            return False

    @staticmethod
    def delete_user(user_email: str) -> None:
        logging.debug(f"Attempting to delete user: {user_email}")
        user = UserCRUD.get_user_by_email(email=user_email)
        user.delete()
        logging.info(f"User deleted: {user_email}")

    @staticmethod
    def update_username(user_email: str, new_username: str) -> None:
        logging.debug(f"Attempting to update username for user: {user_email}")
        user = UserCRUD.get_user_by_email(email=user_email)
        user.username = new_username
        user.save()
        logging.info(f"Username updated for user {user_email} to {new_username}")

    @staticmethod
    def update_email(user_email: str, new_email: str) -> None:
        logging.debug(f"Attempting to update email for user: {user_email}")
        user = UserCRUD.get_user_by_email(email=user_email)
        user.email = new_email
        user.save()
        logging.info(f"Email updated for user {user_email} to {new_email}")

    @staticmethod
    def update_password(user_email: str, new_password: str) -> None:
        logging.debug(f"Attempting to update password for user: {user_email}")
        user = UserCRUD.get_user_by_email(email=user_email)
        User.set_hash_password(self=user, password=new_password)
        user.save()
        logging.info(f"Password updated for user {user_email}")

    @staticmethod
    def revert_user_to_original(user_email: str, original_password_hash: str, original_email: str,
                                original_username: str) -> None:
        logging.debug(f"Attempting to revert user to original data: {user_email}")
        user = UserCRUD.get_user_by_email(email=user_email)
        user.password_hash = original_password_hash
        user.email = original_email
        user.username = original_username
        user.save()
        logging.info(f"User reverted to original data: {user_email}")
